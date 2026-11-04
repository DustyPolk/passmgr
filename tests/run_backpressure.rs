//! A `run` client that stops reading must backpressure the child, not time out
//! (TODO R.49).
//!
//! The daemon serves `run` on a worker with a non-blocking socket: when the
//! client's queue is full the worker waits in `poll` and keeps checking the
//! run's stop conditions. Before R.49 the socket kept a 5 s write timeout, so a
//! reader paused for longer than that got a truncated stream with no terminal
//! frame and the child was killed; `lock` also had to wait for that timeout.
//!
//! Both tests use a child that writes far more than a Unix socket buffers, so
//! it is provably blocked on the reader. The pause in the first test is a
//! scenario, not synchronization; the second waits until the client's receive
//! queue stops growing before it sends `lock`.

#![cfg(unix)]

mod support;

use support::*;

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use passmgr::protocol::{self, Request, Response, RunExit, RunFrame};

/// Bytes the child writes to stdout: 64 x 64 KiB = 4 MiB, well past any socket
/// buffer, so a client that does not read keeps the child blocked on its pipe.
const OUTPUT_BYTES: usize = 64 * 65536;

/// A child that writes [`OUTPUT_BYTES`] to stdout and nothing to stderr.
const WRITE_FOUR_MIB: &str = "dd if=/dev/zero bs=65536 count=64 2>/dev/null";

/// How long a reader may refuse to read in the first test. Longer than the old
/// 5 s socket write timeout, which is exactly what used to truncate the run.
const READER_PAUSE: Duration = Duration::from_secs(7);

fn run_stream(fixture: &Fixture) -> UnixStream {
    let mut stream = UnixStream::connect(fixture.socket()).expect("connect");
    stream
        .set_read_timeout(Some(WAIT))
        .expect("set read timeout");
    stream
        .write_all(
            &protocol::encode(
                &fixture.token,
                &fixture.run_request("API_KEY", &["/bin/sh", "-c", WRITE_FOUR_MIB]),
            )
            .expect("encode request"),
        )
        .expect("write request");
    stream
}

fn next_frame(decoder: &mut protocol::FrameDecoder) -> Option<RunFrame> {
    let body = decoder.next_frame().expect("decode frame")?;
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    Some(protocol::decode_run_frame(&framed).expect("decode run frame"))
}

fn read_until_eof(mut stream: UnixStream) -> Vec<RunFrame> {
    let mut decoder = protocol::FrameDecoder::new();
    let mut frames = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).expect("read run stream");
        if read == 0 {
            break;
        }
        decoder.push(&buffer[..read]).expect("framing");
        while let Some(frame) = next_frame(&mut decoder) {
            frames.push(frame);
        }
    }
    frames
}

/// How many bytes the peer could still send before the client reads anything.
fn queued_bytes(stream: &UnixStream) -> libc::c_int {
    let mut bytes: libc::c_int = 0;
    // SAFETY: `FIONREAD` writes one `int` to the valid pointer; the fd is open
    // for the lifetime of `stream`.
    let result = unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &mut bytes) };
    assert_eq!(result, 0, "FIONREAD failed");
    bytes
}

/// Wait until the client's queue has stopped growing: the daemon can no longer
/// write and is therefore parked in its write wait. Deadline-bounded, so a
/// daemon that does not block fails the test instead of hanging it.
fn wait_until_the_reader_is_the_bottleneck(stream: &UnixStream) {
    let deadline = Instant::now() + WAIT;
    let mut previous = -1;
    let mut stable_samples = 0;
    loop {
        let queued = queued_bytes(stream);
        if queued >= 64 * 1024 && queued == previous {
            stable_samples += 1;
            if stable_samples >= 2 {
                return;
            }
        } else {
            stable_samples = 0;
        }
        previous = queued;
        assert!(
            Instant::now() < deadline,
            "the daemon never blocked on the stalled reader (last {queued} bytes queued)"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_paused_reader_gets_every_byte_and_the_exit_frame() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let stream = run_stream(&fixture);

    // Refuse to read while the child fills its pipe, the frame channel and
    // both socket buffers. The old write timeout killed the run here.
    std::thread::sleep(READER_PAUSE);

    let frames = read_until_eof(stream);
    let stdout = stdout_bytes(&frames);
    assert_eq!(
        stdout.len(),
        OUTPUT_BYTES,
        "the paused reader lost child output"
    );
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));
    assert!(
        !stdout
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "the secret reached the run stream"
    );

    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn lock_is_not_delayed_by_a_stalled_run_client() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let stream = run_stream(&fixture);

    // Do not read: the child is blocked behind a full socket. Once the client
    // queue is stable, the daemon worker is waiting for room to write.
    wait_until_the_reader_is_the_bottleneck(&stream);

    let started = Instant::now();
    let response = request(&fixture.socket(), &fixture.token, &Request::Lock);
    let elapsed = started.elapsed();

    assert_eq!(response, Response::Locked);
    assert!(
        elapsed < Duration::from_secs(2),
        "lock waited {elapsed:?} behind a stalled run write"
    );

    // The lock cancelled the run: the client got what was already queued, then
    // EOF without an exit frame, so nothing claims the child finished.
    let frames = read_until_eof(stream);
    assert_ne!(
        frames.last(),
        Some(&RunFrame::Exit(RunExit::Code(0))),
        "a cancelled run claimed to finish"
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}
