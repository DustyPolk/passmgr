//! End-to-end proof that redaction's holdback is not a prefix oracle (R.36).
//!
//! An agent that controls bytes a granted program relays can print
//! `known + guess`, pause, and watch whether the output is delayed. If the
//! redactor only held back bytes that looked like a prefix of the secret, a
//! correct guess would stall and a wrong one would pass through. The redactor
//! now holds a fixed-length window regardless of content, so both cases must
//! stay silent during the pause.

#![cfg(unix)]

mod support;

use support::{Fixture, SECRET, WAIT, assert_exited};

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use passmgr::protocol::{self, FrameDecoder, RunFrame};

/// How long to watch for output that must be held back. The child pauses for
/// two seconds, so a leak shows up well inside this window.
const QUIET: Duration = Duration::from_millis(500);

/// A sentinel the child prints before the guess. It is longer than the window,
/// so the daemon must emit exactly these bytes before the pause, which tells
/// the test that the guess has reached the redactor.
const SENTINEL: &[u8] = b"RELAY-READY";

/// The child prints the sentinel, then `$1`, pauses, then a tail.
const PROGRAM: &str = r#"printf RELAY-READY; printf %s "$1"; sleep 2; printf ' tail'"#;

struct Relay {
    decoder: FrameDecoder,
    frames: Vec<RunFrame>,
    raw: Vec<u8>,
}

impl Relay {
    fn new() -> Self {
        Self {
            decoder: FrameDecoder::new(),
            frames: Vec::new(),
            raw: Vec::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
        self.decoder.push(bytes).expect("valid framing");
        while let Some(body) = self.decoder.next_frame().expect("decode frame") {
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            self.frames
                .push(protocol::decode_run_frame(&frame).expect("run frame"));
        }
    }

    fn stdout(&self) -> Vec<u8> {
        support::stdout_bytes(&self.frames)
    }
}

/// Run one guess and prove it is not relayed while the child pauses.
fn exercise(guess: &str) {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    let mut stream = UnixStream::connect(&socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    let request = fixture.run_request("API_KEY", &["/bin/sh", "-c", PROGRAM, "sh", guess]);
    stream
        .write_all(&protocol::encode(&fixture.token, &request).expect("encode request"))
        .expect("write request");

    let mut relay = Relay::new();
    let mut buffer = [0u8; 4096];
    while relay.stdout().len() < SENTINEL.len() {
        let read = stream.read(&mut buffer).expect("read sentinel");
        assert!(read > 0, "the daemon closed the run before the sentinel");
        relay.feed(&buffer[..read]);
    }
    // The window is `SECRET.len() - 1` and the guess is exactly that long, so
    // only the sentinel may have been emitted before the pause.
    assert_eq!(
        relay.stdout(),
        SENTINEL,
        "unexpected output before the pause: {:?}",
        relay.frames
    );

    stream
        .set_read_timeout(Some(QUIET))
        .expect("quiet read timeout");
    match stream.read(&mut buffer) {
        Ok(0) => panic!("the daemon closed the run during the pause"),
        Ok(read) => panic!(
            "{read} bytes of a held prefix were relayed during the pause: {:?}",
            &buffer[..read]
        ),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => panic!("reading during the pause: {err}"),
    }

    // With more output and then EOF, the held bytes must come out in order.
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    loop {
        let read = stream.read(&mut buffer).expect("drain the run");
        if read == 0 {
            break;
        }
        relay.feed(&buffer[..read]);
    }

    let expected = [SENTINEL, guess.as_bytes(), b" tail"].concat();
    assert_eq!(relay.stdout(), expected, "frames: {:?}", relay.frames);
    assert_exited(&relay.frames, 0);
    assert!(
        !relay
            .raw
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "the canary reached the relayed bytes"
    );

    assert_eq!(
        support::request(&socket, &fixture.token, &protocol::Request::Lock),
        protocol::Response::Locked
    );
    assert!(support::wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn a_held_prefix_does_not_reveal_whether_it_is_correct() {
    // The last byte of a proper prefix is flipped: same length, different
    // content. Both must be treated identically.
    let correct = SECRET.as_bytes()[..SECRET.len() - 1].to_vec();
    let mut wrong = correct.clone();
    let last = wrong.len() - 1;
    wrong[last] ^= 0x01;
    assert_ne!(correct, wrong);
    assert!(!SECRET.as_bytes().starts_with(&wrong));

    exercise(std::str::from_utf8(&correct).expect("ascii"));
    exercise(std::str::from_utf8(&wrong).expect("ascii"));
}
