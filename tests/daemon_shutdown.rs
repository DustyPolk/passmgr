//! Cancellation and shutdown tests for the unlock daemon (`pmd`).
//!
//! `lock` and `SIGTERM`/`SIGINT` must kill every in-flight child (and its
//! process group) and leave no socket, session file or key behind, even when a
//! grandchild keeps the output pipes open. The idle timeout wipes the key when
//! nothing is running, but never kills a command that is still in flight.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use passmgr::protocol::{Request, Response, RunExit, RunFrame};
use passmgr::socket::RuntimePaths;

/// A `run` whose child reports its pid, closes both output pipes and then
/// sleeps. The daemon has nothing left to relay, but the process is alive.
fn detached_output_run(fixture: &Fixture, pid_file: &Path) -> Request {
    let script = format!(
        "echo $$ > {}; exec >&- 2>&-; exec sleep 30",
        pid_file.display()
    );
    fixture.run_request("API_KEY", &["/bin/sh", "-c", &script])
}

/// Poll until the child has written its pid to `path`.
fn wait_for_pid(path: &Path) -> libc::pid_t {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<libc::pid_t>() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the child did not report its pid"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll until `pid` no longer exists, proving the daemon reaped the child.
fn wait_for_process_exit(pid: libc::pid_t) {
    wait_for_process_exit_within(pid, WAIT);
}

/// As [`wait_for_process_exit`], but with a caller-chosen deadline.
fn wait_for_process_exit_within(pid: libc::pid_t, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: signal 0 only checks for the process's existence; the pid
        // came from a child of this test's daemon.
        if unsafe { libc::kill(pid, 0) } != 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH),
                "unexpected error probing for the child"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon did not kill and reap the injected child"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A run whose client disconnects must be cancelled: the child cannot keep
/// the secret in its environment because nobody is listening any more, and the
/// idle deadline cannot stay suspended for as long as that child happens to
/// live.
#[test]
fn a_run_whose_client_disconnects_is_cancelled_and_lets_the_idle_timeout_expire() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();
    let pid_file = fixture.temp_path("child.pid");
    // Report the pid, then keep both output pipes open and stay alive. The
    // daemon has nothing to relay, so only the client socket can tell it that
    // the caller is gone.
    let script = format!("echo $$ > {}; exec sleep 30", pid_file.display());
    let ask = fixture.run_request("API_KEY", &["/bin/sh", "-c", &script]);

    let mut stream = UnixStream::connect(&socket).expect("connect");
    stream
        .write_all(&passmgr::protocol::encode(&fixture.token, &ask).expect("encode request"))
        .expect("write run request");

    let pid = wait_for_pid(&pid_file);
    let started = Instant::now();
    // What an agent host does when a tool call times out.
    drop(stream);

    wait_for_process_exit_within(pid, Duration::from_secs(2));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the daemon only noticed the disconnect after the child exited"
    );

    // The run is unregistered, so the idle deadline is reached and the key is
    // wiped. Without the cancellation this run would suspend the deadline for
    // the child's full 30 s.
    let status = wait_for_exit(&mut child, Duration::from_secs(6));
    assert!(status.success(), "pmd exit status after idle: {status:?}");
    assert!(!socket.exists(), "an idle timeout removes the socket");
}

#[test]
fn lock_cancels_a_run_whose_child_keeps_running() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let pid_file = fixture.temp_path("child.pid");
    let ask = detached_output_run(&fixture, &pid_file);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let run = std::thread::spawn(move || read_run(&run_socket, &token, &ask));

    let pid = wait_for_pid(&pid_file);
    let started = Instant::now();
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "lock had to wait for the child to exit"
    );

    let (frames, _) = run.join().expect("run thread");
    assert!(
        frames.is_empty(),
        "a cancelled run emits no terminal frame: {frames:?}"
    );

    assert!(wait_for_exit(&mut child, WAIT).success());
    wait_for_process_exit(pid);
    assert!(!socket.exists(), "lock removes the socket");
}

#[test]
fn sigterm_cancels_a_run_whose_child_keeps_running() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let pid_file = fixture.temp_path("child.pid");
    let ask = detached_output_run(&fixture, &pid_file);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let run = std::thread::spawn(move || read_run(&run_socket, &token, &ask));

    let pid = wait_for_pid(&pid_file);
    let pmd_pid = child.id() as libc::pid_t;
    // SAFETY: the pid belongs to a live child of this process.
    assert_eq!(
        unsafe { libc::kill(pmd_pid, libc::SIGTERM) },
        0,
        "kill failed"
    );

    let started = Instant::now();
    assert!(wait_for_exit(&mut child, WAIT).success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "SIGTERM had to wait for the child to exit"
    );

    let (frames, _) = run.join().expect("run thread");
    assert!(frames.is_empty(), "a cancelled run emits no terminal frame");
    wait_for_process_exit(pid);
}

/// The idle deadline must not kill a command that is still running. A run
/// accepted 0.5 s before the deadline keeps the daemon (and its key) alive
/// until the child finishes; then the timer starts again.
#[test]
fn a_run_in_flight_is_not_killed_by_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "3"]);
    let socket = fixture.socket();

    // Let the idle deadline get close before starting a command that outlives
    // it by seconds.
    std::thread::sleep(Duration::from_millis(2_500));
    let ask = fixture.run_request("API_KEY", &["/bin/sh", "-c", "sleep 5; printf done"]);
    let (frames, _) = read_run(&socket, &fixture.token, &ask);

    assert_eq!(
        stdout_bytes(&frames),
        b"done",
        "the idle timeout killed the run: {frames:?}"
    );
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the daemon stopped while the run was still going"
    );

    // With no run in flight, the idle timer expires normally.
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status after idle: {status:?}");
    assert!(!socket.exists(), "an idle timeout removes the socket");
}

/// The idle timeout wipes the key when no run is in flight: the socket and the
/// session file are gone and a reconnect is refused.
#[test]
fn idle_timeout_removes_the_socket_and_session_file_and_refuses_a_reconnect() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();
    let session_path = store_session(&fixture);

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status after idle: {status:?}");
    assert!(!socket.exists(), "an idle timeout removes the socket");
    assert!(
        !session_path.exists(),
        "an idle timeout removes the session file"
    );
    assert!(
        UnixStream::connect(&socket).is_err(),
        "a daemon that went idle must not accept a reconnect"
    );
}

/// A `run` whose child exits at once but leaves a grandchild (`sleep`) holding
/// both output pipes, so the relay never sees EOF. This is the shape that made
/// `lock` and `SIGTERM` wait for the grandchild to exit.
fn grandchild_output_run(fixture: &Fixture, pid_file: &Path) -> Request {
    let script = format!("sleep 30 & echo $! > {}", pid_file.display());
    fixture.run_request("API_KEY", &["/bin/sh", "-c", &script])
}

/// Write this daemon's session file, as `passmgr unlock` does, and return its
/// path so a test can prove the daemon removed it.
fn store_session(fixture: &Fixture) -> PathBuf {
    let paths = RuntimePaths::at(&fixture.runtime);
    passmgr::session::store(&paths, &fixture.token).expect("store session");
    paths.session()
}

#[test]
fn lock_cancels_a_run_whose_grandchild_holds_the_pipes() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let session_path = store_session(&fixture);
    let pid_file = fixture.temp_path("grandchild.pid");
    let ask = grandchild_output_run(&fixture, &pid_file);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let run = std::thread::spawn(move || read_run(&run_socket, &token, &ask));

    let grandchild = wait_for_pid(&pid_file);
    let started = Instant::now();
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "lock waited for the grandchild holding the pipes"
    );
    // The acknowledgement is written last, so by the time the client sees it
    // the socket, the session file and the key are already gone.
    assert!(!socket.exists(), "lock removes the socket before answering");
    assert!(
        !session_path.exists(),
        "lock removes the session file before answering"
    );

    assert!(wait_for_exit(&mut child, WAIT).success());
    let (frames, _) = run.join().expect("run thread");
    assert!(
        frames.is_empty(),
        "a cancelled run emits no terminal frame: {frames:?}"
    );
    wait_for_process_exit(grandchild);
}

#[test]
fn sigterm_cancels_a_run_whose_grandchild_holds_the_pipes() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let session_path = store_session(&fixture);
    let pid_file = fixture.temp_path("grandchild.pid");
    let ask = grandchild_output_run(&fixture, &pid_file);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let run = std::thread::spawn(move || read_run(&run_socket, &token, &ask));

    let grandchild = wait_for_pid(&pid_file);
    let pmd_pid = child.id() as libc::pid_t;
    // SAFETY: the pid belongs to a live child of this process.
    assert_eq!(
        unsafe { libc::kill(pmd_pid, libc::SIGTERM) },
        0,
        "kill failed"
    );

    let started = Instant::now();
    assert!(wait_for_exit(&mut child, WAIT).success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "SIGTERM waited for the grandchild holding the pipes"
    );
    let (frames, _) = run.join().expect("run thread");
    assert!(frames.is_empty(), "a cancelled run emits no terminal frame");
    wait_for_process_exit(grandchild);
    assert!(!socket.exists(), "SIGTERM removes the socket");
    assert!(!session_path.exists(), "SIGTERM removes the session file");
}
