//! End-to-end tests for the unlock daemon (`pmd`).
//!
//! Each test runs a real `pmd` against a disposable runtime directory and a
//! vault created with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The vault secret is generated here and must never appear
//! in daemon output, arguments, environment or socket traffic.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use passmgr::crypto::{self, KEY_LEN, KdfParams};
use passmgr::protocol::{self, Request, Response, ResponseError, RunRequest};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use tempfile::TempDir;
use zeroize::Zeroizing;

const MASTER: &str = "daemon test master password";
const SECRET: &str = "s3cret-injected-value-must-never-leak";
const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
    _directory: TempDir,
    vault: PathBuf,
    runtime: PathBuf,
    key: Zeroizing<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        // tempfile creates the directory 0700, which is exactly what the
        // runtime directory check requires.
        let vault = directory.path().join("vault.dat");
        let runtime = directory.path().join("run");

        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(SECRET.into()),
        )
        .expect("credential");
        let plaintext = store::encode(&[credential]).expect("encode store");
        let container = crypto::encrypt(&plaintext, MASTER, KdfParams::new(8 * 1024, 1, 1))
            .expect("encrypt vault");
        fs::write(&vault, &container).expect("write vault");
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).expect("chmod vault");

        let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
        crypto::derive_vault_key(&container, MASTER, key.as_mut_slice()).expect("derive key");

        Self {
            _directory: directory,
            vault,
            runtime,
            key,
        }
    }

    fn socket(&self) -> PathBuf {
        RuntimePaths::at(&self.runtime).socket()
    }

    fn spawn(&self) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
        command
            .arg("--vault")
            .arg(&self.vault)
            .arg("--runtime-dir")
            .arg(&self.runtime)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn pmd");
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(self.key.as_slice()).expect("send key");
        drop(stdin);
        child
    }

    /// Start `pmd` and wait until it answers a ping.
    ///
    /// The returned child is owned by the caller, which always reaps it. If
    /// readiness fails, the child is killed and reaped before panicking.
    #[allow(clippy::zombie_processes)] // the `return child` path transfers ownership
    fn start(&self) -> Child {
        let mut child = self.spawn();
        let deadline = Instant::now() + WAIT;
        loop {
            if let Ok(Response::Pong) = try_request(&self.socket(), &Request::Ping) {
                return child;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pmd did not become ready");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn read_response(stream: &mut UnixStream) -> Response {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read response");
    protocol::decode_response(&bytes).expect("decode response")
}

fn try_request(socket: &Path, request: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream
        .write_all(&protocol::encode(request).expect("encode request"))
        .expect("write request");
    Ok(read_response(&mut stream))
}

fn request(socket: &Path, request: &Request) -> Response {
    try_request(socket, request).expect("daemon request")
}

/// Send arbitrary bytes, half-close, and decode the daemon's answer.
fn raw_request(socket: &Path, bytes: &[u8]) -> Response {
    use std::net::Shutdown;
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream.write_all(bytes).expect("write bytes");
    stream.shutdown(Shutdown::Write).expect("shutdown write");
    read_response(&mut stream)
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(Instant::now() < deadline, "pmd did not exit in time");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn ping_then_lock_wipes_the_key_and_removes_the_socket() {
    let fixture = Fixture::new();
    let mut child = fixture.start();

    assert_eq!(request(&fixture.socket(), &Request::Ping), Response::Pong);
    assert_eq!(request(&fixture.socket(), &Request::Lock), Response::Locked);

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(
        !fixture.socket().exists(),
        "a clean shutdown must remove the socket"
    );
}

#[test]
fn sigterm_and_sigint_shut_down_cleanly() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let fixture = Fixture::new();
        let mut child = fixture.start();
        let pid = child.id() as libc::pid_t;
        // SAFETY: the pid belongs to a live child of this process.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "kill failed");

        let status = wait_for_exit(&mut child, WAIT);
        assert!(status.success(), "signal {signal} exit status: {status:?}");
        assert!(!fixture.socket().exists());
    }
}

#[test]
fn malformed_oversized_and_unknown_requests_are_rejected_without_a_crash() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    // An empty connection.
    assert_eq!(
        raw_request(&socket, b""),
        Response::Error(ResponseError::BadRequest)
    );

    // A length prefix far above the 64 KiB cap.
    assert_eq!(
        raw_request(&socket, &u32::MAX.to_be_bytes()),
        Response::Error(ResponseError::BadRequest)
    );

    // Truncated JSON.
    assert_eq!(
        raw_request(&socket, &[0, 0, 0, 5, b'{']),
        Response::Error(ResponseError::BadRequest)
    );

    // Unknown request type.
    let body = br#"{"version":1,"request":{"type":"steal"}}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // `run` is well-formed but not implemented in this iteration.
    assert_eq!(
        request(
            &socket,
            &Request::Run(RunRequest {
                env: "API_KEY".into(),
                reference: "pm://00112233445566778899aabbccddeeff".into(),
                command: vec!["true".into()],
            })
        ),
        Response::Error(ResponseError::Unsupported)
    );

    // Still alive and serving the owner.
    assert_eq!(request(&socket, &Request::Ping), Response::Pong);
    assert_eq!(request(&socket, &Request::Lock), Response::Locked);
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn a_wrong_key_never_creates_a_socket() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
    command
        .arg("--vault")
        .arg(&fixture.vault)
        .arg("--runtime-dir")
        .arg(&fixture.runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn pmd");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(&[0u8; KEY_LEN]).expect("send wrong key");
    drop(stdin);

    let status = wait_for_exit(&mut child, WAIT);
    assert!(!status.success(), "a wrong key must not start the daemon");
    assert!(
        !fixture.socket().exists(),
        "a rejected key must not leave a socket behind"
    );
}

#[test]
fn a_second_daemon_is_refused_and_the_first_keeps_serving() {
    let fixture = Fixture::new();
    let mut first = fixture.start();

    let mut second = fixture.spawn();
    let status = wait_for_exit(&mut second, WAIT);
    assert!(!status.success(), "the second daemon must fail to start");

    assert_eq!(request(&fixture.socket(), &Request::Ping), Response::Pong);
    assert_eq!(request(&fixture.socket(), &Request::Lock), Response::Locked);
    assert!(wait_for_exit(&mut first, WAIT).success());
}

#[test]
fn the_secret_never_reaches_output_arguments_environment_or_the_socket() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    // Responses carry status only.
    let mut traffic = Vec::new();
    for request in [
        Request::Ping,
        Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            command: vec!["sh".into(), "-c".into(), "true".into()],
        }),
    ] {
        let mut stream = UnixStream::connect(&socket).expect("connect");
        stream.set_read_timeout(Some(WAIT)).expect("read timeout");
        stream
            .write_all(&protocol::encode(&request).expect("encode"))
            .expect("write");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).expect("read");
        traffic.extend_from_slice(&bytes);
        assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    }

    // On Linux the daemon cleared PR_SET_DUMPABLE, so its cmdline/environ are
    // not readable by same-uid processes. If they are readable, they must
    // still not contain the secret.
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", child.id())) {
        assert!(!String::from_utf8_lossy(&cmdline).contains(SECRET));
    }
    if let Ok(environ) = fs::read(format!("/proc/{}/environ", child.id())) {
        assert!(!String::from_utf8_lossy(&environ).contains(SECRET));
    }
    assert!(!String::from_utf8_lossy(&traffic).contains(SECRET));

    assert_eq!(request(&socket, &Request::Lock), Response::Locked);
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}
