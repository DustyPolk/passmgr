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
use passmgr::protocol::{
    self, MAX_CHUNK_BYTES, Request, Response, ResponseError, RunExit, RunFrame, RunRequest,
};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
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
    token: SessionToken,
    /// The vault entry's `pm://…` reference, so tests can run it.
    reference: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_secret(SECRET)
    }

    fn with_secret(secret: &str) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        // tempfile creates the directory 0700, which is exactly what the
        // runtime directory check requires.
        let vault = directory.path().join("vault.dat");
        let runtime = directory.path().join("run");

        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(secret.into()),
        )
        .expect("credential");
        let reference = credential.reference();
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
            token: SessionToken::generate().expect("session token"),
            reference,
        }
    }

    /// A path inside this fixture's private temp directory. Used to prove a
    /// command did (or did not) run.
    fn temp_path(&self, name: &str) -> PathBuf {
        self._directory.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        RuntimePaths::at(&self.runtime).socket()
    }

    fn spawn(&self) -> Child {
        self.spawn_with(&[])
    }

    fn spawn_with(&self, extra: &[&str]) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
        command
            .arg("--vault")
            .arg(&self.vault)
            .arg("--runtime-dir")
            .arg(&self.runtime)
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn pmd");
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(self.key.as_slice()).expect("send key");
        stdin.write_all(self.token.as_bytes()).expect("send token");
        drop(stdin);
        child
    }

    /// Start `pmd` and wait until it answers a ping.
    ///
    /// The returned child is owned by the caller, which always reaps it. If
    /// readiness fails, the child is killed and reaped before panicking.
    #[allow(clippy::zombie_processes)] // the `return child` path transfers ownership
    fn start(&self) -> Child {
        self.start_with(&[])
    }

    /// `start`, with extra `pmd` arguments (for example `--idle-timeout`).
    #[allow(clippy::zombie_processes)] // the `return child` path transfers ownership
    fn start_with(&self, extra: &[&str]) -> Child {
        let mut child = self.spawn_with(extra);
        let deadline = Instant::now() + WAIT;
        loop {
            if let Ok(Response::Pong) = try_request(&self.socket(), &self.token, &Request::Ping) {
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

fn try_read_response(stream: &mut UnixStream) -> std::io::Result<Response> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    protocol::decode_response(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid response frame"))
}

fn read_response(stream: &mut UnixStream) -> Response {
    try_read_response(stream).expect("read response")
}

fn try_request(
    socket: &Path,
    token: &SessionToken,
    request: &Request,
) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    // The daemon can expire between `connect` and this write; report that as
    // an I/O error so callers that probe can stop instead of panicking.
    stream.write_all(&protocol::encode(token, request).expect("encode request"))?;
    try_read_response(&mut stream)
}

fn request(socket: &Path, token: &SessionToken, request: &Request) -> Response {
    try_request(socket, token, request).expect("daemon request")
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

/// Send one `run` request and collect every frame plus the raw socket bytes.
///
/// Reads until the daemon closes the connection (a terminal frame is always
/// followed by close), so a missing terminal frame fails the test timeout.
fn read_run(socket: &Path, token: &SessionToken, request: &Request) -> (Vec<RunFrame>, Vec<u8>) {
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream
        .write_all(&protocol::encode(token, request).expect("encode request"))
        .expect("write request");

    let mut decoder = protocol::FrameDecoder::new();
    let mut frames = Vec::new();
    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer).expect("read run stream");
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        decoder
            .push(&buffer[..read])
            .expect("run frames are validly framed");
        while let Some(body) = decoder.next_frame().expect("decode frame") {
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            frames.push(protocol::decode_run_frame(&frame).expect("decode run frame"));
        }
    }
    (frames, raw)
}

fn stdout_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stdout(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

fn stderr_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stderr(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_request(reference: &str, env: &str, command: &[&str]) -> Request {
    Request::Run(RunRequest {
        env: env.into(),
        reference: reference.into(),
        command: command.iter().map(|arg| (*arg).to_string()).collect(),
    })
}

#[test]
fn ping_then_lock_wipes_the_key_and_removes_the_socket() {
    let fixture = Fixture::new();
    let mut child = fixture.start();

    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );

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
    let token = fixture.token.to_hex();
    let body = format!(
        r#"{{"version":2,"token":"{}","request":{{"type":"steal"}}}}"#,
        token.as_str()
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // A well-formed frame whose token is not 64 lowercase hex characters.
    let body = br#"{"version":2,"token":"nope","request":{"type":"ping"}}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    assert_eq!(
        raw_request(&socket, &frame),
        Response::Error(ResponseError::BadRequest)
    );

    // `run` for an unknown reference answers with a terminal run frame and
    // leaves the daemon healthy.
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            command: vec!["true".into()],
        }),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);

    // Still alive and serving the owner.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn idle_timeout_wipes_the_key_and_stops_the_daemon() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "1"]);
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );

    // No `lock`, no signal: the daemon must stop on its own.
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(
        !fixture.socket().exists(),
        "an idle shutdown must remove the socket"
    );
}

#[test]
fn successful_requests_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();

    // Keep pinging for longer than the timeout. Every answered request resets
    // the clock, so the daemon must still be alive at the end.
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        assert_eq!(
            request(&socket, &fixture.token, &Request::Ping),
            Response::Pong
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "activity before the deadline must keep the daemon alive"
    );

    // Now go quiet: it must expire.
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
}

#[test]
fn malformed_requests_do_not_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();

    // Send rejected requests for longer than the timeout. They are answered
    // (with `bad_request`) but are not activity, so the daemon must still
    // expire on schedule.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(4);
    let mut rejected = 0;
    while Instant::now() < deadline {
        let Ok(mut stream) = UnixStream::connect(&socket) else {
            break;
        };
        stream.set_read_timeout(Some(WAIT)).expect("read timeout");
        let sent = stream
            .write_all(b"not a frame")
            .and_then(|()| stream.shutdown(std::net::Shutdown::Write));
        let mut bytes = Vec::new();
        if sent.is_err() || stream.read_to_end(&mut bytes).is_err() {
            // The daemon expired between our connect and the request.
            break;
        }
        match protocol::decode_response(&bytes) {
            Ok(Response::Error(ResponseError::BadRequest)) => rejected += 1,
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(rejected >= 2, "expected repeated rejected requests");

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
    // Rejected traffic must not have extended the key's lifetime: if it had,
    // the loop above would have kept the daemon alive past its deadline and
    // the exit would only come seconds later.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "rejected requests extended the idle timeout (stopped after {:?})",
        started.elapsed()
    );
}

/// Rejections must not count as activity, or a client with the wrong token
/// could keep the vault key in memory indefinitely.
#[test]
fn unauthorized_requests_do_not_refresh_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();
    let wrong = SessionToken::generate().expect("wrong token");

    let started = Instant::now();
    let deadline = started + Duration::from_secs(4);
    let mut rejected = 0;
    while Instant::now() < deadline {
        match try_request(&socket, &wrong, &Request::Ping) {
            Ok(Response::Error(ResponseError::Unauthorized)) => rejected += 1,
            // The daemon expired between our connect and the request.
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(rejected >= 2, "expected repeated unauthorized requests");

    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status: {status:?}");
    assert!(!fixture.socket().exists());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "unauthorized requests extended the idle timeout (stopped after {:?})",
        started.elapsed()
    );
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

    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&fixture.socket(), &fixture.token, &Request::Lock),
        Response::Locked
    );
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
            .write_all(&protocol::encode(&fixture.token, &request).expect("encode"))
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

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

/// A client that cannot present the session token is rejected, and rejection
/// is not activity: the daemon keeps serving the owner.
#[test]
fn a_wrong_token_is_rejected_and_the_owner_is_served() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let wrong = SessionToken::generate().expect("wrong token");

    assert_eq!(
        request(&socket, &wrong, &Request::Ping),
        Response::Error(ResponseError::Unauthorized)
    );
    assert_eq!(
        request(&socket, &wrong, &Request::Lock),
        Response::Error(ResponseError::Unauthorized)
    );
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "an unauthorized `lock` must not stop the daemon"
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// The token is a credential: it must not be echoed, logged or put in argv.
#[test]
fn the_session_token_never_reaches_socket_traffic_or_daemon_output() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();
    let token_hex = fixture.token.to_hex();

    // An unauthorized request gets a status-only answer.
    let wrong = SessionToken::generate().expect("wrong token");
    let wrong_hex = wrong.to_hex();
    let body = format!(
        r#"{{"version":2,"token":"{}","request":{{"type":"ping"}}}}"#,
        wrong_hex.as_str()
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    let mut stream = UnixStream::connect(&socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream.write_all(&frame).expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read");
    assert_eq!(
        protocol::decode_response(&bytes).expect("decode"),
        Response::Error(ResponseError::Unauthorized)
    );
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(wrong_hex.as_str()));
    assert!(!text.contains(token_hex.as_str()));

    // The token reaches the daemon over stdin, not argv.
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", child.id())) {
        let cmdline = String::from_utf8_lossy(&cmdline);
        assert!(!cmdline.contains(token_hex.as_str()));
        assert!(!cmdline.contains(SECRET));
    }

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(!text.contains(token_hex.as_str()));
        assert!(!text.contains(SECRET));
    }
}

#[test]
fn run_injects_the_secret_and_redacts_stdout_and_stderr() {
    let fixture = Fixture::new();
    let child = fixture.start();
    let socket = fixture.socket();

    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "API_KEY",
            &[
                "/bin/sh",
                "-c",
                "printf %s \"$API_KEY\"; printf %s \"$API_KEY\" >&2",
            ],
        ),
    );

    assert_eq!(stdout_bytes(&frames), b"[REDACTED]");
    assert_eq!(stderr_bytes(&frames), b"[REDACTED]");
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert!(
        !raw.windows(hex(SECRET.as_bytes()).len())
            .any(|window| { window == hex(SECRET.as_bytes()).as_bytes() })
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

#[test]
fn run_reports_a_missing_reference_and_a_spawn_failure_without_dying() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            "pm://00112233445566778899aabbccddeeff",
            "API_KEY",
            &["/bin/true"],
        ),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::NotFound)]);

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "API_KEY",
            &["/nonexistent/passmgr-run-test"],
        ),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::SpawnFailed)]);

    // Neither failure is fatal.
    assert_eq!(
        request(&socket, &fixture.token, &Request::Ping),
        Response::Pong
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_refuses_loader_and_shell_hook_variables_without_spawning() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let marker = fixture.temp_path("spawned");

    for env in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "IFS",
        "PATH",
        "HOME",
        "SHELLOPTS",
        "PS4",
    ] {
        let (frames, _) = read_run(
            &socket,
            &fixture.token,
            &run_request(
                &fixture.reference,
                env,
                &["/bin/sh", "-c", &format!("touch {}", marker.display())],
            ),
        );
        assert_eq!(
            frames,
            vec![RunFrame::Error(ResponseError::BadRequest)],
            "injecting {env} must be refused"
        );
        assert!(!marker.exists(), "a refused run must not spawn: {env}");
    }

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

#[test]
fn run_streams_large_output_in_protocol_sized_chunks_and_redacts() {
    // The vault caps a password at 4096 bytes; the runner's unit tests cover
    // a value split across pipe reads with a longer value. Here the prefix
    // pushes the value to a read boundary anyway, and the output proves the
    // frame cap.
    let secret = format!("{}{}", SECRET, "z".repeat(4096 - SECRET.len()));
    let fixture = Fixture::with_secret(&secret);
    let child = fixture.start();
    let socket = fixture.socket();

    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &run_request(
            &fixture.reference,
            "BIG_SECRET",
            &[
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=1024 count=40 2>/dev/null | tr '\\000' x; printf %s \"$BIG_SECRET\"",
            ],
        ),
    );

    let chunks: Vec<&Vec<u8>> = frames
        .iter()
        .filter_map(|frame| match frame {
            RunFrame::Stdout(data) => Some(data),
            _ => None,
        })
        .collect();
    assert!(chunks.len() > 1, "long output must span several frames");
    assert!(
        chunks.iter().all(|chunk| chunk.len() <= MAX_CHUNK_BYTES),
        "a frame must never exceed the protocol cap"
    );

    let stdout = stdout_bytes(&frames);
    assert_eq!(stdout.len(), 40 * 1024 + b"[REDACTED]".len());
    assert!(stdout[..40 * 1024].iter().all(|byte| *byte == b'x'));
    assert_eq!(&stdout[40 * 1024..], b"[REDACTED]");
    assert_eq!(frames.last(), Some(&RunFrame::Exit(RunExit::Code(0))));

    assert!(
        !raw.windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let encoded = hex(secret.as_bytes());
    assert!(
        !raw.windows(encoded.len())
            .any(|window| window == encoded.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    let output = child.wait_with_output().expect("wait for pmd");
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

/// A `run` whose child reports its pid, closes both output pipes and then
/// sleeps. The daemon has nothing left to relay, but the process is alive.
fn detached_output_run(fixture: &Fixture, pid_file: &Path) -> Request {
    let script = format!(
        "echo $$ > {}; exec >&- 2>&-; exec sleep 30",
        pid_file.display()
    );
    run_request(&fixture.reference, "API_KEY", &["/bin/sh", "-c", &script])
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
    let deadline = Instant::now() + WAIT;
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

#[test]
fn idle_timeout_cancels_a_run_whose_child_keeps_running() {
    let fixture = Fixture::new();
    let mut child = fixture.start_with(&["--idle-timeout", "2"]);
    let socket = fixture.socket();
    let pid_file = fixture.temp_path("child.pid");
    let ask = detached_output_run(&fixture, &pid_file);
    let token = fixture.token.clone();
    let run_socket = socket.clone();
    let run = std::thread::spawn(move || read_run(&run_socket, &token, &ask));

    let pid = wait_for_pid(&pid_file);
    let status = wait_for_exit(&mut child, WAIT);
    assert!(status.success(), "pmd exit status after idle: {status:?}");

    let (frames, _) = run.join().expect("run thread");
    assert!(
        frames.is_empty(),
        "an idle-cancelled run emits no exit frame"
    );
    wait_for_process_exit(pid);
    assert!(!socket.exists(), "an idle timeout removes the socket");
}
