//! End-to-end tests for the unlock daemon (`pmd`).
//!
//! Each test runs a real `pmd` against a disposable runtime directory and a
//! vault created with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The vault secret is generated here and must never appear
//! in daemon output, arguments, environment or socket traffic.

#![allow(dead_code)] // each integration-test binary uses a different subset

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use passmgr::crypto::{self, KEY_LEN, KdfParams};
use passmgr::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
use passmgr::protocol::{
    self, EnvBinding, Request, Response, RunExit, RunFinished, RunFrame, RunRequest,
};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const MASTER: &str = "daemon test master password";
pub const SECRET: &str = "s3cret-injected-value-must-never-leak";
pub const SECOND_SECRET: &str = "s3cond-injected-value-must-never-leak";
pub const WAIT: Duration = Duration::from_secs(10);

pub struct Fixture {
    pub _directory: TempDir,
    pub vault: PathBuf,
    pub runtime: PathBuf,
    pub key: Zeroizing<Vec<u8>>,
    pub token: SessionToken,
    /// The vault entry's `pm://…` reference, so tests can run it.
    pub reference: String,
    /// The second entry, only in fixtures built by [`Fixture::with_two_secrets`].
    pub second_reference: Option<String>,
    /// The grant token `run` must present.
    pub grant: GrantToken,
    /// A 0600 file holding the grant token's hex, for the CLI tests.
    pub grant_file: PathBuf,
    /// An executable copy of `/bin/true` that is inside the grant scope. A
    /// test chmods it to prove a spawn failure is reported distinctly.
    pub spawn_fail_program: PathBuf,
    /// When the fixture's grant expires (Unix seconds).
    pub grant_expires_at: u64,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_secret(SECRET)
    }

    pub fn with_secret(secret: &str) -> Self {
        Self::with_secret_and_uses(secret, None)
    }

    /// A fixture whose grant may be used exactly `max_uses` times.
    pub fn with_max_uses(max_uses: u32) -> Self {
        Self::with_secret_and_uses(SECRET, Some(max_uses))
    }

    /// A fixture with two credentials, both in the grant scope.
    pub fn with_two_secrets() -> Self {
        Self::build_two(SECRET, SECOND_SECRET, None, 3600, Capabilities::RUN)
    }

    /// A fixture whose grant expires `seconds` after it is created.
    pub fn with_grant_expiring_in(seconds: u64) -> Self {
        Self::build(SECRET, None, seconds, Capabilities::RUN)
    }

    /// A fixture whose grant carries exactly `capabilities`.
    pub fn with_capabilities(capabilities: Capabilities) -> Self {
        Self::build(SECRET, None, 3600, capabilities)
    }

    fn with_secret_and_uses(secret: &str, max_uses: Option<u32>) -> Self {
        Self::build(secret, max_uses, 3600, Capabilities::RUN)
    }

    fn build(
        secret: &str,
        max_uses: Option<u32>,
        expires_in: u64,
        capabilities: Capabilities,
    ) -> Self {
        Self::build_credentials(
            &[(secret, "example.test", "alice")],
            max_uses,
            expires_in,
            capabilities,
        )
    }

    fn build_two(
        first: &str,
        second: &str,
        max_uses: Option<u32>,
        expires_in: u64,
        capabilities: Capabilities,
    ) -> Self {
        Self::build_credentials(
            &[
                (first, "example.test", "alice"),
                (second, "second.test", "bob"),
            ],
            max_uses,
            expires_in,
            capabilities,
        )
    }

    fn build_credentials(
        secrets: &[(&str, &str, &str)],
        max_uses: Option<u32>,
        expires_in: u64,
        capabilities: Capabilities,
    ) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        // tempfile creates the directory 0700, which is exactly what the
        // runtime directory check requires.
        let vault = directory.path().join("vault.dat");
        // `RuntimePaths::resolve()` under XDG_RUNTIME_DIR appends "passmgr".
        let runtime = directory.path().join("passmgr");

        let credentials: Vec<Credential> = secrets
            .iter()
            .map(|(secret, service, username)| {
                Credential::new(
                    (*service).into(),
                    (*username).into(),
                    Zeroizing::new((*secret).into()),
                )
                .expect("credential")
            })
            .collect();
        let reference = credentials[0].reference();
        let second_reference = credentials.get(1).map(Credential::reference);
        let ids = credentials.iter().map(Credential::id).collect();

        // Programs the tests may run. Canonicalize them here because the
        // daemon resolves the request path before matching the grant.
        let sh = fs::canonicalize("/bin/sh").expect("canonical /bin/sh");
        let truth = fs::canonicalize("/bin/true").expect("canonical /bin/true");
        let spawn_fail = directory.path().join("spawn-fail-program");
        fs::copy(&truth, &spawn_fail).expect("copy program");
        fs::set_permissions(&spawn_fail, fs::Permissions::from_mode(0o755)).expect("chmod program");
        let spawn_fail_program =
            fs::canonicalize(&spawn_fail).expect("canonical spawn-fail program");

        let grant_token = GrantToken::generate().expect("grant token");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let scope = Scope::new(ids, Vec::new(), None).expect("scope");
        let grant_expires_at = now + expires_in;
        let grant = Grant::create(
            GrantSpec {
                label: "daemon test run grant".into(),
                scope,
                commands: vec![sh, truth, spawn_fail_program.clone()],
                capabilities,
                expires_at: grant_expires_at,
                max_uses,
            },
            grant_token.hash(),
            now,
        )
        .expect("create grant");
        let grant_file = directory.path().join("grant.token");
        fs::write(&grant_file, format!("{}\n", grant_token.to_hex().as_str()))
            .expect("write grant file");
        fs::set_permissions(&grant_file, fs::Permissions::from_mode(0o600))
            .expect("chmod grant file");

        let plaintext = store::encode(&credentials, &[grant]).expect("encode store");
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
            second_reference,
            grant: grant_token,
            grant_file,
            spawn_fail_program,
            grant_expires_at,
        }
    }

    /// A `run` request authorized by this fixture's grant.
    pub fn run_request(&self, env: &str, command: &[&str]) -> Request {
        Request::Run(RunRequest {
            limits: Default::default(),
            env: vec![EnvBinding {
                name: env.into(),
                reference: self.reference.clone(),
            }],
            plain_env: Vec::new(),
            command: command.iter().map(|arg| (*arg).to_string()).collect(),
            cwd: "/".into(),
            grant: self.grant.clone(),
        })
    }

    /// A path inside this fixture's private temp directory. Used to prove a
    /// command did (or did not) run.
    pub fn temp_path(&self, name: &str) -> PathBuf {
        self._directory.path().join(name)
    }

    pub fn socket(&self) -> PathBuf {
        RuntimePaths::at(&self.runtime).socket()
    }

    pub fn spawn(&self) -> Child {
        self.spawn_with(&[])
    }

    pub fn spawn_with(&self, extra: &[&str]) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
        command
            .arg("--vault")
            .arg(&self.vault)
            .arg("--runtime-dir")
            .arg(&self.runtime)
            .args(extra)
            // Never let a test daemon write the real user's audit log
            // (TODO 3.8).
            .env("XDG_STATE_HOME", self._directory.path().join("state"))
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
    pub fn start(&self) -> Child {
        self.start_with(&[])
    }

    /// `start`, with extra `pmd` arguments (for example `--idle-timeout`).
    #[allow(clippy::zombie_processes)] // the `return child` path transfers ownership
    pub fn start_with(&self, extra: &[&str]) -> Child {
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

pub fn try_read_response(stream: &mut UnixStream) -> std::io::Result<Response> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    protocol::decode_response(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid response frame"))
}

pub fn read_response(stream: &mut UnixStream) -> Response {
    try_read_response(stream).expect("read response")
}

pub fn try_request(
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

pub fn request(socket: &Path, token: &SessionToken, request: &Request) -> Response {
    try_request(socket, token, request).expect("daemon request")
}

/// Send arbitrary bytes, half-close, and decode the daemon's answer.
pub fn raw_request(socket: &Path, bytes: &[u8]) -> Response {
    use std::net::Shutdown;
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream.set_read_timeout(Some(WAIT)).expect("read timeout");
    stream.write_all(bytes).expect("write bytes");
    stream.shutdown(Shutdown::Write).expect("shutdown write");
    read_response(&mut stream)
}

pub fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
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
pub fn read_run(
    socket: &Path,
    token: &SessionToken,
    request: &Request,
) -> (Vec<RunFrame>, Vec<u8>) {
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

/// The terminal frame of a run, or a panic naming what arrived instead.
///
/// The daemon fills in `redactions` and `duration_ms` per run, so a test can
/// never compare a whole [`RunFinished`] against a literal; it asserts on the
/// fields it controls.
pub fn exit_frame(frames: &[RunFrame]) -> &RunFinished {
    match frames.last() {
        Some(RunFrame::Exit(finished)) => finished,
        other => panic!("expected a terminal exit frame, found {other:?}"),
    }
}

/// Whether the run ended with an untimed exit of `code`.
pub fn is_exited(frames: &[RunFrame], code: u8) -> bool {
    let Some(RunFrame::Exit(finished)) = frames.last() else {
        return false;
    };
    finished.exit == RunExit::Code(code) && !finished.timed_out
}

/// Assert that the run ended with an untimed exit of `code`.
pub fn assert_exited(frames: &[RunFrame], code: u8) {
    assert!(
        is_exited(frames, code),
        "expected exit {code}, got {frames:?}"
    );
}

pub fn stdout_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stdout(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

pub fn stderr_bytes(frames: &[RunFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        if let RunFrame::Stderr(data) = frame {
            bytes.extend_from_slice(data);
        }
    }
    bytes
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Replace the vault's contents without changing the container header, so the
/// running daemon's key still opens it (the salt and KDF parameters are kept).
pub fn rewrite_vault(fixture: &Fixture, credentials: &[Credential], grants: &[Grant]) {
    let plaintext = store::encode(credentials, grants).expect("encode store");
    let template = fs::read(&fixture.vault).expect("read vault");
    let container = crypto::encrypt_with_key(&plaintext, fixture.key.as_slice(), &template)
        .expect("encrypt vault");
    fs::write(&fixture.vault, &container).expect("write vault");
}
