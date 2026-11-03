//! End-to-end tests for `passmgr unlock` and `passmgr lock`.
//!
//! These run the real CLI binary, which derives the key and spawns a real
//! `pmd`. The vault uses deliberately cheap Argon2 parameters (this file does
//! not test the KDF) and contains a known fake secret that must never appear
//! in any output, argument list or environment.
//!
//! The daemon is located through `XDG_RUNTIME_DIR`, set per test, so tests
//! never touch the developer's real daemon.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use passmgr::crypto::{self, KdfParams};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
use tempfile::TempDir;
use zeroize::Zeroizing;

const MASTER: &str = "unlock test master password";
const SECRET: &str = "s3cret-unlock-value-must-never-leak";
const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = directory.path().join("vault.dat");
        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(SECRET.into()),
        )
        .expect("credential");
        let plaintext = store::encode(&[credential], &[]).expect("encode store");
        let container = crypto::encrypt(&plaintext, MASTER, KdfParams::new(8 * 1024, 1, 1))
            .expect("encrypt vault");
        fs::write(&vault, &container).expect("write vault");
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).expect("chmod vault");
        Self { directory, vault }
    }

    /// The per-test `XDG_RUNTIME_DIR`. `tempfile` creates it 0700.
    fn runtime(&self) -> &Path {
        self.directory.path()
    }

    fn daemon_paths(&self) -> RuntimePaths {
        RuntimePaths::at(self.runtime().join("passmgr"))
    }

    fn socket(&self) -> PathBuf {
        self.daemon_paths().socket()
    }

    /// A command with this test's runtime directory and no agent markers.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_passmgr"));
        command.args(args);
        command.env("XDG_RUNTIME_DIR", self.runtime());
        for marker in passmgr::agent::AGENT_MARKERS {
            command.env_remove(marker);
        }
        command
    }

    fn run(&self, args: &[&str], input: &str) -> Output {
        let mut command = self.command(args);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("failed to start passmgr");
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(input.as_bytes())
            .expect("failed to write stdin");
        child
            .wait_with_output()
            .expect("failed to wait for passmgr")
    }

    /// `unlock` at a human terminal with the correct password.
    #[cfg(target_os = "linux")]
    fn unlock_on_pty(&self) -> PtyOutput {
        self.unlock_on_pty_with(&[], "unlock", MASTER)
    }

    /// `unlock` with extra arguments (for example `--idle-timeout`) on a pty.
    #[cfg(target_os = "linux")]
    fn unlock_on_pty_args(&self, args: &[&str]) -> PtyOutput {
        let database = self.vault.to_str().expect("vault path is UTF-8");
        let mut values = vec!["--db", database];
        values.extend_from_slice(args);
        let command = self.command(&values);
        run_on_pty(command, &format!("{MASTER}\n"))
    }

    #[cfg(target_os = "linux")]
    fn unlock_on_pty_with(
        &self,
        envs: &[(&str, &str)],
        subcommand: &str,
        password: &str,
    ) -> PtyOutput {
        let mut command = self.command(&["--db", self.vault.to_str().unwrap(), subcommand]);
        for (name, value) in envs {
            command.env(name, value);
        }
        run_on_pty(command, &format!("{password}\n"))
    }

    /// The session token `unlock` wrote (TODO 2.5).
    fn session_token(&self) -> SessionToken {
        passmgr::session::load(&self.daemon_paths()).expect("session token file")
    }

    /// Whether a daemon is up *and* accepts the token on disk. Missing token
    /// or daemon both count as "not answering".
    fn daemon_answers(&self) -> bool {
        let Ok(token) = passmgr::session::load(&self.daemon_paths()) else {
            return false;
        };
        passmgr::client::ping(&self.daemon_paths(), &token).is_ok()
    }

    /// Wait until the daemon answers a ping, or fail the test.
    fn wait_ready(&self) {
        let deadline = Instant::now() + WAIT;
        while !self.daemon_answers() {
            assert!(
                Instant::now() < deadline,
                "the daemon did not become ready within {WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_socket_gone(&self) {
        let deadline = Instant::now() + WAIT;
        while self.socket().exists() {
            assert!(
                Instant::now() < deadline,
                "the daemon socket still exists after the daemon stopped"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never leave a detached daemon behind, even if an assertion failed.
        let _ = self
            .command(&["lock"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// The pid printed by `unlock`, used to inspect the daemon's process state.
#[cfg(target_os = "linux")]
fn daemon_pid(output: &PtyOutput) -> u32 {
    let after = output
        .stdout
        .split("pid ")
        .nth(1)
        .expect("unlock should print the daemon pid");
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("pid should be numeric")
}

#[cfg(target_os = "linux")]
struct PtyOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Run a prepared command with both stdin and stdout on a pseudo-terminal.
/// stderr stays piped, so it can be asserted on and so a refusal message is
/// readable even though stdout is a terminal.
#[cfg(target_os = "linux")]
fn run_on_pty(mut command: Command, input: &str) -> PtyOutput {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    // SAFETY: the returned descriptors are valid and each is owned by exactly
    // one `File` afterwards.
    let (mut master, slave) = unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(
            master >= 0,
            "posix_openpt failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname failed");
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
        assert!(
            slave >= 0,
            "opening the pty slave failed: {}",
            std::io::Error::last_os_error()
        );
        (File::from_raw_fd(master), File::from_raw_fd(slave))
    };

    command.stdin(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    command.stdout(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    command.stderr(Stdio::piped());

    let child = command.spawn().expect("failed to start passmgr");
    // The child holds the only remaining slave reference; close ours so reads
    // on the master see end-of-file once the child exits.
    drop(slave);
    master
        .write_all(input.as_bytes())
        .expect("failed to write to the pty");

    let output = child
        .wait_with_output()
        .expect("failed to wait for passmgr");
    PtyOutput {
        status: output.status,
        stdout: read_pty(&mut master),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Drain a pty master after the child exited. Linux reports EIO once the last
/// slave is closed.
#[cfg(target_os = "linux")]
fn read_pty(master: &mut std::fs::File) -> String {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    // SAFETY: `master` is an open file descriptor owned by this function.
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0, "fcntl F_GETFL failed");
        assert!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0,
            "fcntl F_SETFL failed"
        );
    }

    let mut collected = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => collected.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => panic!("reading the pty failed: {error}"),
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

/// An agent without a terminal must not start a session.
#[test]
fn unlock_is_refused_without_a_terminal() {
    let fixture = Fixture::new();
    let output = fixture.run(
        &["--db", fixture.vault.to_str().unwrap(), "unlock"],
        &format!("{MASTER}\n"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5));
    assert!(stderr.contains("reserved for a human"), "stderr: {stderr}");
    assert!(
        !stderr.contains("Master Password"),
        "the password must not be prompted before the refusal"
    );
    assert!(!fixture.socket().exists(), "no daemon may be started");
}

/// An agent environment marker refuses even with a terminal.
#[cfg(target_os = "linux")]
#[test]
fn unlock_is_refused_in_an_agent_context() {
    let fixture = Fixture::new();
    let output = fixture.unlock_on_pty_with(&[("PASSMGR_AGENT", "1")], "unlock", MASTER);
    assert_eq!(output.status.code(), Some(5));
    assert!(
        output.stderr.contains("agent"),
        "stderr was: {}",
        output.stderr
    );
    assert!(!fixture.socket().exists());
}

/// The main path: unlock at a TTY, prove the daemon is up, then lock.
#[cfg(target_os = "linux")]
#[test]
fn unlock_then_lock_round_trip_never_prints_a_secret() {
    let fixture = Fixture::new();
    let unlocked = fixture.unlock_on_pty();
    assert_eq!(
        unlocked.status.code(),
        Some(0),
        "stderr: {}",
        unlocked.stderr
    );
    assert!(
        unlocked.stdout.contains("Vault unlocked"),
        "stdout was: {}",
        unlocked.stdout
    );
    assert!(
        unlocked.stderr.contains("Master Password"),
        "the human should be prompted once: {}",
        unlocked.stderr
    );
    for output in [&unlocked.stdout, &unlocked.stderr] {
        assert!(!output.contains(SECRET), "a secret reached the output");
    }

    fixture.wait_ready();

    // The session token is the client's credential. It must live in a 0600
    // file and must never be printed by `unlock`.
    let token = fixture.session_token();
    let token_hex = token.to_hex();
    for output in [&unlocked.stdout, &unlocked.stderr] {
        assert!(
            !output.contains(token_hex.as_str()),
            "the session token reached the output"
        );
    }
    let session = fixture.daemon_paths().session();
    let mode = fs::metadata(&session)
        .expect("session token file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "session token mode: {mode:04o}");

    let pid = daemon_pid(&unlocked);
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).expect("daemon cmdline");
    let cmdline = String::from_utf8_lossy(&cmdline);
    assert!(!cmdline.contains(SECRET) && !cmdline.contains(MASTER));
    assert!(cmdline.contains("--vault"), "cmdline: {cmdline}");
    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(bytes) => {
            let environ = String::from_utf8_lossy(&bytes);
            assert!(!environ.contains(SECRET) && !environ.contains(MASTER));
        }
        // `PR_SET_DUMPABLE, 0` makes /proc/<pid>/environ unreadable even by the
        // owning user. That is the daemon hardening working, not a failure.
        Err(error) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "unexpected error reading the daemon environment: {error}"
        ),
    }
    assert!(fixture.socket().exists());

    let locked = fixture.command(&["lock"]).output().expect("run lock");
    assert_eq!(locked.status.code(), Some(0));
    let locked_out = String::from_utf8_lossy(&locked.stdout);
    assert!(locked_out.contains("stopped"), "stdout: {locked_out}");
    assert!(!locked_out.contains(SECRET));
    assert!(locked.stderr.is_empty(), "lock must not prompt");

    fixture.wait_socket_gone();
    assert!(
        !fixture.daemon_answers(),
        "the daemon must be gone after lock"
    );
    assert!(
        !fixture.daemon_paths().session().exists(),
        "lock must remove the session token file"
    );
}

/// A session token file with loose permissions is refused, not trusted.
#[cfg(target_os = "linux")]
#[test]
fn a_world_readable_session_token_is_refused() {
    let fixture = Fixture::new();
    fixture.unlock_on_pty();
    fixture.wait_ready();
    let session = fixture.daemon_paths().session();
    fs::set_permissions(&session, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let refused = fixture.command(&["lock"]).output().expect("run lock");
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("0600"), "stderr: {stderr}");
    // The daemon is untouched: a refused client must not stop it.
    assert!(!fixture.daemon_answers());

    // Restoring the permissions restores the client's access.
    fs::set_permissions(&session, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    fixture.wait_ready();
    let locked = fixture.command(&["lock"]).output().expect("run lock");
    assert_eq!(locked.status.code(), Some(0));
    fixture.wait_socket_gone();
}

/// `unlock --idle-timeout` reaches the daemon: it wipes its key and stops
/// without `pm lock` or a signal.
#[cfg(target_os = "linux")]
#[test]
fn unlock_passes_the_idle_timeout_to_the_daemon() {
    let fixture = Fixture::new();
    let unlocked = fixture.unlock_on_pty_args(&["unlock", "--idle-timeout", "1"]);
    assert_eq!(
        unlocked.status.code(),
        Some(0),
        "stderr: {}",
        unlocked.stderr
    );
    assert!(
        unlocked.stdout.contains("after 1s"),
        "stdout was: {}",
        unlocked.stdout
    );
    let pid = daemon_pid(&unlocked);

    // An idle shutdown must also clear the session token, so a later client
    // cannot keep using a token for a daemon that no longer exists.
    fixture.wait_socket_gone();
    assert!(!fixture.daemon_paths().session().exists());

    let started = Instant::now();
    loop {
        // SAFETY: `pid` was printed by the daemon spawned for this test.
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !alive {
            break;
        }
        assert!(
            started.elapsed() < WAIT,
            "the daemon did not expire within {WAIT:?}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    fixture.wait_socket_gone();
    assert!(!fixture.daemon_answers());
    assert!(!fixture.daemon_paths().session().exists());
}

/// A second unlock must not prompt or start a second daemon.
#[cfg(target_os = "linux")]
#[test]
fn unlock_refuses_when_a_daemon_is_already_running() {
    let fixture = Fixture::new();
    fixture.unlock_on_pty();
    fixture.wait_ready();

    let again = fixture.unlock_on_pty();
    assert_eq!(again.status.code(), Some(1));
    assert!(
        again.stderr.contains("already running"),
        "stderr was: {}",
        again.stderr
    );
    assert!(
        !again.stderr.contains("Master Password"),
        "a duplicate unlock must not prompt"
    );
}

/// A wrong master password fails in the short-lived client: no daemon, no socket.
#[cfg(target_os = "linux")]
#[test]
fn a_wrong_password_never_starts_a_daemon() {
    let fixture = Fixture::new();
    let output = fixture.unlock_on_pty_with(&[], "unlock", "definitely wrong");
    assert_eq!(output.status.code(), Some(4), "stderr: {}", output.stderr);
    assert!(!output.stdout.contains(SECRET));
    assert!(!fixture.socket().exists());
}

/// `lock` without a daemon is a clean runtime error, not a prompt or a panic.
#[test]
fn lock_without_a_daemon_reports_not_running() {
    let fixture = Fixture::new();
    let output = fixture.run(&["lock"], "");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no passmgr daemon is running"), "{stderr}");
}
