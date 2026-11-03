//! End-to-end tests for `passmgr run`: the agent-facing injection surface.
//!
//! Each test starts a real `pmd` against a disposable runtime directory and a
//! vault encrypted with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The secret is a canary generated here; it must never
//! appear in the CLI's stdout, stderr or exit path. The CLI process is the one
//! an agent would actually drive: non-TTY stdio, no master password.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use passmgr::client;
use passmgr::crypto::{self, KEY_LEN, KdfParams};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
use tempfile::TempDir;
use zeroize::Zeroizing;

const MASTER: &str = "run test master password";
const SECRET: &str = "s3cret-run-value-must-never-leak";
const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
    _directory: TempDir,
    vault: PathBuf,
    runtime: PathBuf,
    key: Zeroizing<Vec<u8>>,
    token: SessionToken,
    reference: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = directory.path().join("vault.dat");
        // `RuntimePaths::resolve()` under XDG_RUNTIME_DIR appends "passmgr".
        let runtime = directory.path().join("passmgr");

        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(SECRET.into()),
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

    fn xdg_runtime_dir(&self) -> &Path {
        self._directory.path()
    }

    fn paths(&self) -> RuntimePaths {
        RuntimePaths::at(&self.runtime)
    }
}

/// A fixture plus a running `pmd`; dropping it kills and reaps the daemon.
struct Daemon {
    fixture: Fixture,
    child: Child,
}

impl Daemon {
    fn start() -> Self {
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
        stdin.write_all(fixture.key.as_slice()).expect("send key");
        stdin
            .write_all(fixture.token.as_bytes())
            .expect("send token");
        drop(stdin);

        let deadline = Instant::now() + WAIT;
        loop {
            if client::ping(&fixture.paths(), &fixture.token).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pmd did not become ready");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // `unlock` writes the session file next to the socket; do the same so
        // the CLI can authenticate exactly as it would after a human unlock.
        passmgr::session::store(&fixture.paths(), &fixture.token).expect("store session token");
        Self { fixture, child }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl std::ops::Deref for Daemon {
    type Target = Fixture;

    fn deref(&self) -> &Self::Target {
        &self.fixture
    }
}

/// Build a `passmgr` invocation pointed at `xdg_runtime_dir`, with non-TTY
/// stdio and no inherited agent marker unless the test adds one.
fn command_at(xdg_runtime_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_passmgr"));
    command.env("XDG_RUNTIME_DIR", xdg_runtime_dir);
    for marker in passmgr::agent::AGENT_MARKERS {
        command.env_remove(marker);
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run(fixture: &Fixture, args: &[&str]) -> Output {
    command_at(fixture.xdg_runtime_dir(), args)
        .output()
        .expect("run passmgr")
}

fn env_argument(fixture: &Fixture, name: &str) -> String {
    format!("{name}={}", fixture.reference)
}

/// stderr used for assertions; the daemon is asked to relay child output only.
fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn run_injects_a_secret_and_redacts_both_streams() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            r#"printf %s "$API_KEY"; printf %s "$API_KEY" >&2"#,
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"[REDACTED]");
    assert_eq!(output.stderr, b"[REDACTED]");
    assert!(
        !output
            .stdout
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
            && !output
                .stderr
                .windows(SECRET.len())
                .any(|w| w == SECRET.as_bytes()),
        "the canary reached the CLI output"
    );
}

#[test]
fn run_propagates_the_child_exit_status() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            "exit 7",
        ],
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty());
}

#[test]
fn run_reports_a_signal_as_128_plus_the_signal() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            "kill -TERM $$",
        ],
    );
    // The daemon keeps "signal 15" distinct from "exit 143" on the wire; the
    // shell-visible rendering is the usual 128 + N.
    assert_eq!(output.status.code(), Some(143), "{output:?}");
}

#[test]
fn run_is_the_agent_surface_and_works_in_agent_mode() {
    let daemon = Daemon::start();
    let output = command_at(
        daemon.xdg_runtime_dir(),
        &[
            "--agent",
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            r#"printf %s "$API_KEY""#,
        ],
    )
    .env("CLAUDECODE", "1")
    .output()
    .expect("run passmgr");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"[REDACTED]");
    // stdin is /dev/null: a master-password prompt would fail, not hang.
    assert!(stderr_text(&output).is_empty(), "{output:?}");
}

#[test]
fn run_without_a_daemon_is_a_clear_runtime_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    let output = command_at(
        directory.path(),
        &[
            "run",
            "--env",
            "API_KEY=pm://00112233445566778899aabbccddeeff",
            "--",
            "true",
        ],
    )
    .output()
    .expect("run passmgr");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("no passmgr daemon is running"), "{stderr}");
    assert!(stderr.contains("passmgr unlock"), "{stderr}");
}

#[test]
fn run_refuses_dangerous_variables_without_spawning() {
    let directory = tempfile::tempdir().expect("tempdir");
    let marker = directory.path().join("spawned");
    let script = format!("touch {}", marker.display());

    for name in ["PATH", "LD_PRELOAD", "BASH_ENV", "IFS"] {
        let output = command_at(
            directory.path(),
            &[
                "run",
                "--env",
                &format!("{name}=pm://00112233445566778899aabbccddeeff"),
                "--",
                "/bin/sh",
                "-c",
                &script,
            ],
        )
        .output()
        .expect("run passmgr");

        assert_eq!(output.status.code(), Some(5), "{name}: {output:?}");
        let stderr = stderr_text(&output);
        assert!(
            stderr.contains("refusing to inject into"),
            "{name}: {stderr}"
        );
        assert!(
            !marker.exists(),
            "{name}: the daemon must not spawn the child"
        );
    }
}

#[test]
fn run_rejects_a_malformed_spec_with_a_usage_exit_code() {
    let directory = tempfile::tempdir().expect("tempdir");
    let output = command_at(directory.path(), &["run", "--env", "API_KEY", "--", "true"])
        .output()
        .expect("run passmgr");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("--env expects NAME=<ref>"), "{stderr}");
    assert!(stderr.contains("Usage:"), "{stderr}");
}

#[test]
fn run_maps_daemon_refusals_to_stable_exit_codes() {
    let daemon = Daemon::start();

    let missing = run(
        &daemon,
        &[
            "run",
            "--env",
            "API_KEY=pm://00000000000000000000000000000000",
            "--",
            "true",
        ],
    );
    assert_eq!(missing.status.code(), Some(3), "{missing:?}");
    assert!(
        stderr_text(&missing).contains("pm://00000000000000000000000000000000"),
        "{missing:?}"
    );

    let unspawnable = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/nonexistent/passmgr-run-test",
        ],
    );
    assert_eq!(unspawnable.status.code(), Some(1), "{unspawnable:?}");
    assert!(
        stderr_text(&unspawnable).contains("could not start the command"),
        "{unspawnable:?}"
    );

    // The daemon is still healthy after both refusals.
    assert!(client::ping(&daemon.paths(), &daemon.token).is_ok());
}
