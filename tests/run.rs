//! End-to-end tests for `passmgr run`: the agent-facing injection surface.
//!
//! Each test starts a real `pmd` against a disposable runtime directory and a
//! vault encrypted with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The secret is a canary generated here; it must never
//! appear in the CLI's stdout, stderr or exit path. The CLI process is the one
//! an agent would actually drive: non-TTY stdio, no master password.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use passmgr::client;
use passmgr::crypto::{self, KEY_LEN, KdfParams};
use passmgr::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
use passmgr::vault::Vault;
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
    grant_file: PathBuf,
}

impl Fixture {
    /// A fixture whose run grant allows `/bin/sh`, `/bin/true` and `extra`.
    /// Extra programs must already exist and be canonicalized by the caller.
    fn with_commands(extra: &[PathBuf]) -> Self {
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
        let id = credential.id();

        let sh = fs::canonicalize("/bin/sh").expect("canonical /bin/sh");
        let truth = fs::canonicalize("/bin/true").expect("canonical /bin/true");
        let mut commands = vec![sh, truth];
        commands.extend(extra.iter().cloned());
        let grant_token = GrantToken::generate().expect("grant token");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let scope = Scope::new(vec![id], Vec::new(), None).expect("scope");
        let grant = Grant::create(
            GrantSpec {
                label: "run test grant".into(),
                scope,
                commands,
                capabilities: Capabilities::RUN,
                expires_at: now + 3600,
                max_uses: None,
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

        let plaintext = store::encode(&[credential], &[grant]).expect("encode store");
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
            grant_file,
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
        Self::start_in(None, None)
    }

    fn start_with_commands(commands: &[PathBuf]) -> Self {
        Self::start_in_with(None, None, commands)
    }

    /// Start `pmd` with a specific working directory and `PATH`, so a test can
    /// give the daemon a different cwd/PATH from the CLI that talks to it.
    fn start_in(cwd: Option<&Path>, path: Option<&Path>) -> Self {
        Self::start_in_with(cwd, path, &[])
    }

    fn start_in_with(cwd: Option<&Path>, path: Option<&Path>, commands: &[PathBuf]) -> Self {
        let fixture = Fixture::with_commands(commands);
        let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
        command
            .arg("--vault")
            .arg(&fixture.vault)
            .arg("--runtime-dir")
            .arg(&fixture.runtime)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        if let Some(path) = path {
            command.env("PATH", path);
        }
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
    // `run` refuses an exported PASSMGR_DB when a grant selects the daemon
    // (see below); tests must not inherit one from the developer's shell, and
    // a grant comes only from a test.
    command.env_remove("PASSMGR_DB");
    command.env_remove("PASSMGR_GRANT_FILE");
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
        .env("PASSMGR_GRANT_FILE", &fixture.grant_file)
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

/// Write an executable shell script into `dir`.
fn write_program(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write program");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod program");
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
fn redaction_replaces_only_the_exact_secret_not_its_encodings() {
    // This pins the documented limit (README, `--help`, SECURITY.md limit 3):
    // redaction is streaming and exact-bytes only, so a base64 copy of the
    // canary is relayed verbatim. If encoded redaction (TODO 4.6) lands, the
    // documents and this test must change together; until then, an agent that
    // encodes the value itself gets it back, and no document may claim
    // otherwise.
    let daemon = Daemon::start();
    let encoded = base64(SECRET.as_bytes());
    assert_ne!(encoded, SECRET, "the fixture must actually be encoded");
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "/bin/sh",
            "-c",
            // Print the raw value (must be redacted), a newline, then the
            // base64 of the value (documented as not redacted).
            r#"printf %s "$API_KEY"; printf '\n'; printf %s "$1""#,
            "sh",
            encoded.as_str(),
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let expected = format!("[REDACTED]\n{encoded}");
    assert_eq!(output.stdout, expected.as_bytes(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(
        !output
            .stdout
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes()),
        "the raw canary reached the CLI output"
    );
}

/// Standard base64 with padding, computed here so the test does not depend on
/// an external `base64` binary being on the child's fixed `PATH`.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b1 = u32::from(chunk[0]);
        let b2 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b3 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b1 << 16) | (b2 << 8) | b3;
        let index = |shift: u32| ALPHABET[((triple >> shift) & 0x3f) as usize] as char;
        out.push(index(18));
        out.push(index(12));
        out.push(if chunk.len() > 1 { index(6) } else { '=' });
        out.push(if chunk.len() > 2 { index(0) } else { '=' });
    }
    out
}

#[test]
fn run_executes_relative_programs_in_the_callers_working_directory() {
    // The daemon was started from a directory that also contains `rel.sh`.
    // Running the daemon's copy instead of the caller's would hand the secret
    // to a different script, so this is a security property, not a nicety.
    let daemon_dir = tempfile::tempdir().expect("tempdir");
    let caller_dir = tempfile::tempdir().expect("tempdir");
    write_program(daemon_dir.path(), "rel.sh", "printf daemon-directory");
    write_program(caller_dir.path(), "rel.sh", "printf caller-directory");
    let caller_program = fs::canonicalize(caller_dir.path().join("rel.sh")).expect("canonical");
    let daemon = Daemon::start_in_with(Some(daemon_dir.path()), None, &[caller_program]);

    let output = command_at(
        daemon.xdg_runtime_dir(),
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "./rel.sh",
        ],
    )
    .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
    .current_dir(caller_dir.path())
    .output()
    .expect("run passmgr");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"caller-directory", "{output:?}");
    assert!(
        !stderr_text(&output).contains("daemon-directory"),
        "the daemon's working directory must not be used: {output:?}"
    );
}

/// A grant-backed `run` cannot choose a vault: the daemon injects from the
/// vault it was unlocked with. Accepting `--db`/`PASSMGR_DB` and ignoring it
/// would inject from a vault the human did not name, so both are usage errors
/// (exit 2) before any connection or spawn. A grant-less local run is a
/// different path and does accept them (tests/run_local.rs).
#[test]
fn run_refuses_db_selection_before_connecting_or_running() {
    let daemon = Daemon::start();
    let other = tempfile::tempdir().expect("tempdir");
    let other_vault = other.path().join("other.dat");
    fs::write(&other_vault, b"not the daemon's vault").expect("write other vault");
    let marker = other.path().join("ran-marker");
    let marker_text = marker.to_str().expect("marker path is UTF-8").to_owned();
    let env = env_argument(&daemon, "API_KEY");
    let argv = [
        "--env",
        env.as_str(),
        "--",
        "/bin/sh",
        "-c",
        "printf ran > \"$1\"",
        "sh",
        marker_text.as_str(),
    ];

    let mut flag_argv = vec!["--db", other_vault.to_str().expect("UTF-8"), "run"];
    flag_argv.extend_from_slice(&argv);
    let output = run(&daemon, &flag_argv);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("--db"), "{stderr}");
    assert!(stderr.contains("does not accept"), "{stderr}");

    let mut env_argv = vec!["run"];
    env_argv.extend_from_slice(&argv);
    let output = command_at(daemon.xdg_runtime_dir(), &env_argv)
        .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
        .env("PASSMGR_DB", &other_vault)
        .output()
        .expect("run passmgr");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("PASSMGR_DB"), "{stderr}");
    assert!(stderr.contains("does not accept"), "{stderr}");

    assert!(
        !marker.exists(),
        "the child must never run when the vault is ambiguous"
    );
    assert!(
        !stderr.contains(SECRET) && !String::from_utf8_lossy(&output.stdout).contains(SECRET),
        "the canary must not appear in the refusal"
    );
    // The refusals happened before the daemon was asked to do anything.
    assert!(client::ping(&daemon.paths(), &daemon.token).is_ok());
}

#[test]
fn run_resolves_a_bare_command_through_the_callers_path() {
    // `pmd` keeps the PATH of the shell that ran `unlock`. A bare program name
    // must still resolve against the caller's PATH, or `run` would execute a
    // same-named binary the human never approved.
    let daemon_bin = tempfile::tempdir().expect("tempdir");
    let caller_bin = tempfile::tempdir().expect("tempdir");
    write_program(daemon_bin.path(), "pm-fake-tool", "printf daemon-path");
    write_program(caller_bin.path(), "pm-fake-tool", "printf caller-path");
    let caller_tool = fs::canonicalize(caller_bin.path().join("pm-fake-tool")).expect("canonical");
    let daemon = Daemon::start_in_with(None, Some(daemon_bin.path()), &[caller_tool]);

    let output = command_at(
        daemon.xdg_runtime_dir(),
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "pm-fake-tool",
        ],
    )
    .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
    .env("PATH", caller_bin.path())
    .output()
    .expect("run passmgr");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"caller-path", "{output:?}");
}

#[test]
fn run_refuses_an_unresolvable_command_with_a_usage_error() {
    let daemon = Daemon::start();
    let output = run(
        &daemon,
        &[
            "run",
            "--env",
            &env_argument(&daemon, "API_KEY"),
            "--",
            "passmgr-no-such-program",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("cannot find the command"), "{stderr}");
    assert!(
        stderr.contains("passmgr-no-such-program"),
        "the caller must learn which program was missing: {stderr}"
    );
    // The refusal happened before the daemon was asked to run anything.
    assert!(client::ping(&daemon.paths(), &daemon.token).is_ok());
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
    .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
    .env("CLAUDECODE", "1")
    .output()
    .expect("run passmgr");

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"[REDACTED]");
    // stdin is /dev/null: a master-password prompt would fail, not hang.
    assert!(stderr_text(&output).is_empty(), "{output:?}");
}

#[test]
fn run_requires_a_grant_and_refuses_a_readable_token_file() {
    let daemon = Daemon::start();
    let argv = [
        "run",
        "--env",
        &env_argument(&daemon, "API_KEY"),
        "--",
        "/bin/true",
    ];

    // The session token alone does not authorize a daemon use. With no grant
    // file this invocation is the human-only local path instead, and this
    // test has no terminal, so it is refused (exit 5) before opening a vault.
    let output = command_at(daemon.xdg_runtime_dir(), &argv)
        .output()
        .expect("run passmgr");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("local vault"), "{stderr}");
    assert!(stderr.contains("not a terminal"), "{stderr}");
    assert!(!stderr.contains(SECRET), "{stderr}");

    // The flag names the file explicitly.
    let grant_file = daemon.grant_file.to_str().expect("utf-8 path");
    let mut flagged = vec!["run", "--grant-file", grant_file];
    flagged.extend_from_slice(&argv[1..]);
    let output = command_at(daemon.xdg_runtime_dir(), &flagged)
        .output()
        .expect("run passmgr");
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    // A token file other users can read is not a secret store.
    fs::set_permissions(&daemon.grant_file, fs::Permissions::from_mode(0o644))
        .expect("chmod grant file");
    let output = command_at(daemon.xdg_runtime_dir(), &flagged)
        .output()
        .expect("run passmgr");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = stderr_text(&output);
    assert!(stderr.contains("grant"), "{stderr}");
    assert!(
        stderr.contains("0600") || stderr.contains("group"),
        "{stderr}"
    );
    assert!(!stderr.contains(SECRET), "{stderr}");
}

#[test]
fn run_without_a_daemon_is_a_clear_runtime_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    // A grant token selects the daemon path even when no daemon is running;
    // without one this would be the local human path instead.
    let grant_file = directory.path().join("grant.token");
    fs::write(&grant_file, "00".repeat(32)).expect("write grant token");
    fs::set_permissions(&grant_file, fs::Permissions::from_mode(0o600)).expect("chmod grant token");
    let output = command_at(
        directory.path(),
        &[
            "run",
            "--grant-file",
            grant_file.to_str().expect("UTF-8 path"),
            "--env",
            "API_KEY=pm://00112233445566778899aabbccddeeff",
            "--",
            "/bin/true",
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
    let unspawnable_dir = tempfile::tempdir().expect("tempdir");
    let unspawnable_program = unspawnable_dir.path().join("unspawnable");
    fs::write(&unspawnable_program, b"#!/bin/sh\nexit 0\n").expect("write program");
    fs::set_permissions(&unspawnable_program, fs::Permissions::from_mode(0o755))
        .expect("chmod program");
    let unspawnable_program = fs::canonicalize(&unspawnable_program).expect("canonical");
    let daemon = Daemon::start_with_commands(std::slice::from_ref(&unspawnable_program));
    // Now make it non-executable: the path still resolves and is inside the
    // grant, but `exec` fails, which is a spawn failure rather than a denial.
    fs::set_permissions(&unspawnable_program, fs::Permissions::from_mode(0o644))
        .expect("chmod program");

    let missing = run(
        &daemon,
        &[
            "run",
            "--env",
            "API_KEY=pm://00000000000000000000000000000000",
            "--",
            "/bin/true",
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
            unspawnable_program.to_str().expect("utf-8 path"),
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Replace the vault's contents without changing the container header, so the
/// running daemon's key still opens it (the salt and KDF parameters are kept).
fn rewrite_vault(fixture: &Fixture, credentials: &[Credential], grants: &[Grant]) {
    let plaintext = store::encode(credentials, grants).expect("encode store");
    let template = fs::read(&fixture.vault).expect("read vault");
    let container = crypto::encrypt_with_key(&plaintext, fixture.key.as_slice(), &template)
        .expect("encrypt vault");
    fs::write(&fixture.vault, &container).expect("write vault");
}

/// R.31: the CLI must not turn a grant token into an existence oracle. For
/// each state in which the grant can never be used, an existing and a
/// nonexistent reference must have the same exit status; a credential that
/// exists but is outside the scope must exit like a missing one.
#[test]
fn a_denied_run_exit_code_does_not_reveal_whether_a_reference_exists() {
    let daemon = Daemon::start();
    let now = unix_now();

    let (credentials, base_grant) = {
        let vault = Vault::open_with_key(&daemon.vault, daemon.key.as_slice()).expect("open");
        (vault.list().to_vec(), vault.grants()[0].clone())
    };
    let token_hash = *base_grant.token_hash();
    let scope = base_grant.scope().clone();
    let commands = base_grant.commands().to_vec();
    let absent = "pm://00000000000000000000000000000000";
    let absent_env = format!("API_KEY={absent}");

    let mut revoked = base_grant.clone();
    revoked.revoke(now).expect("revoke");
    // `Grant::create` refuses an expiry that is not after its `now`, so the
    // grant is created in the past and is already expired when stored.
    let expired = Grant::create(
        GrantSpec {
            label: "expired".into(),
            scope: scope.clone(),
            commands: commands.clone(),
            capabilities: Capabilities::RUN,
            expires_at: now - 3_600,
            max_uses: None,
        },
        token_hash,
        now - 7_200,
    )
    .expect("expired grant");
    let mut exhausted = Grant::create(
        GrantSpec {
            label: "exhausted".into(),
            scope: scope.clone(),
            commands: commands.clone(),
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: Some(1),
        },
        token_hash,
        now,
    )
    .expect("exhausted grant");
    exhausted.mark_used(now).expect("use");
    let unlisted = Credential::new(
        "other.test".into(),
        "bob".into(),
        Zeroizing::new("other-run-canary-value".into()),
    )
    .expect("credential");
    let out_of_scope = Grant::create(
        GrantSpec {
            label: "out of scope".into(),
            scope: Scope::new(vec![unlisted.id()], Vec::new(), None).expect("scope"),
            commands,
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: None,
        },
        token_hash,
        now,
    )
    .expect("out-of-scope grant");
    let credentials = vec![credentials[0].clone(), unlisted];

    let cases = [
        ("revoked", revoked, 5),
        ("expired", expired, 5),
        ("exhausted", exhausted, 5),
        ("out of scope", out_of_scope, 3),
    ];
    for (label, grant, expected) in cases {
        rewrite_vault(&daemon, &credentials, std::slice::from_ref(&grant));
        // The base credential exists. For the out-of-scope grant it exists
        // but is outside the scope, which must look exactly like a missing
        // reference.
        let existing_env = env_argument(&daemon, "API_KEY");
        let existing = run(&daemon, &["run", "--env", &existing_env, "--", "/bin/true"]);
        let missing = run(&daemon, &["run", "--env", &absent_env, "--", "/bin/true"]);

        assert_eq!(
            existing.status.code(),
            Some(expected),
            "{label}: existing reference: {existing:?}"
        );
        assert_eq!(
            missing.status.code(),
            Some(expected),
            "{label}: nonexistent reference: {missing:?}"
        );
        let expected_message = if expected == 3 {
            "no credential found"
        } else {
            "refused the run"
        };
        for output in [&existing, &missing] {
            let stderr = stderr_text(output);
            assert!(stderr.contains(expected_message), "{label}: {stderr}");
            assert!(!stderr.contains(SECRET), "{label}: {stderr}");
            assert!(
                !stderr.contains("other-run-canary-value"),
                "{label}: {stderr}"
            );
        }
    }

    // The vault rewrites did not disturb the running daemon.
    assert!(client::ping(&daemon.paths(), &daemon.token).is_ok());
}

/// A caller that stops reading (`| head -1`, a host that closed its pipe)
/// must not turn a failing command into a success. `run` cannot relay the
/// child's status any more, so it cancels the run and exits 141; the child is
/// killed instead of being left running with nobody watching (TODO R.47).
#[test]
fn a_closed_output_pipe_cancels_the_run_and_exits_nonzero() {
    let daemon = Daemon::start();
    let flag = daemon.xdg_runtime_dir().join("release");
    let pid_file = daemon.xdg_runtime_dir().join("child.pid");
    // Print, wait to be released by the test, print again and then linger.
    // The second print is what makes the CLI write into a closed pipe; the
    // long sleep proves the daemon cancelled the child (it is killed long
    // before the script could finish). The padding matters: the redactor
    // holds back the last `secret.len() - 1` bytes of *every* chunk, whether
    // or not they match, so a short first line is not relayed until more
    // output follows it.
    let script = r#"echo $$ > "$1"
printf 'ready\n'
printf 'skip-skip-skip-skip-skip-skip-skip-skip-skip\n'
while [ ! -e "$0" ]; do sleep 0.02; done
printf 'more-more-more-more-more-more-more-more\n'
sleep 30"#;
    let environment = env_argument(&daemon, "API_KEY");
    let mut child = command_at(
        daemon.xdg_runtime_dir(),
        &[
            "run",
            "--env",
            &environment,
            "--",
            "/bin/sh",
            "-c",
            script,
            flag.to_str().expect("flag path"),
            pid_file.to_str().expect("pid path"),
        ],
    )
    .env("PASSMGR_GRANT_FILE", &daemon.grant_file)
    .spawn()
    .expect("spawn passmgr run");

    // Read exactly the first line, then close our end of the pipe while the
    // child is still running.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut first = [0u8; 6];
    stdout.read_exact(&mut first).expect("read the first line");
    assert_eq!(&first, b"ready\n", "the child's first line must be relayed");
    drop(stdout);
    let pid = wait_for_pid(&pid_file);
    fs::write(&flag, b"go").expect("release the child");

    let status = wait_for_exit(&mut child, WAIT);
    assert_eq!(
        status.code(),
        Some(141),
        "a closed pipe must not look like success: {status:?}"
    );
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(
        stderr.contains("pipe closed") && stderr.contains("cancelled"),
        "the exit is explained on stderr: {stderr:?}"
    );
    assert!(!stderr.contains(SECRET), "the canary reached stderr");

    // The daemon noticed the disconnect and killed the child before it
    // reached the end of its 30-second sleep.
    wait_for_process_exit(pid);
}

/// Poll for the pid a test child reported, with a deadline.
fn wait_for_pid(path: &Path) -> libc::pid_t {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse() {
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

/// Poll until `pid` no longer exists (the daemon killed and reaped it).
fn wait_for_process_exit(pid: libc::pid_t) {
    let deadline = Instant::now() + WAIT;
    loop {
        // SAFETY: signal 0 only checks for existence; the pid came from a
        // child of this test's daemon.
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
            "the daemon did not kill the child after its output pipe closed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for a spawned process to exit, polling with a deadline instead of
/// sleeping for a fixed time.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
