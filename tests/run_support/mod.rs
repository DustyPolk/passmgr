#![allow(dead_code)] // each integration-test binary uses a different subset

use std::fs;
use std::io::Write;
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
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const MASTER: &str = "run test master password";
pub const SECRET: &str = "s3cret-run-value-must-never-leak";
pub const WAIT: Duration = Duration::from_secs(10);

pub struct Fixture {
    pub _directory: TempDir,
    pub vault: PathBuf,
    pub runtime: PathBuf,
    pub key: Zeroizing<Vec<u8>>,
    pub token: SessionToken,
    pub reference: String,
    pub grant_file: PathBuf,
}

impl Fixture {
    /// A fixture whose run grant allows `/bin/sh`, `/bin/true` and `extra`.
    /// Extra programs must already exist and be canonicalized by the caller.
    pub fn with_commands(extra: &[PathBuf]) -> Self {
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

    pub fn xdg_runtime_dir(&self) -> &Path {
        self._directory.path()
    }

    pub fn paths(&self) -> RuntimePaths {
        RuntimePaths::at(&self.runtime)
    }
}

/// A fixture plus a running `pmd`; dropping it kills and reaps the daemon.
pub struct Daemon {
    pub fixture: Fixture,
    pub child: Child,
}

impl Daemon {
    pub fn start() -> Self {
        Self::start_in(None, None)
    }

    pub fn start_with_commands(commands: &[PathBuf]) -> Self {
        Self::start_in_with(None, None, commands)
    }

    /// Start `pmd` with a specific working directory and `PATH`, so a test can
    /// give the daemon a different cwd/PATH from the CLI that talks to it.
    pub fn start_in(cwd: Option<&Path>, path: Option<&Path>) -> Self {
        Self::start_in_with(cwd, path, &[])
    }

    pub fn start_in_with(cwd: Option<&Path>, path: Option<&Path>, commands: &[PathBuf]) -> Self {
        let fixture = Fixture::with_commands(commands);
        let mut command = Command::new(env!("CARGO_BIN_EXE_pmd"));
        command
            .arg("--vault")
            .arg(&fixture.vault)
            .arg("--runtime-dir")
            .arg(&fixture.runtime)
            .env("XDG_STATE_HOME", fixture._directory.path().join("state"))
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
pub fn command_at(xdg_runtime_dir: &Path, args: &[&str]) -> Command {
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

pub fn run(fixture: &Fixture, args: &[&str]) -> Output {
    command_at(fixture.xdg_runtime_dir(), args)
        .env("PASSMGR_GRANT_FILE", &fixture.grant_file)
        .env("XDG_STATE_HOME", fixture._directory.path().join("state"))
        .output()
        .expect("run passmgr")
}

pub fn env_argument(fixture: &Fixture, name: &str) -> String {
    format!("{name}={}", fixture.reference)
}

/// stderr used for assertions; the daemon is asked to relay child output only.
pub fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Write an executable shell script into `dir`.
pub fn write_program(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write program");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod program");
}
