//! A request that never reached `pmd` must never look successful (TODO R.60).
//!
//! `main` maps a bare `Error::Io(BrokenPipe)` to exit 0 because the CLI's own
//! output pipe going away (`passmgr list | head -1`) is not a failure. A
//! *socket* write fails the same way when `pmd` exits after accepting the
//! connection (a lock, the idle timeout, a crash), so `client` maps every
//! request write to `Error::Daemon`; these tests prove the user-visible half.
//! The stub listener accepts and closes without reading, which gives the
//! client's frame write `EPIPE`.
//!
//! This lives apart from `tests/run.rs` to keep that file under the layout
//! limit.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};

use passmgr::grant::GrantToken;
use passmgr::socket::RuntimePaths;
use passmgr::token::SessionToken;
use tempfile::TempDir;

/// A runtime directory with a session file and a valid grant token file. No
/// vault and no daemon: the CLI must fail before either could matter.
fn stub_fixture() -> (TempDir, RuntimePaths, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let paths = RuntimePaths::at(directory.path().join("passmgr"));
    let token = SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let grant = directory.path().join("grant.token");
    let grant_token = GrantToken::generate().expect("grant token");
    fs::write(&grant, format!("{}\n", grant_token.to_hex().as_str())).expect("grant file");
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).expect("chmod grant file");
    (directory, paths, grant)
}

/// Build a `passmgr` invocation with non-TTY stdio and no inherited agent
/// marker.
fn command_at(xdg_runtime_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_passmgr"));
    command
        .env("XDG_RUNTIME_DIR", xdg_runtime_dir)
        .env_remove("PASSMGR_DB")
        .env_remove("PASSMGR_GRANT_FILE");
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

/// Exit 0 here would tell an agent the command ran when no child was spawned,
/// no grant was checked and no use was recorded.
#[test]
fn run_fails_when_the_daemon_goes_away_before_the_request() {
    let (directory, paths, grant) = stub_fixture();
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");
    let server = std::thread::spawn(move || {
        // Close without reading: the framed request has no reader.
        drop(listener.accept().expect("accept").0);
    });

    let variable = "API_KEY=pm://00112233445566778899aabbccddeeff";
    let output = command_at(
        directory.path(),
        &["run", "--env", variable, "--", "/bin/true"],
    )
    .env("PASSMGR_GRANT_FILE", &grant)
    .output()
    .expect("run passmgr");
    server.join().expect("stub server finished");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unlock daemon"),
        "the failure must name the daemon: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}
