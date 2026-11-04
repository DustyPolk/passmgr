//! `run` without a grant token: the human-only local path (TODO 3.7).
//!
//! With no `--grant-file` and no `PASSMGR_GRANT_FILE`, `run` prompts for the
//! master password and injects from the vault named by `--db`. The gate is the
//! same as `unlock`/`get --reveal`: both standard streams must be terminals
//! and no agent marker may be set. These tests drive the real binary through a
//! pseudo-terminal so the TTY gate is exercised, not bypassed.

#![cfg(target_os = "linux")]

mod cli_support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cli_support::*;
use tempfile::TempDir;

struct LocalVault {
    dir: TempDir,
    vault: String,
    reference: String,
}

impl LocalVault {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = vault_path(&dir);
        add_example(&vault);
        let reference = get_reference(&run(&["--db", &vault, "get", "example.com"], "master\n"));
        assert_canonical_reference(&reference);
        Self {
            dir,
            vault,
            reference,
        }
    }

    fn runtime(&self) -> &str {
        self.dir.path().to_str().expect("temporary path is UTF-8")
    }

    fn state(&self) -> String {
        self.dir
            .path()
            .join("state")
            .to_str()
            .expect("UTF-8 path")
            .to_owned()
    }

    fn env_argument(&self) -> String {
        format!("API_KEY={}", self.reference)
    }
}

fn write_program(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, body).expect("write child program");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("make child program executable");
    path
}

#[test]
fn local_run_injects_and_redacts_both_streams() {
    let _guard = serial();
    let local = LocalVault::new();
    let program = write_program(
        local.dir.path(),
        "show-secret.sh",
        "#!/bin/sh\n\
         printf 'out:%s\\n' \"$API_KEY\"\n\
         printf 'err:%s\\n' \"$API_KEY\" >&2\n\
         exit 7\n",
    );
    let env_argument = local.env_argument();
    let state = local.state();
    let output = run_on_pty(
        &[
            "--db",
            &local.vault,
            "run",
            "--env",
            &env_argument,
            "--",
            program.to_str().expect("UTF-8 path"),
        ],
        "master\n",
        true,
        true,
        &[
            ("XDG_RUNTIME_DIR", local.runtime()),
            ("XDG_STATE_HOME", state.as_str()),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "the child's status must pass through\nstdout: {}\nstderr: {}",
        output.stdout,
        output.stderr
    );
    assert!(
        output.stdout.contains("out:[REDACTED]"),
        "stdout must be redacted: {}",
        output.stdout
    );
    assert!(
        output.stderr.contains("err:[REDACTED]"),
        "stderr must be redacted: {}",
        output.stderr
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !stream.contains(EXAMPLE_SECRET),
            "the canary must never be relayed: {stream}"
        );
    }

    // A human local run is a credential use too, so it is audited with the
    // same metadata-only rule as a daemon run (TODO 3.8).
    let audit_path = local
        .dir
        .path()
        .join("state")
        .join("passmgr")
        .join("audit.jsonl");
    let text = std::fs::read_to_string(&audit_path).expect("read the audit log");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "one local run, one record: {text}");
    let record: serde_json::Value = serde_json::from_str(lines[0]).expect("audit JSON");
    assert_eq!(record["source"], "local");
    assert_eq!(record["outcome"], "allowed");
    assert_eq!(record["ref"], local.reference);
    assert_eq!(record["exit"], 7);
    assert_eq!(record["command"], program.to_str().expect("UTF-8 path"));
    assert!(record["grant"].is_null());
    assert!(
        !text.contains(EXAMPLE_SECRET),
        "the local audit record must not contain the secret"
    );
}

#[test]
fn local_run_is_refused_for_every_agent_marker() {
    let _guard = serial();
    let local = LocalVault::new();
    let marker_file = local.dir.path().join("ran");
    let env_argument = local.env_argument();
    let script = format!(
        "printf '%s' \"$API_KEY\"; : > '{}'",
        marker_file.to_str().expect("UTF-8 path")
    );

    for marker in passmgr::agent::AGENT_MARKERS {
        let output = run_with_env(
            &[
                "--db",
                &local.vault,
                "run",
                "--env",
                &env_argument,
                "--",
                "/bin/sh",
                "-c",
                &script,
            ],
            "master\n",
            &[(marker, "1"), ("XDG_RUNTIME_DIR", local.runtime())],
        );
        assert_eq!(
            output.status.code(),
            Some(5),
            "{marker} must select the agent refusal\nstdout: {}\nstderr: {}",
            stdout(&output),
            stderr(&output)
        );
        let message = stderr(&output);
        assert!(message.contains("agent context"), "{marker}: {message}");
        assert!(message.contains(marker), "{marker}: {message}");
        assert!(stdout(&output).is_empty(), "{marker} leaked stdout");
        assert!(
            !message.contains(EXAMPLE_SECRET),
            "{marker} leaked the canary"
        );
        assert!(!marker_file.exists(), "{marker} still ran the command");
    }
}

#[test]
fn local_run_is_refused_without_a_terminal_on_stdin() {
    let _guard = serial();
    let local = LocalVault::new();
    let marker_file = local.dir.path().join("ran");
    let env_argument = local.env_argument();
    let script = format!(
        "printf '%s' \"$API_KEY\"; : > '{}'",
        marker_file.to_str().expect("UTF-8 path")
    );

    // A pipe is not a human terminal, even when it carries the right master
    // password. The refusal must happen before the vault is opened.
    let output = run_with_env(
        &[
            "--db",
            &local.vault,
            "run",
            "--env",
            &env_argument,
            "--",
            "/bin/sh",
            "-c",
            &script,
        ],
        "master\n",
        &[("XDG_RUNTIME_DIR", local.runtime())],
    );
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(message.contains("stdin is not a terminal"), "{message}");
    assert!(stdout(&output).is_empty());
    assert!(!message.contains(EXAMPLE_SECRET));
    assert!(!marker_file.exists(), "the command must not run");
}

#[test]
fn the_agent_flag_refuses_local_run_on_a_terminal() {
    let _guard = serial();
    let local = LocalVault::new();
    let env_argument = local.env_argument();
    let output = run_on_pty(
        &[
            "--agent",
            "--db",
            &local.vault,
            "run",
            "--env",
            &env_argument,
            "--",
            "/bin/true",
        ],
        "master\n",
        true,
        true,
        &[("XDG_RUNTIME_DIR", local.runtime())],
    );
    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(output.stderr.contains("--agent flag"), "{}", output.stderr);
    assert!(!output.stdout.contains(EXAMPLE_SECRET));
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

#[test]
fn local_run_is_refused_when_stdout_is_not_a_terminal() {
    let _guard = serial();
    let local = LocalVault::new();
    let env_argument = local.env_argument();
    let output = run_on_pty(
        &[
            "--db",
            &local.vault,
            "run",
            "--env",
            &env_argument,
            "--",
            "/bin/true",
        ],
        "master\n",
        true,
        false,
        &[("XDG_RUNTIME_DIR", local.runtime())],
    );
    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(
        output.stderr.contains("stdout is not a terminal"),
        "{}",
        output.stderr
    );
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

#[test]
fn a_grant_file_always_selects_the_daemon_path() {
    let _guard = serial();
    let local = LocalVault::new();
    let grant_file = local.dir.path().join("grant.token");
    std::fs::write(&grant_file, "00".repeat(32)).expect("write fake grant token");
    std::fs::set_permissions(&grant_file, std::fs::Permissions::from_mode(0o600))
        .expect("chmod grant token");
    let env_argument = local.env_argument();
    let output = run_on_pty(
        &[
            "run",
            "--grant-file",
            grant_file.to_str().expect("UTF-8 path"),
            "--env",
            &env_argument,
            "--",
            "/bin/true",
        ],
        "master\n",
        true,
        true,
        &[("XDG_RUNTIME_DIR", local.runtime())],
    );
    // No daemon is running for this runtime dir, so the grant path fails
    // instead of silently falling back to the local vault.
    assert_eq!(output.status.code(), Some(1), "{}", output.stderr);
    assert!(
        output.stderr.contains("no passmgr daemon is running"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Enter Master Password"),
        "the grant path must not prompt: {}",
        output.stderr
    );
    assert!(!output.stdout.contains(EXAMPLE_SECRET));
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

#[test]
fn local_run_reports_an_unknown_reference_with_exit_3() {
    let _guard = serial();
    let local = LocalVault::new();
    // Valid `pm://` syntax, but nothing in this vault uses the id.
    let env_argument = "API_KEY=pm://ffffffffffffffffffffffffffffffff";
    let output = run_on_pty(
        &[
            "--db",
            &local.vault,
            "run",
            "--env",
            env_argument,
            "--",
            "/bin/true",
        ],
        "master\n",
        true,
        true,
        &[("XDG_RUNTIME_DIR", local.runtime())],
    );
    assert_eq!(output.status.code(), Some(3), "{}", output.stderr);
    assert!(
        output.stderr.contains("no credential found for reference"),
        "{}",
        output.stderr
    );
    assert!(!output.stdout.contains(EXAMPLE_SECRET));
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

#[test]
fn a_local_run_whose_audit_append_fails_exits_non_zero() {
    // The preflight creates the log; the child makes it unwritable so the
    // *post-run* append fails. The human must not see exit 0 for a use that
    // is missing from the audit trail (TODO R.68), and stderr must name the
    // log so the cause is actionable.
    let _guard = serial();
    let local = LocalVault::new();
    let audit = format!("{}/passmgr/audit.jsonl", local.state());
    let program = write_program(
        local.dir.path(),
        "break-audit.sh",
        "#!/bin/sh\nprintf 'ran\\n'\nchmod 400 \"$1\"\n",
    );
    let env_argument = local.env_argument();
    let state = local.state();
    let output = run_on_pty(
        &[
            "--db",
            &local.vault,
            "run",
            "--env",
            &env_argument,
            "--",
            program.to_str().expect("UTF-8 path"),
            &audit,
        ],
        "master\n",
        true,
        true,
        &[
            ("XDG_RUNTIME_DIR", local.runtime()),
            ("XDG_STATE_HOME", state.as_str()),
        ],
    );

    assert!(
        output.stdout.contains("ran"),
        "the child must have run before the append failed: {}",
        output.stdout
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "an unrecorded run must exit non-zero\nstdout: {}\nstderr: {}",
        output.stdout,
        output.stderr
    );
    assert!(
        output.stderr.contains("audit record could not be written"),
        "stderr must name the failure: {}",
        output.stderr
    );
    assert!(
        output.stderr.contains("audit.jsonl"),
        "stderr must name the audit log: {}",
        output.stderr
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !stream.contains(EXAMPLE_SECRET),
            "the canary must never be relayed: {stream}"
        );
    }
}
