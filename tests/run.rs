//! End-to-end tests for `passmgr run`: the agent-facing injection surface.
//!
//! Each test starts a real `pmd` against a disposable runtime directory and a
//! vault encrypted with deliberately cheap Argon2 parameters (this file is not
//! testing the KDF). The secret is a canary generated here; it must never
//! appear in the CLI's stdout, stderr or exit path. The CLI process is the one
//! an agent would actually drive: non-TTY stdio, no master password.

#![cfg(unix)]

mod run_support;

use run_support::*;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use passmgr::client;
use passmgr::crypto;
use passmgr::grant::{Capabilities, Grant, GrantSpec, Scope};
use passmgr::store::{self, Credential};
use passmgr::vault::Vault;
use zeroize::Zeroizing;

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
