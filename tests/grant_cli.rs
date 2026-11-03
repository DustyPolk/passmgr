//! End-to-end tests for `passmgr grant create` (TODO 3.4d).
//!
//! The CLI is exercised on a real pseudo-terminal against a real `pmd`, or
//! against a stub socket when the test must prove that no daemon request was
//! made. Vaults use deliberately cheap Argon2 parameters; this file is not
//! testing the KDF. Every test uses its own `XDG_RUNTIME_DIR` and temp vault.

#![cfg(unix)]

mod cli_support;

use cli_support::*;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use passmgr::crypto::{self, KdfParams};
use passmgr::grant::{
    Capabilities, Grant, GrantSpec, MAX_GRANTS, Scope, TokenHash, is_interpreter,
};
use passmgr::socket::RuntimePaths;
use passmgr::store::{self, Credential};
use passmgr::token::SessionToken;
use passmgr::vault::Vault;
use tempfile::TempDir;
use zeroize::Zeroizing;

const MASTER: &str = "grant cli test master password";
const SECRET: &str = "s3cret-grant-cli-value-must-never-leak";
const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
    reference: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_grants(0)
    }

    fn with_grants(count: usize) -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = directory.path().join("vault.dat");
        let credential = Credential::new(
            "example.test".into(),
            "alice".into(),
            Zeroizing::new(SECRET.into()),
        )
        .expect("credential");
        let reference = credential.reference();

        let now = unix_now();
        let grants: Vec<Grant> = (0..count)
            .map(|index| {
                let spec = GrantSpec {
                    label: format!("seed grant {index}"),
                    scope: Scope::new(vec![], vec!["prod".into()], None).expect("scope"),
                    commands: vec![PathBuf::from("/usr/bin/true")],
                    capabilities: Capabilities::RUN,
                    expires_at: now + 3_600,
                    max_uses: None,
                };
                Grant::create(
                    spec,
                    TokenHash::of(format!("seed-token-{index}").as_bytes()),
                    now,
                )
                .expect("seed grant")
            })
            .collect();

        let plaintext = store::encode(&[credential], &grants).expect("encode store");
        let container = crypto::encrypt(&plaintext, MASTER, KdfParams::new(8 * 1024, 1, 1))
            .expect("encrypt vault");
        fs::write(&vault, &container).expect("write vault");
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).expect("chmod vault");

        Self {
            directory,
            vault,
            reference,
        }
    }

    fn runtime(&self) -> &Path {
        self.directory.path()
    }

    fn runtime_text(&self) -> &str {
        self.runtime().to_str().expect("runtime path is UTF-8")
    }

    fn db(&self) -> &str {
        self.vault.to_str().expect("vault path is UTF-8")
    }

    fn daemon_paths(&self) -> RuntimePaths {
        RuntimePaths::at(self.runtime().join("passmgr"))
    }

    fn temp_path(&self, name: &str) -> PathBuf {
        self.runtime().join(name)
    }

    fn run_pty(&self, args: &[&str], input: &str) -> PtyOutput {
        run_on_pty(
            args,
            input,
            true,
            true,
            &[("XDG_RUNTIME_DIR", self.runtime_text())],
        )
    }

    fn unlock(&self) {
        let output = self.run_pty(&["--db", self.db(), "unlock"], &format!("{MASTER}\n"));
        assert!(output.status.success(), "unlock failed: {}", output.stderr);
        self.wait_ready();
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + WAIT;
        loop {
            let ready = passmgr::session::load(&self.daemon_paths())
                .ok()
                .is_some_and(|token| passmgr::client::ping(&self.daemon_paths(), &token).is_ok());
            if ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not become ready within {WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never leave a detached daemon behind, even after a failed assertion.
        let _ = base_command(&["lock"])
            .env("XDG_RUNTIME_DIR", self.runtime())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex has an even number of digits");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit"))
        .collect()
}

fn assert_ok(output: &PtyOutput) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        output.stdout,
        output.stderr
    );
}

/// A successful creation stores a scoped grant, writes the raw token only to a
/// new 0600 file, never prints it, and leaves the daemon holding a usable key.
#[test]
fn grant_create_writes_a_scoped_grant_and_never_prints_the_token() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let out = fixture.temp_path("deploy.token");
    let out_text = out.to_str().expect("path is UTF-8");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--ref",
            &fixture.reference,
            "--tag",
            "prod",
            "--command",
            "/bin/true",
            "--expires",
            "1h",
            "--max-uses",
            "2",
            "--out",
            out_text,
        ],
        &format!("{MASTER}\n"),
    );
    assert_ok(&output);

    let token_text = fs::read_to_string(&out).expect("token file");
    let token_hex = token_text.trim_end();
    assert_eq!(token_hex.len(), 64, "a grant token is 32 bytes of hex");
    assert!(
        token_hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "the token file holds lowercase hex"
    );
    assert_eq!(token_text, format!("{token_hex}\n"));
    assert_eq!(
        fs::metadata(&out).expect("metadata").permissions().mode() & 0o777,
        0o600,
        "the token file must be private"
    );
    for text in [&output.stdout, &output.stderr] {
        assert!(!text.contains(token_hex), "the token reached the terminal");
        assert!(
            !text.contains(SECRET),
            "the vault secret reached the terminal"
        );
    }

    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert_eq!(vault.grants().len(), 1);
    let grant = &vault.grants()[0];
    assert_eq!(grant.label(), "deploy prod");
    assert_eq!(grant.scope().refs().len(), 1);
    assert_eq!(grant.scope().refs()[0].to_ref(), fixture.reference);
    assert_eq!(grant.scope().tags(), ["prod"]);
    assert_eq!(grant.scope().fields(), None);
    assert!(grant.capabilities().contains(Capabilities::RUN));
    assert_eq!(
        grant.commands(),
        [fs::canonicalize("/bin/true").expect("canonical true")]
    );
    assert_eq!(grant.max_uses(), Some(2));
    let expected = TokenHash::of(&decode_hex(token_hex));
    assert!(grant.token_hash().matches(&expected));

    let now = unix_now();
    assert!(grant.expires_at_unix() > now);
    assert!(grant.expires_at_unix() <= now + 3_600 + 60);

    // The CLI rewrote the vault with the key it derived; the daemon's hot key
    // must still open the new bytes and serve an injected run.
    let run = run_with_env(
        &[
            "run",
            "--env",
            &format!("TOKEN={}", fixture.reference),
            "--",
            "/usr/bin/env",
        ],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&run);
    assert!(
        stdout(&run).contains("TOKEN=[REDACTED]"),
        "{}",
        stdout(&run)
    );
    assert!(!stdout(&run).contains(SECRET));
}

/// An existing `--out` file is never truncated, even when everything else is
/// valid; the command fails before it prompts for the master password.
#[test]
fn grant_create_refuses_to_overwrite_an_existing_token_file() {
    let _guard = serial();
    let fixture = Fixture::new();
    fixture.unlock();

    let out = fixture.temp_path("existing.token");
    fs::write(&out, b"keep me").expect("seed token file");
    fs::set_permissions(&out, fs::Permissions::from_mode(0o600)).expect("chmod");

    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "deploy",
            "--tag",
            "prod",
            "--command",
            "/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("refusing to overwrite"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("Master Password"),
        "the refusal must happen before the prompt: {}",
        output.stderr
    );
    assert_eq!(fs::read(&out).expect("token file"), b"keep me");
    assert!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .is_empty()
    );
}

/// Interpreter and shell paths are refused before any prompt, file or socket
/// work unless the human explicitly allows them.
#[test]
fn grant_create_refuses_an_interpreter_without_the_flag() {
    let _guard = serial();
    let fixture = Fixture::new();
    let out = fixture.temp_path("shell.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "shell",
            "--tag",
            "prod",
            "--command",
            "/bin/sh",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(output.stderr.contains("interpreter"), "{}", output.stderr);
    assert!(!output.stderr.contains("Master Password"));
    assert!(!out.exists(), "a refused grant must not leave a token file");
    assert!(is_interpreter(Path::new("/bin/sh")));
}

/// Agent context is refused with exit 5, even on a terminal.
#[test]
fn grant_create_is_refused_in_agent_context() {
    let _guard = serial();
    let fixture = Fixture::new();
    let out = fixture.temp_path("agent.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "--agent",
            "grant",
            "create",
            "--label",
            "agent",
            "--tag",
            "prod",
            "--command",
            "/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(5), "{}", output.stderr);
    assert!(
        output.stderr.contains("reserved for a human"),
        "{}",
        output.stderr
    );
    assert!(!output.stderr.contains("Master Password"));
    assert!(!out.exists());
}

/// A full vault is refused before the approval is requested: the CLI opens the
/// vault and checks writability, so no `challenge`/`prove` frame reaches the
/// stub socket and no approval is spent (TODO R.22b).
#[test]
fn grant_create_refuses_a_full_vault_before_asking_the_daemon() {
    let _guard = serial();
    let fixture = Fixture::with_grants(MAX_GRANTS);
    let paths = fixture.daemon_paths();
    let token = SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let out = fixture.temp_path("full.token");
    let output = fixture.run_pty(
        &[
            "--db",
            fixture.db(),
            "grant",
            "create",
            "--label",
            "too many",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/true",
            "--expires",
            "1h",
            "--out",
            out.to_str().expect("path is UTF-8"),
        ],
        &format!("{MASTER}\n"),
    );

    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert!(
        output.stderr.contains("too many grants"),
        "{}",
        output.stderr
    );
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a full vault must not send challenge/prove to the daemon"
    );
    assert!(
        !out.exists(),
        "a refused grant must remove the token file it created"
    );
    assert_eq!(
        Vault::open(&fixture.vault, MASTER)
            .expect("vault")
            .grants()
            .len(),
        MAX_GRANTS
    );
}

/// Open the fixture vault with the master password and return its grant ids.
fn grant_ids(fixture: &Fixture) -> Vec<passmgr::grant::GrantId> {
    Vault::open(&fixture.vault, MASTER)
        .expect("open vault")
        .grants()
        .iter()
        .map(|grant| grant.id())
        .collect()
}

/// Every seed token's hash in hex, for canary checks on agent-facing output.
fn seed_hashes(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| TokenHash::of(format!("seed-token-{index}").as_bytes()).to_hex())
        .collect()
}

fn assert_no_canary(text: &str, hashes: &[String]) {
    assert!(!text.contains(SECRET), "the vault secret leaked");
    for hash in hashes {
        assert!(!text.contains(hash), "a grant token hash leaked");
    }
}

/// `grant list` prints id, label, scope, uses and status for every grant and
/// nothing that could stand in for a token; `--json` carries the same
/// metadata with no token or hash field.
#[test]
fn grant_list_prints_metadata_only() {
    let _guard = serial();
    let fixture = Fixture::with_grants(2);
    fixture.unlock();
    let ids = grant_ids(&fixture);
    let hashes = seed_hashes(2);

    let output = run_with_env(
        &["--db", fixture.db(), "grant", "list"],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    for text in [&stdout(&output), &stderr(&output)] {
        assert_no_canary(text, &hashes);
        assert!(!text.contains("token"), "{text}");
    }
    assert!(
        stdout(&output).contains(&ids[0].to_hex()),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("seed grant 0"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("tags: prod"),
        "{}",
        stdout(&output)
    );
    assert!(stdout(&output).contains("[active]"), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("uses: 0 (unlimited)"),
        "{}",
        stdout(&output)
    );

    let output = run_with_env(
        &["--db", fixture.db(), "grant", "list", "--json"],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    assert_no_canary(&stdout(&output), &hashes);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let grants = parsed["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 2);
    let first = grants
        .iter()
        .find(|grant| grant["id"] == serde_json::json!(ids[0].to_hex()))
        .expect("first seeded grant");
    assert_eq!(first["label"], serde_json::json!("seed grant 0"));
    assert_eq!(first["tags"], serde_json::json!(["prod"]));
    assert_eq!(first["refs"], serde_json::json!([]));
    assert_eq!(first["commands"], serde_json::json!(["/usr/bin/true"]));
    assert_eq!(first["status"], serde_json::json!("active"));
    assert!(first["expires_at"].is_string());
    for grant in grants {
        for forbidden in ["token", "token_hash", "secret", "value"] {
            assert!(
                grant.get(forbidden).is_none(),
                "grant JSON must not carry '{forbidden}': {grant}"
            );
        }
    }
}

/// `grant show` prints exactly one grant, by id, and an unknown id is a
/// not-found (exit 3) that changes nothing.
#[test]
fn grant_show_names_one_grant_and_unknown_ids_are_not_found() {
    let _guard = serial();
    let fixture = Fixture::with_grants(2);
    fixture.unlock();
    let ids = grant_ids(&fixture);
    let hashes = seed_hashes(2);

    let output = run_with_env(
        &[
            "--db",
            fixture.db(),
            "grant",
            "show",
            &ids[1].to_hex(),
            "--json",
        ],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    assert_no_canary(&stdout(&output), &hashes);
    let shown: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(shown["id"], serde_json::json!(ids[1].to_hex()));
    assert_eq!(shown["label"], serde_json::json!("seed grant 1"));
    assert_eq!(shown["status"], serde_json::json!("active"));

    let human = run_with_env(
        &["--db", fixture.db(), "grant", "show", &ids[0].to_hex()],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&human);
    assert_no_canary(&stdout(&human), &hashes);
    assert!(
        stdout(&human).contains(&format!("Grant {} (seed grant 0)", ids[0])),
        "{}",
        stdout(&human)
    );
    assert!(stdout(&human).contains("commands: /usr/bin/true"));

    let unknown = "ffffffffffffffffffffffffffffffff";
    let output = run_with_env(
        &["--db", fixture.db(), "grant", "show", unknown],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no grant found with id"),
        "{}",
        stderr(&output)
    );
    // The other grant is untouched and no secret was printed.
    assert_no_canary(&stdout(&output), &hashes);
    assert_no_canary(&stderr(&output), &hashes);
    assert_eq!(grant_ids(&fixture).len(), 2);
}

/// Revocation needs no password, no terminal and no human marker, and the
/// daemon persists it: the vault on disk shows `revoked_at`, and a second
/// revoke is a successful no-op that keeps the first timestamp.
#[test]
fn grant_revoke_needs_no_password_and_persists() {
    let _guard = serial();
    let fixture = Fixture::with_grants(1);
    fixture.unlock();
    let id = grant_ids(&fixture)[0];
    let hashes = seed_hashes(1);

    // Piped stdin and stdout: no TTY, no password input, no prompt.
    let output = run_with_env(
        &["grant", "revoke", &id.to_hex()],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    assert!(
        stderr(&output).contains(&format!("Revoked grant '{id}'")),
        "{}",
        stderr(&output)
    );
    assert_no_canary(&stdout(&output), &hashes);
    assert_no_canary(&stderr(&output), &hashes);

    let revoked_at = {
        let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
        let grant = &vault.grants()[0];
        assert!(grant.is_revoked(), "revocation must be persisted");
        grant.revoked_at_unix().expect("revoked_at")
    };

    // The next read of the vault reports it as revoked.
    let listed = run_with_env(
        &["--db", fixture.db(), "grant", "list", "--json"],
        &format!("{MASTER}\n"),
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&listed);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&listed)).expect("valid JSON");
    assert_eq!(parsed["grants"][0]["status"], serde_json::json!("revoked"));
    assert!(parsed["grants"][0]["revoked_at"].is_string());

    // Revoking again succeeds and changes nothing.
    let again = run_with_env(
        &["grant", "revoke", &id.to_hex()],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&again);
    assert!(
        stderr(&again).contains("already revoked"),
        "{}",
        stderr(&again)
    );
    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert_eq!(vault.grants()[0].revoked_at_unix(), Some(revoked_at));
}

/// An agent context may revoke: it only removes access. The same call with
/// `--agent` and no terminal succeeds and reports a count in `--json`.
#[test]
fn grant_revoke_works_in_agent_context_and_reports_json() {
    let _guard = serial();
    let fixture = Fixture::with_grants(2);
    fixture.unlock();
    let id = grant_ids(&fixture)[0];

    let output = run_with_env(
        &["--agent", "grant", "revoke", &id.to_hex(), "--json"],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(parsed, serde_json::json!({ "revoked": 1 }));

    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    let revoked: Vec<_> = vault.grants().iter().filter(|g| g.is_revoked()).collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].id(), id);
}

/// `--all` revokes every active grant, counts only those it changed, and a
/// second `--all` is a successful no-op.
#[test]
fn grant_revoke_all_revokes_every_active_grant_once() {
    let _guard = serial();
    let fixture = Fixture::with_grants(3);
    fixture.unlock();

    let output = run_with_env(
        &["grant", "revoke", "--all"],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&output);
    assert!(
        stderr(&output).contains("Revoked 3 grant(s)"),
        "{}",
        stderr(&output)
    );
    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert!(vault.grants().iter().all(|grant| grant.is_revoked()));

    let again = run_with_env(
        &["grant", "revoke", "--all"],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_success(&again);
    assert!(
        stderr(&again).contains("No active grants to revoke"),
        "{}",
        stderr(&again)
    );
}

/// An unknown id is exit 3 and changes nothing; without a daemon the command
/// says how to start one instead of pretending the grant was revoked.
#[test]
fn grant_revoke_reports_unknown_ids_and_a_missing_daemon() {
    let _guard = serial();
    let fixture = Fixture::with_grants(1);
    fixture.unlock();

    let unknown = "ffffffffffffffffffffffffffffffff";
    let output = run_with_env(
        &["grant", "revoke", unknown],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(&format!("no grant found with id '{unknown}'")),
        "{}",
        stderr(&output)
    );
    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert!(!vault.grants()[0].is_revoked());

    let idle = Fixture::with_grants(1);
    let id = grant_ids(&idle)[0];
    let output = run_with_env(
        &["grant", "revoke", &id.to_hex()],
        "",
        &[("XDG_RUNTIME_DIR", idle.runtime_text())],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no passmgr daemon is running"),
        "{}",
        stderr(&output)
    );
}
