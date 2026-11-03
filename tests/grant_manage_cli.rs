//! End-to-end tests for `passmgr grant list`, `show` and `revoke`.
//!
//! The CLI runs on a real pseudo-terminal against a real `pmd`; the reads are
//! local and the revocations go through the daemon's socket.

#![cfg(unix)]

mod grant_support;

use passmgr::grant::TokenHash;
use passmgr::vault::Vault;

use grant_support::*;

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

/// A `not_found` answer to `--all` is a clean error, not a panic: `--all` has
/// no id to name, and any same-user process can replace the socket and answer
/// whatever it likes (TODO R.27).
#[test]
fn grant_revoke_all_reports_a_not_found_answer_without_panicking() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let _guard = serial();
    let fixture = Fixture::with_grants(1);
    let paths = fixture.daemon_paths();
    let token = passmgr::token::SessionToken::generate().expect("session token");
    passmgr::session::store(&paths, &token).expect("session file");
    let listener = UnixListener::bind(paths.socket()).expect("stub socket");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream.set_read_timeout(Some(WAIT)).expect("read timeout");
        let mut decoder = passmgr::protocol::FrameDecoder::new();
        let mut buffer = [0u8; 4096];
        let authenticated = loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert!(read > 0, "the client closed before sending a request");
            decoder.push(&buffer[..read]).expect("valid frame");
            let Some(body) = decoder.next_frame().expect("decode frame") else {
                continue;
            };
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            break passmgr::protocol::decode(&frame).expect("decode request");
        };
        assert!(
            matches!(
                authenticated.request(),
                passmgr::protocol::Request::GrantRevoke(passmgr::protocol::GrantRevokeRequest::All)
            ),
            "the CLI must ask to revoke every grant"
        );
        let answer = passmgr::protocol::encode_response(&passmgr::protocol::Response::Error(
            passmgr::protocol::ResponseError::NotFound,
        ))
        .expect("encode response");
        stream.write_all(&answer).expect("write response");
    });

    let output = run_with_env(
        &["grant", "revoke", "--all"],
        "",
        &[("XDG_RUNTIME_DIR", fixture.runtime_text())],
    );
    server.join().expect("stub server finished");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("the unlock daemon refused the revocation (not_found)"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("panicked at"),
        "an error answer must not panic: {}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("not_found implies an id"),
        "{}",
        stderr(&output)
    );
    // The stub wrote nothing, and the CLI never touched the vault.
    let vault = Vault::open(&fixture.vault, MASTER).expect("open vault");
    assert!(!vault.grants()[0].is_revoked());
}
