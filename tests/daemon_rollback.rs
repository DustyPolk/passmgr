//! End-to-end tests that a rollback of the vault file cannot restore a spent
//! use or undo a revocation the daemon has seen (R.44). Split from
//! `tests/daemon_run.rs` to keep both files under the layout limit.

#![cfg(unix)]

mod support;

use support::*;

use std::fs;

use passmgr::grant::Capabilities;
use passmgr::protocol::{
    GrantRevokeRequest, ListRequest, Request, Response, ResponseError, RunFrame,
};
use passmgr::vault::Vault;

/// R.44: the vault is an ordinary file, so an attacker running as the same
/// user can put an older copy back. That copy still opens with the daemon's
/// key, but the daemon remembers that this grant already spent its one use and
/// refuses instead of running it again.
#[test]
fn restoring_an_older_vault_cannot_restore_a_spent_use() {
    let fixture = Fixture::with_max_uses(1);
    let mut child = fixture.start();
    let socket = fixture.socket();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");

    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_exited(&frames, 0);

    fs::write(&fixture.vault, &snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// R.44: a rollback must not clear a revocation either -- and it must not be
/// able to disable the kill switch, so revoking the rolled-back vault still
/// works and is recorded.
#[test]
fn restoring_an_older_vault_cannot_clear_a_revocation() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let socket = fixture.socket();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");

    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 1 }
    );
    let (frames, _) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);

    fs::write(&fixture.vault, &snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );

    // The kill switch still works on the rolled-back file.
    assert_eq!(
        request(
            &socket,
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 1 }
    );

    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(&mut child, WAIT).success());
}

/// Revoke every grant on disk behind the daemon's back, as `pm grant revoke`
/// in another process would.
fn revoke_on_disk(fixture: &Fixture) {
    let vault = Vault::open_with_key(&fixture.vault, fixture.key.as_slice()).expect("open vault");
    let credentials = vault.list().to_vec();
    let mut grants = vault.grants().to_vec();
    for grant in &mut grants {
        grant.revoke(unix_now()).expect("revoke");
    }
    rewrite_vault(fixture, &credentials, &grants);
}

/// Put `snapshot` (taken before the revocation) back and prove the daemon
/// still refuses to run with the grant, then stop it.
fn assert_rollback_is_refused(fixture: &Fixture, child: &mut std::process::Child, snapshot: &[u8]) {
    let socket = fixture.socket();
    fs::write(&fixture.vault, snapshot).expect("restore older vault");
    let (frames, raw) = read_run(
        &socket,
        &fixture.token,
        &fixture.run_request("API_KEY", &["/bin/true"]),
    );
    assert_eq!(frames, vec![RunFrame::Error(ResponseError::Denied)]);
    assert!(
        !raw.windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    assert_eq!(
        request(&socket, &fixture.token, &Request::Lock),
        Response::Locked
    );
    assert!(wait_for_exit(child, WAIT).success());
}

/// SECURITY.md limit 7 promises that a revocation this daemon has seen cannot
/// be rolled back. Seeing one at startup counts: the daemon opens the vault
/// to verify its key before it serves anything.
#[test]
fn a_revocation_seen_at_startup_survives_a_rollback() {
    let fixture = Fixture::new();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    let mut child = fixture.start();
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}

/// A revocation that only ever reached this daemon as a no-op `grant_revoke`
/// (nothing to change, nothing saved) is still one it has seen.
#[test]
fn a_revocation_seen_as_a_no_op_revoke_survives_a_rollback() {
    let fixture = Fixture::new();
    let mut child = fixture.start();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    assert_eq!(
        request(
            &fixture.socket(),
            &fixture.token,
            &Request::GrantRevoke(GrantRevokeRequest::All)
        ),
        Response::GrantRevoked { revoked: 0 }
    );
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}

/// A revocation that this daemon only saw while denying a metadata read is
/// still one it has seen.
#[test]
fn a_revocation_seen_by_a_denied_list_survives_a_rollback() {
    let fixture = Fixture::with_capabilities(Capabilities::RUN.union(Capabilities::LIST));
    let mut child = fixture.start();
    let snapshot = fs::read(&fixture.vault).expect("snapshot vault");
    revoke_on_disk(&fixture);
    assert_eq!(
        request(
            &fixture.socket(),
            &fixture.token,
            &Request::List(ListRequest {
                tags: Vec::new(),
                query: None,
                grant: fixture.grant.clone(),
            })
        ),
        Response::Error(ResponseError::Denied)
    );
    assert_rollback_is_refused(&fixture, &mut child, &snapshot);
}
