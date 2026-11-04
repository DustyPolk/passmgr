//! Daemon `list` tests (TODO 4.4b): metadata only, authorized one candidate
//! at a time. Split out of `src/daemon/tests.rs` to keep it under the
//! ~1,000-line limit.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
use crate::presence;
use crate::protocol::{self, ListRequest, Request, Response, ResponseError};
use crate::store::{Credential, EntryId};
use crate::token::SessionToken;
use crate::vault::Vault;

use super::super::{LockedKey, unix_now};
use super::exchange_frame_at;

// ---------------------------------------------------------------------------
// `list` (TODO 4.4b): metadata only, authorized one candidate at a time.
// ---------------------------------------------------------------------------

/// A vault with one credential per `(service, username, tags)` and a unique
/// canary password each, plus whatever grants `make_grants` builds from the
/// new refs.
struct ListFixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    key: LockedKey,
    /// `(reference, service, password canary)` in vault order.
    entries: Vec<(String, String, String)>,
}

fn list_fixture<F>(credentials: &[(&str, &str, &[&str])], make_grants: F) -> ListFixture
where
    F: FnOnce(&[(EntryId, String)]) -> Vec<Grant>,
{
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.dat");
    let master = "correct horse battery staple";
    let mut vault = Vault::open_for_add(&path, master).expect("create vault");
    let mut built = Vec::new();
    for (service, username, tags) in credentials {
        let canary = format!("canary-{service}-8d3f21");
        let credential = Credential::new(
            (*service).to_owned(),
            (*username).to_owned(),
            Zeroizing::new(canary.clone()),
        )
        .expect("credential")
        .with_tags(tags.iter().map(|tag| (*tag).to_owned()).collect())
        .expect("tags");
        built.push((
            credential.id(),
            credential.reference(),
            (*service).to_owned(),
            canary,
        ));
        vault.add(credential).expect("add credential");
    }
    let ids: Vec<(EntryId, String)> = built
        .iter()
        .map(|(id, reference, _, _)| (*id, reference.clone()))
        .collect();
    for grant in make_grants(&ids) {
        vault.add_grant(grant).expect("add grant");
    }
    vault.save(master).expect("save");
    drop(vault);
    let container = std::fs::read(&path).expect("read vault");
    let key = crate::crypto::unlock_key(&container, master).expect("unlock");
    let key = LockedKey::new(key).expect("lock key");
    ListFixture {
        _directory: directory,
        path,
        key,
        entries: built
            .into_iter()
            .map(|(_, reference, service, canary)| (reference, service, canary))
            .collect(),
    }
}

fn list_grant(
    token: &GrantToken,
    refs: Vec<EntryId>,
    tags: Vec<&str>,
    capabilities: Capabilities,
    created: u64,
    expires_at: u64,
) -> Grant {
    Grant::create(
        GrantSpec {
            label: "list test".into(),
            scope: Scope::new(refs, tags.into_iter().map(str::to_owned).collect(), None)
                .expect("scope"),
            commands: vec![PathBuf::from("/usr/bin/true")],
            capabilities,
            expires_at,
            max_uses: None,
        },
        token.hash(),
        created,
    )
    .expect("grant")
}

fn list_request(token: &GrantToken, tags: &[&str], query: Option<&str>) -> Request {
    Request::List(ListRequest {
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
        query: query.map(str::to_owned),
        grant: token.clone(),
    })
}

fn ask_list(fixture: &ListFixture, token: &SessionToken, request: &Request) -> Response {
    let frame = protocol::encode(token, request).expect("encode");
    let mut challenges = presence::Challenges::new();
    let mut approvals = presence::Approvals::new();
    exchange_frame_at(
        &fixture.path,
        &frame,
        token,
        &fixture.key,
        &mut challenges,
        &mut approvals,
    )
}

fn entries_of(response: Response) -> (Vec<crate::protocol::Entry>, bool) {
    match response {
        Response::Entries { entries, truncated } => (entries, truncated),
        other => panic!("expected entries, got {other:?}"),
    }
}

#[test]
fn list_returns_only_the_entries_the_grant_covers() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = list_fixture(
        &[
            ("alpha", "alice", &["prod"]),
            ("beta", "bob", &["prod"]),
            ("gamma", "carol", &["dev"]),
        ],
        |entries| {
            vec![list_grant(
                &token,
                vec![entries[0].0],
                Vec::new(),
                Capabilities::LIST,
                now,
                now + 600,
            )]
        },
    );

    let request = list_request(&token, &[], None);
    let response = ask_list(&fixture, &session, &request);
    let (entries, truncated) = entries_of(response.clone());
    assert!(!truncated);
    assert_eq!(entries.len(), 1, "only the ref-scoped entry is listed");
    let entry = &entries[0];
    assert_eq!(entry.reference, fixture.entries[0].0);
    assert_eq!(entry.service, "alpha");
    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert_eq!(entry.tags, vec!["prod".to_owned()]);

    let frame = protocol::encode_response(&response).expect("encode response");
    let text = String::from_utf8_lossy(&frame);
    for (_, service, canary) in &fixture.entries {
        assert!(
            !text.contains(canary.as_str()),
            "{service}'s password must never reach the socket"
        );
    }
    assert!(
        !text.contains("beta") && !text.contains("gamma"),
        "out-of-scope names must be absent"
    );
}

#[test]
fn list_filters_narrow_but_never_widen_the_scope() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = list_fixture(
        &[
            ("github prod", "alice", &["prod"]),
            ("gitlab dev", "bob", &["dev"]),
        ],
        |_| {
            vec![list_grant(
                &token,
                Vec::new(),
                vec!["prod"],
                Capabilities::LIST,
                now,
                now + 600,
            )]
        },
    );

    let all = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &[], None),
    ));
    assert_eq!(all.0.len(), 1, "the tag-scoped grant lists one entry");
    assert_eq!(all.0[0].service, "github prod");

    // The query is a case-insensitive substring of the service name.
    let hit = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &[], Some("GITHUB")),
    ));
    assert_eq!(hit.0.len(), 1);

    // A filter that matches an out-of-scope entry cannot pull it in.
    let out = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &[], Some("gitlab")),
    ));
    assert!(out.0.is_empty(), "an out-of-scope name finds nothing");
    let untagged = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &["dev"], None),
    ));
    assert!(untagged.0.is_empty(), "an out-of-scope tag finds nothing");

    // Filters intersect, and a matching tag keeps the entry.
    let both = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &["dev"], Some("github")),
    ));
    assert!(both.0.is_empty());
    let tagged = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&token, &["prod"], Some("github")),
    ));
    assert_eq!(tagged.0.len(), 1);
}

#[test]
fn list_without_a_matching_grant_is_denied() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let other = GrantToken::generate().expect("other token");
    let now = unix_now().expect("clock");
    let fixture = list_fixture(&[("alpha", "alice", &["prod"])], |_| {
        vec![list_grant(
            &other,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now,
            now + 600,
        )]
    });

    let response = ask_list(&fixture, &session, &list_request(&token, &[], None));
    assert_eq!(response, Response::Error(ResponseError::Denied));
}

#[test]
fn list_with_an_inactive_or_run_only_grant_is_denied() {
    let session = SessionToken::generate().expect("session");
    let revoked = GrantToken::generate().expect("revoked token");
    let expired = GrantToken::generate().expect("expired token");
    let run_only = GrantToken::generate().expect("run token");
    let now = unix_now().expect("clock");
    let fixture = list_fixture(&[("alpha", "alice", &["prod"])], |_| {
        let mut revoked_grant = list_grant(
            &revoked,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now - 100,
            now + 600,
        );
        revoked_grant.revoke(now).expect("revoke");
        vec![
            revoked_grant,
            list_grant(
                &expired,
                Vec::new(),
                vec!["prod"],
                Capabilities::LIST,
                now - 100,
                now - 1,
            ),
            list_grant(
                &run_only,
                Vec::new(),
                vec!["prod"],
                Capabilities::RUN,
                now,
                now + 600,
            ),
        ]
    });

    for (token, why) in [
        (&revoked, "revoked"),
        (&expired, "expired"),
        (&run_only, "run-only"),
    ] {
        assert_eq!(
            ask_list(&fixture, &session, &list_request(token, &[], None)),
            Response::Error(ResponseError::Denied),
            "a {why} grant must be denied"
        );
    }
}

#[test]
fn list_checks_the_grant_before_enumerating_an_empty_vault() {
    let session = SessionToken::generate().expect("session");
    let revoked = GrantToken::generate().expect("revoked token");
    let active = GrantToken::generate().expect("active token");
    let now = unix_now().expect("clock");
    let fixture = list_fixture(&[], |_| {
        let mut revoked_grant = list_grant(
            &revoked,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now - 100,
            now + 600,
        );
        revoked_grant.revoke(now).expect("revoke");
        vec![
            revoked_grant,
            list_grant(
                &active,
                Vec::new(),
                vec!["prod"],
                Capabilities::LIST,
                now,
                now + 600,
            ),
        ]
    });

    // A per-candidate check alone would answer "no entries" here; the grant
    // itself is checked first, so revocation stays visible.
    assert_eq!(
        ask_list(&fixture, &session, &list_request(&revoked, &[], None)),
        Response::Error(ResponseError::Denied)
    );
    let (entries, truncated) = entries_of(ask_list(
        &fixture,
        &session,
        &list_request(&active, &[], None),
    ));
    assert!(entries.is_empty());
    assert!(!truncated);
}
