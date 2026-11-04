//! Daemon `describe` tests (TODO 4.4c): one entry's metadata, authorized per
//! candidate, with one collapsed answer for missing and out-of-scope refs.
//! Split out of `src/daemon/tests.rs` to keep it under the ~1,000-line limit.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope};
use crate::presence;
use crate::protocol::{self, DescribeRequest, Request, Response, ResponseError};
use crate::store::{Credential, EntryId};
use crate::token::SessionToken;
use crate::vault::Vault;

use super::super::{LockedKey, unix_now};
use super::exchange_frame_at;

/// A vault with one credential per `(service, username, tags)` and a unique
/// canary password each, plus whatever grants `make_grants` builds from the
/// new refs.
struct DescribeFixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    key: LockedKey,
    /// `(reference, service, password canary)` in vault order.
    entries: Vec<(String, String, String)>,
}

fn fixture<F>(credentials: &[(&str, &str, &[&str])], make_grants: F) -> DescribeFixture
where
    F: FnOnce(&[(EntryId, String)]) -> Vec<Grant>,
{
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.dat");
    let master = "correct horse battery staple";
    let mut vault = Vault::open_for_add(&path, master).expect("create vault");
    let mut built = Vec::new();
    for (service, username, tags) in credentials {
        let canary = format!("canary-{service}-4c7a19");
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
    DescribeFixture {
        _directory: directory,
        path,
        key,
        entries: built
            .into_iter()
            .map(|(_, reference, service, canary)| (reference, service, canary))
            .collect(),
    }
}

fn metadata_grant(
    token: &GrantToken,
    refs: Vec<EntryId>,
    tags: Vec<&str>,
    capabilities: Capabilities,
    now: u64,
) -> Grant {
    Grant::create(
        GrantSpec {
            label: "describe test".into(),
            scope: Scope::new(refs, tags.into_iter().map(str::to_owned).collect(), None)
                .expect("scope"),
            commands: vec![PathBuf::from("/usr/bin/true")],
            capabilities,
            expires_at: now + 600,
            max_uses: None,
        },
        token.hash(),
        now,
    )
    .expect("grant")
}

fn describe_request(token: &GrantToken, reference: &str) -> Request {
    Request::Describe(DescribeRequest {
        reference: reference.to_owned(),
        grant: token.clone(),
    })
}

fn ask_describe(fixture: &DescribeFixture, token: &SessionToken, request: &Request) -> Response {
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

/// A reference no fixture credential can have: all-zero id.
const MISSING_REF: &str = "pm://00000000000000000000000000000000";

fn entry_of(response: Response) -> crate::protocol::Entry {
    match response {
        Response::Entry(entry) => entry,
        other => panic!("expected one entry, got {other:?}"),
    }
}

#[test]
fn describe_returns_one_entry_metadata_and_never_the_value() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = fixture(
        &[("alpha", "alice", &["prod"]), ("beta", "bob", &["prod"])],
        |entries| {
            vec![metadata_grant(
                &token,
                vec![entries[0].0],
                Vec::new(),
                Capabilities::LIST,
                now,
            )]
        },
    );

    let response = ask_describe(
        &fixture,
        &session,
        &describe_request(&token, &fixture.entries[0].0),
    );
    let entry = entry_of(response.clone());
    assert_eq!(entry.reference, fixture.entries[0].0);
    assert_eq!(entry.service, "alpha");
    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert_eq!(entry.tags, vec!["prod".to_owned()]);
    assert!(entry.fields.is_empty(), "fields arrive with TODO 6.1");
    assert!(entry.url.is_none(), "urls arrive with TODO 6.1");
    assert!(entry.created.is_some());
    assert!(entry.last_rotated.is_some());

    let frame = protocol::encode_response(&response).expect("encode response");
    let text = String::from_utf8_lossy(&frame);
    for (_, service, canary) in &fixture.entries {
        assert!(
            !text.contains(canary.as_str()),
            "{service}'s password must never reach the socket"
        );
    }
    assert!(
        !text.contains("beta"),
        "an entry outside the grant must not be described"
    );
}

#[test]
fn describe_collapses_missing_and_out_of_scope_into_identical_bytes() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = fixture(
        &[("alpha", "alice", &["prod"]), ("beta", "bob", &["prod"])],
        |entries| {
            vec![metadata_grant(
                &token,
                vec![entries[0].0],
                Vec::new(),
                Capabilities::LIST,
                now,
            )]
        },
    );

    let out_of_scope = ask_describe(
        &fixture,
        &session,
        &describe_request(&token, &fixture.entries[1].0),
    );
    let missing = ask_describe(&fixture, &session, &describe_request(&token, MISSING_REF));
    assert_eq!(out_of_scope, Response::Error(ResponseError::NotFound));
    assert_eq!(missing, Response::Error(ResponseError::NotFound));
    assert_eq!(
        protocol::encode_response(&out_of_scope).expect("encode"),
        protocol::encode_response(&missing).expect("encode"),
        "the two answers must be byte-identical"
    );
}

#[test]
fn describe_scope_is_decided_per_candidate_by_tags() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = fixture(
        &[
            ("github prod", "alice", &["prod"]),
            ("gitlab dev", "bob", &["dev"]),
        ],
        |_| {
            vec![metadata_grant(
                &token,
                Vec::new(),
                vec!["dev"],
                Capabilities::LIST,
                now,
            )]
        },
    );

    let dev = ask_describe(
        &fixture,
        &session,
        &describe_request(&token, &fixture.entries[1].0),
    );
    assert_eq!(entry_of(dev).service, "gitlab dev");

    let prod = ask_describe(
        &fixture,
        &session,
        &describe_request(&token, &fixture.entries[0].0),
    );
    assert_eq!(
        prod,
        Response::Error(ResponseError::NotFound),
        "a tag filter cannot widen the grant"
    );
}

#[test]
fn describe_canonicalizes_an_upper_case_reference() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let now = unix_now().expect("clock");
    let fixture = fixture(&[("alpha", "alice", &["prod"])], |entries| {
        vec![metadata_grant(
            &token,
            vec![entries[0].0],
            Vec::new(),
            Capabilities::LIST,
            now,
        )]
    });

    let upper = format!(
        "pm://{}",
        fixture.entries[0]
            .0
            .trim_start_matches("pm://")
            .to_uppercase()
    );
    let entry = entry_of(ask_describe(
        &fixture,
        &session,
        &describe_request(&token, &upper),
    ));
    assert_eq!(
        entry.reference, fixture.entries[0].0,
        "the answer must use the canonical lower-case reference"
    );
}

#[test]
fn describe_without_a_matching_grant_is_denied() {
    let session = SessionToken::generate().expect("session");
    let token = GrantToken::generate().expect("grant token");
    let other = GrantToken::generate().expect("other token");
    let now = unix_now().expect("clock");
    let fixture = fixture(&[("alpha", "alice", &["prod"])], |_| {
        vec![metadata_grant(
            &other,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now,
        )]
    });

    assert_eq!(
        ask_describe(
            &fixture,
            &session,
            &describe_request(&token, &fixture.entries[0].0),
        ),
        Response::Error(ResponseError::Denied)
    );
}

#[test]
fn describe_with_an_inactive_or_run_only_grant_is_denied() {
    let session = SessionToken::generate().expect("session");
    let revoked = GrantToken::generate().expect("revoked token");
    let expired = GrantToken::generate().expect("expired token");
    let run_only = GrantToken::generate().expect("run token");
    let now = unix_now().expect("clock");
    let fixture = fixture(&[("alpha", "alice", &["prod"])], |_| {
        let mut revoked_grant = metadata_grant(
            &revoked,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now - 100,
        );
        revoked_grant.revoke(now).expect("revoke");
        let expired_grant = Grant::create(
            GrantSpec {
                label: "expired describe test".into(),
                scope: Scope::new(Vec::new(), vec!["prod".into()], None).expect("scope"),
                commands: vec![PathBuf::from("/usr/bin/true")],
                capabilities: Capabilities::LIST,
                expires_at: now - 1,
                max_uses: None,
            },
            expired.hash(),
            now - 100,
        )
        .expect("expired grant");
        vec![
            revoked_grant,
            expired_grant,
            metadata_grant(&run_only, Vec::new(), vec!["prod"], Capabilities::RUN, now),
        ]
    });

    for (token, why) in [
        (&revoked, "revoked"),
        (&expired, "expired"),
        (&run_only, "run-only"),
    ] {
        assert_eq!(
            ask_describe(
                &fixture,
                &session,
                &describe_request(token, &fixture.entries[0].0),
            ),
            Response::Error(ResponseError::Denied),
            "a {why} grant must be denied"
        );
    }
}

#[test]
fn describe_checks_the_grant_before_looking_up_the_reference() {
    let session = SessionToken::generate().expect("session");
    let revoked = GrantToken::generate().expect("revoked token");
    let now = unix_now().expect("clock");
    let fixture = fixture(&[], |_| {
        let mut revoked_grant = metadata_grant(
            &revoked,
            Vec::new(),
            vec!["prod"],
            Capabilities::LIST,
            now - 100,
        );
        revoked_grant.revoke(now).expect("revoke");
        vec![revoked_grant]
    });

    // A missing reference answers `denied`, not `not_found`: the grant is
    // checked before any lookup, so a dead token cannot tell whether a
    // reference exists.
    assert_eq!(
        ask_describe(&fixture, &session, &describe_request(&revoked, MISSING_REF)),
        Response::Error(ResponseError::Denied),
        "a revoked grant must be refused before the lookup"
    );
}
