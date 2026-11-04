//! Unit tests for the grant model.

use super::*;

fn grant() -> Grant {
    Grant::create(
        GrantSpec {
            label: "deploy prod".to_owned(),
            scope: Scope::new(vec![EntryId::generate().unwrap()], Vec::new(), None).unwrap(),
            commands: vec![PathBuf::from("/usr/bin/env")],
            capabilities: Capabilities::RUN,
            expires_at: 1_700_003_600,
            max_uses: Some(2),
        },
        TokenHash::of(b"canary-store-symmetry-token"),
        1_700_000_000,
    )
    .unwrap()
}

/// The payload writer runs the reader's checks, so a `Grant` the decoder
/// would refuse can never be written. Without this, `Vault::save` would
/// replace a good vault with one that every later open rejects (R.17).
#[test]
fn the_payload_writer_refuses_a_grant_its_reader_would_reject() {
    let mut revoked = grant();
    revoked.revoked_at = Some(MAX_TIMESTAMP_UNIX + 1);
    assert!(Grant::from_stored(revoked.to_stored()).is_err());
    assert!(matches!(
        crate::store::encode(&[], std::slice::from_ref(&revoked)).unwrap_err(),
        Error::InvalidInput(message) if message.contains("revoked_at")
    ));

    // The check is not only about timestamps: any stored-field rule the
    // reader enforces also blocks the writer.
    let mut hidden = grant();
    hidden.label = "deploy\u{202E}prod".to_owned();
    assert!(Grant::from_stored(hidden.to_stored()).is_err());
    assert!(matches!(
        crate::store::encode(&[], std::slice::from_ref(&hidden)).unwrap_err(),
        Error::InvalidInput(message) if message.contains("label")
    ));

    // The untouched grant is writable: the check rejects only bad state.
    assert!(Grant::check_stored(&grant().to_stored()).is_ok());
    assert!(crate::store::encode(&[], std::slice::from_ref(&grant())).is_ok());
}

/// R.31: the daemon asks these questions before it looks a credential up,
/// so a dead grant or a disallowed command must answer without one.
#[test]
fn the_credential_independent_run_checks_cover_state_capability_and_command() {
    let now = 1_700_000_000;
    let allowed = Path::new("/usr/bin/env");
    let refused = Path::new("/usr/bin/other");

    let active = grant();
    assert_eq!(active.check_grant_for_run(allowed, now), Ok(()));
    assert_eq!(
        active.check_grant_for_run(refused, now),
        Err(Denied::CommandNotAllowed)
    );

    let mut revoked = grant();
    revoked.revoke(now).unwrap();
    assert_eq!(
        revoked.check_grant_for_run(allowed, now),
        Err(Denied::Revoked)
    );
    // A dead grant reports that first, never a command detail.
    assert_eq!(
        revoked.check_grant_for_run(refused, now),
        Err(Denied::Revoked)
    );

    let mut exhausted = grant();
    exhausted.mark_used(now).unwrap();
    exhausted.mark_used(now).unwrap();
    assert_eq!(
        exhausted.check_grant_for_run(allowed, now),
        Err(Denied::UsedUp)
    );

    let list_only = Grant::create(
        GrantSpec {
            label: "list only".to_owned(),
            scope: Scope::new(vec![EntryId::generate().unwrap()], Vec::new(), None).unwrap(),
            commands: Vec::new(),
            capabilities: Capabilities::LIST,
            expires_at: now + 3_600,
            max_uses: None,
        },
        TokenHash::of(b"canary-list-only-token"),
        now,
    )
    .unwrap();
    assert_eq!(
        list_only.check_grant_for_run(allowed, now),
        Err(Denied::NotCapable(Capability::Run))
    );
}

#[test]
fn a_scope_refuses_more_tags_than_a_credential_can_carry() {
    let tags = |count: usize| (0..count).map(|index| format!("tag-{index}")).collect();
    let max = crate::store::MAX_TAGS_PER_CREDENTIAL;
    Scope::new(Vec::new(), tags(max), None).expect("a full tag set");
    let error = Scope::new(Vec::new(), tags(max + 1), None).expect_err("one tag too many");
    assert!(error.to_string().contains("too many tags"), "{error}");
}
