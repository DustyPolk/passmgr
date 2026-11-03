//! Unit tests for `crate::cli::grant`, moved out to keep the module reviewable.

use super::*;

use crate::cli::grant_summary::{
    ScopeEntry, ScopePreview, describe_request, humanize_seconds, preview_scope, render_warning,
    runner_warnings, write_scope,
};

#[test]
fn expiry_accepts_the_documented_units() {
    assert_eq!(parse_expiry("30m").unwrap(), Duration::from_secs(1_800));
    assert_eq!(parse_expiry("1h").unwrap(), Duration::from_secs(3_600));
    assert_eq!(parse_expiry("7d").unwrap(), Duration::from_secs(604_800));
    assert_eq!(parse_expiry("30d").unwrap(), Duration::from_secs(2_592_000));
}

#[test]
fn expiry_refuses_unknown_or_unbounded_values() {
    for text in [
        "",
        "0m",
        "0",
        "1s",
        "1h30m",
        "d",
        "1.5h",
        "-1h",
        "31d",
        "999999999999d",
    ] {
        assert!(parse_expiry(text).is_err(), "{text:?}");
    }
}

/// `--out` is argv and may be agent-suggested, so a control character in
/// it must never be echoed raw: neither the success line nor the
/// existing-file error may write an escape sequence to the terminal.
#[cfg(unix)]
#[test]
fn a_token_path_with_hidden_characters_is_rendered_as_text() {
    let path = Path::new("/tmp/out\u{1b}]52;c;Y2FuYXJ5\u{7}");
    let created = grant_created_message("deploy prod", path);
    assert!(created.contains("token written to"), "{created}");
    assert!(
        created.contains("/tmp/out\\u{1b}]52;c;Y2FuYXJ5\\u{7}'"),
        "{created}"
    );
    assert!(!created.contains('\u{1b}'), "{created}");
    assert!(!created.contains('\u{7}'), "{created}");

    let directory = tempfile::tempdir().unwrap();
    let existing = directory.path().join("tok\u{1b}[2K\r");
    std::fs::write(&existing, b"keep me").unwrap();
    let error = match TokenFile::create(&existing) {
        Ok(_) => panic!("an existing token file must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("tok\\u{1b}[2K\\r"), "{error}");
    assert!(!error.contains('\u{1b}'), "{error}");
    assert!(!error.contains('\r'), "{error}");
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");
}

#[cfg(unix)]
#[test]
fn an_existing_token_file_is_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    std::fs::write(&path, b"keep me").unwrap();
    // The cheap pre-check and the authoritative create must agree.
    assert!(TokenFile::check_available(&path).is_err());
    assert!(TokenFile::create(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");

    // A dangling symlink names something too, so `--out` must not take it
    // over later (`symlink_metadata` does not follow it).
    let dangling = directory.path().join("dangling");
    std::os::unix::fs::symlink(directory.path().join("missing"), &dangling).unwrap();
    assert!(TokenFile::check_available(&dangling).is_err());
}

fn sample_request(now: u64, commands: &[&str]) -> GrantRequest {
    GrantRequest::new(
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(
                vec![
                    passmgr::store::EntryId::from_hex("00112233445566778899aabbccddeeff")
                        .expect("entry id"),
                ],
                vec!["prod".into()],
                None,
            )
            .expect("scope"),
            commands: commands.iter().map(PathBuf::from).collect(),
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: Some(2),
        },
        passmgr::grant::TokenHash::of(b"approval-canary-token"),
    )
    .expect("request")
}

/// The human approves exactly what the summary shows: the label, the
/// credentials behind the scope, commands, capabilities, expiry and use
/// limit. No secret exists at this point, and the request's token hash has
/// no accessor here.
#[test]
fn the_approval_summary_names_every_value_being_approved() {
    let now = 1_700_000_000;
    let preview = ScopePreview {
        refs: vec![ScopeEntry {
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            service: "example.test".into(),
            username: "alice".into(),
        }],
        tags: vec![(
            "prod".into(),
            vec![ScopeEntry {
                reference: "pm://ffeeddccbbaa99887766554433221100".into(),
                service: "prod.test".into(),
                username: "bob".into(),
            }],
        )],
    };
    let summary = describe_request(&sample_request(now, &["/usr/bin/gh"]), now, &preview);
    assert!(summary.starts_with("Grant request:\n"), "{summary}");
    assert!(summary.contains("  label: deploy prod"), "{summary}");
    assert!(
        summary.contains("      example.test (alice) [pm://00112233445566778899aabbccddeeff]"),
        "{summary}"
    );
    assert!(summary.contains("    tags:\n      prod:\n"), "{summary}");
    assert!(
        summary.contains("        prod.test (bob) [pm://ffeeddccbbaa99887766554433221100]"),
        "{summary}"
    );
    assert!(
        summary.contains("  commands:\n    /usr/bin/gh\n"),
        "{summary}"
    );
    assert!(summary.contains("  capabilities: run"), "{summary}");
    assert!(
        summary.contains("expires: 2023-11-14T23:13:20Z (in 1h 0m)"),
        "{summary}"
    );
    assert!(summary.contains("  max uses: 2"), "{summary}");
    assert!(!summary.contains("approval-canary-token"), "{summary}");
}

fn credential(service: &str, username: &str, tags: &[&str]) -> passmgr::store::Credential {
    passmgr::store::Credential::new(
        service.to_owned(),
        username.to_owned(),
        zeroize::Zeroizing::new("unit-test-canary-password".to_owned()),
    )
    .expect("credential")
    .with_tags(tags.iter().map(|tag| (*tag).to_owned()).collect())
    .expect("tags")
}

fn empty_vault(directory: &tempfile::TempDir) -> vault::Vault {
    vault::Vault::empty(directory.path().join("vault.dat"))
}

/// TODO R.41: a ref is shown with the service and username it names, so a
/// label cannot steer an approval onto a different credential.
#[test]
fn a_ref_is_shown_with_its_service_and_username() {
    let directory = tempfile::tempdir().unwrap();
    let mut vault = empty_vault(&directory);
    vault
        .add(credential("github.com", "octocat", &[]))
        .expect("add");
    let id = vault.list()[0].id();
    let scope = Scope::new(vec![id], vec![], None).expect("scope");

    let preview = preview_scope(&scope, &vault).expect("preview");
    let mut text = String::new();
    write_scope(&mut text, &preview, None);
    assert!(text.contains("      github.com (octocat) [pm://"), "{text}");
    assert!(text.contains(&id.to_ref()), "{text}");
    assert!(!text.contains("unit-test-canary-password"), "{text}");
}

/// A tag expands to every credential it currently matches, and a tag that
/// matches nothing says so instead of looking approved.
#[test]
fn a_tag_is_shown_with_every_credential_it_matches() {
    let directory = tempfile::tempdir().unwrap();
    let mut vault = empty_vault(&directory);
    vault
        .add(credential("one.test", "alice", &["prod"]))
        .expect("add");
    vault
        .add(credential("two.test", "bob", &["prod", "work"]))
        .expect("add");
    vault
        .add(credential("three.test", "carol", &["work"]))
        .expect("add");
    let scope =
        Scope::new(vec![], vec!["prod".to_owned(), "missing".to_owned()], None).expect("scope");

    let preview = preview_scope(&scope, &vault).expect("preview");
    assert_eq!(preview.tags.len(), 2);
    // `Scope` sorts its tags, so look them up by name, not position.
    let matched = |tag: &str| -> Vec<&str> {
        preview
            .tags
            .iter()
            .find(|(name, _)| name == tag)
            .map(|(_, entries)| entries.iter().map(|entry| entry.service.as_str()).collect())
            .expect("tag present")
    };
    assert_eq!(matched("prod"), ["one.test", "two.test"]);
    assert!(
        matched("missing").is_empty(),
        "a missing tag matches nothing"
    );

    let mut text = String::new();
    write_scope(&mut text, &preview, None);
    assert!(
        text.contains("      prod:\n        one.test (alice) [pm://"),
        "{text}"
    );
    assert!(text.contains("        two.test (bob) [pm://"), "{text}");
    assert!(
        text.contains("      missing:\n        (no credential currently matches)"),
        "{text}"
    );
    assert!(!text.contains("three.test"), "{text}");
}

/// A ref the vault does not hold is refused before the summary and before
/// any daemon contact; approving it could only create a grant that names
/// nothing (TODO R.41).
#[test]
fn an_unknown_ref_is_refused_before_the_summary() {
    let directory = tempfile::tempdir().unwrap();
    let vault = empty_vault(&directory);
    let missing =
        passmgr::store::EntryId::from_hex("ffffffffffffffffffffffffffffffff").expect("id");
    let scope = Scope::new(vec![missing], vec![], None).expect("scope");

    match preview_scope(&scope, &vault) {
        Err(Error::EntryNotFound(reference)) => {
            assert_eq!(reference, missing.to_ref());
        }
        other => panic!("an unknown ref must be refused, got {other:?}"),
    }
}

/// Names come from the vault, but they are still display text: a stored
/// bidi override or escape must never reach the terminal raw (R.41/R.48).
#[test]
fn credential_names_are_escaped_in_the_summary() {
    let directory = tempfile::tempdir().unwrap();
    let mut vault = empty_vault(&directory);
    vault
        .add(credential(
            "bank\u{202e}moc.test",
            "al\u{202e}ice",
            &["prod"],
        ))
        .expect("add");
    let id = vault.list()[0].id();
    let scope = Scope::new(vec![id], vec!["prod".to_owned()], None).expect("scope");

    let preview = preview_scope(&scope, &vault).expect("preview");
    let mut text = String::new();
    write_scope(&mut text, &preview, None);
    assert!(!text.contains('\u{202e}'), "{text}");
    assert!(
        text.contains("bank\\u{202e}moc.test (al\\u{202e}ice)"),
        "{text}"
    );
    assert!(text.contains("      prod:\n"), "{text}");
}

#[test]
fn only_program_runners_produce_a_warning() {
    let now = 1_700_000_000;
    let warnings = runner_warnings(&sample_request(now, &["/usr/bin/gh"]));
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("WARNING: '/usr/bin/gh'"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("can run any command"), "{warnings:?}");

    assert!(runner_warnings(&sample_request(now, &["/usr/bin/true", "/bin/echo"])).is_empty());
}

#[test]
fn a_warning_is_only_coloured_for_a_terminal() {
    assert_eq!(render_warning("WARNING", false), "WARNING");
    assert_eq!(render_warning("WARNING", true), "\x1b[1;31mWARNING\x1b[0m");
}

fn sample_grant(now: u64) -> Grant {
    Grant::create(
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(
                vec![
                    passmgr::store::EntryId::from_hex("00112233445566778899aabbccddeeff")
                        .expect("entry id"),
                ],
                vec!["prod".into()],
                Some(vec!["password".into()]),
            )
            .expect("scope"),
            commands: vec![PathBuf::from("/usr/bin/gh")],
            capabilities: Capabilities::RUN,
            expires_at: now + 3_600,
            max_uses: Some(2),
        },
        passmgr::grant::TokenHash::of(b"metadata-canary-token"),
        now,
    )
    .expect("grant")
}

/// The JSON form of a grant is the whole agent-facing surface of `grant
/// list`/`show`; it must carry no token and no hash, not even an encoded
/// form of one.
#[test]
fn grant_metadata_never_carries_a_token_or_its_hash() {
    let now = 1_700_000_000;
    let grant = sample_grant(now);
    let value = grant_metadata(&grant, now);
    let text = value.to_string();
    let hash_hex = grant.token_hash().to_hex();

    assert!(!text.contains(&hash_hex), "{text}");
    assert!(!text.contains("metadata-canary-token"), "{text}");
    assert!(!text.contains("token"), "no field may name a token: {text}");
    assert_eq!(value["id"], serde_json::json!(grant.id().to_hex()));
    assert_eq!(value["label"], serde_json::json!("deploy prod"));
    assert_eq!(
        value["refs"],
        serde_json::json!(["pm://00112233445566778899aabbccddeeff"])
    );
    assert_eq!(value["tags"], serde_json::json!(["prod"]));
    assert_eq!(value["fields"], serde_json::json!(["password"]));
    assert_eq!(value["commands"], serde_json::json!(["/usr/bin/gh"]));
    assert_eq!(value["capabilities"], serde_json::json!(["run"]));
    assert_eq!(value["max_uses"], serde_json::json!(2));
    assert_eq!(value["uses"], serde_json::json!(0));
    assert_eq!(value["uses_left"], serde_json::json!(2));
    assert_eq!(value["revoked_at"], serde_json::Value::Null);
    assert_eq!(value["status"], serde_json::json!("active"));
}

#[test]
fn grant_status_puts_revoked_before_expired_and_exhausted() {
    let now = 1_700_000_000;
    let active = sample_grant(now);
    assert_eq!(active.status(now).name(), "active");

    let mut expired = sample_grant(now);
    assert_eq!(expired.status(now + 3_600).name(), "expired");

    let mut exhausted = sample_grant(now);
    exhausted.mark_used(now).expect("first use");
    exhausted.mark_used(now).expect("second use");
    assert_eq!(exhausted.status(now).name(), "exhausted");

    // Revoking an expired grant still reads as revoked, not expired.
    expired.revoke(now + 10).expect("revoke");
    assert_eq!(expired.status(now + 3_600).name(), "revoked");
}

#[test]
fn humanized_durations_are_coarse_and_never_negative() {
    assert_eq!(humanize_seconds(7 * 86_400 + 3 * 3_600), "7d 3h");
    assert_eq!(humanize_seconds(3_600 + 120), "1h 2m");
    assert_eq!(humanize_seconds(59 * 60), "59m");
    assert_eq!(humanize_seconds(12), "12s");
    assert_eq!(humanize_seconds(0), "0s");
}

#[test]
fn uses_and_scope_descriptions_name_metadata_only() {
    let now = 1_700_000_000;
    let grant = sample_grant(now);
    assert_eq!(describe_uses(&grant), "uses: 0 of 2 (2 left)");
    assert_eq!(
        describe_scope(grant.scope()),
        "refs: pm://00112233445566778899aabbccddeeff; tags: prod; fields: password"
    );
    assert!(describe_expiry(&grant, now).contains("expires: "));
    assert!(describe_expiry(&grant, now).contains("(in 1h 0m)"));
    assert!(describe_expiry(&grant, now + 3_600).starts_with("expired: "));
}

#[cfg(unix)]
#[test]
fn a_new_token_file_is_0600_and_removed_when_uncommitted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    {
        let mut file = TokenFile::create(&path).unwrap();
        file.write_token(&GrantToken::generate().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(!path.exists(), "an uncommitted token file must be removed");
}
