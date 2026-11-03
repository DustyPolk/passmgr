//! Grant model and authorization rules (TODO 3.2a).

use std::path::{Path, PathBuf};

use passmgr::grant::{
    AccessRequest, Capabilities, Capability, Denied, Grant, GrantId, GrantSpec,
    MAX_GRANT_LIFETIME_SECS, Scope, Target, TokenHash, validate_field_name,
};
use passmgr::store::EntryId;

const NOW: u64 = 1_700_000_000;
const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

fn ref_id(seed: u8) -> EntryId {
    EntryId::from_hex(&format!("{seed:02x}").repeat(16)).expect("valid id")
}

fn tags(list: &[&str]) -> Vec<String> {
    list.iter().map(|tag| (*tag).to_string()).collect()
}

fn spec(capabilities: Capabilities) -> GrantSpec {
    GrantSpec {
        label: "test grant".into(),
        scope: Scope::new(vec![ref_id(1)], Vec::new(), None).expect("scope"),
        commands: vec![PathBuf::from("/usr/bin/gh")],
        capabilities,
        expires_at: NOW + 3600,
        max_uses: None,
    }
}

fn grant(capabilities: Capabilities) -> Grant {
    Grant::create(spec(capabilities), TokenHash::of(TOKEN), NOW).expect("grant")
}

fn run_request<'a>(target: &'a Target<'a>, command: &'a Path) -> AccessRequest<'a> {
    AccessRequest::run(*target, Some("password"), command)
}

#[test]
fn token_hash_is_sha256_of_the_raw_token() {
    // FIPS 180-2 test vector for "abc".
    let hash = TokenHash::of(b"abc");
    let hex: String = hash
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(hash.matches(&TokenHash::of(b"abc")));
    assert!(!hash.matches(&TokenHash::of(b"abd")));
    assert_eq!(format!("{hash:?}"), "TokenHash(<redacted>)");
}

#[test]
fn grant_ids_round_trip_and_reject_bad_input() {
    let id = GrantId::generate().expect("id");
    let hex = id.to_hex();
    assert_eq!(hex.len(), 32);
    assert_eq!(GrantId::from_hex(&hex).expect("parse"), id);
    assert_eq!(GrantId::from_hex(&hex.to_uppercase()).expect("parse"), id);
    assert_eq!(format!("{id}"), hex);
    for bad in [
        "",
        "00",
        &hex[..31],
        &format!("{hex}0"),
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        assert!(GrantId::from_hex(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn capabilities_are_a_strict_bit_set() {
    let both = Capabilities::LIST.union(Capabilities::RUN);
    assert!(both.contains(Capabilities::LIST));
    assert!(both.contains(Capabilities::RUN));
    assert!(!Capabilities::LIST.contains(Capabilities::RUN));
    assert_eq!(both.names(), vec!["list", "run"]);
    assert_eq!(Capabilities::from_bits(both.bits()).expect("bits"), both);
    assert!(Capabilities::from_bits(0).is_err());
    assert!(Capabilities::from_bits(0b1000_0000).is_err());
    assert_eq!(
        format!("{both:?}"),
        r#"{"list", "run"}"#,
        "Debug should be readable"
    );
}

#[test]
fn create_rejects_invalid_specs() {
    let cases: Vec<(&str, GrantSpec, &str)> = vec![
        (
            "empty label",
            GrantSpec {
                label: "  ".into(),
                ..spec(Capabilities::RUN)
            },
            "label",
        ),
        (
            "control character in label",
            GrantSpec {
                label: "bad\u{7}label".into(),
                ..spec(Capabilities::RUN)
            },
            "control",
        ),
        (
            "expiry in the past",
            GrantSpec {
                expires_at: NOW,
                ..spec(Capabilities::RUN)
            },
            "future",
        ),
        (
            "expiry beyond 30 days",
            GrantSpec {
                expires_at: NOW + MAX_GRANT_LIFETIME_SECS + 1,
                ..spec(Capabilities::RUN)
            },
            "at most 30 days",
        ),
        (
            "no capabilities",
            GrantSpec {
                capabilities: Capabilities::NONE,
                ..spec(Capabilities::RUN)
            },
            "capability",
        ),
        (
            "run grant without commands",
            GrantSpec {
                commands: Vec::new(),
                ..spec(Capabilities::RUN)
            },
            "command",
        ),
        (
            "relative command",
            GrantSpec {
                commands: vec![PathBuf::from("gh")],
                ..spec(Capabilities::RUN)
            },
            "absolute",
        ),
        (
            "max_uses zero",
            GrantSpec {
                max_uses: Some(0),
                ..spec(Capabilities::RUN)
            },
            "at least 1",
        ),
    ];
    for (name, bad, needle) in cases {
        let err = Grant::create(bad, TokenHash::of(TOKEN), NOW)
            .expect_err(&format!("{name} was accepted"));
        assert!(
            err.to_string().contains(needle),
            "{name}: unexpected error {err}"
        );
    }
}

/// Code points a stored label must never keep. Spelled out here on purpose:
/// the module's table is the code under test, so re-using it as the oracle
/// would prove nothing (TODO R.14). Controls, bidi controls, zero-width and
/// format characters, separators and variation selectors.
const FORBIDDEN_IN_LABELS: [char; 29] = [
    '\u{0}',
    '\u{7}',
    '\u{9B}',
    '\u{AD}',
    '\u{61C}',
    '\u{180E}',
    '\u{200B}',
    '\u{200C}',
    '\u{200D}',
    '\u{200E}',
    '\u{200F}',
    '\u{202A}',
    '\u{202B}',
    '\u{202C}',
    '\u{202D}',
    '\u{202E}',
    '\u{2028}',
    '\u{2029}',
    '\u{2060}',
    '\u{2066}',
    '\u{2067}',
    '\u{2068}',
    '\u{2069}',
    '\u{FE0F}',
    '\u{FEFF}',
    '\u{FFF9}',
    '\u{E0041}',
    '\u{E0100}',
    '\u{1D173}',
];

#[test]
fn create_rejects_hidden_and_reordering_label_characters() {
    for bad in FORBIDDEN_IN_LABELS {
        let label = format!("prod{bad}deploy");
        let err = Grant::create(
            GrantSpec {
                label: label.clone(),
                ..spec(Capabilities::RUN)
            },
            TokenHash::of(TOKEN),
            NOW,
        )
        .expect_err(&format!("label {label:?} was accepted"));
        assert!(
            err.to_string().contains("control, bidi or zero-width"),
            "{bad:?}: unexpected error {err}"
        );
        // The refusal must not echo the untrusted label back to a terminal.
        assert!(
            !err.to_string().contains(&label),
            "{bad:?}: error echoed the label: {err}"
        );
    }
}

#[test]
fn accepted_labels_hold_only_visible_characters() {
    // Ordinary visible text, including non-Latin scripts, an emoji and a
    // combining accent, must stay usable.
    let visible = [
        "prod deploy",
        "工作",
        "إنتاج",
        "cafe\u{301}",
        "🔑 deploy",
        "a.b/c",
        "Grüße—2026",
    ];
    for label in visible {
        let grant = Grant::create(
            GrantSpec {
                label: label.into(),
                ..spec(Capabilities::RUN)
            },
            TokenHash::of(TOKEN),
            NOW,
        )
        .unwrap_or_else(|err| panic!("visible label {label:?} was rejected: {err}"));
        assert_eq!(grant.label(), label);
        // Every rendering surface (`pm grant list`, logs, `Debug`) prints the
        // stored label verbatim, so a label free of these code points cannot
        // smuggle bidi or invisible text into a human's terminal.
        for rendering in [grant.label().to_owned(), format!("{grant:?}")] {
            for character in rendering.chars() {
                assert!(
                    !FORBIDDEN_IN_LABELS.contains(&character),
                    "label {label:?} rendered {character:?}"
                );
            }
        }
    }
}

#[test]
fn commands_are_sorted_deduplicated_and_must_be_absolute() {
    let spec = GrantSpec {
        commands: vec![
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/usr/bin/gh"),
            PathBuf::from("/usr/bin/git"),
        ],
        ..spec(Capabilities::RUN)
    };
    let grant = Grant::create(spec, TokenHash::of(TOKEN), NOW).expect("grant");
    assert_eq!(
        grant.commands(),
        &[PathBuf::from("/usr/bin/gh"), PathBuf::from("/usr/bin/git")]
    );
    assert!(grant.allows_command(Path::new("/usr/bin/gh")));
    assert!(!grant.allows_command(Path::new("/usr/bin/gh ")));
    assert!(!grant.allows_command(Path::new("/opt/gh")));
    assert!(!grant.allows_command(Path::new("gh")));
}

#[test]
fn scope_needs_a_selector_and_normalizes_its_input() {
    let err = Scope::new(Vec::new(), Vec::new(), None).expect_err("empty scope");
    assert!(err.to_string().contains("ref or tag"), "{err}");

    let scope = Scope::new(
        vec![ref_id(2), ref_id(1), ref_id(2)],
        tags(&["prod", "db", "prod"]),
        Some(vec!["token".into(), "password".into(), "token".into()]),
    )
    .expect("scope");
    assert_eq!(scope.refs(), &[ref_id(1), ref_id(2)]);
    assert_eq!(scope.tags(), ["db", "prod"]);
    assert_eq!(
        scope.fields().map(|fields| fields.join(",")),
        Some("password,token".into())
    );

    assert!(Scope::new(Vec::new(), Vec::new(), Some(Vec::new())).is_err());
    assert!(Scope::new(Vec::new(), tags(&["Bad"]), None).is_err());
    assert!(Scope::new(Vec::new(), Vec::new(), Some(vec!["Bad".into()])).is_err());
}

#[test]
fn field_names_follow_the_documented_charset() {
    for valid in ["password", "token", "api_key", "a", "_x", "x-1"] {
        assert!(validate_field_name(valid).is_ok(), "rejected {valid}");
    }
    for invalid in [
        "",
        "Password",
        "has space",
        "with/slash",
        "ümlaut",
        &"x".repeat(33),
    ] {
        assert!(
            validate_field_name(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn scope_matches_by_ref_or_by_every_tag() {
    let entry = ref_id(1);
    let other = ref_id(9);
    let own_tags = tags(&["prod", "db"]);

    let by_ref = Scope::new(vec![entry], Vec::new(), None).expect("scope");
    assert!(by_ref.matches(&Target::new(entry, &[])));
    assert!(!by_ref.matches(&Target::new(other, &own_tags)));

    let by_tags = Scope::new(Vec::new(), tags(&["prod", "db"]), None).expect("scope");
    assert!(by_tags.matches(&Target::new(other, &own_tags)));
    assert!(
        !by_tags.matches(&Target::new(other, &tags(&["prod"]))),
        "all listed tags are required"
    );
    assert!(!by_tags.matches(&Target::new(other, &[])));

    let either = Scope::new(vec![entry], tags(&["prod"]), None).expect("scope");
    assert!(either.matches(&Target::new(entry, &[])));
    assert!(either.matches(&Target::new(other, &tags(&["prod"]))));
}

#[test]
fn field_scope_covers_exactly_the_listed_fields() {
    let unrestricted = Scope::new(vec![ref_id(1)], Vec::new(), None).expect("scope");
    assert!(unrestricted.matches_field(None));
    assert!(unrestricted.matches_field(Some("password")));
    assert!(unrestricted.matches_field(Some("token")));

    let restricted =
        Scope::new(vec![ref_id(1)], Vec::new(), Some(vec!["token".into()])).expect("scope");
    assert!(restricted.matches_field(Some("token")));
    assert!(!restricted.matches_field(Some("password")));
    assert!(!restricted.matches_field(None));
}

#[test]
fn authorizes_decides_expiry_revocation_and_use_limits() {
    let target = Target::new(ref_id(1), &[]);
    let command = Path::new("/usr/bin/gh");
    let request = run_request(&target, command);

    let active = grant(Capabilities::RUN);
    assert_eq!(active.authorizes(&request, NOW), Ok(()));

    let expired = Grant::create(
        GrantSpec {
            expires_at: NOW + 1,
            ..spec(Capabilities::RUN)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    assert_eq!(expired.authorizes(&request, NOW), Ok(()));
    assert_eq!(expired.authorizes(&request, NOW + 1), Err(Denied::Expired));

    let mut revoked = grant(Capabilities::RUN);
    revoked.revoke(NOW - 10);
    assert_eq!(revoked.authorizes(&request, NOW), Err(Denied::Revoked));
    assert_eq!(revoked.revoked_at_unix(), Some(NOW - 10));

    let mut limited = Grant::create(
        GrantSpec {
            max_uses: Some(1),
            ..spec(Capabilities::RUN)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    assert_eq!(limited.uses_left(), Some(1));
    assert_eq!(limited.authorizes(&request, NOW), Ok(()));
    limited.mark_used(NOW).expect("first use");
    assert_eq!(limited.uses(), 1);
    assert_eq!(limited.last_used_unix(), Some(NOW));
    assert_eq!(limited.authorizes(&request, NOW), Err(Denied::UsedUp));
    assert_eq!(limited.mark_used(NOW), Err(Denied::UsedUp));
    assert_eq!(limited.uses_left(), Some(0));

    let mut revoke_twice = grant(Capabilities::RUN);
    revoke_twice.revoke(NOW);
    revoke_twice.revoke(NOW + 100);
    assert_eq!(revoke_twice.revoked_at_unix(), Some(NOW));
}

#[test]
fn authorizes_requires_the_capability() {
    let target = Target::new(ref_id(1), &[]);
    let run_only = grant(Capabilities::RUN);
    assert_eq!(
        run_only.authorizes(&AccessRequest::list(target, None), NOW),
        Err(Denied::NotCapable(Capability::List))
    );
    let list_only = Grant::create(
        GrantSpec {
            commands: Vec::new(),
            ..spec(Capabilities::LIST)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    let command = Path::new("/usr/bin/gh");
    assert_eq!(
        list_only.authorizes(&run_request(&target, command), NOW),
        Err(Denied::NotCapable(Capability::Run))
    );
    assert_eq!(
        list_only.authorizes(&AccessRequest::list(target, None), NOW),
        Ok(())
    );
}

#[test]
fn list_requests_are_scope_checked_like_run_requests() {
    let in_scope = Target::new(ref_id(1), &[]);
    let out_scope = Target::new(ref_id(2), &[]);
    let list_only = Grant::create(
        GrantSpec {
            commands: Vec::new(),
            ..spec(Capabilities::LIST)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");

    assert_eq!(
        list_only.authorizes(&AccessRequest::list(in_scope, None), NOW),
        Ok(())
    );
    assert_eq!(
        list_only.authorizes(&AccessRequest::list(out_scope, None), NOW),
        Err(Denied::OutOfScope)
    );

    // Tag scope is enforced for list too, not just for run.
    let tagged = Grant::create(
        GrantSpec {
            scope: Scope::new(Vec::new(), tags(&["prod"]), None).expect("scope"),
            commands: Vec::new(),
            ..spec(Capabilities::LIST)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    assert_eq!(
        tagged.authorizes(
            &AccessRequest::list(Target::new(ref_id(9), &tags(&["prod"])), None),
            NOW
        ),
        Ok(())
    );
    assert_eq!(
        tagged.authorizes(
            &AccessRequest::list(Target::new(ref_id(9), &tags(&["dev"])), None),
            NOW
        ),
        Err(Denied::OutOfScope)
    );
}

#[test]
fn list_requests_respect_field_scope() {
    let in_scope = Target::new(ref_id(1), &[]);
    let by_field = Grant::create(
        GrantSpec {
            scope: Scope::new(vec![ref_id(1)], Vec::new(), Some(vec!["token".into()]))
                .expect("scope"),
            commands: Vec::new(),
            ..spec(Capabilities::LIST)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");

    assert_eq!(
        by_field.authorizes(&AccessRequest::list(in_scope, Some("token")), NOW),
        Ok(())
    );
    assert_eq!(
        by_field.authorizes(&AccessRequest::list(in_scope, Some("password")), NOW),
        Err(Denied::OutOfScope)
    );
    assert_eq!(
        by_field.authorizes(&AccessRequest::list(in_scope, None), NOW),
        Err(Denied::OutOfScope)
    );
}

#[test]
fn authorizes_enforces_ref_tag_field_and_command_scope() {
    let command = Path::new("/usr/bin/gh");
    let in_scope = Target::new(ref_id(1), &[]);
    let out_scope = Target::new(ref_id(2), &[]);
    let grant = grant(Capabilities::RUN);

    assert_eq!(
        grant.authorizes(&run_request(&out_scope, command), NOW),
        Err(Denied::OutOfScope)
    );
    assert_eq!(
        grant.authorizes(&run_request(&in_scope, Path::new("/usr/bin/git")), NOW),
        Err(Denied::CommandNotAllowed)
    );
    // A request that names no target or no command is not representable: the
    // `AccessRequest` variants carry them, so `authorizes` can never return
    // `Ok(())` for a request without a scope check.

    let tagged = Grant::create(
        GrantSpec {
            scope: Scope::new(Vec::new(), tags(&["prod"]), None).expect("scope"),
            ..spec(Capabilities::RUN)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    let prod_tags = tags(&["prod", "db"]);
    assert_eq!(
        tagged.authorizes(
            &run_request(&Target::new(ref_id(2), &prod_tags), command),
            NOW
        ),
        Ok(())
    );

    let by_field = Grant::create(
        GrantSpec {
            scope: Scope::new(vec![ref_id(1)], Vec::new(), Some(vec!["token".into()]))
                .expect("scope"),
            ..spec(Capabilities::RUN)
        },
        TokenHash::of(TOKEN),
        NOW,
    )
    .expect("grant");
    assert_eq!(
        by_field.authorizes(
            &AccessRequest::run(in_scope, Some("password"), command),
            NOW
        ),
        Err(Denied::OutOfScope)
    );
    assert_eq!(
        by_field.authorizes(&AccessRequest::run(in_scope, None, command), NOW),
        Err(Denied::OutOfScope)
    );
    assert_eq!(
        by_field.authorizes(&AccessRequest::run(in_scope, Some("token"), command), NOW),
        Ok(())
    );
}

#[test]
fn debug_never_contains_the_token_hash() {
    let hash = TokenHash::of(TOKEN);
    let grant = Grant::create(spec(Capabilities::RUN), hash, NOW).expect("grant");
    let debug = format!("{grant:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    let hex: String = hash
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(!debug.contains(&hex), "token hash reached Debug: {debug}");
    assert!(!debug.contains("TokenHash(0"), "{debug}");
    assert!(!debug.contains(&String::from_utf8_lossy(TOKEN).to_string()));
    // Metadata that a human needs is present.
    assert!(debug.contains("test grant"), "{debug}");
    assert!(debug.contains(&grant.id().to_hex()), "{debug}");
}

#[test]
fn target_is_built_from_a_credential_without_its_secret() {
    use passmgr::store::Credential;
    use zeroize::Zeroizing;

    let credential = Credential::new(
        "github".into(),
        "octocat".into(),
        Zeroizing::new("canary-value-never-read".into()),
    )
    .expect("credential")
    .with_tags(vec!["prod".into()])
    .expect("tags");
    let target = Target::from(&credential);
    assert_eq!(target.entry, credential.id());
    assert_eq!(target.tags, ["prod"]);
}
