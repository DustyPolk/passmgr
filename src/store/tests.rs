//! Tests for the store model and the payload codec.

use super::*;

use crate::grant::{
    Capabilities, GRANT_ID_BYTES, Grant, GrantSpec, MAX_GRANTS, MAX_LABEL_BYTES, Scope,
    TOKEN_HASH_BYTES, TokenHash,
};

fn credential(service: &str, username: &str, password: &str) -> Credential {
    Credential::new(
        service.to_owned(),
        username.to_owned(),
        Zeroizing::new(password.to_owned()),
    )
    .unwrap()
}

/// Credential-only convenience over the full payload codec, so the
/// credential tests do not repeat `&[]` everywhere.
fn encode_credentials(credentials: &[Credential]) -> Result<Zeroizing<Vec<u8>>> {
    encode(credentials, &[])
}

fn decode_credentials(data: &[u8]) -> Result<Vec<Credential>> {
    decode(data).map(|payload| payload.credentials)
}

/// A grant with one ref, one allowed command and the given capabilities.
fn test_grant(label: &str, capabilities: Capabilities) -> Grant {
    Grant::create(
        GrantSpec {
            label: label.to_owned(),
            scope: Scope::new(vec![EntryId::generate().unwrap()], Vec::new(), None).unwrap(),
            commands: vec![std::path::PathBuf::from("/usr/bin/env")],
            capabilities,
            expires_at: 1_700_003_600,
            max_uses: None,
        },
        TokenHash::of(b"canary-grant-token"),
        1_700_000_000,
    )
    .unwrap()
}

fn assert_grants_equal(actual: &Grant, expected: &Grant) {
    assert_eq!(actual.id(), expected.id());
    assert!(actual.matches_token(expected.token_hash()));
    assert_eq!(actual.label(), expected.label());
    assert_eq!(actual.scope(), expected.scope());
    assert_eq!(actual.commands(), expected.commands());
    assert_eq!(actual.capabilities(), expected.capabilities());
    assert_eq!(actual.created_unix(), expected.created_unix());
    assert_eq!(actual.expires_at_unix(), expected.expires_at_unix());
    assert_eq!(actual.max_uses(), expected.max_uses());
    assert_eq!(actual.uses(), expected.uses());
    assert_eq!(actual.revoked_at_unix(), expected.revoked_at_unix());
    assert_eq!(actual.last_used_unix(), expected.last_used_unix());
}

/// Build a store version 1 payload (no entry ids) by hand, the way the
/// previous release wrote it.
fn encode_v1(credentials: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut out = vec![STORE_VERSION_WITHOUT_IDS];
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for (service, username, password) in credentials {
        for field in [*service, *username, *password] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
    }
    out
}

#[test]
fn roundtrip_handles_arbitrary_text() {
    let credentials = vec![
        credential("example.com", "user", "p:a:ss\nword"),
        credential("emoji.example", "üser", "🔐 secret"),
        credential("no-username.example", "", "x"),
    ];
    let encoded = encode_credentials(&credentials).unwrap();
    assert_eq!(encoded[0], STORE_VERSION);
    let decoded = decode_credentials(&encoded).unwrap();
    assert_eq!(decoded.len(), credentials.len());
    for (actual, expected) in decoded.iter().zip(&credentials) {
        assert_eq!(actual.id(), expected.id());
        assert_eq!(actual.created_unix(), expected.created_unix());
        assert_eq!(actual.last_rotated_unix(), expected.last_rotated_unix());
        assert_eq!(actual.service(), expected.service());
        assert_eq!(actual.username(), expected.username());
        assert_eq!(actual.password(), expected.password());
    }
}

/// Build a store version 2 payload (ids, no tags) by hand, the way the
/// previous release wrote it.
fn encode_v2(credentials: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut out = vec![STORE_VERSION_WITHOUT_TAGS];
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for (service, username, password) in credentials {
        out.extend_from_slice(&EntryId::generate().unwrap().0);
        for field in [*service, *username, *password] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
    }
    out
}

/// Build a store version 3 payload (ids and tags, no timestamps) by hand,
/// the way the previous release wrote it.
fn encode_v3(credentials: &[(&str, &str, &str, &[&str])]) -> Vec<u8> {
    let mut out = vec![STORE_VERSION_WITHOUT_TIMESTAMPS];
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for (service, username, password, tags) in credentials {
        out.extend_from_slice(&EntryId::generate().unwrap().0);
        for field in [*service, *username, *password] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        for tag in *tags {
            out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
            out.extend_from_slice(tag.as_bytes());
        }
    }
    out
}

/// Build a store version 4 payload (credentials with ids, tags and
/// timestamps, but no grant list) by hand, the way the previous release
/// wrote it.
fn encode_v4(
    credentials: &[(&str, &str, &str, &[&str])],
    created: u64,
    last_rotated: u64,
) -> Vec<u8> {
    let mut out = vec![STORE_VERSION_WITHOUT_GRANTS];
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for (service, username, password, tags) in credentials {
        out.extend_from_slice(&[0x22; ENTRY_ID_BYTES]);
        out.extend_from_slice(&created.to_le_bytes());
        out.extend_from_slice(&last_rotated.to_le_bytes());
        for field in [*service, *username, *password] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&(tags.len() as u32).to_le_bytes());
        for tag in *tags {
            out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
            out.extend_from_slice(tag.as_bytes());
        }
    }
    out
}

#[test]
fn empty_vault_roundtrips() {
    let encoded = encode_credentials(&[]).unwrap();
    assert_eq!(&*encoded, &[5, 0, 0, 0, 0, 0, 0, 0, 0]);
    let decoded = decode(&encoded).unwrap();
    assert!(decoded.credentials.is_empty());
    assert!(decoded.grants.is_empty());

    // A version 4 empty payload (no grant count) still decodes.
    let migrated = decode(&[4, 0, 0, 0, 0]).unwrap();
    assert!(migrated.credentials.is_empty());
    assert!(migrated.grants.is_empty());
}

#[test]
fn tags_roundtrip_sorted_and_unique() {
    let credential = credential("tagged.example", "user", "secret")
        .with_tags(vec![
            "work".to_owned(),
            "prod".to_owned(),
            "work".to_owned(),
        ])
        .unwrap();
    assert_eq!(credential.tags(), ["prod", "work"]);
    assert!(credential.has_tag("prod"));
    assert!(!credential.has_tag("dev"));
    assert!(credential.has_all_tags(&["prod".to_owned(), "work".to_owned()]));
    assert!(!credential.has_all_tags(&["prod".to_owned(), "dev".to_owned()]));

    let decoded = decode_credentials(&encode_credentials(&[credential]).unwrap()).unwrap();
    assert_eq!(decoded[0].tags(), ["prod", "work"]);
    assert_eq!(decoded[0].service(), "tagged.example");
}

#[test]
fn version_3_payload_is_migrated_with_timestamps_unknown() {
    let payload = encode_v3(&[("v3.example", "alice", "secret", &["prod", "work"])]);
    let migrated = decode_credentials(&payload).unwrap();
    assert_eq!(migrated.len(), 1);
    assert_eq!(migrated[0].service(), "v3.example");
    assert_eq!(migrated[0].tags(), ["prod", "work"]);
    assert_eq!(migrated[0].created_unix(), 0);
    assert_eq!(migrated[0].last_rotated_unix(), 0);

    // Saving upgrades to store version 5 and preserves id, tags and the
    // "unknown" timestamps instead of inventing a creation date.
    let upgraded = encode_credentials(&migrated).unwrap();
    assert_eq!(upgraded[0], STORE_VERSION);
    let reopened = decode_credentials(&upgraded).unwrap();
    assert_eq!(reopened[0].id(), migrated[0].id());
    assert_eq!(reopened[0].tags(), ["prod", "work"]);
    assert_eq!(reopened[0].created_unix(), 0);
    assert_eq!(reopened[0].last_rotated_unix(), 0);
}

#[test]
fn version_2_payload_is_migrated_without_data_loss() {
    let payload = encode_v2(&[("old.example", "alice", "secret-one")]);
    let migrated = decode_credentials(&payload).unwrap();
    assert_eq!(migrated.len(), 1);
    assert_eq!(migrated[0].service(), "old.example");
    assert_eq!(migrated[0].username(), "alice");
    assert_eq!(migrated[0].password(), "secret-one");
    assert!(migrated[0].tags().is_empty());
    assert_eq!(migrated[0].created_unix(), 0);
    assert_eq!(migrated[0].last_rotated_unix(), 0);

    // Saving writes store version 5 and preserves the id.
    let upgraded = encode_credentials(&migrated).unwrap();
    assert_eq!(upgraded[0], STORE_VERSION);
    let reopened = decode_credentials(&upgraded).unwrap();
    assert_eq!(reopened[0].id(), migrated[0].id());
}

/// A tag or reference typed on the command line reaches a human inside an
/// error message, so a control character in it must be named, not executed.
#[test]
fn rejection_messages_escape_control_characters() {
    let attack = "bad\u{1b}]52;c;ZXZpbA==\u{7}";

    let error = validate_tag(attack).unwrap_err().to_string();
    assert!(error.contains(r"\u{1b}"), "{error}");
    assert!(!error.contains('\u{1b}'), "{error}");
    assert!(!error.contains('\u{7}'), "{error}");

    // The second branch echoes the offending character itself, so a lone
    // control character there needs the same treatment.
    let error = validate_tag("ok\u{7}").unwrap_err().to_string();
    assert!(error.contains(r"\u{7}"), "{error}");
    assert!(!error.contains('\u{7}'), "{error}");

    let error = EntryId::parse_ref(&format!("pm://{attack}"))
        .unwrap_err()
        .to_string();
    assert!(error.contains(r"\u{1b}"), "{error}");
    assert!(!error.contains('\u{1b}'), "{error}");
    assert!(!error.contains('\u{7}'), "{error}");
}

/// A service name or username is printed by `list`, `get` and `show`, and a
/// grant scope can name it, so it is held to the same character table as a
/// grant label: no bidi overrides, zero-width or variation-selector
/// characters that make the printed name differ from the stored one (TODO
/// R.48). The rejection names the class and does not echo the value.
#[test]
fn new_identities_refuse_hidden_and_reordering_characters() {
    let hidden = [
        "git\u{202e}moc.buh",
        "github.com\u{202c}",
        "ali\u{200b}ce",
        "heart\u{fe0f}",
        "sep\u{2028}arator",
        "nul\0",
        "bell\u{7}",
    ];
    for bad in hidden {
        let errors = [
            validate_service(bad).unwrap_err(),
            validate_username(bad).unwrap_err(),
            Credential::new(
                bad.to_owned(),
                "alice".to_owned(),
                Zeroizing::new("p".to_owned()),
            )
            .unwrap_err(),
            Credential::new(
                "svc".to_owned(),
                bad.to_owned(),
                Zeroizing::new("p".to_owned()),
            )
            .unwrap_err(),
        ];
        for error in errors {
            assert!(matches!(error, Error::InvalidInput(_)), "{bad:?}: {error}");
            let message = error.to_string();
            assert!(
                message.contains(HIDDEN_FORBIDDEN_CLASSES),
                "{bad:?}: {message}"
            );
            assert!(!message.contains('\u{202e}'), "{bad:?}: {message}");
            assert!(!message.contains('\u{200b}'), "{bad:?}: {message}");
        }
    }

    // Visible text stays allowed: other scripts, accents, combining marks and
    // emoji without a variation selector.
    for good in ["пример.рф", "café", "e\u{301}mail", "🔐.example", "a b"] {
        validate_identity(good, good).unwrap_or_else(|err| panic!("{good:?} rejected: {err}"));
        credential(good, good, "p");
    }
}

/// A vault written before TODO R.48 may hold a service name or username with
/// a hidden character, because the old validators only refused C0/C1
/// controls. The reader must still open it -- refusing would cost the human
/// every credential in the vault -- and the value must survive a re-save
/// unchanged.
#[test]
fn a_legacy_payload_keeps_a_hidden_name_and_can_be_saved_again() {
    let service = "git\u{202e}moc.buh";
    let username = "ali\u{200b}ce";
    let payload = encode_v4(
        &[(service, username, "secret", &["prod"])],
        1_700_000_000,
        1_700_000_100,
    );
    let decoded = decode_credentials(&payload).expect("a pre-R.48 vault must still open");
    assert_eq!(decoded[0].service(), service);
    assert_eq!(decoded[0].username(), username);

    let upgraded = encode_credentials(&decoded).unwrap();
    assert_eq!(upgraded[0], STORE_VERSION);
    let reopened = decode_credentials(&upgraded).unwrap();
    assert_eq!(reopened[0].service(), service);
    assert_eq!(reopened[0].username(), username);
}

/// The reader keeps the boundary every released build had: C0/C1 controls are
/// still refused, because no passmgr build ever wrote one there and a payload
/// holding one did not come from this program.
#[test]
fn a_legacy_payload_still_refuses_control_characters_in_identity() {
    for bad in ["svc\u{1b}[2J", "svc\u{9b}31m"] {
        let payload = encode_v4(&[(bad, "alice", "secret", &[])], 0, 0);
        let error = decode_credentials(&payload).unwrap_err();
        assert!(matches!(error, Error::MalformedVault(_)), "{error}");
    }
}

#[test]
fn tag_validation_rejects_ambiguous_names() {
    for bad in [
        "",
        "Prod",
        "-leading",
        "_leading",
        ".leading",
        "has space",
        "has\ncontrol",
        "slash/inside",
        "colon:inside",
        "é",
    ] {
        assert!(
            validate_tag(bad).is_err(),
            "invalid tag '{bad}' was accepted"
        );
    }
    for good in ["a", "prod", "prod-1", "team_a.backup", "0"] {
        validate_tag(good).unwrap_or_else(|err| panic!("valid tag '{good}' rejected: {err}"));
    }
    assert!(validate_tag(&"x".repeat(MAX_TAG_BYTES + 1)).is_err());
    let too_many: Vec<String> = (0..=MAX_TAGS_PER_CREDENTIAL)
        .map(|index| format!("tag{index}"))
        .collect();
    assert!(normalize_tags(too_many).is_err());
    let exactly_full: Vec<String> = (0..MAX_TAGS_PER_CREDENTIAL)
        .map(|index| format!("tag{index}"))
        .collect();
    assert_eq!(
        normalize_tags(exactly_full).unwrap().len(),
        MAX_TAGS_PER_CREDENTIAL
    );

    let mut credential = credential("svc", "u", "p");
    assert!(credential.set_tags(vec!["Prod".to_owned()]).is_err());
    assert!(
        credential.tags().is_empty(),
        "a failed set_tags must leave the credential untouched"
    );
}

#[test]
fn rejects_duplicate_or_excessive_tags_in_payload() {
    let encoded = encode_credentials(&[credential("svc", "u", "p")
        .with_tags(vec!["a".to_owned()])
        .unwrap()])
    .unwrap()
    .to_vec();
    // Drop the trailing grant count, then edit the credential record.
    let mut record = encoded[..encoded.len() - 4].to_vec();
    // The tag count is the last four bytes before the single tag entry.
    let tag_count_offset = record.len() - (4 + 4 + 1);
    record[tag_count_offset..tag_count_offset + 4].copy_from_slice(&2u32.to_le_bytes());
    let mut duplicated = record.clone();
    duplicated.extend_from_slice(&(1u32.to_le_bytes()));
    duplicated.extend_from_slice(b"a");
    duplicated.extend_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        decode(&duplicated).unwrap_err(),
        Error::MalformedVault(message) if message.contains("duplicate tag")
    ));

    let mut excessive = record;
    excessive[tag_count_offset..tag_count_offset + 4]
        .copy_from_slice(&((MAX_TAGS_PER_CREDENTIAL + 1) as u32).to_le_bytes());
    assert!(matches!(
        decode(&excessive).unwrap_err(),
        Error::MalformedVault(message) if message.contains("tag count")
    ));
}

#[test]
fn entry_ids_are_unique_and_stable_across_saves() {
    let credentials = vec![
        credential("one.example", "a", "p1"),
        credential("two.example", "b", "p2"),
    ];
    assert_ne!(credentials[0].id(), credentials[1].id());

    let first = decode_credentials(&encode_credentials(&credentials).unwrap()).unwrap();
    let second = decode_credentials(&encode_credentials(&first).unwrap()).unwrap();
    for (original, reencoded) in credentials.iter().zip(&second) {
        assert_eq!(original.id(), reencoded.id());
    }
    assert_eq!(first[0].id(), second[0].id());
    assert_eq!(first[1].id(), second[1].id());
}

#[test]
fn version_1_payload_is_migrated_without_data_loss() {
    let payload = encode_v1(&[
        ("old.example", "alice", "secret-one"),
        ("other.example", "bob", "secret-two"),
    ]);
    let migrated = decode_credentials(&payload).unwrap();
    assert_eq!(migrated.len(), 2);
    assert_eq!(migrated[0].service(), "old.example");
    assert_eq!(migrated[0].username(), "alice");
    assert_eq!(migrated[0].password(), "secret-one");
    assert!(migrated[0].tags().is_empty());
    assert_eq!(migrated[1].service(), "other.example");
    assert_eq!(migrated[1].password(), "secret-two");
    assert_eq!(migrated[1].created_unix(), 0);
    assert_eq!(migrated[1].last_rotated_unix(), 0);
    assert_ne!(migrated[0].id(), migrated[1].id());

    // Saving writes the new store version, and the migrated ids stick.
    let upgraded = encode_credentials(&migrated).unwrap();
    assert_eq!(upgraded[0], STORE_VERSION);
    let reopened = decode_credentials(&upgraded).unwrap();
    assert_eq!(reopened[0].id(), migrated[0].id());
    assert_eq!(reopened[1].id(), migrated[1].id());
}

#[test]
fn entry_id_hex_and_ref_syntax() {
    let id = EntryId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    assert_eq!(id.to_hex(), "000102030405060708090a0b0c0d0e0f");
    assert_eq!(id.to_ref(), "pm://000102030405060708090a0b0c0d0e0f");
    assert_eq!(EntryId::parse_ref(&id.to_ref()).unwrap(), id);
    // Upper-case hex is accepted but normalized to lower case.
    assert_eq!(
        EntryId::parse_ref("pm://000102030405060708090A0B0C0D0E0F")
            .unwrap()
            .to_hex(),
        id.to_hex()
    );

    for bad in [
        "",
        "pm://",
        "pm://00010203",
        "pm://000102030405060708090a0b0c0d0e0",
        "pm://000102030405060708090a0b0c0d0e0ff",
        "pm://000102030405060708090a0b0c0d0e0g",
        "http://000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
    ] {
        assert!(
            EntryId::parse_ref(bad).is_err(),
            "'{bad}' was accepted as a reference"
        );
    }

    let generated = EntryId::generate().unwrap();
    assert_eq!(generated.to_hex().len(), ENTRY_ID_HEX_CHARS);
    assert!(generated.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(generated.to_ref().starts_with(ENTRY_REF_PREFIX));
    assert_ne!(generated, EntryId::generate().unwrap());
}

#[test]
fn rejects_duplicate_entry_ids() {
    let encoded = encode_credentials(&[credential("one", "u", "p")])
        .unwrap()
        .to_vec();
    // Repeat the single credential's body with the same id, before the
    // trailing grant count.
    let record_start = 1 + 4;
    let record_end = encoded.len() - 4;
    let mut duplicated = encoded[..record_start].to_vec();
    duplicated[1..5].copy_from_slice(&2u32.to_le_bytes());
    duplicated.extend_from_slice(&encoded[record_start..record_end]);
    duplicated.extend_from_slice(&encoded[record_start..record_end]);
    duplicated.extend_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        decode_credentials(&duplicated).unwrap_err(),
        Error::MalformedVault(message) if message.contains("duplicate entry id")
    ));
}

#[test]
fn rejects_invalid_credentials() {
    assert!(Credential::new("".into(), "u".into(), Zeroizing::new("p".into())).is_err());
    assert!(Credential::new("s".into(), "u".into(), Zeroizing::new(String::new())).is_err());
    assert!(
        Credential::new(
            "bad\nservice".into(),
            "u".into(),
            Zeroizing::new("p".into())
        )
        .is_err()
    );
}

#[test]
fn rejects_truncated_data() {
    let encoded = encode_credentials(&[credential("service", "user", "password")]).unwrap();
    for len in 0..encoded.len() {
        assert!(
            decode_credentials(&encoded[..len]).is_err(),
            "length {len} was accepted"
        );
    }
}

#[test]
fn rejects_trailing_bytes() {
    let mut encoded = encode_credentials(&[]).unwrap().to_vec();
    encoded.push(0);
    assert!(matches!(
        decode_credentials(&encoded).unwrap_err(),
        Error::MalformedVault(_)
    ));
}

#[test]
fn setters_validate_and_replace_fields() {
    let mut credential = credential("service", "user", "old-password");
    credential.set_service("new-service".into()).unwrap();
    credential.set_username("new-user".into()).unwrap();
    credential
        .set_password(Zeroizing::new("new-password".into()))
        .unwrap();
    assert_eq!(credential.service(), "new-service");
    assert_eq!(credential.username(), "new-user");
    assert_eq!(credential.password(), "new-password");

    assert!(credential.set_service(String::new()).is_err());
    assert!(credential.set_service("bad\nservice".into()).is_err());
    assert!(credential.set_username("bad\nuser".into()).is_err());
    assert!(
        credential
            .set_password(Zeroizing::new(String::new()))
            .is_err()
    );
    // Failed setters must leave the credential untouched.
    assert_eq!(credential.service(), "new-service");
    assert_eq!(credential.username(), "new-user");
    assert_eq!(credential.password(), "new-password");
}

#[test]
fn new_entries_record_creation_and_rotation_times() {
    let mut credential = credential("timed.example", "user", "first");
    let created = credential.created_unix();
    assert!(created > 0, "a new entry gets a real timestamp");
    assert!(created <= MAX_TIMESTAMP_UNIX);
    assert_eq!(credential.last_rotated_unix(), created);

    // Pretend the entry was last rotated long ago, then rotate it. Only the
    // rotation time moves; the creation time is immutable.
    credential.timestamps.last_rotated = 1_000_000;
    credential
        .set_password(Zeroizing::new("second".to_owned()))
        .unwrap();
    assert_eq!(credential.created_unix(), created);
    assert!(credential.last_rotated_unix() > 1_000_000);
    assert!(credential.last_rotated_unix() <= MAX_TIMESTAMP_UNIX);

    // A rejected password leaves the rotation time unchanged.
    let before = credential.last_rotated_unix();
    assert!(
        credential
            .set_password(Zeroizing::new(String::new()))
            .is_err()
    );
    assert_eq!(credential.last_rotated_unix(), before);

    let decoded = decode_credentials(&encode_credentials(&[credential]).unwrap()).unwrap();
    assert_eq!(decoded[0].created_unix(), created);
    assert!(decoded[0].last_rotated_unix() >= before);
}

#[test]
fn rejects_out_of_range_timestamps_in_payload() {
    let encoded = encode_credentials(&[credential("timed.example", "u", "p")])
        .unwrap()
        .to_vec();
    // Layout: version(1) + count(4) + id(16) + created(8).
    let created_offset = 1 + 4 + ENTRY_ID_BYTES;
    let mut payload = encoded;
    payload[created_offset..created_offset + 8]
        .copy_from_slice(&(MAX_TIMESTAMP_UNIX + 1).to_le_bytes());
    assert!(matches!(
        decode_credentials(&payload).unwrap_err(),
        Error::MalformedVault(message) if message.contains("created timestamp")
    ));

    // Encoding must refuse the same value rather than write a payload that
    // its own reader would reject.
    let mut credential = credential("timed.example", "u", "p");
    credential.timestamps.created = MAX_TIMESTAMP_UNIX + 1;
    assert!(matches!(
        encode_credentials(&[credential]).unwrap_err(),
        Error::InvalidInput(message) if message.contains("created timestamp")
    ));
}

#[test]
fn version_4_payload_is_migrated_with_no_grants() {
    let payload = encode_v4(
        &[("v4.example", "alice", "secret", &["prod"])],
        1_700_000_000,
        1_700_000_000,
    );
    let decoded = decode(&payload).unwrap();
    assert!(decoded.grants.is_empty());
    assert_eq!(decoded.credentials.len(), 1);
    assert_eq!(decoded.credentials[0].service(), "v4.example");
    assert_eq!(decoded.credentials[0].created_unix(), 1_700_000_000);
    assert_eq!(decoded.credentials[0].tags(), ["prod"]);

    // Saving upgrades to store version 5 and keeps the credentials and
    // the (still empty) grant list intact.
    let upgraded = encode(&decoded.credentials, &decoded.grants).unwrap();
    assert_eq!(upgraded[0], STORE_VERSION);
    let reopened = decode(&upgraded).unwrap();
    assert!(reopened.grants.is_empty());
    assert_eq!(reopened.credentials[0].id(), decoded.credentials[0].id());
    assert_eq!(reopened.credentials[0].tags(), ["prod"]);
}

#[test]
fn every_older_version_decodes_with_no_grants() {
    for payload in [
        encode_v1(&[("v1.example", "u", "p")]),
        encode_v2(&[("v2.example", "u", "p")]),
        encode_v3(&[("v3.example", "u", "p", &["prod"])]),
        encode_v4(&[("v4.example", "u", "p", &["prod"])], 1, 1),
    ] {
        let decoded = decode(&payload).unwrap();
        assert!(decoded.grants.is_empty(), "an old payload grew a grant");
        assert_eq!(decoded.credentials.len(), 1);
        assert_eq!(decoded.credentials[0].username(), "u");
    }
}

#[test]
fn grants_roundtrip_with_every_optional_field() {
    let mut run = Grant::create(
        GrantSpec {
            label: "deploy prod".to_owned(),
            scope: Scope::new(
                vec![EntryId::generate().unwrap()],
                vec!["prod".to_owned()],
                Some(vec!["password".to_owned()]),
            )
            .unwrap(),
            commands: vec![
                std::path::PathBuf::from("/usr/bin/gh"),
                std::path::PathBuf::from("/usr/bin/env"),
            ],
            capabilities: Capabilities::LIST.union(Capabilities::RUN),
            expires_at: 1_700_003_600,
            max_uses: Some(3),
        },
        TokenHash::of(b"canary-run-token"),
        1_700_000_000,
    )
    .unwrap();
    run.mark_used(1_700_000_100).unwrap();
    run.revoke(1_700_000_200).unwrap();
    let list = test_grant("read only", Capabilities::LIST);

    let encoded = encode(&[credential("svc", "u", "p")], &[run.clone(), list.clone()]).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded.credentials[0].password(), "p");
    assert_eq!(decoded.grants.len(), 2);
    assert_grants_equal(&decoded.grants[0], &run);
    assert_grants_equal(&decoded.grants[1], &list);
}

#[test]
fn every_grant_mutation_round_trips_through_the_payload() {
    // Every public way to build a `Grant` state must survive a save, so
    // the writer never emits what the reader refuses (TODO R.17).
    let base = || {
        Grant::create(
            GrantSpec {
                label: "rotate db".to_owned(),
                scope: Scope::new(vec![EntryId::generate().unwrap()], Vec::new(), None).unwrap(),
                commands: vec![std::path::PathBuf::from("/usr/bin/env")],
                capabilities: Capabilities::RUN,
                expires_at: 1_700_003_600,
                max_uses: Some(2),
            },
            TokenHash::of(b"canary-roundtrip-token"),
            1_700_000_000,
        )
        .unwrap()
    };
    let mut used_then_revoked = base();
    used_then_revoked.mark_used(1_700_000_100).unwrap();
    used_then_revoked.revoke(1_700_000_150).unwrap();
    let mut revoked = base();
    revoked.revoke(1_700_000_200).unwrap();

    for grant in [base(), used_then_revoked, revoked] {
        let encoded = encode(&[], std::slice::from_ref(&grant)).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.grants.len(), 1);
        assert_grants_equal(&decoded.grants[0], &grant);
    }
}

#[test]
fn encode_refuses_duplicate_and_excessive_grants() {
    let grant = test_grant("dup", Capabilities::LIST);
    assert!(matches!(
        encode(&[], &[grant.clone(), grant]).unwrap_err(),
        Error::InvalidInput(message) if message.contains("duplicate grant id")
    ));

    let grants: Vec<Grant> = (0..=MAX_GRANTS)
        .map(|index| test_grant(&format!("g{index}"), Capabilities::LIST))
        .collect();
    assert!(matches!(
        encode(&[], &grants).unwrap_err(),
        Error::InvalidInput(message) if message.contains("too many grants")
    ));
}

#[test]
fn rejects_duplicate_grant_ids_in_payload() {
    let encoded = encode(&[], &[test_grant("dup", Capabilities::LIST)])
        .unwrap()
        .to_vec();
    // version(1) + credential count(4) + grant count(4)
    let record_start = 9;
    let mut duplicated = encoded[..record_start].to_vec();
    duplicated[5..9].copy_from_slice(&2u32.to_le_bytes());
    duplicated.extend_from_slice(&encoded[record_start..]);
    duplicated.extend_from_slice(&encoded[record_start..]);
    assert!(matches!(
        decode(&duplicated).unwrap_err(),
        Error::MalformedVault(message) if message.contains("duplicate grant id")
    ));
}

#[test]
fn rejects_truncated_grant_records() {
    let encoded = encode(&[], &[test_grant("truncated", Capabilities::LIST)]).unwrap();
    let record_start = 9;
    assert!(encoded.len() > record_start);
    for len in record_start..encoded.len() {
        assert!(
            decode(&encoded[..len]).is_err(),
            "truncated grant length {len} was accepted"
        );
    }
}

#[test]
fn rejects_unknown_grant_bits_and_field_modes() {
    let encoded = encode(&[], &[test_grant("bits", Capabilities::LIST)])
        .unwrap()
        .to_vec();
    // version(1) + credential count(4) + grant count(4) + id(16) + hash(32)
    let capabilities_offset = 9 + GRANT_ID_BYTES + TOKEN_HASH_BYTES;

    let mut unknown_capability = encoded.clone();
    unknown_capability[capabilities_offset] = 0b1000_0000;
    assert!(matches!(
        decode(&unknown_capability).unwrap_err(),
        Error::MalformedVault(message) if message.contains("capability bits")
    ));

    let mut zero_capability = encoded.clone();
    zero_capability[capabilities_offset] = 0;
    assert!(matches!(
        decode(&zero_capability).unwrap_err(),
        Error::MalformedVault(message) if message.contains("capability")
    ));

    let mut unknown_flag = encoded.clone();
    unknown_flag[capabilities_offset + 1] = 0b1000_0000;
    assert!(matches!(
        decode(&unknown_flag).unwrap_err(),
        Error::MalformedVault(message) if message.contains("grant flag bits")
    ));

    // The field-scope mode byte sits after the label, refs and tags, and
    // before the command list: 4-byte count + 4-byte length + path.
    let mut unknown_field_mode = encoded.clone();
    let mode_offset = unknown_field_mode.len() - (4 + 4 + "/usr/bin/env".len() + 1);
    unknown_field_mode[mode_offset] = 7;
    assert!(matches!(
        decode(&unknown_field_mode).unwrap_err(),
        Error::MalformedVault(message) if message.contains("field scope mode")
    ));
}

#[test]
fn rejects_oversized_grant_label() {
    let encoded = encode(&[], &[test_grant("label", Capabilities::LIST)])
        .unwrap()
        .to_vec();
    // version(1) + credential count(4) + grant count(4) + id(16) +
    // hash(32) + capabilities(1) + flags(1) + created(8) + expires(8) +
    // uses(4)
    let label_len_offset = 9 + 16 + 32 + 1 + 1 + 8 + 8 + 4;
    let mut oversized = encoded;
    oversized[label_len_offset..label_len_offset + 4]
        .copy_from_slice(&((MAX_LABEL_BYTES + 1) as u32).to_le_bytes());
    assert!(matches!(
        decode(&oversized).unwrap_err(),
        Error::MalformedVault(message) if message.contains("grant label length")
    ));
}

#[test]
fn payload_debug_redacts_passwords_and_token_hashes() {
    let encoded = encode(
        &[credential("svc", "u", "canary-payload-password")],
        &[test_grant("debug", Capabilities::LIST)],
    )
    .unwrap();
    let payload = decode(&encoded).unwrap();
    let debug = format!("{payload:?}");
    assert!(!debug.contains("canary-payload-password"), "{debug}");
    let hash = payload.grants[0].token_hash();
    let hex: String = hash
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(!debug.contains(&hex), "token hash reached Debug: {debug}");
    assert!(debug.contains("svc"), "{debug}");
    assert!(debug.contains("debug"), "{debug}");
}

#[test]
fn rejects_bad_store_version() {
    assert!(matches!(
        decode_credentials(&[6, 0, 0, 0, 0]).unwrap_err(),
        Error::MalformedVault(_)
    ));
}

#[test]
fn rejects_oversized_field_length() {
    let mut encoded = vec![STORE_VERSION, 1, 0, 0, 0];
    encoded.extend_from_slice(&[0u8; ENTRY_ID_BYTES]);
    encoded.extend_from_slice(&((MAX_FIELD_BYTES + 1) as u32).to_le_bytes());
    assert!(matches!(
        decode_credentials(&encoded).unwrap_err(),
        Error::MalformedVault(_)
    ));
}

/// TODO R.46/R.61: a stored grant grows after it is created — `revoked_at`
/// and `last_used` each add 8 bytes, and `max_uses` is fixed at creation. The
/// container's plaintext headroom must cover that growth for every grant the
/// payload can hold, or a vault written at the content cap could never record
/// a revocation or a use (the kill switch would fail).
///
/// The growth is measured from the codec — the encoded payload before and
/// after the two post-creation transitions — instead of restating a constant,
/// and the fixture sets every optional field so the measured record is the
/// largest one the format allows. The measurement is tied to the accounting
/// `encode` uses: bytes the encoder adds on a transition must be exactly the
/// bytes the content cap excludes.
#[test]
fn grant_growth_headroom_covers_the_whole_grant_cap() {
    let mut grant = Grant::create(
        GrantSpec {
            label: "every optional field".to_owned(),
            scope: Scope::new(
                vec![EntryId::generate().unwrap(), EntryId::generate().unwrap()],
                vec!["git".to_owned(), "prod".to_owned()],
                Some(vec!["password".to_owned(), "username".to_owned()]),
            )
            .unwrap(),
            commands: vec![
                std::path::PathBuf::from("/usr/bin/git"),
                std::path::PathBuf::from("/usr/bin/gh"),
            ],
            capabilities: Capabilities::LIST.union(Capabilities::RUN),
            expires_at: 1_700_003_600,
            max_uses: Some(2),
        },
        TokenHash::of(b"canary-growth-token"),
        1_700_000_000,
    )
    .unwrap();

    let encoded_len = |grant: &Grant| encode(&[], std::slice::from_ref(grant)).unwrap().len();

    let created = encoded_len(&grant);
    grant.mark_used(1_700_000_100).unwrap();
    let used = encoded_len(&grant);
    grant.revoke(1_700_000_200).unwrap();
    let revoked_and_used = encoded_len(&grant);

    assert!(used > created, "mark_used must add its field to the record");
    assert!(
        revoked_and_used > used,
        "revoke must add its field to the record"
    );
    let measured_growth = revoked_and_used - created;

    // The bytes the encoder really adds are exactly the bytes `encode`
    // attributes to post-creation growth, so the content size a save reports
    // does not move when a grant is used or revoked.
    assert_eq!(measured_growth, super::payload::grant_growth_bytes(&grant));
    assert_eq!(
        revoked_and_used - measured_growth,
        created,
        "a post-creation transition must not grow the content size"
    );

    // The container reserves this much for every grant the payload can hold.
    assert!(
        measured_growth * MAX_GRANTS <= crate::crypto::MAX_PLAINTEXT_GROWTH_BYTES,
        "MAX_PLAINTEXT_GROWTH_BYTES must cover {measured_growth} bytes x {MAX_GRANTS} grants"
    );
}
