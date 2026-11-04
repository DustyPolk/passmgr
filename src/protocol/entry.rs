//! Metadata-only credential entries carried by `list` responses.
//!
//! An [`Entry`] holds what an agent needs to *choose* a credential: its
//! reference, service name, username, tags, field **names**, URL and
//! timestamps. It has no field that can hold a secret value, and
//! [`Entry::from_json`] refuses anything that is not that shape, so a buggy or
//! malicious daemon cannot turn the response into a plaintext channel that the
//! MCP server would relay.
//!
//! The module also owns the two filters `list` applies (tags and a
//! case-insensitive service substring) and the byte budget that keeps a large
//! vault's answer inside one protocol frame. Filters only ever *narrow*: the
//! daemon authorizes every candidate on its own before asking these helpers.

use serde_json::{Map, Value, json};

use super::{MAX_MESSAGE_BYTES, ProtocolError};
use crate::grant::validate_field_name;
use crate::store::{
    self, Credential, EntryId, MAX_FIELD_BYTES, MAX_TAGS_PER_CREDENTIAL, MAX_TIMESTAMP_UNIX,
};

/// Bytes reserved for everything around the `entries` array: the version, the
/// response type, the `truncated` flag, the array brackets and the length
/// prefix. Deliberately generous, because an entry that does not fit is
/// dropped rather than sent in a frame the peer would refuse.
const LIST_ENVELOPE_BYTES: usize = 256;

/// The most an `entries` array may occupy, commas included.
pub const MAX_LIST_BODY_BYTES: usize = MAX_MESSAGE_BYTES - LIST_ENVELOPE_BYTES;

/// One credential's public metadata, as returned by `list` (and later
/// `describe`).
///
/// The fields mirror the `Entry` shape in `MCP.md`. `fields` and `url` are
/// always empty until TODO 6.1 adds fields to the vault format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Canonical `pm://` reference (lowercase hex).
    pub reference: String,
    /// The service name a human would recognize.
    pub service: String,
    /// The username, or `None` when the credential has none.
    pub username: Option<String>,
    /// Tags, sorted and deduplicated by the store.
    pub tags: Vec<String>,
    /// Field *names* only, never values.
    pub fields: Vec<String>,
    /// A URL associated with the credential, if the vault has one.
    pub url: Option<String>,
    /// Creation time, or `None` when unknown.
    pub created: Option<u64>,
    /// Last rotation time, or `None` when unknown.
    pub last_rotated: Option<u64>,
}

impl Entry {
    /// Project a decrypted credential onto its metadata.
    ///
    /// The password is never read here, so no code path from this function can
    /// copy a secret into the response.
    pub fn from_credential(credential: &Credential) -> Entry {
        let username = credential.username();
        Entry {
            reference: credential.reference(),
            service: credential.service().to_owned(),
            username: (!username.is_empty()).then(|| username.to_owned()),
            tags: credential.tags().to_vec(),
            fields: Vec::new(),
            url: None,
            created: nonzero(credential.created_unix()),
            last_rotated: nonzero(credential.last_rotated_unix()),
        }
    }

    /// The wire form. `None` becomes JSON `null`.
    pub(super) fn to_json(&self) -> Value {
        json!({
            "ref": self.reference,
            "service": self.service,
            "username": self.username,
            "tags": self.tags,
            "fields": self.fields,
            "url": self.url,
            "created": self.created,
            "last_rotated": self.last_rotated,
        })
    }

    /// Parse one untrusted `Entry` object from a response body.
    ///
    /// Every string is bounded and checked for control characters, tags and
    /// field names go through the same validators the store uses, and the
    /// reference is canonicalized, so the decoded value cannot carry anything
    /// the encoder would not have produced.
    pub(super) fn from_json(value: &Value) -> Result<Entry, ProtocolError> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("each 'response.entries' item must be an object"))?;
        let reference = required_text(object, "ref")?;
        let id = EntryId::parse_ref(&reference)
            .map_err(|_| malformed("'entry.ref' is not a pm:// reference"))?;
        let service = required_text(object, "service")?;
        check_text("service", &service, true)?;
        let username = optional_text(object, "username")?;
        if let Some(username) = &username {
            check_text("username", username, true)?;
        }
        let url = optional_text(object, "url")?;
        if let Some(url) = &url {
            check_text("url", url, false)?;
        }
        let tags = text_array(object, "tags")?;
        if tags.len() > MAX_TAGS_PER_CREDENTIAL {
            return Err(malformed("'entry.tags' has too many tags"));
        }
        for tag in &tags {
            store::validate_tag(tag).map_err(|_| malformed("'entry.tags' must be valid tags"))?;
        }
        let fields = text_array(object, "fields")?;
        for field in &fields {
            validate_field_name(field)
                .map_err(|_| malformed("'entry.fields' must be field names"))?;
        }
        Ok(Entry {
            reference: id.to_ref(),
            service,
            username,
            tags,
            fields,
            url,
            created: optional_timestamp(object, "created")?,
            last_rotated: optional_timestamp(object, "last_rotated")?,
        })
    }
}

/// Encode an entry list as the `entries` array of a response.
pub(super) fn entries_json(entries: &[Entry]) -> Value {
    Value::Array(entries.iter().map(Entry::to_json).collect())
}

/// Decode the `entries` array (and the `truncated` flag) of a response body.
pub(super) fn decode_entries(
    response: &Map<String, Value>,
) -> Result<(Vec<Entry>, bool), ProtocolError> {
    let values = response
        .get("entries")
        .ok_or_else(|| malformed("missing 'response.entries'"))?
        .as_array()
        .ok_or_else(|| malformed("'response.entries' must be an array"))?;
    let entries = values
        .iter()
        .map(Entry::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = match response.get("truncated") {
        None | Some(Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| malformed("'response.truncated' must be a boolean"))?,
    };
    Ok((entries, truncated))
}

/// Whether a credential passes the `list` filters.
///
/// `tags` requires all of them (intersection); `query` is a case-insensitive
/// substring of the service name. An empty filter matches everything: this is
/// only a convenience for the caller, never an authorization decision.
pub fn matches_filters(credential: &Credential, tags: &[String], query: Option<&str>) -> bool {
    if !tags.is_empty() && !credential.has_all_tags(tags) {
        return false;
    }
    match query {
        None => true,
        Some(query) => {
            let needle = query.to_lowercase();
            credential.service().to_lowercase().contains(&needle)
        }
    }
}

/// Keep as many whole entries as fit one frame, and report whether any were
/// dropped.
///
/// The answer is always a prefix of the input, so `truncated` is the only
/// thing the caller has to look at; it never silently reorders or samples.
pub fn fit_entries(entries: Vec<Entry>) -> (Vec<Entry>, bool) {
    let mut used = 0usize;
    let mut kept = Vec::with_capacity(entries.len().min(16));
    for entry in entries {
        let size = wire_len(&entry);
        if used.saturating_add(size) > MAX_LIST_BODY_BYTES {
            return (kept, true);
        }
        used += size;
        kept.push(entry);
    }
    (kept, false)
}

/// Serialized size of one array element, plus the comma that follows it. The
/// last element has no comma, so this over-counts by one byte: safe.
fn wire_len(entry: &Entry) -> usize {
    serde_json::to_vec(&entry.to_json()).map_or(MAX_LIST_BODY_BYTES, |bytes| bytes.len()) + 1
}

fn nonzero(seconds: u64) -> Option<u64> {
    (seconds != 0).then_some(seconds)
}

fn malformed(message: &str) -> ProtocolError {
    ProtocolError::MalformedJson(message.to_owned())
}

fn required_text(object: &Map<String, Value>, key: &str) -> Result<String, ProtocolError> {
    match object.get(key) {
        None => Err(malformed(&format!("missing 'entry.{key}'"))),
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| malformed(&format!("'entry.{key}' must be a string"))),
    }
}

fn optional_text(object: &Map<String, Value>, key: &str) -> Result<Option<String>, ProtocolError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(value.as_str().map(str::to_owned).ok_or_else(
            || malformed(&format!("'entry.{key}' must be a string or null")),
        )?)),
    }
}

fn text_array(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, ProtocolError> {
    let values = match object.get(key) {
        None => return Err(malformed(&format!("missing 'entry.{key}'"))),
        Some(value) => value
            .as_array()
            .ok_or_else(|| malformed(&format!("'entry.{key}' must be an array")))?,
    };
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| malformed(&format!("'entry.{key}' entries must be strings")))
        })
        .collect()
}

fn optional_timestamp(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, ProtocolError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let seconds = value
                .as_u64()
                .ok_or_else(|| malformed(&format!("'entry.{key}' must be a timestamp or null")))?;
            if seconds == 0 || seconds > MAX_TIMESTAMP_UNIX {
                return Err(malformed(&format!("'entry.{key}' is out of range")));
            }
            Ok(Some(seconds))
        }
    }
}

fn check_text(field: &str, value: &str, required: bool) -> Result<(), ProtocolError> {
    if required && value.is_empty() {
        return Err(malformed(&format!("'entry.{field}' must not be empty")));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(malformed(&format!("'entry.{field}' is too long")));
    }
    if value.chars().any(char::is_control) {
        return Err(malformed(&format!(
            "'entry.{field}' must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Response, decode_response, encode_response};

    /// A unique value per test: if it ever shows up in an encoded response the
    /// test fails, and no real credential is involved.
    const CANARY: &str = "canary-2f8c1d9e-should-never-be-encoded";

    fn credential(service: &str, username: &str, tags: &[&str]) -> Credential {
        Credential::new(
            service.to_owned(),
            username.to_owned(),
            zeroize::Zeroizing::new(CANARY.to_owned()),
        )
        .expect("credential")
        .with_tags(tags.iter().map(|tag| (*tag).to_owned()).collect())
        .expect("tags")
    }

    #[test]
    fn entry_from_credential_carries_metadata_but_never_the_password() {
        let credential = credential("GitHub", "octocat", &["prod", "git"]);
        let entry = Entry::from_credential(&credential);

        assert_eq!(entry.reference, credential.reference());
        assert_eq!(entry.service, "GitHub");
        assert_eq!(entry.username.as_deref(), Some("octocat"));
        assert_eq!(entry.tags, vec!["git".to_owned(), "prod".to_owned()]);
        assert!(entry.fields.is_empty(), "fields arrive with TODO 6.1");
        assert!(entry.url.is_none(), "urls arrive with TODO 6.1");
        assert!(entry.created.is_some(), "creation time is known");
        assert!(
            entry.last_rotated.is_some(),
            "a new credential counts as rotated"
        );

        let frame = encode_response(&Response::Entries {
            entries: vec![entry],
            truncated: false,
        })
        .expect("encode");
        let body = String::from_utf8_lossy(&frame);
        assert!(
            !body.contains(CANARY),
            "a list response must never carry a secret value: {body}"
        );
        assert!(!format!("{:?}", decode_response(&frame)).contains(CANARY));
    }

    #[test]
    fn entry_round_trips_through_json() {
        let entry = Entry {
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            service: "GitHub".into(),
            username: Some("octocat".into()),
            tags: vec!["prod".into()],
            fields: vec!["password".into(), "token".into()],
            url: Some("https://example.test/login".into()),
            created: Some(1_700_000_000),
            last_rotated: None,
        };
        assert_eq!(Entry::from_json(&entry.to_json()).expect("decode"), entry);

        let frame = encode_response(&Response::Entries {
            entries: vec![entry.clone()],
            truncated: true,
        })
        .expect("encode");
        assert_eq!(
            decode_response(&frame).expect("decode"),
            Response::Entries {
                entries: vec![entry],
                truncated: true,
            }
        );
    }

    #[test]
    fn decode_refuses_entries_that_are_not_metadata() {
        let valid = Entry {
            reference: "pm://00112233445566778899aabbccddeeff".into(),
            service: "GitHub".into(),
            username: None,
            tags: vec!["prod".into()],
            fields: Vec::new(),
            url: None,
            created: Some(1_700_000_000),
            last_rotated: None,
        }
        .to_json();

        let mut cases: Vec<(&str, Value)> = vec![
            ("a non-object entry", serde_json::json!("secret")),
            ("a missing ref", valid.clone()),
        ];
        cases[1].1.as_object_mut().expect("object").remove("ref");
        let mutations: Vec<(&str, &str, Value)> = vec![
            ("ref", "ref", serde_json::json!("pm://zz")),
            ("service", "service", serde_json::json!("")),
            ("service", "service", serde_json::json!("Git\u{1b}Hub")),
            ("username", "username", serde_json::json!(7)),
            ("tags", "tags", serde_json::json!("prod")),
            ("tags", "tags", serde_json::json!(["Prod"])),
            ("fields", "fields", serde_json::json!(["Password"])),
            ("url", "url", serde_json::json!("https://x/\u{7}")),
            ("created", "created", serde_json::json!(0)),
            (
                "created",
                "created",
                serde_json::json!(MAX_TIMESTAMP_UNIX + 1),
            ),
            ("created", "created", serde_json::json!("yesterday")),
            ("last_rotated", "last_rotated", serde_json::json!(-1)),
        ];
        for (name, key, value) in mutations {
            let mut entry = valid.clone();
            entry
                .as_object_mut()
                .expect("object")
                .insert(key.to_owned(), value);
            cases.push((name, entry));
        }
        let mut too_many = valid.clone();
        too_many.as_object_mut().expect("object").insert(
            "tags".to_owned(),
            Value::Array(
                (0..=MAX_TAGS_PER_CREDENTIAL)
                    .map(|_| Value::from("prod"))
                    .collect(),
            ),
        );
        cases.push(("too many tags", too_many));

        for (name, value) in cases {
            assert!(
                Entry::from_json(&value).is_err(),
                "{name} must be refused, not decoded into an entry"
            );
        }

        // A response that omits `truncated` still decodes (it defaults to
        // false), but a non-boolean flag is refused.
        let body = serde_json::json!({ "entries": [valid], "truncated": "yes" });
        assert!(
            decode_entries(body.as_object().expect("object")).is_err(),
            "a non-boolean truncated flag must be refused"
        );
    }

    #[test]
    fn fit_entries_keeps_a_prefix_and_stays_inside_one_frame() {
        // Long service names make each entry big, so the vault below cannot
        // fit in one frame.
        let service = "a".repeat(MAX_FIELD_BYTES);
        let entries: Vec<Entry> = (0..24)
            .map(|_| Entry::from_credential(&credential(&service, "", &[])))
            .collect();
        let total = entries.len();
        let (kept, truncated) = fit_entries(entries.clone());

        assert!(truncated, "24 maximum-size entries cannot fit one frame");
        assert!(!kept.is_empty(), "at least one entry must fit");
        assert!(kept.len() < total);
        assert_eq!(kept, entries[..kept.len()], "the answer must be a prefix");

        let frame = encode_response(&Response::Entries {
            entries: kept.clone(),
            truncated,
        })
        .expect("a truncated response must still encode");
        assert!(
            frame.len() <= MAX_MESSAGE_BYTES,
            "{} bytes exceeds the frame limit",
            frame.len()
        );
        assert_eq!(
            decode_response(&frame).expect("decode"),
            Response::Entries {
                entries: kept,
                truncated: true,
            }
        );

        // Everything fits when the entries are small.
        let small = vec![Entry::from_credential(&credential("GitHub", "", &[]))];
        let (kept, truncated) = fit_entries(small.clone());
        assert!(!truncated);
        assert_eq!(kept, small);
    }

    #[test]
    fn filters_narrow_by_tags_and_service_substring() {
        let credential = credential("GitHub Prod", "octocat", &["prod", "git"]);
        assert!(matches_filters(&credential, &[], None));
        assert!(matches_filters(&credential, &["prod".into()], None));
        assert!(matches_filters(
            &credential,
            &["prod".into(), "git".into()],
            None
        ));
        assert!(!matches_filters(&credential, &["dev".into()], None));
        assert!(!matches_filters(
            &credential,
            &["prod".into(), "dev".into()],
            None
        ));
        assert!(matches_filters(&credential, &[], Some("git")));
        assert!(matches_filters(&credential, &[], Some("PROD")));
        assert!(matches_filters(&credential, &[], Some("")));
        assert!(!matches_filters(&credential, &[], Some("lab")));
        // A filter never re-admits a credential the tags exclude.
        assert!(!matches_filters(&credential, &["dev".into()], Some("git")));
    }
}
