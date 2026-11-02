//! Credential model and the encoding of the decrypted vault payload.
//!
//! The payload is versioned binary data (integers little-endian):
//!
//! ```text
//! u8                     store version (3)
//! u32                    credential count
//! for each credential:
//!     byte[16]           entry id
//!     u32 + bytes        service  (UTF-8)
//!     u32 + bytes        username (UTF-8)
//!     u32 + bytes        password (UTF-8)
//!     u32                tag count
//!     for each tag:
//!         u32 + bytes    tag      (UTF-8)
//! ```
//!
//! Store version 1 had no entry ids and version 2 had no tags. Both are still
//! read for migration; missing ids are generated in memory and written out on
//! the next save (no data loss, no crypto change).
//!
//! Length-prefixing means services, usernames, and passwords may contain any
//! characters (including `:` and newlines) without escaping.

use std::collections::HashSet;
use std::fmt;

use getrandom::fill;
use zeroize::Zeroizing;

use crate::crypto::MAX_PLAINTEXT_BYTES;
use crate::error::{Error, Result};

pub const MAX_CREDENTIALS: usize = 10_000;
pub const MAX_FIELD_BYTES: usize = 4096;
pub const MAX_TAGS_PER_CREDENTIAL: usize = 32;
pub const MAX_TAG_BYTES: usize = 32;

pub const ENTRY_ID_BYTES: usize = 16;
const ENTRY_ID_HEX_CHARS: usize = ENTRY_ID_BYTES * 2;
const ENTRY_REF_PREFIX: &str = "pm://";

const STORE_VERSION: u8 = 3;
/// Version 2 is read-only for migration: it has ids but no tags.
const STORE_VERSION_WITHOUT_TAGS: u8 = 2;
/// Version 1 is read-only for migration: it has no ids and no tags.
const STORE_VERSION_WITHOUT_IDS: u8 = 1;

/// A stable random identifier for a credential (16 bytes, rendered as 32
/// lowercase hex characters). Agents use the `pm://<hex>` reference form; the
/// id is metadata, never a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId([u8; ENTRY_ID_BYTES]);

impl EntryId {
    /// Generate a fresh id from the operating system RNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; ENTRY_ID_BYTES];
        fill(&mut bytes)
            .map_err(|err| Error::Crypto(format!("failed to generate an entry id: {err}")))?;
        Ok(Self(bytes))
    }

    fn from_bytes(bytes: [u8; ENTRY_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut hex = String::with_capacity(ENTRY_ID_HEX_CHARS);
        for byte in self.0 {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    }

    /// Render the canonical agent-facing reference, `pm://<32 hex chars>`.
    pub fn to_ref(self) -> String {
        format!("{ENTRY_REF_PREFIX}{}", self.to_hex())
    }

    /// Parse a bare 32-character hex id (upper or lower case).
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex.as_bytes();
        if bytes.len() != ENTRY_ID_HEX_CHARS {
            return Err(Error::InvalidInput(format!(
                "entry id must be {ENTRY_ID_HEX_CHARS} hex characters"
            )));
        }
        let mut id = [0u8; ENTRY_ID_BYTES];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            id[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Self(id))
    }

    /// Parse the `pm://<32 hex chars>` reference form. The full id is
    /// required: prefixes are rejected so a reference is never ambiguous.
    pub fn parse_ref(reference: &str) -> Result<Self> {
        let invalid = || {
            Error::InvalidInput(format!(
                "invalid entry reference '{reference}': expected {ENTRY_REF_PREFIX}<{ENTRY_ID_HEX_CHARS} hex characters>"
            ))
        };
        let hex = reference
            .strip_prefix(ENTRY_REF_PREFIX)
            .ok_or_else(invalid)?;
        Self::from_hex(hex).map_err(|_| invalid())
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_ref())
    }
}

impl fmt::Debug for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryId({})", self.to_ref())
    }
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidInput(
            "entry id contains a non-hex character".into(),
        )),
    }
}

/// A single stored credential. Its fields are wiped when the value is dropped.
#[derive(Clone)]
pub struct Credential {
    id: EntryId,
    service: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    /// Non-secret labels. Kept sorted and duplicate-free.
    tags: Vec<String>,
}

impl Credential {
    /// Create a credential with a freshly generated id and no tags.
    pub fn new(service: String, username: String, password: Zeroizing<String>) -> Result<Self> {
        Self::with_id(
            EntryId::generate()?,
            service,
            username,
            password,
            Vec::new(),
        )
    }

    fn with_id(
        id: EntryId,
        service: String,
        username: String,
        password: Zeroizing<String>,
        tags: Vec<String>,
    ) -> Result<Self> {
        validate_identity(&service, &username)?;
        validate_password(&password)?;
        let tags = normalize_tags(tags)?;
        Ok(Self {
            id,
            service: Zeroizing::new(service),
            username: Zeroizing::new(username),
            password,
            tags,
        })
    }

    /// Attach a set of tags while constructing a credential.
    pub fn with_tags(mut self, tags: Vec<String>) -> Result<Self> {
        self.set_tags(tags)?;
        Ok(self)
    }

    /// The stable id, independent of the service name.
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// The agent-facing reference for this credential.
    pub fn reference(&self) -> String {
        self.id.to_ref()
    }

    pub fn service(&self) -> &str {
        self.service.as_str()
    }

    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Replace the service name. The caller is responsible for checking that
    /// the new name is not already taken.
    pub fn set_service(&mut self, service: String) -> Result<()> {
        validate_service(&service)?;
        self.service = Zeroizing::new(service);
        Ok(())
    }

    pub fn set_username(&mut self, username: String) -> Result<()> {
        validate_username(&username)?;
        self.username = Zeroizing::new(username);
        Ok(())
    }

    pub fn set_password(&mut self, password: Zeroizing<String>) -> Result<()> {
        validate_password(&password)?;
        self.password = password;
        Ok(())
    }

    /// The credential's tags, sorted and duplicate-free. Tags are metadata, not
    /// secrets, so they are returned as ordinary strings.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|stored| stored == tag)
    }

    /// True when the credential carries every tag in `tags`.
    pub fn has_all_tags(&self, tags: &[String]) -> bool {
        tags.iter().all(|tag| self.has_tag(tag))
    }

    /// Replace the tag set. Existing tags are left untouched on error.
    pub fn set_tags(&mut self, tags: Vec<String>) -> Result<()> {
        let tags = normalize_tags(tags)?;
        self.tags = tags;
        Ok(())
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id())
            .field("service", &self.service())
            .field("username", &self.username())
            .field("password", &"<redacted>")
            .field("tags", &self.tags())
            .finish()
    }
}

/// Validate the non-secret parts of a credential before prompting for a
/// password or touching an existing vault.
pub fn validate_identity(service: &str, username: &str) -> Result<()> {
    validate_service(service)?;
    validate_username(username)
}

pub fn validate_service(service: &str) -> Result<()> {
    validate_field("service", service, true)?;
    if service.chars().any(char::is_control) {
        return Err(Error::InvalidInput(
            "service name must not contain control characters".into(),
        ));
    }
    Ok(())
}

pub fn validate_username(username: &str) -> Result<()> {
    validate_field("username", username, false)?;
    if username.chars().any(char::is_control) {
        return Err(Error::InvalidInput(
            "username must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    validate_field("password", password, true)
}

/// Tags are used for grant scopes, so they have a deliberately small and
/// unambiguous alphabet: lowercase ASCII letters, digits, `-`, `_` and `.`,
/// starting with a letter or digit. This keeps matching case-sensitive and
/// free of whitespace or control-character tricks.
pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(Error::InvalidInput("tag cannot be empty".into()));
    }
    if tag.len() > MAX_TAG_BYTES {
        return Err(Error::InvalidInput(format!(
            "tag is too long ({} bytes; maximum is {MAX_TAG_BYTES})",
            tag.len()
        )));
    }
    let mut chars = tag.chars();
    let first = chars.next().expect("the tag is not empty");
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(Error::InvalidInput(format!(
            "invalid tag '{tag}': must start with a lowercase letter or digit"
        )));
    }
    if let Some(bad) = chars
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')))
    {
        return Err(Error::InvalidInput(format!(
            "invalid tag '{tag}': '{bad}' is not allowed (use lowercase letters, digits, '-', '_' or '.')"
        )));
    }
    Ok(())
}

/// Validate, sort and de-duplicate a tag list. Callers that accept tags from
/// the command line use this so the stored order is deterministic;
/// duplicates are merged rather than rejected.
pub fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>> {
    let mut tags = tags;
    for tag in &tags {
        validate_tag(tag)?;
    }
    tags.sort();
    tags.dedup();
    if tags.len() > MAX_TAGS_PER_CREDENTIAL {
        return Err(Error::InvalidInput(format!(
            "too many tags ({}, maximum is {MAX_TAGS_PER_CREDENTIAL})",
            tags.len()
        )));
    }
    Ok(tags)
}

fn validate_field(name: &str, value: &str, required: bool) -> Result<()> {
    if required && value.is_empty() {
        return Err(Error::InvalidInput(format!("{name} cannot be empty")));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(Error::InvalidInput(format!(
            "{name} is too long ({} bytes; maximum is {MAX_FIELD_BYTES})",
            value.len()
        )));
    }
    Ok(())
}

fn byte_len(credentials: &[Credential]) -> Result<usize> {
    let mut total: usize = 1 + 4;
    for credential in credentials {
        total = total
            .checked_add(ENTRY_ID_BYTES)
            .ok_or_else(|| Error::InvalidInput("vault contents are too large".into()))?;
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            total = total
                .checked_add(4 + field.len())
                .ok_or_else(|| Error::InvalidInput("vault contents are too large".into()))?;
        }
        total = total
            .checked_add(4)
            .ok_or_else(|| Error::InvalidInput("vault contents are too large".into()))?;
        for tag in credential.tags() {
            total = total
                .checked_add(4 + tag.len())
                .ok_or_else(|| Error::InvalidInput("vault contents are too large".into()))?;
        }
    }
    Ok(total)
}

/// Serialize credentials for encryption.
pub fn encode(credentials: &[Credential]) -> Result<Zeroizing<Vec<u8>>> {
    if credentials.len() > MAX_CREDENTIALS {
        return Err(Error::InvalidInput(format!(
            "too many credentials ({}, maximum is {MAX_CREDENTIALS})",
            credentials.len()
        )));
    }
    let total = byte_len(credentials)?;
    if total > MAX_PLAINTEXT_BYTES {
        return Err(Error::InvalidInput(format!(
            "vault contents are too large ({total} bytes; maximum is {MAX_PLAINTEXT_BYTES})"
        )));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.push(STORE_VERSION);
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for credential in credentials {
        out.extend_from_slice(&credential.id.0);
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&(credential.tags().len() as u32).to_le_bytes());
        for tag in credential.tags() {
            out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
            out.extend_from_slice(tag.as_bytes());
        }
    }
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or_else(|| Error::MalformedVault("unexpected end of credential data".into()))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("read_bytes returned four bytes"),
        ))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| Error::MalformedVault("credential length overflow".into()))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| Error::MalformedVault("unexpected end of credential data".into()))?;
        self.position = end;
        Ok(bytes)
    }

    fn read_id(&mut self) -> Result<EntryId> {
        let bytes: [u8; ENTRY_ID_BYTES] = self
            .read_bytes(ENTRY_ID_BYTES)?
            .try_into()
            .expect("read_bytes returned the requested length");
        Ok(EntryId::from_bytes(bytes))
    }

    fn read_string(&mut self, field: &str) -> Result<String> {
        let len = self.read_u32()? as usize;
        if len > MAX_FIELD_BYTES {
            return Err(Error::MalformedVault(format!(
                "{field} length {len} exceeds the maximum of {MAX_FIELD_BYTES} bytes"
            )));
        }
        let bytes = self.read_bytes(len)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::MalformedVault(format!("{field} is not valid UTF-8")))?;
        Ok(text.to_owned())
    }

    fn is_at_end(&self) -> bool {
        self.position == self.data.len()
    }
}

/// Parse decrypted vault contents.
pub fn decode(data: &[u8]) -> Result<Vec<Credential>> {
    if data.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::MalformedVault("credential data is too large".into()));
    }
    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    let (has_ids, has_tags) = match version {
        STORE_VERSION => (true, true),
        STORE_VERSION_WITHOUT_TAGS => (true, false),
        STORE_VERSION_WITHOUT_IDS => (false, false),
        other => {
            return Err(Error::MalformedVault(format!(
                "unsupported credential store version {other}"
            )));
        }
    };
    let count = cursor.read_u32()? as usize;
    if count > MAX_CREDENTIALS {
        return Err(Error::MalformedVault(format!(
            "credential count {count} exceeds the maximum of {MAX_CREDENTIALS}"
        )));
    }

    let mut credentials = Vec::with_capacity(count);
    let mut seen_ids = HashSet::with_capacity(count);
    for _ in 0..count {
        // Store version 1 has no ids: generate them now so the entry gets a
        // stable id as soon as it is written back in version 2.
        let id = if has_ids {
            cursor.read_id()?
        } else {
            EntryId::generate()?
        };
        if !seen_ids.insert(id) {
            return Err(Error::MalformedVault(format!(
                "duplicate entry id {}",
                id.to_ref()
            )));
        }
        let service = cursor.read_string("service")?;
        let username = cursor.read_string("username")?;
        let password = Zeroizing::new(cursor.read_string("password")?);
        let tags = if has_tags {
            let count = cursor.read_u32()? as usize;
            if count > MAX_TAGS_PER_CREDENTIAL {
                return Err(Error::MalformedVault(format!(
                    "tag count {count} exceeds the maximum of {MAX_TAGS_PER_CREDENTIAL}"
                )));
            }
            let mut tags: Vec<String> = Vec::with_capacity(count);
            let mut seen_tags = HashSet::with_capacity(count);
            for _ in 0..count {
                let tag = cursor.read_string("tag")?;
                validate_tag(&tag).map_err(|err| Error::MalformedVault(err.to_string()))?;
                if !seen_tags.insert(tag.clone()) {
                    return Err(Error::MalformedVault(format!(
                        "duplicate tag '{tag}' on one credential"
                    )));
                }
                tags.push(tag);
            }
            tags
        } else {
            Vec::new()
        };
        let credential = Credential::with_id(id, service, username, password, tags)
            .map_err(|err| Error::MalformedVault(err.to_string()))?;
        credentials.push(credential);
    }
    if !cursor.is_at_end() {
        return Err(Error::MalformedVault(
            "trailing bytes after credential data".into(),
        ));
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(service: &str, username: &str, password: &str) -> Credential {
        Credential::new(
            service.to_owned(),
            username.to_owned(),
            Zeroizing::new(password.to_owned()),
        )
        .unwrap()
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
        let encoded = encode(&credentials).unwrap();
        assert_eq!(encoded[0], STORE_VERSION);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), credentials.len());
        for (actual, expected) in decoded.iter().zip(&credentials) {
            assert_eq!(actual.id(), expected.id());
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

    #[test]
    fn empty_vault_roundtrips() {
        let encoded = encode(&[]).unwrap();
        assert_eq!(&*encoded, &[3, 0, 0, 0, 0]);
        assert!(decode(&encoded).unwrap().is_empty());
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

        let decoded = decode(&encode(&[credential]).unwrap()).unwrap();
        assert_eq!(decoded[0].tags(), ["prod", "work"]);
        assert_eq!(decoded[0].service(), "tagged.example");
    }

    #[test]
    fn version_2_payload_is_migrated_without_data_loss() {
        let payload = encode_v2(&[("old.example", "alice", "secret-one")]);
        let migrated = decode(&payload).unwrap();
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].service(), "old.example");
        assert_eq!(migrated[0].username(), "alice");
        assert_eq!(migrated[0].password(), "secret-one");
        assert!(migrated[0].tags().is_empty());

        // Saving writes store version 3 and preserves the id.
        let upgraded = encode(&migrated).unwrap();
        assert_eq!(upgraded[0], STORE_VERSION);
        let reopened = decode(&upgraded).unwrap();
        assert_eq!(reopened[0].id(), migrated[0].id());
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
        let encoded = encode(&[credential("svc", "u", "p")
            .with_tags(vec!["a".to_owned()])
            .unwrap()])
        .unwrap()
        .to_vec();
        // The tag count is the last four bytes before the single tag entry.
        let tag_count_offset = encoded.len() - (4 + 4 + 1);
        let mut duplicated = encoded.clone();
        duplicated[tag_count_offset..tag_count_offset + 4].copy_from_slice(&2u32.to_le_bytes());
        duplicated.extend_from_slice(&(1u32.to_le_bytes()));
        duplicated.extend_from_slice(b"a");
        assert!(matches!(
            decode(&duplicated).unwrap_err(),
            Error::MalformedVault(message) if message.contains("duplicate tag")
        ));

        let mut excessive = encoded;
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

        let first = decode(&encode(&credentials).unwrap()).unwrap();
        let second = decode(&encode(&first).unwrap()).unwrap();
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
        let migrated = decode(&payload).unwrap();
        assert_eq!(migrated.len(), 2);
        assert_eq!(migrated[0].service(), "old.example");
        assert_eq!(migrated[0].username(), "alice");
        assert_eq!(migrated[0].password(), "secret-one");
        assert!(migrated[0].tags().is_empty());
        assert_eq!(migrated[1].service(), "other.example");
        assert_eq!(migrated[1].password(), "secret-two");
        assert_ne!(migrated[0].id(), migrated[1].id());

        // Saving writes the new store version, and the migrated ids stick.
        let upgraded = encode(&migrated).unwrap();
        assert_eq!(upgraded[0], STORE_VERSION);
        let reopened = decode(&upgraded).unwrap();
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
        let encoded = encode(&[credential("one", "u", "p")]).unwrap().to_vec();
        // Repeat the single credential's body with the same id.
        let mut duplicated = encoded.clone();
        duplicated[1..5].copy_from_slice(&2u32.to_le_bytes());
        duplicated.extend_from_slice(&encoded[5..]);
        assert!(matches!(
            decode(&duplicated).unwrap_err(),
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
        let encoded = encode(&[credential("service", "user", "password")]).unwrap();
        for len in 0..encoded.len() {
            assert!(
                decode(&encoded[..len]).is_err(),
                "length {len} was accepted"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode(&[]).unwrap().to_vec();
        encoded.push(0);
        assert!(matches!(
            decode(&encoded).unwrap_err(),
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
    fn rejects_bad_store_version() {
        assert!(matches!(
            decode(&[4, 0, 0, 0, 0]).unwrap_err(),
            Error::MalformedVault(_)
        ));
    }

    #[test]
    fn rejects_oversized_field_length() {
        let mut encoded = vec![STORE_VERSION, 1, 0, 0, 0];
        encoded.extend_from_slice(&[0u8; ENTRY_ID_BYTES]);
        encoded.extend_from_slice(&((MAX_FIELD_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            decode(&encoded).unwrap_err(),
            Error::MalformedVault(_)
        ));
    }
}
