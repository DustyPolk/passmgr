//! Credential model and the encoding of the decrypted vault payload.
//!
//! The payload is versioned binary data (integers little-endian):
//!
//! ```text
//! u8                     store version (5)
//! u32                    credential count
//! for each credential:
//!     byte[16]           entry id
//!     u64                created      (Unix seconds, UTC; 0 = unknown)
//!     u64                last_rotated (Unix seconds, UTC; 0 = unknown)
//!     u32 + bytes        service  (UTF-8)
//!     u32 + bytes        username (UTF-8)
//!     u32 + bytes        password (UTF-8)
//!     u32                tag count
//!     for each tag:
//!         u32 + bytes    tag      (UTF-8)
//! u32                    grant count
//! for each grant:        see `encode_grant`/`decode_grant`
//! ```
//!
//! Store version 1 had no entry ids, version 2 had no tags, version 3 had no
//! timestamps and version 4 had no grants. All are still read for migration;
//! missing ids are generated in memory, missing timestamps decode as 0
//! ("unknown") and missing grants decode as an empty list, and the next save
//! writes store version 5 (no data loss, no crypto change).
//!
//! Length-prefixing means services, usernames, and passwords may contain any
//! characters (including `:` and newlines) without escaping.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill;
use zeroize::Zeroizing;

use crate::crypto::MAX_PLAINTEXT_BYTES;
use crate::error::{Error, Result};
use crate::grant::{
    Capabilities, GRANT_ID_BYTES, Grant, GrantId, MAX_COMMANDS, MAX_FIELD_NAME_BYTES, MAX_GRANTS,
    MAX_LABEL_BYTES, MAX_SCOPE_FIELDS, MAX_SCOPE_REFS, Scope, StoredGrant, TOKEN_HASH_BYTES,
    TokenHash,
};
use crate::protocol::MAX_PATH_BYTES;

pub const MAX_CREDENTIALS: usize = 10_000;
pub const MAX_FIELD_BYTES: usize = 4096;
pub const MAX_TAGS_PER_CREDENTIAL: usize = 32;
pub const MAX_TAG_BYTES: usize = 32;

pub const ENTRY_ID_BYTES: usize = 16;
const ENTRY_ID_HEX_CHARS: usize = ENTRY_ID_BYTES * 2;
const ENTRY_REF_PREFIX: &str = "pm://";

/// Timestamps are unsigned Unix seconds (UTC). Zero means "unknown": it is
/// what a pre-v4 payload decodes to. The upper bound is 9999-12-31T23:59:59Z,
/// which keeps date rendering from overflowing and rejects nonsense values.
pub const MAX_TIMESTAMP_UNIX: u64 = 253_402_300_799;

const STORE_VERSION: u8 = 5;
/// Version 4 is read-only for migration: it has credentials with ids, tags and
/// timestamps, but no grant list.
const STORE_VERSION_WITHOUT_GRANTS: u8 = 4;
/// Version 3 is read-only for migration: it has ids and tags but no
/// timestamps.
const STORE_VERSION_WITHOUT_TIMESTAMPS: u8 = 3;
/// Version 2 is read-only for migration: it has ids but no tags.
const STORE_VERSION_WITHOUT_TAGS: u8 = 2;
/// Version 1 is read-only for migration: it has no ids and no tags.
const STORE_VERSION_WITHOUT_IDS: u8 = 1;

/// Presence bits for a grant record's optional fields. Unset bits mean the
/// optional value is absent, so `None` is never encoded as a magic timestamp
/// that a real clock could produce.
const GRANT_FLAG_REVOKED: u8 = 0b0000_0001;
const GRANT_FLAG_LAST_USED: u8 = 0b0000_0010;
const GRANT_FLAG_MAX_USES: u8 = 0b0000_0100;
const GRANT_FLAG_KNOWN: u8 = GRANT_FLAG_REVOKED | GRANT_FLAG_LAST_USED | GRANT_FLAG_MAX_USES;
/// Field-scope mode byte: `0` = every field, `1` = only the listed names.
const FIELD_SCOPE_ALL: u8 = 0;
const FIELD_SCOPE_LISTED: u8 = 1;

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

    /// The raw id bytes, for encoding the vault payload only. Ids are
    /// metadata, never secrets, but they are still not rendered raw.
    pub fn as_bytes(&self) -> &[u8; ENTRY_ID_BYTES] {
        &self.0
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

/// Creation and last-rotation times, in Unix seconds. Both are metadata, not
/// secrets, so they live in plain `u64` fields. Zero means unknown (a payload
/// migrated from store version 3 or older).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Timestamps {
    created: u64,
    last_rotated: u64,
}

impl Timestamps {
    /// The current time for a newly created credential. Creating a credential
    /// counts as its first rotation.
    fn now() -> Result<Self> {
        let now = now_unix_seconds()?;
        Ok(Self {
            created: now,
            last_rotated: now,
        })
    }

    /// Migration sentinel for payloads that predate timestamps.
    fn unknown() -> Self {
        Self {
            created: 0,
            last_rotated: 0,
        }
    }
}

/// Read the system clock as Unix seconds, refusing values that cannot be a
/// real timestamp. A clock failure is an environment failure (exit 1), not a
/// usage error.
fn now_unix_seconds() -> Result<u64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Io(io::Error::other("system clock is before the Unix epoch")))?
        .as_secs();
    if seconds > MAX_TIMESTAMP_UNIX {
        return Err(Error::Io(io::Error::other(
            "system clock is beyond the supported timestamp range",
        )));
    }
    Ok(seconds)
}

/// A single stored credential. Its secret fields are wiped when the value is
/// dropped; ids, tags and timestamps are metadata.
#[derive(Clone)]
pub struct Credential {
    id: EntryId,
    timestamps: Timestamps,
    service: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    /// Non-secret labels. Kept sorted and duplicate-free.
    tags: Vec<String>,
}

impl Credential {
    /// Create a credential with a freshly generated id, no tags, and the
    /// current time as both `created` and `last_rotated`.
    pub fn new(service: String, username: String, password: Zeroizing<String>) -> Result<Self> {
        Self::with_id(
            EntryId::generate()?,
            Timestamps::now()?,
            service,
            username,
            password,
            Vec::new(),
        )
    }

    fn with_id(
        id: EntryId,
        timestamps: Timestamps,
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
            timestamps,
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

    /// When the credential was created, in Unix seconds (0 = unknown).
    pub fn created_unix(&self) -> u64 {
        self.timestamps.created
    }

    /// When the password last changed, in Unix seconds (0 = unknown).
    pub fn last_rotated_unix(&self) -> u64 {
        self.timestamps.last_rotated
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

    /// Replace the password and record the rotation time. Rotation is the only
    /// way `last_rotated` moves; `created` never changes.
    pub fn set_password(&mut self, password: Zeroizing<String>) -> Result<()> {
        let now = now_unix_seconds()?;
        validate_password(&password)?;
        self.password = password;
        self.timestamps.last_rotated = now;
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
            .field("created_unix", &self.created_unix())
            .field("last_rotated_unix", &self.last_rotated_unix())
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

fn contents_too_large() -> Error {
    Error::InvalidInput("vault contents are too large".into())
}

fn byte_len(credentials: &[Credential], grants: &[Grant]) -> Result<usize> {
    let mut total: usize = 1 + 4 + 4;
    for credential in credentials {
        total = total
            .checked_add(ENTRY_ID_BYTES + 8 + 8)
            .ok_or_else(contents_too_large)?;
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            total = total
                .checked_add(4 + field.len())
                .ok_or_else(contents_too_large)?;
        }
        total = total.checked_add(4).ok_or_else(contents_too_large)?;
        for tag in credential.tags() {
            total = total
                .checked_add(4 + tag.len())
                .ok_or_else(contents_too_large)?;
        }
    }
    for grant in grants {
        total = total
            .checked_add(grant_byte_len(grant))
            .ok_or_else(contents_too_large)?;
    }
    Ok(total)
}

/// Encoded size of one grant record. Every part is already bounded
/// (`MAX_*` counts and byte lengths), so this cannot overflow on a supported
/// target; the caller still checks the total against the payload cap.
fn grant_byte_len(grant: &Grant) -> usize {
    let scope = grant.scope();
    let mut total = GRANT_ID_BYTES
        + TOKEN_HASH_BYTES
        + 1 // capabilities
        + 1 // optional-field flags
        + 8 // created
        + 8 // expires_at
        + 4 // uses
        + 4
        + grant.label().len()
        + 4
        + ENTRY_ID_BYTES * scope.refs().len()
        + 4;
    for tag in scope.tags() {
        total += 4 + tag.len();
    }
    total += 1;
    if let Some(fields) = scope.fields() {
        total += 4;
        for field in fields {
            total += 4 + field.len();
        }
    }
    total += 4;
    for command in grant.commands() {
        total += 4 + command.as_os_str().len();
    }
    if grant.revoked_at_unix().is_some() {
        total += 8;
    }
    if grant.last_used_unix().is_some() {
        total += 8;
    }
    if grant.max_uses().is_some() {
        total += 4;
    }
    total
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// Serialize credentials and grants for encryption.
pub fn encode(credentials: &[Credential], grants: &[Grant]) -> Result<Zeroizing<Vec<u8>>> {
    if credentials.len() > MAX_CREDENTIALS {
        return Err(Error::InvalidInput(format!(
            "too many credentials ({}, maximum is {MAX_CREDENTIALS})",
            credentials.len()
        )));
    }
    if grants.len() > MAX_GRANTS {
        return Err(Error::InvalidInput(format!(
            "too many grants ({}, maximum is {MAX_GRANTS})",
            grants.len()
        )));
    }
    let total = byte_len(credentials, grants)?;
    if total > MAX_PLAINTEXT_BYTES {
        return Err(Error::InvalidInput(format!(
            "vault contents are too large ({total} bytes; maximum is {MAX_PLAINTEXT_BYTES})"
        )));
    }

    for credential in credentials {
        validate_timestamps(credential.timestamps)?;
    }
    let mut seen_grants = HashSet::with_capacity(grants.len());
    for grant in grants {
        if !seen_grants.insert(grant.id()) {
            return Err(Error::InvalidInput(format!(
                "duplicate grant id {}",
                grant.id()
            )));
        }
    }

    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.push(STORE_VERSION);
    out.extend_from_slice(&(credentials.len() as u32).to_le_bytes());
    for credential in credentials {
        out.extend_from_slice(&credential.id.0);
        out.extend_from_slice(&credential.created_unix().to_le_bytes());
        out.extend_from_slice(&credential.last_rotated_unix().to_le_bytes());
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            write_string(&mut out, field);
        }
        out.extend_from_slice(&(credential.tags().len() as u32).to_le_bytes());
        for tag in credential.tags() {
            write_string(&mut out, tag);
        }
    }
    out.extend_from_slice(&(grants.len() as u32).to_le_bytes());
    for grant in grants {
        encode_grant(&mut out, grant);
    }
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Append one grant record.
///
/// ```text
/// byte[16]   grant id
/// byte[32]   token hash (SHA-256; the token itself is never stored)
/// u8         capability bits (list = 1, run = 2)
/// u8         presence flags (bit0 revoked_at, bit1 last_used, bit2 max_uses)
/// u64        created
/// u64        expires_at
/// [u64]      revoked_at   when bit0 is set
/// [u64]      last_used    when bit1 is set
/// [u32]      max_uses     when bit2 is set
/// u32        uses
/// u32 + bytes  label (UTF-8)
/// u32        ref count; each byte[16] entry id
/// u32        tag count; each u32 + bytes
/// u8         field mode (0 = all fields, 1 = listed)
///            when 1: u32 field count; each u32 + bytes
/// u32        command count; each u32 + bytes absolute path (UTF-8)
/// ```
fn encode_grant(out: &mut Vec<u8>, grant: &Grant) {
    out.extend_from_slice(grant.id().as_bytes());
    out.extend_from_slice(grant.token_hash().as_bytes());
    out.push(grant.capabilities().bits());
    let mut flags = 0u8;
    if grant.revoked_at_unix().is_some() {
        flags |= GRANT_FLAG_REVOKED;
    }
    if grant.last_used_unix().is_some() {
        flags |= GRANT_FLAG_LAST_USED;
    }
    if grant.max_uses().is_some() {
        flags |= GRANT_FLAG_MAX_USES;
    }
    out.push(flags);
    out.extend_from_slice(&grant.created_unix().to_le_bytes());
    out.extend_from_slice(&grant.expires_at_unix().to_le_bytes());
    if let Some(revoked_at) = grant.revoked_at_unix() {
        out.extend_from_slice(&revoked_at.to_le_bytes());
    }
    if let Some(last_used) = grant.last_used_unix() {
        out.extend_from_slice(&last_used.to_le_bytes());
    }
    if let Some(max_uses) = grant.max_uses() {
        out.extend_from_slice(&max_uses.to_le_bytes());
    }
    out.extend_from_slice(&grant.uses().to_le_bytes());
    write_string(out, grant.label());
    let scope = grant.scope();
    out.extend_from_slice(&(scope.refs().len() as u32).to_le_bytes());
    for entry in scope.refs() {
        out.extend_from_slice(entry.as_bytes());
    }
    out.extend_from_slice(&(scope.tags().len() as u32).to_le_bytes());
    for tag in scope.tags() {
        write_string(out, tag);
    }
    match scope.fields() {
        None => out.push(FIELD_SCOPE_ALL),
        Some(fields) => {
            out.push(FIELD_SCOPE_LISTED);
            out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
            for field in fields {
                write_string(out, field);
            }
        }
    }
    out.extend_from_slice(&(grant.commands().len() as u32).to_le_bytes());
    for command in grant.commands() {
        let text = command
            .to_str()
            .expect("grant commands were validated as UTF-8");
        write_string(out, text);
    }
}

fn validate_timestamps(timestamps: Timestamps) -> Result<()> {
    for (name, value) in [
        ("created", timestamps.created),
        ("last_rotated", timestamps.last_rotated),
    ] {
        if value > MAX_TIMESTAMP_UNIX {
            return Err(Error::InvalidInput(format!(
                "{name} timestamp {value} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
            )));
        }
    }
    Ok(())
}

fn validate_decoded_timestamps(timestamps: Timestamps) -> Result<()> {
    for (name, value) in [
        ("created", timestamps.created),
        ("last_rotated", timestamps.last_rotated),
    ] {
        if value > MAX_TIMESTAMP_UNIX {
            return Err(Error::MalformedVault(format!(
                "{name} timestamp {value} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
            )));
        }
    }
    Ok(())
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

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("read_bytes returned eight bytes"),
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
        self.read_string_capped(field, MAX_FIELD_BYTES)
    }

    /// Read a length-prefixed UTF-8 string that must fit in `max` bytes.
    fn read_string_capped(&mut self, field: &str, max: usize) -> Result<String> {
        let len = self.read_u32()? as usize;
        if len > max {
            return Err(Error::MalformedVault(format!(
                "{field} length {len} exceeds the maximum of {max} bytes"
            )));
        }
        let bytes = self.read_bytes(len)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::MalformedVault(format!("{field} is not valid UTF-8")))?;
        Ok(text.to_owned())
    }

    fn read_grant_id(&mut self) -> Result<GrantId> {
        let bytes: [u8; GRANT_ID_BYTES] = self
            .read_bytes(GRANT_ID_BYTES)?
            .try_into()
            .expect("read_bytes returned the requested length");
        Ok(GrantId::from_bytes(bytes))
    }

    fn read_token_hash(&mut self) -> Result<TokenHash> {
        let bytes: [u8; TOKEN_HASH_BYTES] = self
            .read_bytes(TOKEN_HASH_BYTES)?
            .try_into()
            .expect("read_bytes returned the requested length");
        Ok(TokenHash::from_bytes(bytes))
    }

    fn is_at_end(&self) -> bool {
        self.position == self.data.len()
    }
}

/// The decrypted vault payload: credentials and grants.
///
/// `Debug` is derived only so tests can call `unwrap_err`; both fields already
/// redact their secrets in their own `Debug` implementations.
#[derive(Debug)]
pub struct Payload {
    pub credentials: Vec<Credential>,
    pub grants: Vec<Grant>,
}

/// Parse decrypted vault contents.
pub fn decode(data: &[u8]) -> Result<Payload> {
    if data.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::MalformedVault("credential data is too large".into()));
    }
    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    let (has_ids, has_tags, has_timestamps, has_grants) = match version {
        STORE_VERSION => (true, true, true, true),
        STORE_VERSION_WITHOUT_GRANTS => (true, true, true, false),
        STORE_VERSION_WITHOUT_TIMESTAMPS => (true, true, false, false),
        STORE_VERSION_WITHOUT_TAGS => (true, false, false, false),
        STORE_VERSION_WITHOUT_IDS => (false, false, false, false),
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
        // Pre-v4 payloads have no timestamps: carry 0 ("unknown") until the
        // entry is rewritten, so the absence is visible rather than invented.
        let timestamps = if has_timestamps {
            let timestamps = Timestamps {
                created: cursor.read_u64()?,
                last_rotated: cursor.read_u64()?,
            };
            validate_decoded_timestamps(timestamps)?;
            timestamps
        } else {
            Timestamps::unknown()
        };
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
        let credential = Credential::with_id(id, timestamps, service, username, password, tags)
            .map_err(|err| Error::MalformedVault(err.to_string()))?;
        credentials.push(credential);
    }
    let grants = if has_grants {
        decode_grants(&mut cursor)?
    } else {
        Vec::new()
    };
    if !cursor.is_at_end() {
        return Err(Error::MalformedVault(
            "trailing bytes after credential data".into(),
        ));
    }
    Ok(Payload {
        credentials,
        grants,
    })
}

fn decode_grants(cursor: &mut Cursor<'_>) -> Result<Vec<Grant>> {
    let count = cursor.read_u32()? as usize;
    if count > MAX_GRANTS {
        return Err(Error::MalformedVault(format!(
            "grant count {count} exceeds the maximum of {MAX_GRANTS}"
        )));
    }
    let mut grants = Vec::with_capacity(count);
    let mut seen_ids = HashSet::with_capacity(count);
    for _ in 0..count {
        let grant = decode_grant(cursor)?;
        if !seen_ids.insert(grant.id()) {
            return Err(Error::MalformedVault(format!(
                "duplicate grant id {}",
                grant.id()
            )));
        }
        grants.push(grant);
    }
    Ok(grants)
}

fn decode_grant(cursor: &mut Cursor<'_>) -> Result<Grant> {
    let id = cursor.read_grant_id()?;
    let token_hash = cursor.read_token_hash()?;
    let capabilities = Capabilities::from_bits(cursor.read_u8()?)
        .map_err(|err| Error::MalformedVault(err.to_string()))?;
    let flags = cursor.read_u8()?;
    let unknown = flags & !GRANT_FLAG_KNOWN;
    if unknown != 0 {
        return Err(Error::MalformedVault(format!(
            "unknown grant flag bits {unknown:#04b}"
        )));
    }
    let created = cursor.read_u64()?;
    let expires_at = cursor.read_u64()?;
    let revoked_at = if flags & GRANT_FLAG_REVOKED != 0 {
        Some(cursor.read_u64()?)
    } else {
        None
    };
    let last_used = if flags & GRANT_FLAG_LAST_USED != 0 {
        Some(cursor.read_u64()?)
    } else {
        None
    };
    let max_uses = if flags & GRANT_FLAG_MAX_USES != 0 {
        Some(cursor.read_u32()?)
    } else {
        None
    };
    let uses = cursor.read_u32()?;
    let label = cursor.read_string_capped("grant label", MAX_LABEL_BYTES)?;

    let refs = read_grant_refs(cursor)?;
    let tags = read_grant_tags(cursor)?;
    let fields = match cursor.read_u8()? {
        FIELD_SCOPE_ALL => None,
        FIELD_SCOPE_LISTED => Some(read_grant_fields(cursor)?),
        other => {
            return Err(Error::MalformedVault(format!(
                "unknown grant field scope mode {other}"
            )));
        }
    };
    let scope =
        Scope::new(refs, tags, fields).map_err(|err| Error::MalformedVault(err.to_string()))?;
    let commands = read_grant_commands(cursor)?;

    Grant::from_stored(StoredGrant {
        id,
        token_hash,
        label,
        scope,
        commands,
        capabilities,
        created,
        expires_at,
        max_uses,
        uses,
        revoked_at,
        last_used,
    })
    .map_err(|err| Error::MalformedVault(err.to_string()))
}

fn read_grant_refs(cursor: &mut Cursor<'_>) -> Result<Vec<EntryId>> {
    let count = cursor.read_u32()? as usize;
    if count > MAX_SCOPE_REFS {
        return Err(Error::MalformedVault(format!(
            "grant ref count {count} exceeds the maximum of {MAX_SCOPE_REFS}"
        )));
    }
    let mut refs = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let id = cursor.read_id()?;
        if !seen.insert(id) {
            return Err(Error::MalformedVault(format!(
                "duplicate ref {} in one grant",
                id.to_ref()
            )));
        }
        refs.push(id);
    }
    Ok(refs)
}

fn read_grant_tags(cursor: &mut Cursor<'_>) -> Result<Vec<String>> {
    let count = cursor.read_u32()? as usize;
    if count > MAX_TAGS_PER_CREDENTIAL {
        return Err(Error::MalformedVault(format!(
            "grant tag count {count} exceeds the maximum of {MAX_TAGS_PER_CREDENTIAL}"
        )));
    }
    let mut tags = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let tag = cursor.read_string_capped("tag", MAX_TAG_BYTES)?;
        if !seen.insert(tag.clone()) {
            return Err(Error::MalformedVault(format!(
                "duplicate tag '{tag}' in one grant"
            )));
        }
        tags.push(tag);
    }
    Ok(tags)
}

fn read_grant_fields(cursor: &mut Cursor<'_>) -> Result<Vec<String>> {
    let count = cursor.read_u32()? as usize;
    if count > MAX_SCOPE_FIELDS {
        return Err(Error::MalformedVault(format!(
            "grant field count {count} exceeds the maximum of {MAX_SCOPE_FIELDS}"
        )));
    }
    if count == 0 {
        return Err(Error::MalformedVault(
            "grant lists an empty field scope".into(),
        ));
    }
    let mut fields = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let name = cursor.read_string_capped("field name", MAX_FIELD_NAME_BYTES)?;
        if !seen.insert(name.clone()) {
            return Err(Error::MalformedVault(format!(
                "duplicate field '{name}' in one grant"
            )));
        }
        fields.push(name);
    }
    Ok(fields)
}

fn read_grant_commands(cursor: &mut Cursor<'_>) -> Result<Vec<std::path::PathBuf>> {
    let count = cursor.read_u32()? as usize;
    if count > MAX_COMMANDS {
        return Err(Error::MalformedVault(format!(
            "grant command count {count} exceeds the maximum of {MAX_COMMANDS}"
        )));
    }
    let mut commands = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let text = cursor.read_string_capped("command", MAX_PATH_BYTES)?;
        if !seen.insert(text.clone()) {
            return Err(Error::MalformedVault(format!(
                "duplicate command '{text}' in one grant"
            )));
        }
        commands.push(std::path::PathBuf::from(text));
    }
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::grant::GrantSpec;

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
        run.revoke(1_700_000_200);
        let list = test_grant("read only", Capabilities::LIST);

        let encoded = encode(&[credential("svc", "u", "p")], &[run.clone(), list.clone()]).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.credentials[0].password(), "p");
        assert_eq!(decoded.grants.len(), 2);
        assert_grants_equal(&decoded.grants[0], &run);
        assert_grants_equal(&decoded.grants[1], &list);
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
}
