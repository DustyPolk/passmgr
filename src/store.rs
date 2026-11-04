//! Credential model and payload format for the decrypted vault.
//!
//! The binary codec lives in [`payload`]; this module owns the model, its
//! validation and the format version constants.
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

use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::text::{HIDDEN_FORBIDDEN_CLASSES, escape_quoted, is_hidden_or_reordering};

mod payload;
pub use payload::{Payload, decode, encode};

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
                "invalid entry reference '{}': expected {ENTRY_REF_PREFIX}<{ENTRY_ID_HEX_CHARS} hex characters>",
                escape_quoted(reference)
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
        Self::build(
            EntryId::generate()?,
            Timestamps::now()?,
            service,
            username,
            password,
            Vec::new(),
            validate_identity,
        )
    }

    /// Build a credential from the decrypted payload.
    ///
    /// The payload is authenticated, so a service name or username in it was
    /// written by a passmgr build, not by an attacker. Builds before TODO
    /// R.48 accepted hidden and reordering characters there, so refusing the
    /// whole class on read would make an existing vault unopenable and cost
    /// the human every credential in it. The reader therefore keeps the old
    /// rule (no C0/C1 controls) and the CLI escapes hidden characters
    /// whenever it prints a stored name. Every *new* value goes through
    /// [`Credential::new`] and its stricter rule.
    fn from_decoded(
        id: EntryId,
        timestamps: Timestamps,
        service: String,
        username: String,
        password: Zeroizing<String>,
        tags: Vec<String>,
    ) -> Result<Self> {
        Self::build(
            id,
            timestamps,
            service,
            username,
            password,
            tags,
            validate_decoded_identity,
        )
    }

    fn build(
        id: EntryId,
        timestamps: Timestamps,
        service: String,
        username: String,
        password: Zeroizing<String>,
        tags: Vec<String>,
        identity: fn(&str, &str) -> Result<()>,
    ) -> Result<Self> {
        identity(&service, &username)?;
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

/// The rule a *new* service name or username must satisfy (TODO R.48).
///
/// A name is stored and later printed by `list`, `get` and `show`, and a grant
/// scope can select it by tag, so it is held to the same character table as a
/// grant label: a bidi override can reverse the rest of the terminal line
/// (including the `pm://` reference a human is about to copy into a grant) and
/// a zero-width or variation-selector character renders a name that is not the
/// one stored. The whole class is refused and the value is not echoed: the
/// error names the class only, so it cannot carry the problem into the
/// terminal. Ordinary visible text -- accents, other scripts, emoji without a
/// selector -- stays allowed.
pub fn validate_service(service: &str) -> Result<()> {
    validate_field("service", service, true)?;
    reject_hidden_identity("service name", service)
}

pub fn validate_username(username: &str) -> Result<()> {
    validate_field("username", username, false)?;
    reject_hidden_identity("username", username)
}

fn reject_hidden_identity(what: &str, value: &str) -> Result<()> {
    if value.chars().any(is_hidden_or_reordering) {
        return Err(Error::InvalidInput(format!(
            "{what} must not contain {HIDDEN_FORBIDDEN_CLASSES} characters"
        )));
    }
    Ok(())
}

/// The identity rule the payload reader applies to a stored credential.
///
/// Deliberately looser than [`validate_service`]/[`validate_username`]: an
/// existing vault may hold a name an earlier build accepted, and refusing it
/// here would refuse the whole vault. Only C0/C1 controls are rejected, which
/// is exactly what every released build refused (see [`Credential::from_decoded`]).
fn validate_decoded_identity(service: &str, username: &str) -> Result<()> {
    validate_field("service", service, true)?;
    validate_field("username", username, false)?;
    for (what, value) in [("service name", service), ("username", username)] {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(format!(
                "{what} must not contain control characters"
            )));
        }
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
            "invalid tag '{}': must start with a lowercase letter or digit",
            escape_quoted(tag)
        )));
    }
    if let Some(bad) = chars
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')))
    {
        return Err(Error::InvalidInput(format!(
            "invalid tag '{}': '{}' is not allowed (use lowercase letters, digits, '-', '_' or '.')",
            escape_quoted(tag),
            escape_quoted(&bad.to_string())
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

#[cfg(test)]
mod tests;
