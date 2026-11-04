//! Grants: the scoped, expiring authorization an agent uses to touch
//! credentials.
//!
//! The model performs no I/O. A [`Grant`] is a plain value that the vault
//! stores (see `store.rs`) and the daemon consults; [`Grant::authorizes`] is
//! the single decision point, so every rule can be tested without a daemon, a
//! socket, a token or a clock. [`read_grant_token`] is the one exception: it
//! turns the 0600 token file an agent was given into a [`GrantToken`], with
//! the same strict checks as the session-token loader.
//!
//! The token itself is never stored: the vault keeps [`TokenHash`] (SHA-256 of
//! the raw 32 token bytes). Neither the token nor its hash is ever rendered;
//! `Debug` prints metadata only, and there is no `Display` for a grant.
//!
//! Fixed-point rules (recorded in `DECISIONS.md`):
//!
//! - An entry is inside a grant's scope when its id is listed or when it
//!   carries **every** tag the grant lists. A grant must list at least one ref
//!   or tag.
//! - A grant that lists field names covers only those fields; a request that
//!   does not name a field is out of scope for such a grant. A grant without
//!   field names covers every field.
//! - A command must equal an allowlisted path exactly. The daemon canonicalizes
//!   the path before asking, so this module never touches the filesystem.

use std::fmt;
use std::path::{Path, PathBuf};

use getrandom::fill;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::store::{EntryId, MAX_TAGS_PER_CREDENTIAL, MAX_TIMESTAMP_UNIX, normalize_tags};

use validate::{validate_commands, validate_label};

/// Bytes in a grant id (rendered as 32 lowercase hex characters).
pub const GRANT_ID_BYTES: usize = 16;
const GRANT_ID_HEX_CHARS: usize = GRANT_ID_BYTES * 2;
/// Bytes in a SHA-256 token hash.
pub const TOKEN_HASH_BYTES: usize = 32;
/// Longest human-readable grant label.
pub const MAX_LABEL_BYTES: usize = 64;
/// Most grants one vault may hold (checked when the grant list is encoded).
pub const MAX_GRANTS: usize = 1024;
/// Most explicit refs in one grant scope.
pub const MAX_SCOPE_REFS: usize = 256;
/// Most field names in one grant scope.
pub const MAX_SCOPE_FIELDS: usize = 32;
/// Most commands in one grant allowlist.
pub const MAX_COMMANDS: usize = 32;
/// Longest field name in a grant scope (`[a-z0-9_-]`, see `MCP.md`).
pub const MAX_FIELD_NAME_BYTES: usize = 32;
/// The longest grant lifetime, in seconds (30 days).
pub const MAX_GRANT_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// A stable random identifier for a grant.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantId([u8; GRANT_ID_BYTES]);

impl GrantId {
    /// Generate a fresh id from the operating system RNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; GRANT_ID_BYTES];
        fill(&mut bytes)
            .map_err(|err| Error::Crypto(format!("failed to generate a grant id: {err}")))?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; GRANT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; GRANT_ID_BYTES] {
        &self.0
    }

    /// Lowercase hex, the canonical form for `pm grant` arguments and JSON.
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut hex = String::with_capacity(GRANT_ID_HEX_CHARS);
        for byte in self.0 {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    }

    /// Parse a 32-character hex id (upper or lower case).
    pub fn from_hex(text: &str) -> Result<Self> {
        let invalid = || Error::InvalidInput("a grant id is 32 hex characters".into());
        if text.len() != GRANT_ID_HEX_CHARS {
            return Err(invalid());
        }
        let mut id = [0u8; GRANT_ID_BYTES];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            id[index] = (hex_digit(pair[0]).ok_or_else(invalid)? << 4)
                | hex_digit(pair[1]).ok_or_else(invalid)?;
        }
        Ok(Self(id))
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({})", self.to_hex())
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn lowercase_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// SHA-256 of a grant token's raw bytes.
///
/// The raw token exists only in the MCP server's memory; the vault and every
/// log hold this hash instead. It is not reversible, but it is still never
/// printed, so a debugging aid cannot leak a grant's fingerprint.
///
/// Compare with [`TokenHash::matches`], never `==`: there is deliberately no
/// `PartialEq` implementation, because an early-exit comparison would turn a
/// secret-derived digest into a timing oracle. The equality syntax below must
/// not compile; `cargo test` runs this doctest.
///
/// ```compile_fail
/// use passmgr::grant::TokenHash;
///
/// let left = TokenHash::of(b"token");
/// let right = TokenHash::of(b"token");
/// assert!(left == right);
/// ```
///
/// The only supported comparison compiles and is constant-time:
///
/// ```
/// use passmgr::grant::TokenHash;
///
/// let left = TokenHash::of(b"token");
/// assert!(left.matches(&TokenHash::of(b"token")));
/// assert!(!left.matches(&TokenHash::of(b"other")));
/// ```
#[derive(Clone, Copy)]
pub struct TokenHash([u8; TOKEN_HASH_BYTES]);

impl TokenHash {
    /// Hash the raw token bytes (32 random bytes in practice).
    pub fn of(token: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token);
        Self(hasher.finalize().into())
    }

    pub fn from_bytes(bytes: [u8; TOKEN_HASH_BYTES]) -> Self {
        Self(bytes)
    }

    /// The raw digest, for encoding the vault payload only. Never compare
    /// these bytes with `==`; use [`TokenHash::matches`].
    pub fn as_bytes(&self) -> &[u8; TOKEN_HASH_BYTES] {
        &self.0
    }

    /// Constant-time comparison, so a caller cannot learn the hash byte by
    /// byte from timing. The only comparison this type supports.
    pub fn matches(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (left, right) in self.0.iter().zip(other.0.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }

    /// Lowercase hex, the form the daemon protocol carries.
    ///
    /// The hash is not the token, but it is derived from one: never log or
    /// display it. This exists so the wire format can be parsed at the
    /// boundary, not so callers can print it.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;

        let mut hex = String::with_capacity(TOKEN_HASH_BYTES * 2);
        for byte in self.0 {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    }

    /// Parse exactly [`TokenHash::to_hex`]'s lowercase form. Uppercase is
    /// refused so one hash has exactly one encoding on the wire.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != TOKEN_HASH_BYTES * 2 {
            return None;
        }
        let mut bytes = [0u8; TOKEN_HASH_BYTES];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (lowercase_hex_digit(pair[0])? << 4) | lowercase_hex_digit(pair[1])?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(<redacted>)")
    }
}

/// The credential facts a scope is checked against: its id and its tags. The
/// secret fields are deliberately not part of this type.
#[derive(Clone, Copy)]
pub struct Target<'a> {
    pub entry: EntryId,
    pub tags: &'a [String],
}

impl<'a> Target<'a> {
    pub fn new(entry: EntryId, tags: &'a [String]) -> Self {
        Self { entry, tags }
    }
}

impl<'a> From<&'a crate::store::Credential> for Target<'a> {
    fn from(credential: &'a crate::store::Credential) -> Self {
        Self::new(credential.id(), credential.tags())
    }
}

/// What a grant may touch: explicit refs, tags, and optionally a set of field
/// names. At least one of refs and tags is required.
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    refs: Vec<EntryId>,
    tags: Vec<String>,
    /// `None` covers every field; `Some` covers exactly the listed names.
    fields: Option<Vec<String>>,
}

impl Scope {
    /// Build and validate a scope. Refs are sorted and deduplicated; tags go
    /// through the same normalization the vault uses; field names are sorted
    /// and checked against `[a-z0-9_-]{1,32}`.
    pub fn new(refs: Vec<EntryId>, tags: Vec<String>, fields: Option<Vec<String>>) -> Result<Self> {
        let mut refs = refs;
        refs.sort_by_key(|id| id.to_hex());
        refs.dedup();
        if refs.len() > MAX_SCOPE_REFS {
            return Err(Error::InvalidInput(format!(
                "a grant scope holds at most {MAX_SCOPE_REFS} refs"
            )));
        }
        let tags = normalize_tags(tags)?;
        if tags.len() > MAX_TAGS_PER_CREDENTIAL {
            return Err(Error::InvalidInput(format!(
                "a grant scope holds at most {MAX_TAGS_PER_CREDENTIAL} tags"
            )));
        }
        let fields = match fields {
            None => None,
            Some(fields) => {
                let mut fields = fields;
                for field in &fields {
                    validate_field_name(field)?;
                }
                fields.sort();
                fields.dedup();
                if fields.is_empty() {
                    return Err(Error::InvalidInput(
                        "a field-restricted grant scope needs at least one field name".into(),
                    ));
                }
                if fields.len() > MAX_SCOPE_FIELDS {
                    return Err(Error::InvalidInput(format!(
                        "a grant scope holds at most {MAX_SCOPE_FIELDS} field names"
                    )));
                }
                Some(fields)
            }
        };
        if refs.is_empty() && tags.is_empty() {
            return Err(Error::InvalidInput(
                "a grant scope needs at least one ref or tag".into(),
            ));
        }
        Ok(Self { refs, tags, fields })
    }

    pub fn refs(&self) -> &[EntryId] {
        &self.refs
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn fields(&self) -> Option<&[String]> {
        self.fields.as_deref()
    }

    /// True when the target is inside the scope: its id is listed, or it
    /// carries every tag the grant lists.
    pub fn matches(&self, target: &Target<'_>) -> bool {
        if self.refs.contains(&target.entry) {
            return true;
        }
        if self.tags.is_empty() {
            return false;
        }
        self.tags
            .iter()
            .all(|tag| target.tags.iter().any(|own| own == tag))
    }

    /// True when a field is covered. `field = None` means "the whole
    /// credential", which only an unrestricted grant covers.
    pub fn matches_field(&self, field: Option<&str>) -> bool {
        match &self.fields {
            None => true,
            Some(fields) => field.is_some_and(|name| fields.iter().any(|own| own == name)),
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scope")
            .field("refs", &self.refs)
            .field("tags", &self.tags)
            .field("fields", &self.fields)
            .finish()
    }
}

/// One thing an agent asks to do, reduced to what a grant can decide.
///
/// Every variant names the credential it touches, so [`Grant::authorizes`]
/// cannot return `Ok(())` without a scope check. There is deliberately no
/// target-less "may I list?" value: enumeration is authorized one candidate
/// at a time (build a `List` request per credential), which forces the caller
/// to filter instead of trusting a separate scope test.
///
/// `command` is the canonical absolute path (the daemon canonicalizes it
/// first). `field` names the concrete field being used, or `None` for a
/// whole-credential request.
#[derive(Clone, Copy)]
pub enum AccessRequest<'a> {
    /// Read one credential's metadata: `list_credentials` /
    /// `describe_credential`.
    List {
        target: Target<'a>,
        field: Option<&'a str>,
    },
    /// Run a command with one credential's secret injected.
    Run {
        target: Target<'a>,
        field: Option<&'a str>,
        command: &'a Path,
    },
}

impl<'a> AccessRequest<'a> {
    pub fn list(target: Target<'a>, field: Option<&'a str>) -> Self {
        Self::List { target, field }
    }

    pub fn run(target: Target<'a>, field: Option<&'a str>, command: &'a Path) -> Self {
        Self::Run {
            target,
            field,
            command,
        }
    }

    pub fn capability(&self) -> Capability {
        match self {
            Self::List { .. } => Capability::List,
            Self::Run { .. } => Capability::Run,
        }
    }

    /// The credential and field the request touches.
    pub fn target(&self) -> (&Target<'a>, Option<&'a str>) {
        match self {
            Self::List { target, field } | Self::Run { target, field, .. } => (target, *field),
        }
    }
}

/// Why an access request was refused. Messages are agent-facing: they never
/// contain a secret, a token or a hash, and callers must render "not found or
/// not granted" for an out-of-scope ref so the two cannot be told apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Denied {
    Revoked,
    Expired,
    UsedUp,
    /// The grant exists and is active but lacks the requested capability.
    NotCapable(Capability),
    /// The ref, tag or field is not covered by the grant.
    OutOfScope,
    /// The request needs a command and the grant's allowlist lacks it.
    CommandNotAllowed,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => f.write_str("grant revoked"),
            Self::Expired => f.write_str("grant expired"),
            Self::UsedUp => f.write_str("grant has no uses left"),
            Self::NotCapable(capability) => {
                write!(f, "grant does not allow {}", capability.name())
            }
            Self::OutOfScope => f.write_str("not found or not granted"),
            Self::CommandNotAllowed => f.write_str("command is not allowed by this grant"),
        }
    }
}

impl std::error::Error for Denied {}

/// Why a grant mutation did not happen.
///
/// Deliberately separate from [`Denied`]: `Denied` answers "may this request
/// use the grant?" and is rendered in agent-facing messages and the audit log.
/// A timestamp past what the vault format can hold is a caller or clock bug,
/// not an authorization outcome, so it gets its own variant and nothing was
/// recorded when it is returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateError {
    /// The grant is revoked, expired or used up; nothing was recorded.
    Denied(Denied),
    /// `now` is past [`MAX_TIMESTAMP_UNIX`] (31 Dec 9999). Storing it would
    /// make every later open of the vault fail, so nothing was recorded.
    TimestampOutOfRange,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(denied) => denied.fmt(f),
            Self::TimestampOutOfRange => write!(
                f,
                "timestamp is past the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds the vault can store"
            ),
        }
    }
}

impl std::error::Error for UpdateError {}

/// Refuse a timestamp the payload format cannot represent.
///
/// `Grant::create` checks its own `now`; this is the same bound for the two
/// mutators, so no grant this module produces can fail to survive a save.
fn check_storable(now: u64) -> std::result::Result<(), UpdateError> {
    if now > MAX_TIMESTAMP_UNIX {
        return Err(UpdateError::TimestampOutOfRange);
    }
    Ok(())
}

/// Validated input for [`Grant::create`]. Maps to the flags of
/// `pm grant create` (TODO 3.4) and to an approved access request (4.9).
#[derive(Clone)]
pub struct GrantSpec {
    pub label: String,
    pub scope: Scope,
    pub commands: Vec<PathBuf>,
    pub capabilities: Capabilities,
    /// Absolute Unix seconds; must be in `(now, now + 30 days]`.
    pub expires_at: u64,
    pub max_uses: Option<u32>,
}

/// A grant's state at one wall-clock instant.
///
/// One classifier for every caller: authorization, `grant list`/`show` and
/// `revoke --all` all go through [`Grant::status`], so a grant can never be
/// "active" for one caller and not for another. Revoked wins over expired,
/// which wins over exhausted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantStatus {
    Active,
    Expired,
    Exhausted,
    Revoked,
}

impl GrantStatus {
    /// True only for [`GrantStatus::Active`].
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// The word `grant list`/`grant show` print, and the `--json` `status`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

/// A stored authorization.
#[derive(Clone)]
pub struct Grant {
    id: GrantId,
    token_hash: TokenHash,
    label: String,
    scope: Scope,
    commands: Vec<PathBuf>,
    capabilities: Capabilities,
    created: u64,
    expires_at: u64,
    max_uses: Option<u32>,
    uses: u32,
    revoked_at: Option<u64>,
    last_used: Option<u64>,
}

/// The stored fields of one grant, decoded from the vault payload.
///
/// Only the payload decoder builds this. [`Grant::from_stored`] re-checks every
/// invariant [`Grant::create`] enforces, so a corrupt or hand-edited payload
/// cannot produce a grant this build would never have created. The token
/// itself is absent: the payload holds only its SHA-256.
pub struct StoredGrant {
    pub id: GrantId,
    pub token_hash: TokenHash,
    pub label: String,
    pub scope: Scope,
    pub commands: Vec<PathBuf>,
    pub capabilities: Capabilities,
    pub created: u64,
    pub expires_at: u64,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub revoked_at: Option<u64>,
    pub last_used: Option<u64>,
}

/// Check an absolute expiry against `now` and the 30-day cap.
///
/// Shared by [`Grant::create`] and [`GrantRequest::check_approvable`], so the
/// daemon never spends a human's approval on a request no vault write could
/// accept.
pub(crate) fn validate_expiry(expires_at: u64, now: u64) -> Result<()> {
    if expires_at <= now {
        return Err(Error::InvalidInput(
            "a grant must expire in the future".into(),
        ));
    }
    if expires_at > MAX_TIMESTAMP_UNIX {
        return Err(Error::InvalidInput(format!(
            "grant expiry {expires_at} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
        )));
    }
    if expires_at - now > MAX_GRANT_LIFETIME_SECS {
        return Err(Error::InvalidInput(format!(
            "a grant may last at most {} days",
            MAX_GRANT_LIFETIME_SECS / 86_400
        )));
    }
    Ok(())
}

impl Grant {
    /// Create a brand-new grant (no uses yet, not revoked) from validated
    /// input and the hash of its token.
    ///
    /// `now` is passed in rather than read from the clock so the rules are
    /// deterministic. Expiry is exclusive: a grant is inactive once
    /// `now >= expires_at`.
    pub fn create(spec: GrantSpec, token_hash: TokenHash, now: u64) -> Result<Self> {
        if now > MAX_TIMESTAMP_UNIX {
            return Err(Error::InvalidInput(format!(
                "created timestamp {now} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
            )));
        }
        validate_expiry(spec.expires_at, now)?;
        validate_label(&spec.label)?;
        if spec.capabilities.is_empty() {
            return Err(Error::InvalidInput(
                "a grant needs at least one capability".into(),
            ));
        }
        let commands = validate_commands(spec.commands)?;
        if spec.capabilities.contains(Capabilities::RUN) && commands.is_empty() {
            return Err(Error::InvalidInput(
                "a run grant needs at least one allowed command".into(),
            ));
        }
        if spec.max_uses == Some(0) {
            return Err(Error::InvalidInput(
                "max_uses must be at least 1; omit it for no limit".into(),
            ));
        }
        Ok(Self {
            id: GrantId::generate()?,
            token_hash,
            label: spec.label,
            scope: spec.scope,
            commands,
            capabilities: spec.capabilities,
            created: now,
            expires_at: spec.expires_at,
            max_uses: spec.max_uses,
            uses: 0,
            revoked_at: None,
            last_used: None,
        })
    }

    /// Rebuild a grant from decoded payload fields.
    ///
    /// This re-checks every rule [`Grant::create`] enforces, plus the ones
    /// only stored data can violate: a use count past `max_uses`, and
    /// timestamps beyond the maximum this build can represent. Errors are
    /// `InvalidInput`; the payload decoder maps them to `MalformedVault`.
    pub fn from_stored(stored: StoredGrant) -> Result<Self> {
        Self::check_stored(&stored)?;
        Ok(Self {
            id: stored.id,
            token_hash: stored.token_hash,
            label: stored.label,
            scope: stored.scope,
            commands: stored.commands,
            capabilities: stored.capabilities,
            created: stored.created,
            expires_at: stored.expires_at,
            max_uses: stored.max_uses,
            uses: stored.uses,
            revoked_at: stored.revoked_at,
            last_used: stored.last_used,
        })
    }

    /// Check every invariant a stored grant must satisfy, without building it.
    ///
    /// [`Grant::from_stored`] runs this on every decode, and `store::encode`
    /// runs it on [`Grant::to_stored`] output before writing a single byte, so
    /// the payload writer can never emit a grant its own reader would refuse
    /// (TODO R.17). A failure here means the caller holds a `Grant` that
    /// cannot be persisted, not that the stored bytes are corrupt.
    pub fn check_stored(stored: &StoredGrant) -> Result<()> {
        for (name, value) in [
            ("created", stored.created),
            ("expires_at", stored.expires_at),
        ] {
            if value > MAX_TIMESTAMP_UNIX {
                return Err(Error::InvalidInput(format!(
                    "{name} timestamp {value} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
                )));
            }
        }
        for (name, value) in [
            ("revoked_at", stored.revoked_at),
            ("last_used", stored.last_used),
        ] {
            if let Some(value) = value
                && value > MAX_TIMESTAMP_UNIX
            {
                return Err(Error::InvalidInput(format!(
                    "{name} timestamp {value} exceeds the maximum of {MAX_TIMESTAMP_UNIX} Unix seconds"
                )));
            }
        }
        if stored.expires_at <= stored.created {
            return Err(Error::InvalidInput(
                "a stored grant expires before or when it was created".into(),
            ));
        }
        if stored.expires_at - stored.created > MAX_GRANT_LIFETIME_SECS {
            return Err(Error::InvalidInput(format!(
                "a stored grant lasts longer than the maximum of {} days",
                MAX_GRANT_LIFETIME_SECS / 86_400
            )));
        }
        validate_label(&stored.label)?;
        if stored.capabilities.is_empty() {
            return Err(Error::InvalidInput(
                "a stored grant has no capabilities".into(),
            ));
        }
        let specified = stored.commands.len();
        let commands = validate_commands(stored.commands.clone())?;
        if commands.len() != specified {
            return Err(Error::InvalidInput(
                "a stored grant lists the same command twice".into(),
            ));
        }
        if stored.capabilities.contains(Capabilities::RUN) && commands.is_empty() {
            return Err(Error::InvalidInput(
                "a stored run grant has no allowed command".into(),
            ));
        }
        if stored.max_uses == Some(0) {
            return Err(Error::InvalidInput("a stored grant has max_uses 0".into()));
        }
        if let Some(max_uses) = stored.max_uses
            && stored.uses > max_uses
        {
            return Err(Error::InvalidInput(format!(
                "a stored grant used {} times but allows only {max_uses}",
                stored.uses
            )));
        }
        Ok(())
    }

    /// The stored form of this grant: exactly the fields the payload codec
    /// writes. `store::encode` validates it with [`Grant::check_stored`]
    /// before writing, so an unserializable grant can never reach the vault.
    pub fn to_stored(&self) -> StoredGrant {
        StoredGrant {
            id: self.id,
            token_hash: self.token_hash,
            label: self.label.clone(),
            scope: self.scope.clone(),
            commands: self.commands.clone(),
            capabilities: self.capabilities,
            created: self.created,
            expires_at: self.expires_at,
            max_uses: self.max_uses,
            uses: self.uses,
            revoked_at: self.revoked_at,
            last_used: self.last_used,
        }
    }

    pub fn id(&self) -> GrantId {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn commands(&self) -> &[PathBuf] {
        &self.commands
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub fn created_unix(&self) -> u64 {
        self.created
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at
    }

    pub fn max_uses(&self) -> Option<u32> {
        self.max_uses
    }

    pub fn uses(&self) -> u32 {
        self.uses
    }

    /// Remaining uses, or `None` when the grant is unlimited.
    pub fn uses_left(&self) -> Option<u32> {
        self.max_uses.map(|max| max.saturating_sub(self.uses))
    }

    pub fn revoked_at_unix(&self) -> Option<u64> {
        self.revoked_at
    }

    pub fn last_used_unix(&self) -> Option<u64> {
        self.last_used
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Classify the grant at `now`. The order is fixed: a revoked grant never
    /// shows as merely expired, and an expired grant never shows as merely
    /// exhausted.
    pub fn status(&self, now: u64) -> GrantStatus {
        if self.revoked_at.is_some() {
            GrantStatus::Revoked
        } else if now >= self.expires_at {
            GrantStatus::Expired
        } else if self.max_uses.is_some_and(|max| self.uses >= max) {
            GrantStatus::Exhausted
        } else {
            GrantStatus::Active
        }
    }

    /// True exactly when a request at `now` would get past the active check.
    pub fn is_active(&self, now: u64) -> bool {
        self.status(now).is_active()
    }

    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// Constant-time check that `candidate` is this grant's token.
    pub fn matches_token(&self, candidate: &TokenHash) -> bool {
        self.token_hash.matches(candidate)
    }

    /// True when `command` is exactly one of the allowlisted paths. The daemon
    /// canonicalizes first; this function never touches the filesystem.
    pub fn allows_command(&self, command: &Path) -> bool {
        self.commands.iter().any(|allowed| allowed == command)
    }

    /// True when the target and field are inside the scope. A pure helper for
    /// callers that have already passed [`Grant::authorizes`]; it is never a
    /// substitute for that check.
    pub fn scope_allows(&self, target: &Target<'_>, field: Option<&str>) -> bool {
        self.scope.matches(target) && self.scope.matches_field(field)
    }

    /// Decide one request. Checks run in a fixed order so an expired, revoked
    /// grant always reports that first, and a missing capability never leaks
    /// scope information. Scope is checked for `list` and `run` alike, so no
    /// granted request skips it; only `run` additionally needs an allowed
    /// command.
    pub fn authorizes(
        &self,
        request: &AccessRequest<'_>,
        now: u64,
    ) -> std::result::Result<(), Denied> {
        self.check_active(now)?;
        self.check_capability(request.capability())?;
        let (target, field) = request.target();
        if !self.scope_allows(target, field) {
            return Err(Denied::OutOfScope);
        }
        if let AccessRequest::Run { command, .. } = request {
            self.check_command(command)?;
        }
        Ok(())
    }

    /// The parts of a `run` decision that do not need the credential: the
    /// grant's state, the `run` capability and the command allowlist.
    ///
    /// The daemon calls this before it looks a reference up. If it looked the
    /// credential up first, a revoked, expired or exhausted grant would answer
    /// differently for an existing and a nonexistent reference, which is an
    /// existence oracle for a token that can never be used. This method only
    /// fixes that order; `authorizes` repeats the same checks after the scope
    /// check, so it does not relax anything.
    pub(crate) fn check_grant_for_run(
        &self,
        command: &Path,
        now: u64,
    ) -> std::result::Result<(), Denied> {
        self.check_active(now)?;
        self.check_capability(Capability::Run)?;
        self.check_command(command)
    }

    /// The parts of a metadata read (`list`/`describe`) that do not depend on
    /// a candidate: the grant's state and the `list` capability.
    ///
    /// Both requests are authorized per candidate with [`Grant::authorizes`],
    /// but an empty vault (or a describe of a missing reference) would
    /// otherwise turn a revoked or expired grant into a successful empty
    /// answer. The daemon calls this once before it looks at any credential,
    /// so the grant-level answer is the same whether the entry exists or not.
    pub(crate) fn check_grant_for_metadata(&self, now: u64) -> std::result::Result<(), Denied> {
        self.check_active(now)?;
        self.check_capability(Capability::List)
    }

    fn check_capability(&self, capability: Capability) -> std::result::Result<(), Denied> {
        if self.capabilities.contains(capability.flag()) {
            Ok(())
        } else {
            Err(Denied::NotCapable(capability))
        }
    }

    fn check_command(&self, command: &Path) -> std::result::Result<(), Denied> {
        if self.allows_command(command) {
            Ok(())
        } else {
            Err(Denied::CommandNotAllowed)
        }
    }

    /// Record one use. Refuses an inactive grant so a caller can never count a
    /// use it was not authorized to make, and refuses a `now` the vault format
    /// cannot store, so no recorded use can make the vault unreadable.
    pub fn mark_used(&mut self, now: u64) -> std::result::Result<(), UpdateError> {
        check_storable(now)?;
        self.check_active(now).map_err(UpdateError::Denied)?;
        self.uses = self.uses.saturating_add(1);
        self.last_used = Some(now);
        Ok(())
    }

    /// Revoke the grant. Idempotent: the first revocation time is kept. A
    /// `now` the vault format cannot store is refused and changes nothing.
    pub fn revoke(&mut self, now: u64) -> std::result::Result<(), UpdateError> {
        check_storable(now)?;
        if self.revoked_at.is_none() {
            self.revoked_at = Some(now);
        }
        Ok(())
    }

    fn check_active(&self, now: u64) -> std::result::Result<(), Denied> {
        // Callers reach here only through `mark_used`, which bounds `now`
        // first; the comparison is still safe for any `u64`.
        match self.status(now) {
            GrantStatus::Active => Ok(()),
            GrantStatus::Revoked => Err(Denied::Revoked),
            GrantStatus::Expired => Err(Denied::Expired),
            GrantStatus::Exhausted => Err(Denied::UsedUp),
        }
    }
}

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("scope", &self.scope)
            .field("commands", &self.commands)
            .field("capabilities", &self.capabilities)
            .field("created_unix", &self.created)
            .field("expires_at_unix", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("uses", &self.uses)
            .field("revoked_at_unix", &self.revoked_at)
            .field("last_used_unix", &self.last_used)
            .field("token_hash", &"<redacted>")
            .finish()
    }
}

mod capabilities;
mod file;
mod prune;
mod request;
mod token;
mod validate;

pub use crate::text::escape_hidden;
pub use capabilities::{Capabilities, Capability};
pub use file::{GrantFileError, read_grant_token};
pub use prune::{DEAD_GRANT_RETENTION_SECS, prune_dead};
pub use request::GrantRequest;
pub use token::{GRANT_TOKEN_BYTES, GrantToken};
pub use validate::{LABEL_FORBIDDEN_CLASSES, is_program_runner, validate_field_name};

#[cfg(test)]
mod tests;
