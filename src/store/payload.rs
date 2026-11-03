//! Binary codec for the decrypted vault payload.
//!
//! The on-disk format is described in the module documentation of
//! [`crate::store`]. This module owns only the encoding, the decoding and the
//! validation that keeps a writer from emitting a payload its own reader would
//! refuse (TODO R.17).

use std::collections::HashSet;

use zeroize::Zeroizing;

use super::{
    Credential, ENTRY_ID_BYTES, EntryId, FIELD_SCOPE_ALL, FIELD_SCOPE_LISTED, GRANT_FLAG_KNOWN,
    GRANT_FLAG_LAST_USED, GRANT_FLAG_MAX_USES, GRANT_FLAG_REVOKED, MAX_CREDENTIALS,
    MAX_FIELD_BYTES, MAX_TAG_BYTES, MAX_TAGS_PER_CREDENTIAL, MAX_TIMESTAMP_UNIX, STORE_VERSION,
    STORE_VERSION_WITHOUT_GRANTS, STORE_VERSION_WITHOUT_IDS, STORE_VERSION_WITHOUT_TAGS,
    STORE_VERSION_WITHOUT_TIMESTAMPS, Timestamps, validate_tag,
};
use crate::crypto::MAX_PLAINTEXT_BYTES;
use crate::error::{Error, Result};
use crate::grant::{
    Capabilities, GRANT_ID_BYTES, Grant, GrantId, MAX_COMMANDS, MAX_FIELD_NAME_BYTES, MAX_GRANTS,
    MAX_LABEL_BYTES, MAX_SCOPE_FIELDS, MAX_SCOPE_REFS, Scope, StoredGrant, TOKEN_HASH_BYTES,
    TokenHash,
};
use crate::protocol::MAX_PATH_BYTES;

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
    // The payload writer must never emit a grant its own reader would refuse
    // (TODO R.17): derive the stored form once, run the decoder's validation
    // on it, and later serialize that same value.
    let mut stored_grants = Vec::with_capacity(grants.len());
    let mut seen_grants = HashSet::with_capacity(grants.len());
    for grant in grants {
        if !seen_grants.insert(grant.id()) {
            return Err(Error::InvalidInput(format!(
                "duplicate grant id {}",
                grant.id()
            )));
        }
        let stored = grant.to_stored();
        Grant::check_stored(&stored)?;
        stored_grants.push(stored);
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
    out.extend_from_slice(&(stored_grants.len() as u32).to_le_bytes());
    for stored in &stored_grants {
        encode_grant(&mut out, stored);
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
fn encode_grant(out: &mut Vec<u8>, grant: &StoredGrant) {
    out.extend_from_slice(grant.id.as_bytes());
    out.extend_from_slice(grant.token_hash.as_bytes());
    out.push(grant.capabilities.bits());
    let mut flags = 0u8;
    if grant.revoked_at.is_some() {
        flags |= GRANT_FLAG_REVOKED;
    }
    if grant.last_used.is_some() {
        flags |= GRANT_FLAG_LAST_USED;
    }
    if grant.max_uses.is_some() {
        flags |= GRANT_FLAG_MAX_USES;
    }
    out.push(flags);
    out.extend_from_slice(&grant.created.to_le_bytes());
    out.extend_from_slice(&grant.expires_at.to_le_bytes());
    if let Some(revoked_at) = grant.revoked_at {
        out.extend_from_slice(&revoked_at.to_le_bytes());
    }
    if let Some(last_used) = grant.last_used {
        out.extend_from_slice(&last_used.to_le_bytes());
    }
    if let Some(max_uses) = grant.max_uses {
        out.extend_from_slice(&max_uses.to_le_bytes());
    }
    out.extend_from_slice(&grant.uses.to_le_bytes());
    write_string(out, &grant.label);
    let scope = &grant.scope;
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
    out.extend_from_slice(&(grant.commands.len() as u32).to_le_bytes());
    for command in &grant.commands {
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
