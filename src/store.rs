//! Credential model and the encoding of the decrypted vault payload.
//!
//! The payload is versioned binary data (integers little-endian):
//!
//! ```text
//! u8                     store version (1)
//! u32                    credential count
//! for each credential:
//!     u32 + bytes        service  (UTF-8)
//!     u32 + bytes        username (UTF-8)
//!     u32 + bytes        password (UTF-8)
//! ```
//!
//! Length-prefixing means services, usernames, and passwords may contain any
//! characters (including `:` and newlines) without escaping.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::MAX_PLAINTEXT_BYTES;
use crate::error::{Error, Result};

pub const MAX_CREDENTIALS: usize = 10_000;
pub const MAX_FIELD_BYTES: usize = 4096;

const STORE_VERSION: u8 = 1;

/// A single stored credential. Its fields are wiped when the value is dropped.
#[derive(Clone)]
pub struct Credential {
    service: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl Credential {
    pub fn new(service: String, username: String, password: Zeroizing<String>) -> Result<Self> {
        validate_identity(&service, &username)?;
        validate_password(&password)?;
        Ok(Self {
            service: Zeroizing::new(service),
            username: Zeroizing::new(username),
            password,
        })
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
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("service", &self.service())
            .field("username", &self.username())
            .field("password", &"<redacted>")
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
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            total = total
                .checked_add(4 + field.len())
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
        for field in [
            credential.service(),
            credential.username(),
            credential.password(),
        ] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
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
    if version != STORE_VERSION {
        return Err(Error::MalformedVault(format!(
            "unsupported credential store version {version}"
        )));
    }
    let count = cursor.read_u32()? as usize;
    if count > MAX_CREDENTIALS {
        return Err(Error::MalformedVault(format!(
            "credential count {count} exceeds the maximum of {MAX_CREDENTIALS}"
        )));
    }

    let mut credentials = Vec::with_capacity(count);
    for _ in 0..count {
        let service = cursor.read_string("service")?;
        let username = cursor.read_string("username")?;
        let password = Zeroizing::new(cursor.read_string("password")?);
        let credential = Credential::new(service, username, password)
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

    #[test]
    fn roundtrip_handles_arbitrary_text() {
        let credentials = vec![
            credential("example.com", "user", "p:a:ss\nword"),
            credential("emoji.example", "üser", "🔐 secret"),
            credential("no-username.example", "", "x"),
        ];
        let encoded = encode(&credentials).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.len(), credentials.len());
        for (actual, expected) in decoded.iter().zip(&credentials) {
            assert_eq!(actual.service(), expected.service());
            assert_eq!(actual.username(), expected.username());
            assert_eq!(actual.password(), expected.password());
        }
    }

    #[test]
    fn empty_vault_roundtrips() {
        let encoded = encode(&[]).unwrap();
        assert_eq!(&*encoded, &[1, 0, 0, 0, 0]);
        assert!(decode(&encoded).unwrap().is_empty());
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
            decode(&[2, 0, 0, 0, 0]).unwrap_err(),
            Error::MalformedVault(_)
        ));
    }

    #[test]
    fn rejects_oversized_field_length() {
        let mut encoded = vec![1, 1, 0, 0, 0];
        encoded.extend_from_slice(&((MAX_FIELD_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            decode(&encoded).unwrap_err(),
            Error::MalformedVault(_)
        ));
    }
}
