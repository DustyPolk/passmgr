//! Raw grant tokens: the one secret a grant creator hands to the agent.
//!
//! Split out of `src/grant.rs` by TODO 3.4d to keep that file under the
//! ~1,000-line limit.

use std::fmt;

use getrandom::fill;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::TokenHash;

/// Bytes in a raw grant token.
pub const GRANT_TOKEN_BYTES: usize = 32;
/// Length of the token's lowercase hex encoding.
pub const GRANT_TOKEN_HEX_CHARS: usize = GRANT_TOKEN_BYTES * 2;

/// A raw grant token: 32 random bytes shown once to the human who creates the
/// grant, and never stored in the vault (which keeps only its [`TokenHash`]).
///
/// The bytes are zeroized on drop and `Debug` prints nothing derived from
/// them. There is deliberately no `Display` and no `PartialEq`; compare a
/// presented token by hashing it, or use [`TokenHash::matches`] on the hashes.
#[derive(Clone)]
pub struct GrantToken {
    bytes: Zeroizing<[u8; GRANT_TOKEN_BYTES]>,
}

impl GrantToken {
    /// Draw a fresh token from the operating system's CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; GRANT_TOKEN_BYTES]);
        fill(bytes.as_mut_slice())
            .map_err(|error| Error::Crypto(format!("failed to generate a grant token: {error}")))?;
        Ok(Self { bytes })
    }

    /// The raw bytes, for hashing and for the one-time token file.
    pub fn as_bytes(&self) -> &[u8; GRANT_TOKEN_BYTES] {
        &self.bytes
    }

    /// Parse the lowercase hex form used on the wire and in a token file.
    ///
    /// Uppercase hex is rejected so a token has exactly one textual encoding.
    /// The error never echoes `text`.
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != GRANT_TOKEN_HEX_CHARS {
            return Err(invalid_hex());
        }
        let mut bytes = Zeroizing::new([0u8; GRANT_TOKEN_BYTES]);
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_digit(pair[0]).ok_or_else(invalid_hex)?;
            let low = hex_digit(pair[1]).ok_or_else(invalid_hex)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self { bytes })
    }

    /// The SHA-256 hash the vault and protocol carry instead of the token.
    pub fn hash(&self) -> TokenHash {
        TokenHash::of(self.as_bytes())
    }

    /// Lowercase hex, the form written to `--out` for an agent to present.
    pub fn to_hex(&self) -> Zeroizing<String> {
        use std::fmt::Write as _;

        let mut hex = Zeroizing::new(String::with_capacity(GRANT_TOKEN_BYTES * 2));
        for byte in self.bytes.iter() {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn invalid_hex() -> Error {
    Error::InvalidInput(format!(
        "a grant token is exactly {GRANT_TOKEN_HEX_CHARS} lowercase hex characters"
    ))
}

impl fmt::Debug for GrantToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GrantToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_is_strict() {
        let token = GrantToken::generate().expect("token");
        let hex = token.to_hex();
        let parsed = GrantToken::from_hex(&hex).expect("parse generated hex");
        assert!(parsed.hash().matches(&token.hash()));

        let uppercase = hex.to_uppercase();
        let short = &hex[..GRANT_TOKEN_HEX_CHARS - 1];
        let non_hex = "g".repeat(GRANT_TOKEN_HEX_CHARS);
        for bad in [uppercase, short.to_owned(), non_hex] {
            let error = GrantToken::from_hex(&bad).expect_err("must be rejected");
            let text = error.to_string();
            assert!(!text.contains(&bad), "error echoed the token: {text}");
            assert!(!text.contains(&*hex), "error echoed the token: {text}");
        }
    }

    #[test]
    fn a_grant_token_never_renders_its_bytes() {
        let token = GrantToken::generate().unwrap();
        let hex = token.to_hex();
        let debug = format!("{token:?}");
        assert_eq!(debug, "GrantToken(<redacted>)");
        assert!(!debug.contains(&*hex));
        assert!(token.hash().matches(&TokenHash::of(token.as_bytes())));
    }
}
