//! The unlock-session token: generation, strict parsing, redacted rendering.
//!
//! A token is 32 random bytes, rendered as 64 lowercase hex characters both in
//! the session file and in the protocol envelope. It is a bearer credential
//! for the local daemon, not a secret read from the vault: no daemon request
//! can return plaintext, so a leaked token cannot reveal one.
//!
//! It is **not** an agent/human boundary. Every process running as the same
//! user can read a 0600 file, so the token proves only "you could read the
//! owner's runtime directory" — the same processes the socket's peer-uid check
//! already admits. Grants (TODO 3.1) add the scoped, revocable authorization
//! that separates an agent from its owner; the limit is recorded in
//! `PROGRESS.md` and `SECURITY.md`.
//!
//! The bytes live in [`Zeroizing`] storage, `Debug` is redacted, there is no
//! `Display`, and no error message contains token bytes.

use std::fmt;

use zeroize::Zeroizing;

/// Number of random bytes in a session token.
pub const TOKEN_BYTES: usize = 32;
/// Length of the token's lowercase hex encoding.
pub const TOKEN_HEX_CHARS: usize = TOKEN_BYTES * 2;

/// A bearer token authorizing a client to use the unlock daemon.
///
/// Compare with [`SessionToken::matches`], never with `==`: there is
/// deliberately no `PartialEq` implementation that could be used by accident.
#[derive(Clone)]
pub struct SessionToken {
    bytes: Zeroizing<[u8; TOKEN_BYTES]>,
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render token bytes, not even a length-dependent hint.
        f.write_str("SessionToken(<redacted>)")
    }
}

impl SessionToken {
    /// Draw a fresh token from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|err| TokenError::Random(err.to_string()))?;
        Ok(Self { bytes })
    }

    /// Copy token bytes received over the handover pipe.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        let bytes: [u8; TOKEN_BYTES] = bytes.try_into().map_err(|_| {
            TokenError::Invalid(format!("a session token is exactly {TOKEN_BYTES} bytes"))
        })?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Parse the lowercase hex form used on the wire and in the session file.
    ///
    /// Uppercase hex is rejected so a token has exactly one textual encoding
    /// (two encodings of one bearer credential make comparison and logging
    /// rules harder to reason about). The error never echoes `text`.
    pub fn from_hex(text: &str) -> Result<Self, TokenError> {
        if text.len() != TOKEN_HEX_CHARS {
            return Err(invalid_hex());
        }
        let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            let high = lowercase_hex_digit(pair[0]).ok_or_else(invalid_hex)?;
            let low = lowercase_hex_digit(pair[1]).ok_or_else(invalid_hex)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self { bytes })
    }

    /// The lowercase hex form, in zeroizing storage like the bytes.
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(TOKEN_HEX_CHARS));
        for byte in self.bytes.iter() {
            text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }

    /// The raw bytes, for handing the token to `pmd` over its private pipe.
    /// The wire and file forms are hex, so nothing else needs raw bytes.
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.bytes
    }

    /// Compare two tokens without an early exit on the first differing byte.
    ///
    /// Both sides are fixed-length, so the loop count reveals nothing. Timing
    /// is not this token's main defense (a same-user process can read the file
    /// anyway); this only avoids making it an obvious oracle.
    pub fn matches(&self, other: &SessionToken) -> bool {
        let mut difference = 0u8;
        for (left, right) in self.bytes.iter().zip(other.bytes.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn lowercase_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn invalid_hex() -> TokenError {
    TokenError::Invalid(format!(
        "a session token is {TOKEN_HEX_CHARS} lowercase hex characters"
    ))
}

/// Why a token could not be generated or parsed.
///
/// Messages are fixed strings; they never contain token bytes.
#[derive(Debug)]
pub enum TokenError {
    /// The input is not a token, or has the wrong length.
    Invalid(String),
    /// The operating system's random generator failed.
    Random(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => f.write_str(detail),
            Self::Random(detail) => write!(f, "secure random generator failed: {detail}"),
        }
    }
}

impl std::error::Error for TokenError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_unique_and_round_trip_through_hex() {
        let first = SessionToken::generate().expect("generate");
        let second = SessionToken::generate().expect("generate");
        assert!(!first.matches(&second), "two generated tokens collided");

        let hex = first.to_hex();
        assert_eq!(hex.len(), TOKEN_HEX_CHARS);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.chars().all(|c| !c.is_ascii_uppercase()));
        let parsed = SessionToken::from_hex(&hex).expect("parse generated hex");
        assert!(parsed.matches(&first));
    }

    #[test]
    fn hex_parsing_is_strict_and_never_echoes_the_input() {
        let valid = "0".repeat(TOKEN_HEX_CHARS);
        assert!(SessionToken::from_hex(&valid).is_ok());

        let too_short = "a".repeat(TOKEN_HEX_CHARS - 1);
        let too_long = "a".repeat(TOKEN_HEX_CHARS + 1);
        let uppercase = "A".repeat(TOKEN_HEX_CHARS);
        let non_hex = "g".repeat(TOKEN_HEX_CHARS);
        for bad in [too_short, too_long, uppercase, non_hex] {
            let error = SessionToken::from_hex(&bad).expect_err("must be rejected");
            let text = error.to_string();
            assert!(!text.contains(&bad), "error echoed the token: {text}");
            assert!(!text.contains("deadbeef"));
        }
    }

    #[test]
    fn from_bytes_requires_exactly_the_token_length() {
        let token = SessionToken::from_bytes(&[3u8; TOKEN_BYTES]).expect("valid length");
        assert!(token.to_hex().starts_with("0303"));
        assert!(SessionToken::from_bytes(&[3u8; TOKEN_BYTES - 1]).is_err());
        assert!(SessionToken::from_bytes(&[3u8; TOKEN_BYTES + 1]).is_err());
    }

    #[test]
    fn debug_output_is_redacted() {
        let token = SessionToken::from_bytes(&[0xABu8; TOKEN_BYTES]).expect("token");
        let text = format!("{token:?}");
        assert_eq!(text, "SessionToken(<redacted>)");
        assert!(!text.contains("ab"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }
}
