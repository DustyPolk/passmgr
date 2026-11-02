//! Cryptographically secure password generation.

use getrandom::fill;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const MIN_LEN: usize = 4;
pub const MAX_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Preset {
    /// Uppercase, lowercase, digits, and symbols.
    #[default]
    Strong,
    /// Uppercase, lowercase, and digits.
    Simple,
    /// Digits only.
    Pin,
}

impl Preset {
    pub fn default_length(self) -> usize {
        match self {
            Self::Strong => 20,
            Self::Simple => 16,
            Self::Pin => 6,
        }
    }

    fn charset(self) -> &'static [u8] {
        const STRONG: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}";
        const SIMPLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const PIN: &[u8] = b"0123456789";
        match self {
            Self::Strong => STRONG,
            Self::Simple => SIMPLE,
            Self::Pin => PIN,
        }
    }
}

/// Generate a password using rejection sampling to avoid modulo bias.
pub fn generate_password(preset: Preset, length: usize) -> Result<Zeroizing<String>> {
    if !(MIN_LEN..=MAX_LEN).contains(&length) {
        return Err(Error::InvalidInput(format!(
            "password length must be between {MIN_LEN} and {MAX_LEN}"
        )));
    }

    let charset = preset.charset();
    // Discard random bytes at or above this value so every character is
    // equally likely (256 is rarely divisible by the charset size).
    let threshold = 256 - (256 % charset.len());
    let mut password = Zeroizing::new(String::with_capacity(length));
    let mut random = [0u8; 1];

    for _ in 0..length {
        loop {
            fill(&mut random)
                .map_err(|err| Error::Crypto(format!("secure random generator failed: {err}")))?;
            if (random[0] as usize) < threshold {
                break;
            }
        }
        password.push(charset[random[0] as usize % charset.len()] as char);
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_lengths() {
        assert_eq!(Preset::Strong.default_length(), 20);
        assert_eq!(Preset::Simple.default_length(), 16);
        assert_eq!(Preset::Pin.default_length(), 6);
    }

    #[test]
    fn generated_passwords_have_requested_length_and_charset() {
        for preset in [Preset::Strong, Preset::Simple, Preset::Pin] {
            for length in [MIN_LEN, 17, MAX_LEN] {
                let password = generate_password(preset, length).unwrap();
                assert_eq!(password.len(), length);
                assert!(
                    password
                        .chars()
                        .all(|c| preset.charset().contains(&(c as u8)))
                );
            }
        }
    }

    #[test]
    fn pin_is_digits_only() {
        let password = generate_password(Preset::Pin, 32).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn simple_is_alphanumeric() {
        let password = generate_password(Preset::Simple, 128).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn consecutive_passwords_differ() {
        let first = generate_password(Preset::Strong, 20).unwrap();
        let second = generate_password(Preset::Strong, 20).unwrap();
        assert_ne!(*first, *second);
    }

    #[test]
    fn rejects_out_of_range_lengths() {
        assert!(generate_password(Preset::Strong, MIN_LEN - 1).is_err());
        assert!(generate_password(Preset::Strong, MAX_LEN + 1).is_err());
    }
}
