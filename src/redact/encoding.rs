//! Textual encodings of a secret, for redaction.
//!
//! A child process almost never prints an injected secret raw. It logs it
//! hex-encoded, puts it in a URL (percent-encoded), or wraps it in base64 (an
//! `Authorization: Basic` header, a JSON blob in a log line). [`variants`]
//! returns the encoded forms this build removes from relayed output, so
//! [`super::Redactor`] can treat them like the secret itself.
//!
//! The encoders are hand-written on purpose: this is not cryptography, and a
//! base64 or hex crate would add a dependency for a few dozen lines of table
//! lookup.
//!
//! # Limit
//!
//! The list is fixed and small. A tool that prints some other transform
//! (base32, a hash, a different case, a partially quoted copy, compressed
//! bytes) still leaks; see `SECURITY.md`. Redaction is best-effort by design.

/// One textual encoding of a byte string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// `616263` — two lower-case hex digits per byte.
    HexLower,
    /// `616263` with `A`–`F` for digits above nine.
    HexUpper,
    /// RFC 4648 base64 with the standard alphabet and `=` padding.
    Base64,
    /// The standard alphabet without `=` padding.
    Base64NoPad,
    /// RFC 4648 base64 with the URL-safe alphabet (`-` and `_`) and padding.
    Base64Url,
    /// The URL-safe alphabet without `=` padding.
    Base64UrlNoPad,
    /// RFC 3986 percent-encoding, upper-case hex digits.
    Percent,
}

/// Every encoding [`variants`] derives, in a fixed order.
pub const ALL: [Encoding; 7] = [
    Encoding::HexLower,
    Encoding::HexUpper,
    Encoding::Base64,
    Encoding::Base64NoPad,
    Encoding::Base64Url,
    Encoding::Base64UrlNoPad,
    Encoding::Percent,
];

const BASE64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

impl Encoding {
    /// Encode `secret` in this form. The output is always ASCII.
    pub fn encode(self, secret: &[u8]) -> Vec<u8> {
        match self {
            Encoding::HexLower => hex(secret, HEX_LOWER),
            Encoding::HexUpper => hex(secret, HEX_UPPER),
            Encoding::Base64 => base64(secret, BASE64_STD, true),
            Encoding::Base64NoPad => base64(secret, BASE64_STD, false),
            Encoding::Base64Url => base64(secret, BASE64_URL, true),
            Encoding::Base64UrlNoPad => base64(secret, BASE64_URL, false),
            Encoding::Percent => percent(secret),
        }
    }
}

/// Every encoded form of `secret`, without the raw value.
///
/// Duplicates are dropped: a byte string of only hex digits encodes to the
/// same text in both hex cases, a length divisible by three needs no padding,
/// and a value made only of RFC 3986 unreserved characters percent-encodes to
/// itself (which is why a form equal to the raw secret is not returned — the
/// caller already covers the raw value). An empty secret yields no variants.
pub fn variants(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(ALL.len());
    for encoding in ALL {
        let encoded = encoding.encode(secret);
        if encoded == secret || out.contains(&encoded) {
            continue;
        }
        out.push(encoded);
    }
    out
}

fn hex(secret: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret.len() * 2);
    for byte in secret {
        out.push(digits[usize::from(byte >> 4)]);
        out.push(digits[usize::from(byte & 0x0f)]);
    }
    out
}

fn base64(secret: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret.len().div_ceil(3) * 4);
    for chunk in secret.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).copied().map_or(0, u32::from);
        let third = chunk.get(2).copied().map_or(0, u32::from);
        let bits = (first << 16) | (second << 8) | third;
        out.push(alphabet[((bits >> 18) & 0x3f) as usize]);
        out.push(alphabet[((bits >> 12) & 0x3f) as usize]);
        if chunk.len() > 1 {
            out.push(alphabet[((bits >> 6) & 0x3f) as usize]);
        } else if pad {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(bits & 0x3f) as usize]);
        } else if pad {
            out.push(b'=');
        }
    }
    out
}

fn percent(secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret.len());
    for byte in secret {
        if is_unreserved(*byte) {
            out.push(*byte);
        } else {
            out.push(b'%');
            out.push(HEX_UPPER[usize::from(byte >> 4)]);
            out.push(HEX_UPPER[usize::from(byte & 0x0f)]);
        }
    }
    out
}

/// RFC 3986 unreserved characters: `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            other => panic!("not a hex digit: {other:#04x}"),
        }
    }

    fn from_hex(text: &[u8]) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "odd hex length");
        text.chunks(2)
            .map(|pair| (hex_digit(pair[0]) << 4) | hex_digit(pair[1]))
            .collect()
    }

    fn base64_digit(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            other => panic!("not a base64 digit: {other:#04x}"),
        }
    }

    fn from_base64(text: &[u8]) -> Vec<u8> {
        let body: Vec<u8> = text.iter().copied().filter(|byte| *byte != b'=').collect();
        let mut out = Vec::new();
        for chunk in body.chunks(4) {
            assert!(chunk.len() >= 2, "truncated base64 chunk");
            let mut bits = 0u32;
            for (index, byte) in chunk.iter().enumerate() {
                bits |= u32::from(base64_digit(*byte)) << (18 - 6 * index);
            }
            let bytes = chunk.len() - 1;
            for index in 0..bytes {
                out.push((bits >> (16 - 8 * index)) as u8);
            }
        }
        out
    }

    fn from_percent(text: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0;
        while index < text.len() {
            if text[index] == b'%' {
                assert!(index + 2 < text.len(), "truncated percent escape");
                out.push((hex_digit(text[index + 1]) << 4) | hex_digit(text[index + 2]));
                index += 3;
            } else {
                out.push(text[index]);
                index += 1;
            }
        }
        out
    }

    /// Deterministic bytes, so the round-trip test does not depend on a
    /// generator crate or on wall-clock randomness.
    fn deterministic_bytes(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn hex_vectors_cover_both_digit_cases() {
        assert_eq!(Encoding::HexLower.encode(b"abc"), b"616263");
        assert_eq!(Encoding::HexUpper.encode(b"abc"), b"616263");
        assert_eq!(
            Encoding::HexLower.encode(&[0x0a, 0xfb, 0xff, 0x00]),
            b"0afbff00"
        );
        assert_eq!(
            Encoding::HexUpper.encode(&[0x0a, 0xfb, 0xff, 0x00]),
            b"0AFBFF00"
        );
        assert_eq!(Encoding::HexLower.encode(b""), b"");
    }

    #[test]
    fn base64_vectors_cover_every_padding_length_and_alphabet() {
        // One, two and three bytes past a multiple of three.
        assert_eq!(Encoding::Base64.encode(b"a"), b"YQ==");
        assert_eq!(Encoding::Base64NoPad.encode(b"a"), b"YQ");
        assert_eq!(Encoding::Base64.encode(b"ab"), b"YWI=");
        assert_eq!(Encoding::Base64NoPad.encode(b"ab"), b"YWI");
        assert_eq!(Encoding::Base64.encode(b"abc"), b"YWJj");
        assert_eq!(Encoding::Base64NoPad.encode(b"abc"), b"YWJj");
        // 0xfb 0xff selects index 62 and 63, the only two positions where the
        // standard and URL-safe alphabets differ.
        assert_eq!(Encoding::Base64.encode(&[0xfb, 0xff]), b"+/8=");
        assert_eq!(Encoding::Base64Url.encode(&[0xfb, 0xff]), b"-_8=");
        assert_eq!(Encoding::Base64UrlNoPad.encode(&[0xfb, 0xff]), b"-_8");
        assert_eq!(Encoding::Base64.encode(b""), b"");
    }

    #[test]
    fn percent_encoding_follows_rfc3986() {
        assert_eq!(
            Encoding::Percent.encode(b"abcXYZ019-._~"),
            b"abcXYZ019-._~",
            "unreserved characters stay literal"
        );
        assert_eq!(Encoding::Percent.encode(b"a b"), b"a%20b");
        assert_eq!(Encoding::Percent.encode(b"%"), b"%25");
        assert_eq!(Encoding::Percent.encode(b"\xff\xfe\x00"), b"%FF%FE%00");
        assert_eq!(Encoding::Percent.encode(b""), b"");
    }

    #[test]
    fn all_seven_forms_are_distinct_for_a_discriminating_secret() {
        let secret = [0x0a, 0xfb, 0xff, 0x00];
        let variants = variants(&secret);
        assert_eq!(
            variants,
            vec![
                b"0afbff00".to_vec(),
                b"0AFBFF00".to_vec(),
                b"Cvv/AA==".to_vec(),
                b"Cvv/AA".to_vec(),
                b"Cvv_AA==".to_vec(),
                b"Cvv_AA".to_vec(),
                b"%0A%FB%FF%00".to_vec(),
            ]
        );
    }

    #[test]
    fn duplicate_and_raw_equal_forms_are_dropped() {
        // Three unreserved bytes: both hex cases produce the same text, padded
        // and unpadded base64 are identical (the length is divisible by
        // three), and percent-encoding is the raw secret, which must not be
        // repeated.
        assert_eq!(variants(b"abc"), vec![b"616263".to_vec(), b"YWJj".to_vec()]);

        // A hyphen is unreserved too, so the percent form again equals the
        // raw secret while the other forms differ.
        let secret = b"a-b";
        let variants = variants(secret);
        assert!(variants.iter().all(|variant| variant != secret));
        assert_eq!(variants.len(), 3, "{variants:?}");
    }

    #[test]
    fn an_empty_secret_has_no_variants() {
        assert!(variants(b"").is_empty());
    }

    #[test]
    fn every_variant_of_every_byte_value_is_ascii() {
        let secret: Vec<u8> = (0..=u8::MAX).collect();
        for variant in variants(&secret) {
            assert!(!variant.is_empty());
            assert!(
                variant.iter().all(u8::is_ascii),
                "an encoding produced a non-ASCII byte"
            );
        }
    }

    #[test]
    fn test_decoders_round_trip_every_encoding() {
        for seed in [1u32, 7, 42, 0xdead_beef] {
            for len in 0..=40 {
                let secret = deterministic_bytes(seed, len);
                assert_eq!(from_hex(&Encoding::HexLower.encode(&secret)), secret);
                assert_eq!(from_hex(&Encoding::HexUpper.encode(&secret)), secret);
                for encoding in [
                    Encoding::Base64,
                    Encoding::Base64NoPad,
                    Encoding::Base64Url,
                    Encoding::Base64UrlNoPad,
                ] {
                    assert_eq!(
                        from_base64(&encoding.encode(&secret)),
                        secret,
                        "{encoding:?} of len {len}"
                    );
                }
                assert_eq!(from_percent(&Encoding::Percent.encode(&secret)), secret);
            }
        }
    }
}
