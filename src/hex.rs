//! Strict lowercase hex, the one textual encoding of ids, nonces, hashes and
//! tokens on the wire and in files.
//!
//! Decoding refuses upper case so a value has exactly one encoding. A caller
//! that must accept upper case (an id typed on a command line) lowercases the
//! text itself. Secrets decode with [`decode_lower_into`] straight into the
//! caller's zeroizing buffer, so no unwiped intermediate copy exists.

use zeroize::Zeroizing;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// [`encode_lower`] for secret bytes: the text is wiped on drop.
pub fn encode_lower_zeroizing(bytes: &[u8]) -> Zeroizing<String> {
    // `encode_lower` sizes the string exactly, so it never reallocates and
    // leaves no unwiped partial copy behind.
    Zeroizing::new(encode_lower(bytes))
}

/// Fill `out` from exactly `out.len() * 2` lowercase hex digits. `None` on any
/// other length or byte; `out` is then unspecified, so pass a zeroizing buffer
/// when it holds a secret.
pub fn decode_lower_into(text: &str, out: &mut [u8]) -> Option<()> {
    if text.len() != out.len() * 2 {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *slot = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(())
}

/// Exactly `N` bytes of lowercase hex. For secrets use [`decode_lower_into`].
pub fn decode_lower<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    decode_lower_into(text, &mut bytes)?;
    Some(bytes)
}

/// Lowercase hex of any even length.
pub fn decode_lower_vec(text: &str) -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; text.len() / 2];
    decode_lower_into(text, &mut bytes)?;
    Some(bytes)
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        let text = encode_lower(&bytes);
        assert_eq!(text, "000fa5ff");
        assert_eq!(&*encode_lower_zeroizing(&bytes), "000fa5ff");
        assert_eq!(decode_lower::<4>(&text), Some(bytes));
        assert_eq!(decode_lower_vec(&text), Some(bytes.to_vec()));
        assert_eq!(decode_lower_vec(""), Some(Vec::new()));
    }

    #[test]
    fn refuses_odd_length_upper_case_non_hex_and_wrong_length() {
        assert_eq!(decode_lower::<2>("abc"), None);
        assert_eq!(decode_lower_vec("abc"), None);
        assert_eq!(decode_lower::<2>("ABCD"), None);
        assert_eq!(decode_lower::<2>("abcg"), None);
        assert_eq!(decode_lower::<2>("ab\u{e9}"), None);
        assert_eq!(decode_lower::<2>("ab"), None);
        assert_eq!(decode_lower::<2>("abcdef"), None);
        let mut out = [0u8; 2];
        assert_eq!(decode_lower_into("abcd", &mut out), Some(()));
        assert_eq!(out, [0xab, 0xcd]);
    }
}
