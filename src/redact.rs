//! Streaming redaction of an injected secret from child-process output.
//!
//! `passmgr run` injects a secret into a child's environment and relays the
//! child's stdout/stderr back to the caller. The daemon therefore has to remove
//! any occurrence of that value from the stream before a byte of it reaches the
//! agent-facing side.
//!
//! # Streaming, not buffering
//!
//! Output arrives in arbitrary chunks. A naive per-chunk replacement leaks a
//! secret that straddles a chunk boundary, so [`Redactor`] holds back the
//! longest suffix that is still a prefix of the secret (at most
//! `secret.len() - 1` bytes) until the next [`Redactor::push`] decides whether
//! the value completes. [`Redactor::finish`] flushes a trailing partial prefix
//! at end of stream: a prefix is not the secret, and keeping it back forever
//! would truncate legitimate output.
//!
//! # Handling of the secret
//!
//! The value is copied into a private buffer, never exposed through `Debug` or
//! `Display`, and zeroized on drop together with the pending overlap. The
//! redaction marker is chosen so it cannot itself contain the value (a secret
//! such as `"[REDACTED]"` gets a different marker).
//!
//! # Limit
//!
//! Redaction protects the *agent's context* from accidental output. It is not
//! a sandbox: the child process receives the value in its environment, so a
//! deliberately hostile child can exfiltrate it by other means (files, network,
//! `/proc/<pid>/environ`). Only an exact, contiguous occurrence is replaced.

use std::fmt;

use zeroize::Zeroize;

/// The usual replacement marker.
const DEFAULT_MARKER: &[u8] = b"[REDACTED]";

/// Replaces occurrences of one value in a byte stream, across chunk boundaries.
///
/// See the module documentation for the overlap-window behavior and its
/// limits. The type deliberately implements only a redacted [`fmt::Debug`].
pub struct Redactor {
    secret: Vec<u8>,
    marker: Vec<u8>,
    /// Bytes not yet emitted because they may be the start of a split
    /// occurrence. Bounded by `secret.len() - 1` after every `push`.
    pending: Vec<u8>,
}

impl Redactor {
    /// Build a redactor for `secret`.
    ///
    /// An empty secret is allowed and means "nothing to redact"; callers that
    /// inject credentials reject an empty value before getting here.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            marker: choose_marker(secret),
            pending: Vec::new(),
        }
    }

    /// Feed the next chunk of output and return the bytes that are now safe to
    /// emit. The returned buffer never contains a complete occurrence of the
    /// secret, including occurrences that span this chunk and earlier ones.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        if self.secret.is_empty() {
            return data.to_vec();
        }
        self.pending.extend_from_slice(data);
        let mut out = Vec::with_capacity(self.pending.len());
        self.consume(&mut out, false);
        out
    }

    /// Finish the stream and return whatever is still held back.
    ///
    /// A held-back suffix is by construction only a proper prefix of the
    /// secret, so emitting it does not reveal the value.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.secret.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.pending.len());
        self.consume(&mut out, true);
        debug_assert!(self.pending.is_empty(), "finish must drain the overlap");
        out
    }

    /// Scan `pending`, appending safe bytes and the marker to `out`, and drop
    /// the consumed prefix.
    ///
    /// At the end of a stream (`at_end`) a partial prefix is emitted; mid
    /// stream it is kept for the next chunk.
    fn consume(&mut self, out: &mut Vec<u8>, at_end: bool) {
        let secret_len = self.secret.len();
        let mut consumed = 0;
        while consumed < self.pending.len() {
            let remaining = &self.pending[consumed..];
            if remaining[0] == self.secret[0] {
                if remaining.len() >= secret_len {
                    if &remaining[..secret_len] == self.secret.as_slice() {
                        out.extend_from_slice(&self.marker);
                        consumed += secret_len;
                        continue;
                    }
                } else if !at_end && self.secret.starts_with(remaining) {
                    // The chunk ends in the middle of a possible occurrence:
                    // hold it until more bytes arrive.
                    break;
                }
            }
            out.push(remaining[0]);
            consumed += 1;
        }
        self.discard_prefix(consumed);
    }

    /// Remove the first `count` bytes of `pending`, zeroizing the stale copies
    /// the shift leaves behind.
    fn discard_prefix(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let old_len = self.pending.len();
        let new_len = old_len - count;
        self.pending.copy_within(count.., 0);
        // `copy_within` leaves a duplicate of the retained tail in
        // `[new_len..old_len]`; clear it before shrinking the view. Bytes above
        // the old length were zeroed by an earlier call (or never written), so
        // no secret fragment stays in the spare capacity.
        self.pending[new_len..old_len].zeroize();
        self.pending.truncate(new_len);
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.pending.zeroize();
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render secret bytes, not even a preview.
        f.debug_struct("Redactor")
            .field("secret_len", &self.secret.len())
            .field("pending_len", &self.pending.len())
            .finish_non_exhaustive()
    }
}

/// Convenience for a complete in-memory buffer. Streaming callers should use
/// [`Redactor`] directly.
pub fn redact(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut redactor = Redactor::new(secret);
    let mut out = redactor.push(data);
    out.extend_from_slice(&redactor.finish());
    out
}

/// Pick a marker that does not itself contain `secret`.
///
/// The default is readable and almost always safe. When the secret is a
/// substring of it (a password like `"[REDACTED]"` or `"ACT"`), a run of a
/// byte that is absent from the secret is used instead. Such a marker cannot
/// contain the secret, and a secret cannot span the marker boundary because
/// none of its bytes occur in the marker.
fn choose_marker(secret: &[u8]) -> Vec<u8> {
    if secret.is_empty() || !contains_subslice(DEFAULT_MARKER, secret) {
        return DEFAULT_MARKER.to_vec();
    }

    // Fallback only runs when the secret is a substring of the 10-byte default
    // marker, so `secret` is short.
    let byte = (b'!'..=b'~')
        .find(|candidate| !secret.contains(candidate))
        .or_else(|| (0..=u8::MAX).find(|candidate| !secret.contains(candidate)))
        // Only possible when the secret contains every byte value, in which
        // case it is not a run of any single byte and the marker below still
        // cannot equal it.
        .unwrap_or(secret[0]);
    let length = secret.len().saturating_add(1).max(DEFAULT_MARKER.len());
    vec![byte; length]
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"s3cret-injected-value";

    #[test]
    fn replaces_whole_and_repeated_occurrences() {
        assert_eq!(
            redact(SECRET, b"before s3cret-injected-value after"),
            b"before [REDACTED] after"
        );
        assert_eq!(
            redact(SECRET, b"s3cret-injected-value/s3cret-injected-value"),
            b"[REDACTED]/[REDACTED]"
        );
        assert_eq!(redact(SECRET, b"nothing to see"), b"nothing to see");
        assert_eq!(redact(SECRET, b""), b"");
    }

    #[test]
    fn a_value_split_at_any_offset_is_still_redacted() {
        let input = b"before s3cret-injected-value after";
        let expected = b"before [REDACTED] after";
        for split in 0..=input.len() {
            let mut redactor = Redactor::new(SECRET);
            let mut out = redactor.push(&input[..split]);
            out.extend_from_slice(&redactor.push(&input[split..]));
            out.extend_from_slice(&redactor.finish());
            assert_eq!(out, expected, "split at offset {split}");
            assert!(!contains_subslice(&out, SECRET), "leak at split {split}");
        }
    }

    #[test]
    fn byte_at_a_time_input_is_redacted() {
        let input = b"x s3cret-injected-value y s3cret-injected-value z";
        let mut redactor = Redactor::new(SECRET);
        let mut out = Vec::new();
        for byte in input {
            out.extend_from_slice(&redactor.push(&[*byte]));
            assert!(
                !contains_subslice(&out, SECRET),
                "a complete secret escaped after {out:?}"
            );
        }
        out.extend_from_slice(&redactor.finish());
        assert_eq!(out, b"x [REDACTED] y [REDACTED] z");
    }

    #[test]
    fn arbitrary_chunk_sizes_do_not_leak_across_boundaries() {
        let input = b"..s3cret-injected-value..s3cret-injected-value..";
        let expected = b"..[REDACTED]..[REDACTED]..";
        for chunk_size in 1..=input.len() {
            let mut redactor = Redactor::new(SECRET);
            let mut out = Vec::new();
            for chunk in input.chunks(chunk_size) {
                out.extend_from_slice(&redactor.push(chunk));
                assert!(!contains_subslice(&out, SECRET), "chunk {chunk_size}");
            }
            out.extend_from_slice(&redactor.finish());
            assert_eq!(out, expected, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn overlapping_occurrences_are_removed_greedily() {
        let out = redact(b"aba", b"ababa");
        assert_eq!(out, b"[REDACTED]ba");
        assert!(!contains_subslice(&out, b"aba"));

        // A shorter secret with many overlaps must not be recreated by the
        // replacement itself.
        let out = redact(b"aa", b"aaaaa");
        assert!(!contains_subslice(&out, b"aa"), "{out:?}");
        assert_eq!(out, b"[REDACTED][REDACTED]a");
    }

    #[test]
    fn binary_values_and_output_are_supported() {
        let secret = [0u8, 0xff, 0x01, 0x02];
        let input = [9u8, 0, 0xff, 0x01, 0x02, 8, 0, 0xff, 0x01, 0x02];
        let mut expected = vec![9];
        expected.extend_from_slice(DEFAULT_MARKER);
        expected.push(8);
        expected.extend_from_slice(DEFAULT_MARKER);
        assert_eq!(redact(&secret, &input), expected);
    }

    #[test]
    fn an_empty_secret_is_a_passthrough() {
        let mut redactor = Redactor::new(b"");
        assert_eq!(redactor.push(b"anything at all"), b"anything at all");
        assert!(redactor.finish().is_empty());
        assert_eq!(redact(b"", b"\x00\xff"), b"\x00\xff");
    }

    #[test]
    fn finish_flushes_a_trailing_partial_prefix() {
        let mut redactor = Redactor::new(b"abcdef");
        // "abc" is a prefix of the secret and must be held back.
        assert_eq!(redactor.push(b"xabc"), b"x");
        assert_eq!(redactor.pending, b"abc");
        assert_eq!(redactor.finish(), b"abc");
        assert!(redactor.pending.is_empty());

        // A suffix that only looks like a prefix for a while is released as
        // soon as it is disproved.
        let mut redactor = Redactor::new(b"abcdef");
        assert_eq!(redactor.push(b"abcx"), b"abcx");
        assert!(redactor.finish().is_empty());
    }

    #[test]
    fn the_overlap_is_bounded_by_the_secret_length() {
        let mut redactor = Redactor::new(b"abcdef");
        let mut out = Vec::new();
        for byte in b"abcdef" {
            out.extend_from_slice(&redactor.push(&[*byte]));
            assert!(
                redactor.pending.len() < 6,
                "held {} bytes",
                redactor.pending.len()
            );
        }
        out.extend_from_slice(&redactor.finish());
        assert_eq!(out, b"[REDACTED]");
    }

    #[test]
    fn the_marker_never_contains_the_value() {
        // All of these are substrings of the default marker, so they force the
        // fallback marker.
        for secret in [&b"[REDACTED]"[..], b"REDACTED", b"D]", b"ACT"] {
            let out = redact(secret, secret);
            assert!(
                !contains_subslice(&out, secret),
                "marker leaked {secret:?}: {out:?}"
            );
        }
        // Ordinary values still get the readable marker.
        assert_eq!(redact(b"hunter2", b"hunter2"), DEFAULT_MARKER);
    }

    #[test]
    fn debug_never_contains_the_value() {
        let secret = b"super-secret-value";
        let text = format!("{:?}", Redactor::new(secret));
        assert!(text.contains("Redactor"), "{text}");
        assert!(text.contains("secret_len"), "{text}");
        assert!(!text.contains("super-secret-value"), "{text}");
        assert!(!text.contains("115"), "{text}");
    }

    #[test]
    fn dropping_a_half_consumed_stream_does_not_expose_the_secret() {
        // Regression guard for the overlap buffer: the debug rendering of a
        // redactor holding a partial value must stay redacted too.
        let mut redactor = Redactor::new(SECRET);
        assert!(redactor.push(&SECRET[..SECRET.len() - 1]).is_empty());
        let text = format!("{redactor:?}");
        assert!(!text.contains("s3cret"), "{text}");
        assert!(text.contains("pending_len"), "{text}");
        drop(redactor);
    }
}
