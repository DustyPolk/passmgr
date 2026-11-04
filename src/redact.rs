//! Streaming redaction of an injected secret from child-process output.
//!
//! `passmgr run` injects secrets into a child's environment and relays the
//! child's stdout/stderr back to the caller. The daemon therefore has to remove
//! every occurrence of every injected value from the stream before a byte of it
//! reaches the agent-facing side.
//!
//! # Streaming, not buffering
//!
//! Output arrives in arbitrary chunks. A naive per-chunk replacement leaks a
//! secret that straddles a chunk boundary, so [`Redactor`] always holds back
//! the last `max(secret.len()) - 1` bytes of what it has seen, whatever they
//! are, until more output arrives or the stream ends. Any split occurrence of
//! any secret must start within that window, so holding a fixed-length suffix
//! is enough to catch every cross-chunk occurrence. The window is sized by the
//! longest value in the set, so a shorter value can sit entirely inside it; the
//! end-of-stream scan still replaces those before they are emitted.
//! [`Redactor::finish`] flushes the held bytes: a suffix shorter than the
//! shortest secret cannot start an occurrence, and keeping it back forever
//! would truncate legitimate output.
//!
//! The window depends only on how many bytes have been seen, never on whether
//! they match the secret. Holding back only a *matching* prefix would make the
//! relay's timing an oracle: an agent that controls the child's output could
//! send `known + guess`, pause, and learn from whether the bytes were delayed
//! whether `guess` extended a real prefix of the secret.
//!
//! # Handling of the secret
//!
//! The value is copied into a private buffer, never exposed through `Debug` or
//! `Display`, and zeroized on drop together with the pending overlap. Growing
//! the overlap window allocates a fresh buffer and wipes the old one before it
//! drops, so a reallocation never leaves part of the value in freed memory.
//! The redaction marker is chosen so it cannot spell the value together with the
//! raw text around a substitution: it must not contain the value, must not be
//! contained in it, and no suffix of either may be a prefix of the other. A
//! secret such as `"[REDACTED]"` or `"TED]X"` therefore gets a different
//! marker.
//!
//! # Limit
//!
//! Redaction protects the *agent's context* from accidental output. It is not
//! a sandbox: the child process receives the value in its environment, so a
//! deliberately hostile child can exfiltrate it by other means (files, network,
//! `/proc/<pid>/environ`). Only an exact, contiguous occurrence is replaced.

use std::fmt;

use zeroize::Zeroize;

pub mod encoding;

/// The usual replacement marker.
const DEFAULT_MARKER: &[u8] = b"[REDACTED]";

/// Replaces occurrences of a set of values in a byte stream, across chunk
/// boundaries.
///
/// See the module documentation for the overlap-window behavior and its
/// limits. The type deliberately implements only a redacted [`fmt::Debug`].
pub struct Redactor {
    /// Every non-empty value, longest first so a match is greedy.
    secrets: Vec<Vec<u8>>,
    /// The longest value's length; drives the fixed holdback window.
    max_len: usize,
    /// The shortest value's length; at end of stream fewer remaining bytes
    /// cannot start an occurrence.
    min_len: usize,
    /// One marker, safe against every value in the set.
    marker: Vec<u8>,
    /// A fixed window of bytes not yet emitted: always the last
    /// `max_len - 1` bytes seen, regardless of content, so the relay's timing
    /// cannot reveal a correct prefix. Bounded by `max_len - 1` after every
    /// `push`.
    pending: Vec<u8>,
    /// How many occurrences have been replaced, for the run report.
    redactions: u64,
}

impl Redactor {
    /// Build a redactor for one value.
    ///
    /// An empty secret is allowed and means "nothing to redact"; callers that
    /// inject credentials reject an empty value before getting here.
    pub fn new(secret: &[u8]) -> Self {
        Self::new_many(&[secret])
    }

    /// Build a redactor for every value in `secrets`.
    ///
    /// Empty entries are ignored. A value that contains another is matched
    /// greedily (longest first), so the whole occurrence is removed in one
    /// substitution. The set must stay bounded: with more than 127 distinct
    /// first or last bytes no marker can be safe against all of them (see
    /// [`choose_marker_many`]), so callers such as the daemon's `run` handler
    /// cap the number of secrets (32 in the protocol) long before that.
    pub fn new_many(secrets: &[&[u8]]) -> Self {
        let mut secrets: Vec<Vec<u8>> = secrets
            .iter()
            .filter(|secret| !secret.is_empty())
            .map(|secret| secret.to_vec())
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        let max_len = secrets.first().map_or(0, Vec::len);
        let min_len = secrets.last().map_or(0, Vec::len);
        let marker = choose_marker_many(&secrets);
        Self {
            secrets,
            max_len,
            min_len,
            marker,
            pending: Vec::new(),
            redactions: 0,
        }
    }

    /// How many occurrences have been replaced so far.
    pub fn redactions(&self) -> u64 {
        self.redactions
    }

    /// Feed the next chunk of output and return the bytes that are now safe to
    /// emit. The returned buffer never contains a complete occurrence of the
    /// secret, including occurrences that span this chunk and earlier ones.
    ///
    /// How many bytes this returns depends only on the number of bytes fed so
    /// far and the secret's *length*, never on its content: the last
    /// `secret.len() - 1` bytes are always held back until more output or
    /// [`Redactor::finish`].
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        if self.secrets.is_empty() {
            return data.to_vec();
        }
        self.reserve_pending(data.len());
        self.pending.extend_from_slice(data);
        let mut out = Vec::with_capacity(self.pending.len());
        self.consume(&mut out, false);
        out
    }

    /// Finish the stream and return whatever is still held back.
    ///
    /// The held suffix is at most `max_len - 1` bytes, so an occurrence that
    /// starts in it has not been seen whole; the scan replaces any that did fit
    /// (a value shorter than the longest one). Only a tail shorter than every
    /// secret is emitted unchanged, so `finish` cannot reveal a value.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.secrets.is_empty() {
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
    /// Mid stream the final `max_len - 1` bytes are always kept for the next
    /// chunk, whether or not they look like a secret. A suffix shorter than the
    /// longest secret cannot contain a complete occurrence of it, and every
    /// split occurrence starts inside this window, so nothing is missed.
    /// Keeping a fixed window makes the decision independent of content. At the
    /// end of a stream (`at_end`) the window is scanned normally and only a tail
    /// shorter than every secret is emitted unchanged.
    fn consume(&mut self, out: &mut Vec<u8>, at_end: bool) {
        let mut consumed = 0;
        while consumed < self.pending.len() {
            let remaining_len = self.pending.len() - consumed;
            if at_end && remaining_len < self.min_len {
                // No value can start in fewer bytes than the shortest one.
                out.extend_from_slice(&self.pending[consumed..]);
                consumed = self.pending.len();
                break;
            }
            if !at_end && remaining_len < self.max_len {
                // Hold the tail: it may still become part of a secret split
                // across chunks.
                break;
            }
            match self.match_len(&self.pending[consumed..]) {
                Some(len) => {
                    out.extend_from_slice(&self.marker);
                    consumed += len;
                    self.redactions += 1;
                }
                None => {
                    out.push(self.pending[consumed]);
                    consumed += 1;
                }
            }
        }
        self.discard_prefix(consumed);
    }

    /// The length of the longest secret that starts `remaining`, if any.
    ///
    /// `secrets` is sorted longest first, so the first match is the greediest:
    /// a value that contains another is removed whole rather than leaving its
    /// tail in the output.
    fn match_len(&self, remaining: &[u8]) -> Option<usize> {
        self.secrets.iter().find_map(|secret| {
            (remaining.len() >= secret.len() && remaining[..secret.len()] == secret[..])
                .then_some(secret.len())
        })
    }

    /// Make room for `extra` more bytes without leaving secret bytes in a freed
    /// allocation.
    ///
    /// `Vec::extend_from_slice` grows with `realloc`, which frees the old block
    /// untouched, so a window that held part of the secret would leave the
    /// plaintext in freed heap memory (TODO R.50b). Allocate the larger buffer,
    /// copy, wipe the old one and only then let it drop. The spare capacity of
    /// the old buffer is already zero: it was either never written or cleared
    /// by [`Redactor::discard_prefix`].
    fn reserve_pending(&mut self, extra: usize) {
        let needed = self.pending.len() + extra;
        if self.pending.capacity() >= needed {
            return;
        }
        let doubled = self.pending.capacity().saturating_mul(2);
        let mut grown = Vec::with_capacity(needed.max(doubled));
        grown.extend_from_slice(&self.pending);
        self.pending.zeroize();
        self.pending = grown;
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
        for secret in &mut self.secrets {
            secret.zeroize();
        }
        self.pending.zeroize();
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render secret bytes, not even a preview.
        f.debug_struct("Redactor")
            .field("secrets", &self.secrets.len())
            .field("max_len", &self.max_len)
            .field("pending_len", &self.pending.len())
            .field("redactions", &self.redactions)
            .finish_non_exhaustive()
    }
}

/// Convenience for a complete in-memory buffer. Streaming callers should use
/// [`Redactor`] directly.
pub fn redact(secret: &[u8], data: &[u8]) -> Vec<u8> {
    redact_many(&[secret], data)
}

/// [`redact`] for a set of values.
pub fn redact_many(secrets: &[&[u8]], data: &[u8]) -> Vec<u8> {
    let mut redactor = Redactor::new_many(secrets);
    let mut out = redactor.push(data);
    out.extend_from_slice(&redactor.finish());
    out
}

/// Pick one marker that cannot spell any secret together with the text around
/// it.
///
/// The default marker is readable and almost always safe. When it is not, a run
/// of a byte that is neither the first nor the last byte of any secret is used:
/// such a marker contains none of the endpoint bytes, so no secret can start or
/// finish around it. Its length is one more than the longest run of that byte
/// inside any secret, so no secret can contain the whole marker either.
///
/// A safe marker always exists for a bounded set: the marker's first byte must
/// differ from every secret's last byte (otherwise a proper suffix is a prefix
/// of the marker) and from every secret's first byte (otherwise a suffix of the
/// marker is a prefix of the secret). With at most 32 secrets at most 64 byte
/// values are excluded, so 192 remain. For a larger set (more than 127
/// distinct endpoints) no safe marker exists at all; this panics rather than
/// silently relaying a value, and the daemon's protocol caps the set far below
/// that.
fn choose_marker_many(secrets: &[Vec<u8>]) -> Vec<u8> {
    if secrets
        .iter()
        .all(|secret| marker_is_safe(DEFAULT_MARKER, secret))
    {
        return DEFAULT_MARKER.to_vec();
    }

    let forbidden = |byte: u8| {
        secrets
            .iter()
            .any(|secret| secret.first() == Some(&byte) || secret.last() == Some(&byte))
    };
    let Some(byte) = (b'!'..=b'~')
        .find(|candidate| !forbidden(*candidate))
        .or_else(|| (0..=u8::MAX).find(|candidate| !forbidden(*candidate)))
    else {
        // Fail closed: the caller must bound the number of distinct endpoint
        // bytes. Dropping the match instead would be safe too, but silently
        // changing the marker contract is worse than refusing to start.
        panic!("no safe redaction marker exists for this set of secrets")
    };

    // A run longer than any run of `byte` inside a secret cannot be contained
    // in one, and `byte` is not an endpoint, so the marker can neither start
    // nor finish a secret with the surrounding output.
    let longest_run = secrets
        .iter()
        .map(|secret| longest_run_of(secret, byte))
        .max()
        .unwrap_or(0);
    let marker = vec![byte; DEFAULT_MARKER.len().max(longest_run + 1)];
    debug_assert!(secrets.iter().all(|secret| marker_is_safe(&marker, secret)));
    marker
}

/// The longest run of `byte` in `secret`.
fn longest_run_of(secret: &[u8], byte: u8) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for candidate in secret {
        if *candidate == byte {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// Whether `marker` can replace `secret` without the relayed output ever
/// spelling `secret` around the substitution.
///
/// Raw output before a marker can end with any proper prefix of the secret,
/// and raw output after it can start with any proper suffix, so four shapes
/// have to be ruled out:
///
/// * the marker itself contains the secret;
/// * the secret contains the marker, so the text around one substitution can
///   supply the remainder;
/// * the marker starts with a proper suffix of the secret (the prefix comes
///   from output emitted just before it);
/// * the secret starts with a proper suffix of the marker (the marker supplies
///   the start, and output after it completes the value).
///
/// A marker with a byte the secret does not contain satisfies all four.
fn marker_is_safe(marker: &[u8], secret: &[u8]) -> bool {
    if secret.is_empty() || marker.is_empty() {
        return true;
    }
    !contains_subslice(marker, secret)
        && !contains_subslice(secret, marker)
        && !(1..secret.len()).any(|offset| marker.starts_with(&secret[offset..]))
        && !(1..marker.len()).any(|offset| secret.starts_with(&marker[offset..]))
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
        // The fixed window is five bytes, so a four-byte chunk is held whole
        // even though only its tail is a prefix of the secret.
        assert_eq!(redactor.push(b"xabc"), b"");
        assert_eq!(redactor.pending, b"xabc");
        assert_eq!(redactor.finish(), b"xabc");
        assert!(redactor.pending.is_empty());

        // A suffix that only looks like a prefix for a while is held for the
        // same fixed window and released at end of stream.
        let mut redactor = Redactor::new(b"abcdef");
        assert_eq!(redactor.push(b"abcx"), b"");
        assert_eq!(redactor.finish(), b"abcx");
    }

    #[test]
    fn the_holdback_window_does_not_depend_on_content() {
        // R.36: a correct partial prefix and a wrong guess of the same length
        // must be held for the same number of bytes. Otherwise the relay's
        // timing tells an agent how much of a guess was right.
        let secret = SECRET;
        let correct = &secret[..secret.len() - 1];
        let mut wrong = correct.to_vec();
        let last = wrong.len() - 1;
        wrong[last] ^= 0x01;
        assert!(!secret.starts_with(&wrong), "the fixture must be wrong");

        let mut correct_redactor = Redactor::new(secret);
        let mut wrong_redactor = Redactor::new(secret);
        let correct_out = correct_redactor.push(correct);
        let wrong_out = wrong_redactor.push(&wrong);
        assert_eq!(correct_out.len(), 0);
        assert_eq!(wrong_out.len(), correct_out.len());
        assert_eq!(correct_redactor.pending.len(), wrong_redactor.pending.len());

        // Longer than the window: both emit exactly the bytes above it.
        let mut correct_tail = correct.to_vec();
        correct_tail.extend_from_slice(b"tail!");
        let mut wrong_tail = wrong.clone();
        wrong_tail.extend_from_slice(b"tail!");
        let mut correct_redactor = Redactor::new(secret);
        let mut wrong_redactor = Redactor::new(secret);
        let correct_out = correct_redactor.push(&correct_tail);
        let wrong_out = wrong_redactor.push(&wrong_tail);
        assert_eq!(correct_out.len(), 5);
        assert_eq!(wrong_out.len(), correct_out.len());
        assert_eq!(correct_redactor.pending.len(), wrong_redactor.pending.len());
    }

    #[test]
    fn bytes_before_the_window_are_emitted_promptly() {
        let mut redactor = Redactor::new(b"abcdef");
        assert_eq!(redactor.push(b"01234567"), b"012");
        assert_eq!(redactor.pending, b"34567");
        assert_eq!(redactor.finish(), b"34567");
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

    /// R.36a: the marker is substituted for the value, so the text around it
    /// must not combine with it into the value. Each pair is a secret and an
    /// input that leaked `secret` under the old marker rule.
    #[test]
    fn the_marker_never_combines_with_surrounding_output() {
        let cases: &[(&[u8], &[u8])] = &[
            // A suffix of the marker is a prefix of the secret: the marker
            // supplies `TED]` and the following byte completes `TED]X`.
            (b"TED]X", b"TED]XX"),
            // The secret contains the marker: output before and after one
            // substitution supplies the pieces around it.
            (b"xx[REDACTED]yy", b"xxxx[REDACTED]yyyy"),
            // A suffix of the secret is a prefix of the marker: output emitted
            // just before the marker supplies `zz`, the marker `[REDACTED`.
            (b"zz[REDACTED", b"zzzz[REDACTED"),
            // Two substitutions next to each other: the first marker's suffix
            // and the second marker start the secret.
            (b"CTED][REDACT", b"CTED][REDACTCTED][REDACT"),
        ];
        for (secret, input) in cases {
            let out = redact(secret, input);
            assert!(
                !contains_subslice(&out, secret),
                "marker leaked {secret:?} in {out:?}"
            );

            // The same must hold byte at a time, so a chunk boundary cannot
            // assemble what whole-buffer redaction catches.
            let mut redactor = Redactor::new(secret);
            let mut streamed = Vec::new();
            for byte in *input {
                streamed.extend_from_slice(&redactor.push(&[*byte]));
                assert!(
                    !contains_subslice(&streamed, secret),
                    "streaming leaked {secret:?} in {streamed:?}"
                );
            }
            streamed.extend_from_slice(&redactor.finish());
            assert!(
                !contains_subslice(&streamed, secret),
                "streaming leaked {secret:?} in {streamed:?}"
            );
        }
    }

    #[test]
    fn a_secret_using_every_byte_value_still_gets_a_safe_marker() {
        // The default marker is buildable into this value, so a run of a byte
        // that is neither endpoint and appears only once is used; it is long
        // enough that the value cannot contain it.
        let mut secret: Vec<u8> = (0..=u8::MAX).rev().collect();
        secret.extend_from_slice(b"[REDACTED]");
        let marker = choose_marker_many(&[secret.clone()]);
        assert!(marker_is_safe(&marker, &secret), "unsafe marker");
        let out = redact(&secret, &secret);
        assert!(!contains_subslice(&out, &secret));
    }

    #[test]
    fn debug_never_contains_the_value() {
        let secret = b"super-secret-value";
        let text = format!("{:?}", Redactor::new_many(&[secret, b"other-value"]));
        assert!(text.contains("Redactor"), "{text}");
        assert!(text.contains("secrets"), "{text}");
        assert!(text.contains("max_len"), "{text}");
        assert!(!text.contains("super-secret-value"), "{text}");
        assert!(!text.contains("other-value"), "{text}");
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

    #[test]
    fn every_value_in_a_set_is_redacted_at_any_split() {
        let alpha = b"canary-ALPHA-8f3a";
        let beta = b"canary-BETA-91c7";
        let input = b"a canary-ALPHA-8f3a b canary-BETA-91c7 c";
        let expected = b"a [REDACTED] b [REDACTED] c";
        for split in 0..=input.len() {
            let mut redactor = Redactor::new_many(&[alpha.as_slice(), beta.as_slice()]);
            let mut out = redactor.push(&input[..split]);
            out.extend_from_slice(&redactor.push(&input[split..]));
            out.extend_from_slice(&redactor.finish());
            assert_eq!(out, expected, "split at offset {split}");
        }

        let mut redactor = Redactor::new_many(&[alpha.as_slice(), beta.as_slice()]);
        let mut out = Vec::new();
        for byte in input {
            out.extend_from_slice(&redactor.push(&[*byte]));
        }
        out.extend_from_slice(&redactor.finish());
        assert_eq!(out, expected, "byte at a time");
    }

    #[test]
    fn a_longer_value_containing_a_shorter_one_is_removed_whole() {
        let short = b"abcd";
        let long = b"abcdefgh";
        let out = redact_many(&[short.as_slice(), long.as_slice()], b"xabcdefghy");
        assert_eq!(out, b"x[REDACTED]y");
        let out = redact_many(&[short.as_slice(), long.as_slice()], b"xabcdy");
        assert_eq!(out, b"x[REDACTED]y");
    }

    #[test]
    fn overlapping_values_never_leave_a_complete_occurrence() {
        let left = b"abcdef";
        let right = b"defghi";
        let input = b"abcdefghi";
        for split in 0..=input.len() {
            let mut redactor = Redactor::new_many(&[left.as_slice(), right.as_slice()]);
            let mut out = redactor.push(&input[..split]);
            out.extend_from_slice(&redactor.push(&input[split..]));
            out.extend_from_slice(&redactor.finish());
            assert!(!contains_subslice(&out, left), "left at {split}: {out:?}");
            assert!(!contains_subslice(&out, right), "right at {split}: {out:?}");
        }
    }

    #[test]
    fn the_holdback_window_is_sized_by_the_longest_value() {
        let mut redactor = Redactor::new_many(&[b"abcd".as_slice(), b"0123456789ab".as_slice()]);
        // Ten bytes, but the longest value is twelve: nothing is safe to emit.
        assert!(redactor.push(b"zzzzzzzzzz").is_empty());
        assert_eq!(redactor.pending.len(), 10);
        assert_eq!(redactor.finish(), b"zzzzzzzzzz");
    }

    #[test]
    fn a_short_value_hidden_in_the_held_tail_is_redacted_at_end_of_stream() {
        let mut redactor = Redactor::new_many(&[b"abcd".as_slice(), b"0123456789ab".as_slice()]);
        // The tail is held because a twelve-byte value might still follow, but
        // it already contains a complete four-byte value.
        assert!(redactor.push(b"xxabcd").is_empty());
        assert_eq!(redactor.finish(), b"xx[REDACTED]");
    }

    #[test]
    fn one_marker_is_safe_for_every_value_in_the_set() {
        // Both values collide with the default marker: the second one is built
        // out of it and the first one contains it.
        let secrets: &[&[u8]] = &[b"[REDACTED]", b"TED]XY"];
        for secret in secrets {
            let out = redact_many(secrets, secret);
            for value in secrets {
                assert!(!contains_subslice(&out, value), "{value:?} in {out:?}");
            }

            let mut redactor = Redactor::new_many(secrets);
            let mut streamed = Vec::new();
            for byte in *secret {
                streamed.extend_from_slice(&redactor.push(&[*byte]));
            }
            streamed.extend_from_slice(&redactor.finish());
            for value in secrets {
                assert!(
                    !contains_subslice(&streamed, value),
                    "streamed {value:?} in {streamed:?}"
                );
            }
        }
    }

    #[test]
    fn the_redaction_count_covers_every_substitution() {
        let alpha = b"canary-alpha-11";
        let beta = b"canary-beta-22";
        let mut redactor = Redactor::new_many(&[alpha.as_slice(), beta.as_slice()]);
        let mut out = redactor.push(b"canary-alpha-11 canary-beta-22 canary-alpha-11");
        out.extend_from_slice(&redactor.finish());
        assert_eq!(out, b"[REDACTED] [REDACTED] [REDACTED]");
        assert_eq!(redactor.redactions(), 3);
    }

    #[test]
    fn an_empty_set_is_a_passthrough() {
        let data = b"\x00\xffnothing to redact";
        assert_eq!(redact_many(&[], data), data);
        assert_eq!(redact_many(&[b"".as_slice(), b"".as_slice()], data), data);
        let mut redactor = Redactor::new_many(&[]);
        assert_eq!(redactor.push(data), data);
        assert!(redactor.finish().is_empty());
    }
}
