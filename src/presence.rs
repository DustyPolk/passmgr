//! Proof that a human with the master password is present.
//!
//! Creating or approving a grant must not be something an agent (or any other
//! same-user process) can do on its own. The daemon already holds the derived
//! vault key, so "the caller knows the key" is not a property a client can
//! prove by simply being allowed to talk to the socket. The human's `pm`
//! process instead derives the key *itself* from the master password and
//! proves knowledge of it with a MAC:
//!
//! ```text
//! proof = HMAC-SHA256(vault_key, "passmgr-approve-v1" || nonce || digest)
//! ```
//!
//! - `nonce` is a fresh 32-byte value the daemon issues per approval and
//!   accepts at most once, for [`CHALLENGE_LIFETIME`]. A recorded proof is
//!   useless afterwards, so the MAC can travel over the socket.
//! - `digest` commits the proof to the exact request being approved (the
//!   grant fields, in TODO 3.4), so a proof harvested for one approval cannot
//!   authorize a different one. A successful verification stores that digest
//!   as a one-shot approval ([`Approvals`]); the request that actually writes
//!   must consume the same digest, so "a human proved something" can never be
//!   read as "whatever you ask next is approved".
//! - The domain prefix keeps this MAC from doubling as any other MAC computed
//!   with the vault key.
//!
//! Verification is constant-time ([`Proof::verify`] uses the `hmac` crate's
//! constant-time tag check), and the key never leaves the two processes that
//! already have it.
//!
//! # What this does not protect against
//!
//! A process that can read the master password (a keylogger, or an agent with
//! an interpreter in its command allowlist) can produce a valid proof. That is
//! the documented same-user limit; presence proof makes *silent* grant
//! minting impossible, not a compromised owner account safe.

use std::fmt;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Domain separation string, part of the MAC message.
pub const DOMAIN: &[u8] = b"passmgr-approve-v1";
/// Random bytes in a challenge nonce.
pub const NONCE_BYTES: usize = 32;
/// Bytes in the MAC that proves key knowledge.
pub const PROOF_BYTES: usize = 32;
/// Bytes in the digest of the request being approved.
pub const DIGEST_BYTES: usize = 32;
/// How long a challenge nonce may be used after it was issued.
pub const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);
/// Most nonces the daemon keeps outstanding at once.
///
/// Bounds the memory a client can make the daemon hold, and the number of
/// proofs that could still be replayed. Sixteen is far more than one human
/// needs; the oldest-free window is one [`CHALLENGE_LIFETIME`].
///
/// Reaching the cap never refuses a new nonce: the **oldest** pending one is
/// evicted instead. Spending a nonce keeps the rest in issue order, so
/// "oldest" stays true while several approvals are in flight. A `challenge`
/// request only needs the session token, which
/// any same-user process can read, so a client that asked for sixteen nonces
/// must not be able to lock the human out of the one path that mints a grant.
/// The residual risk is documented in [`Challenges::issue`].
pub const MAX_PENDING_CHALLENGES: usize = 16;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// A fresh random value the daemon issues for one approval.
///
/// The nonce is not secret: it is sent to the requester in the clear and is
/// only a replay guard. Comparisons still go through [`Self::matches`] so a
/// caller cannot accidentally introduce a timing side channel on it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChallengeNonce([u8; NONCE_BYTES]);

impl ChallengeNonce {
    /// Draw a nonce from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, PresenceError> {
        let mut bytes = [0u8; NONCE_BYTES];
        getrandom::fill(&mut bytes).map_err(|err| PresenceError::Random(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Parse the lowercase hex form used on the wire.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = decode_hex(text, NONCE_BYTES)?;
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&bytes);
        Some(Self(nonce))
    }

    /// The lowercase hex form sent to the requester and echoed back.
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// The raw bytes, for the MAC message.
    pub fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }

    /// Compare two nonces without an early exit.
    pub fn matches(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for ChallengeNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A nonce is public; showing it makes failed-proof diagnostics useful.
        write!(f, "ChallengeNonce({})", self.to_hex())
    }
}

/// A digest of the request an approval proof is bound to.
///
/// The digest is public (it is sent alongside the proof and can be recomputed
/// from the approved parameters); TODO 3.4 computes it over the grant fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestDigest([u8; DIGEST_BYTES]);

impl RequestDigest {
    /// Wrap an already-computed digest.
    pub fn new(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parse the lowercase hex form used on the wire.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = decode_hex(text, DIGEST_BYTES)?;
        let mut digest = [0u8; DIGEST_BYTES];
        digest.copy_from_slice(&bytes);
        Some(Self(digest))
    }

    /// The lowercase hex form.
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// The raw bytes, for the MAC message.
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestDigest({})", self.to_hex())
    }
}

/// Proof of vault-key (and therefore master-password) knowledge.
///
/// The bytes are key-derived, so they are zeroized on drop, never rendered by
/// `Debug`, and compared only in constant time. Equality is implemented as
/// [`Self::matches`] so deriving `PartialEq` on protocol types cannot leak the
/// MAC byte by byte; there is no `Display`.
#[derive(Clone)]
pub struct Proof(Zeroizing<[u8; PROOF_BYTES]>);

impl Proof {
    /// Compute the proof for `nonce` and `digest` under `key`.
    ///
    /// HMAC accepts a key of any length, so the only failure left is a broken
    /// HMAC implementation, which is reported rather than panicked on.
    pub fn compute(
        key: &[u8],
        nonce: &ChallengeNonce,
        digest: &RequestDigest,
    ) -> Result<Self, PresenceError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).map_err(|_| PresenceError::UnusableKey)?;
        mac.update(DOMAIN);
        mac.update(nonce.as_bytes());
        mac.update(digest.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut proof = Zeroizing::new([0u8; PROOF_BYTES]);
        proof.copy_from_slice(&bytes);
        Ok(Self(proof))
    }

    /// Check this proof against `key`, `nonce` and `digest`, in constant time.
    pub fn verify(&self, key: &[u8], nonce: &ChallengeNonce, digest: &RequestDigest) -> bool {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
            return false;
        };
        mac.update(DOMAIN);
        mac.update(nonce.as_bytes());
        mac.update(digest.as_bytes());
        // `verify_slice` compares the tag without an early exit.
        mac.verify_slice(self.0.as_slice()).is_ok()
    }

    /// Parse the lowercase hex form used on the wire.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = decode_hex(text, PROOF_BYTES)?;
        let mut proof = Zeroizing::new([0u8; PROOF_BYTES]);
        proof.copy_from_slice(&bytes);
        Some(Self(proof))
    }

    /// The lowercase hex form, in zeroizing storage like the bytes.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_hex(self.0.as_slice()))
    }

    /// Compare two proofs without an early exit.
    pub fn matches(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_slice(), other.0.as_slice())
    }
}

impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for Proof {}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render key-derived bytes, not even a prefix or a length hint.
        f.write_str("Proof(<redacted>)")
    }
}

/// Why a challenge or approval could not be issued or accepted.
///
/// The variants are for the daemon's own logging, tests and the write request
/// that consumes an approval. A client only ever sees one `denied` answer for
/// a bad proof: distinguishing "unknown", "expired" and "wrong proof" would
/// tell a peer probing the socket which part of its guess was right, and the
/// human has no use for the difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// No challenge with this nonce is outstanding (never issued or already
    /// spent).
    UnknownChallenge,
    /// The nonce is real but older than [`CHALLENGE_LIFETIME`].
    ExpiredChallenge,
    /// No unconsumed approval matches this digest (never approved, already
    /// consumed by an earlier write, or expired).
    NotApproved,
    /// The operating system's CSPRNG failed.
    Random(String),
    /// The HMAC implementation refused the key length (never for HMAC-SHA256).
    UnusableKey,
}

impl fmt::Display for PresenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChallenge => f.write_str("unknown or already used challenge"),
            Self::ExpiredChallenge => f.write_str("challenge has expired"),
            Self::NotApproved => f.write_str("no approval for this request"),
            Self::Random(detail) => write!(f, "could not generate a challenge: {detail}"),
            Self::UnusableKey => f.write_str("the key cannot be used for HMAC-SHA256"),
        }
    }
}

impl std::error::Error for PresenceError {}

/// Outstanding challenge nonces, with single-use and expiry enforced.
///
/// This is deliberately a plain in-memory structure owned by the daemon: a
/// nonce is worthless after a restart because the client can no longer get a
/// proof accepted for it anyway (the daemon would answer `denied`), and
/// persisting it would only create a new file to protect.
#[derive(Debug, Default)]
pub struct Challenges {
    pending: Vec<Pending>,
}

#[derive(Debug)]
struct Pending {
    nonce: ChallengeNonce,
    issued: Instant,
}

impl Challenges {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a fresh nonce, pruning expired ones first.
    ///
    /// This never refuses because the pool is full: when
    /// [`MAX_PENDING_CHALLENGES`] unexpired nonces are outstanding the oldest
    /// is evicted so the new one always fits. A caller that lost its nonce
    /// this way gets the ordinary `denied` on `prove` and simply asks again.
    ///
    /// The eviction policy is deliberately the oldest, not "whoever holds
    /// the most": the socket cannot tell the human's `pm` process from an
    /// agent (same UID, same session token, a new connection per request), so
    /// any cleverer rule would be spoofable or would need an identity that
    /// does not exist. The policy guarantees that a *single* burst of
    /// challenges — the realistic accident, e.g. an agent retrying in a loop
    /// — cannot block a human who asks afterwards. A peer that keeps issuing
    /// challenges faster than one per human round trip can still evict a
    /// fresh nonce, exactly as it could already kill `pmd` or hold the socket:
    /// that is the documented same-user DoS limit (`SECURITY.md`), not a
    /// privilege escalation.
    ///
    /// `now` is injected so expiry is testable without sleeping.
    pub fn issue(&mut self, now: Instant) -> Result<ChallengeNonce, PresenceError> {
        self.prune(now);
        // `pending` is in issue order, so index 0 is the oldest nonce and the
        // only one whose loss costs the least: it was issued longest ago and
        // has the least chance of a proof being in flight for it.
        if self.pending.len() >= MAX_PENDING_CHALLENGES {
            self.pending.remove(0);
        }
        let nonce = ChallengeNonce::generate()?;
        self.pending.push(Pending { nonce, issued: now });
        Ok(nonce)
    }

    /// Spend `nonce`, accepting it only once and only while fresh.
    ///
    /// The nonce is removed on *every* outcome, including expiry and an
    /// unknown value: a caller that fails the accompanying proof cannot retry
    /// against the same challenge, so one issue allows one attempt.
    ///
    /// Removal preserves issue order, even when the spent nonce is not the
    /// newest. [`Self::issue`] evicts index 0 as "the oldest", so a swap with
    /// the last entry would move the newest nonce to the front and the next
    /// full pool would evict that instead (TODO R.19). The pool holds at most
    /// [`MAX_PENDING_CHALLENGES`] entries, so the memmove is irrelevant.
    pub fn verify_and_consume(
        &mut self,
        nonce: &ChallengeNonce,
        now: Instant,
    ) -> Result<(), PresenceError> {
        let Some(index) = self
            .pending
            .iter()
            .position(|pending| pending.nonce.matches(nonce))
        else {
            return Err(PresenceError::UnknownChallenge);
        };
        let pending = self.pending.remove(index);
        if now.saturating_duration_since(pending.issued) >= CHALLENGE_LIFETIME {
            return Err(PresenceError::ExpiredChallenge);
        }
        Ok(())
    }

    /// Number of nonces still outstanding (including expired, unpruned ones).
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn prune(&mut self, now: Instant) {
        self.pending
            .retain(|pending| now.saturating_duration_since(pending.issued) < CHALLENGE_LIFETIME);
    }
}

/// Most digests a human may have approved but no write has consumed yet.
///
/// Bounds both memory and the window in which an unconsumed approval still
/// authorizes its write. Only a caller that can compute a valid proof can add
/// one, so this cap cannot be used to starve a human (unlike the challenge
/// pool); when it is full the **oldest** approval is dropped, because the one
/// a human just made is the interesting one.
pub const MAX_PENDING_APPROVALS: usize = 16;

/// Digests a human proved and a write must still consume.
///
/// A successful `prove` calls [`Self::record`]; it does **not** authorize
/// anything by itself. The request that performs the write must call
/// [`Self::take`] with the digest of exactly what it is about to do, and may
/// proceed only on `Ok`. The entry is removed on that one success, so the same
/// approval cannot authorize a second write, and a probe with a different
/// digest leaves the human's real approval untouched.
///
/// Like [`Challenges`], this lives only in daemon memory: after a restart the
/// client cannot get a proof accepted anyway, and persisting approvals would
/// add a file to protect for no benefit.
#[derive(Debug, Default)]
pub struct Approvals {
    pending: Vec<Approved>,
}

#[derive(Debug)]
struct Approved {
    digest: RequestDigest,
    issued: Instant,
}

impl Approvals {
    /// No outstanding approvals.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a human proved `digest` at `now`.
    ///
    /// Expired entries are pruned first; if the store is then full the oldest
    /// entry makes room. `now` is injected so expiry and eviction are testable
    /// without sleeping.
    pub fn record(&mut self, digest: RequestDigest, now: Instant) {
        self.prune(now);
        if self.pending.len() >= MAX_PENDING_APPROVALS {
            self.pending.remove(0);
        }
        self.pending.push(Approved {
            digest,
            issued: now,
        });
    }

    /// Consume the one-shot approval for exactly `digest`.
    ///
    /// `Ok` means a human approved this exact request within
    /// [`CHALLENGE_LIFETIME`] and this call spent the approval. Any other
    /// digest is [`PresenceError::NotApproved`] and does not disturb the
    /// approval that is waiting; expired approvals are pruned either way.
    pub fn take(&mut self, digest: &RequestDigest, now: Instant) -> Result<(), PresenceError> {
        self.prune(now);
        let Some(index) = self
            .pending
            .iter()
            .position(|approved| approved.digest == *digest)
        else {
            return Err(PresenceError::NotApproved);
        };
        self.pending.remove(index);
        Ok(())
    }

    /// Number of approvals still stored (including expired, unpruned ones).
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn prune(&mut self, now: Instant) {
        self.pending
            .retain(|approved| now.saturating_duration_since(approved.issued) < CHALLENGE_LIFETIME);
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Strict lowercase hex of exactly `expected` bytes; `None` otherwise.
fn decode_hex(text: &str, expected: usize) -> Option<Vec<u8>> {
    if text.len() != expected * 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(expected);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = lowercase_hex_digit(pair[0])?;
        let low = lowercase_hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn lowercase_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(start: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = start + index as u8;
        }
        bytes
    }

    fn test_digest(start: u8) -> RequestDigest {
        RequestDigest::new(bytes(start))
    }

    fn test_nonce(start: u8) -> ChallengeNonce {
        ChallengeNonce(bytes(start))
    }

    /// Independent oracle: Python's `hmac.new(key,
    /// b"passmgr-approve-v1" + nonce + digest, sha256)`. Pinning the value
    /// proves the domain prefix, field order and hash function, not just that
    /// compute and verify agree with each other.
    #[test]
    fn proof_matches_an_independent_hmac_sha256_vector() {
        let key = [0x0bu8; 32];
        let nonce = ChallengeNonce::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("nonce");
        let digest = RequestDigest::from_hex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        )
        .expect("digest");

        let proof = Proof::compute(&key, &nonce, &digest).expect("compute");
        assert_eq!(
            proof.to_hex().as_str(),
            "3596124510e1fbd47cc55655696b177e71c511593ca8dde627eacf964a1e3f4c"
        );
        assert!(proof.verify(&key, &nonce, &digest));
    }

    #[test]
    fn proof_is_bound_to_the_key_nonce_and_digest() {
        let key = [7u8; 32];
        let nonce = test_nonce(0);
        let digest = test_digest(32);
        let proof = Proof::compute(&key, &nonce, &digest).expect("compute");

        assert!(proof.verify(&key, &nonce, &digest));
        assert!(!proof.verify(&[8u8; 32], &nonce, &digest), "wrong key");
        assert!(
            !proof.verify(&key, &test_nonce(1), &digest),
            "different nonce"
        );
        assert!(
            !proof.verify(&key, &nonce, &test_digest(33)),
            "different digest"
        );

        let tampered = Proof::from_hex(&{
            let mut hex = proof.to_hex().to_string();
            // Flip the last hex nibble: 0 <-> 1, otherwise 0.
            let last = hex.pop().expect("hex");
            hex.push(if last == '0' { '1' } else { '0' });
            hex
        })
        .expect("tampered proof");
        assert!(!tampered.verify(&key, &nonce, &digest), "altered proof");
    }

    #[test]
    fn nonce_and_digest_hex_round_trip_and_reject_other_forms() {
        let nonce = test_nonce(9);
        let digest = test_digest(41);
        assert!(
            ChallengeNonce::from_hex(&nonce.to_hex())
                .expect("nonce hex")
                .matches(&nonce)
        );
        assert_eq!(RequestDigest::from_hex(&digest.to_hex()), Some(digest));

        let upper = nonce.to_hex().to_uppercase();
        assert!(ChallengeNonce::from_hex(&upper).is_none(), "uppercase hex");
        assert!(RequestDigest::from_hex(&upper).is_none(), "uppercase hex");
        assert!(
            ChallengeNonce::from_hex(&nonce.to_hex()[1..]).is_none(),
            "short hex"
        );
        assert!(
            RequestDigest::from_hex(&format!("{}00", digest.to_hex())).is_none(),
            "long hex"
        );
        assert!(Proof::from_hex(&upper).is_none(), "uppercase hex");
        assert!(Proof::from_hex(&"0".repeat(63)).is_none(), "short hex");
    }

    #[test]
    fn proof_hex_round_trips() {
        let proof = Proof::compute(&[1u8; 32], &test_nonce(0), &test_digest(32)).expect("compute");
        let parsed = Proof::from_hex(proof.to_hex().as_str()).expect("parse proof");
        assert_eq!(parsed, proof);
    }

    #[test]
    fn challenge_is_single_use() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        let nonce = challenges.issue(now).expect("issue");
        assert_eq!(
            challenges.verify_and_consume(&nonce, now + Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(
            challenges.verify_and_consume(&nonce, now + Duration::from_secs(1)),
            Err(PresenceError::UnknownChallenge)
        );
        assert_eq!(challenges.pending(), 0);
    }

    #[test]
    fn challenge_expires_after_sixty_seconds() {
        let now = Instant::now();
        let mut challenges = Challenges::new();

        let fresh = challenges.issue(now).expect("issue");
        assert_eq!(
            challenges.verify_and_consume(&fresh, now + Duration::from_secs(59)),
            Ok(())
        );

        let stale = challenges.issue(now).expect("issue");
        assert_eq!(
            challenges.verify_and_consume(&stale, now + CHALLENGE_LIFETIME),
            Err(PresenceError::ExpiredChallenge)
        );
        // Expiry still spends the nonce: it cannot be retried with a clock
        // that claims it is young again.
        assert_eq!(
            challenges.verify_and_consume(&stale, now),
            Err(PresenceError::UnknownChallenge)
        );
    }

    #[test]
    fn an_unknown_nonce_is_rejected() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        let issued = challenges.issue(now).expect("issue");
        let unknown = test_nonce(200);
        assert_ne!(unknown.to_hex(), issued.to_hex());
        assert_eq!(
            challenges.verify_and_consume(&unknown, now),
            Err(PresenceError::UnknownChallenge)
        );
        assert_eq!(challenges.pending(), 1, "the real nonce is untouched");
    }

    #[test]
    fn a_full_challenge_pool_evicts_the_oldest_instead_of_refusing() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        let mut issued = Vec::new();
        for _ in 0..MAX_PENDING_CHALLENGES {
            issued.push(challenges.issue(now).expect("issue within the cap"));
        }

        // The seventeenth request succeeds: asking for nonces must never be a
        // way to deny a human the challenge they need to approve anything.
        let newest = challenges
            .issue(now)
            .expect("a full pool evicts the oldest instead of failing");
        assert_eq!(challenges.pending(), MAX_PENDING_CHALLENGES);

        // Exactly the oldest went away; the next-oldest and the newest work.
        assert_eq!(
            challenges.verify_and_consume(&issued[0], now),
            Err(PresenceError::UnknownChallenge)
        );
        assert_eq!(challenges.verify_and_consume(&issued[1], now), Ok(()));
        assert_eq!(challenges.verify_and_consume(&newest, now), Ok(()));
    }

    #[test]
    fn consuming_the_oldest_nonce_keeps_the_oldest_survivor_evictable() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        let mut issued = Vec::new();
        for _ in 0..MAX_PENDING_CHALLENGES {
            issued.push(challenges.issue(now).expect("issue within the cap"));
        }

        // Spend the oldest nonce: a `swap_remove` would move the *newest*
        // nonce into index 0 and the next eviction would destroy that one
        // instead of the oldest survivor.
        assert_eq!(challenges.verify_and_consume(&issued[0], now), Ok(()));
        let refill = challenges.issue(now).expect("refill the freed slot");
        assert_eq!(challenges.pending(), MAX_PENDING_CHALLENGES);
        let newest = challenges
            .issue(now)
            .expect("a full pool evicts the oldest");

        // Eviction must take the oldest survivor (issued[1]); everything issued
        // after the consumption survives.
        assert_eq!(
            challenges.verify_and_consume(&issued[1], now),
            Err(PresenceError::UnknownChallenge),
            "the oldest survivor is the one evicted"
        );
        assert_eq!(challenges.verify_and_consume(&issued[2], now), Ok(()));
        assert_eq!(challenges.verify_and_consume(&refill, now), Ok(()));
        assert_eq!(challenges.verify_and_consume(&newest, now), Ok(()));
    }

    #[test]
    fn consuming_a_middle_nonce_leaves_the_oldest_at_index_zero() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        let mut issued = Vec::new();
        for _ in 0..MAX_PENDING_CHALLENGES {
            issued.push(challenges.issue(now).expect("issue within the cap"));
        }

        // Two approvals in flight: spend a middle nonce, then force an
        // eviction. Whatever the internal order, the oldest *unspent* nonce
        // (issued[0]) must be the one that goes, and the newer ones stay.
        assert_eq!(challenges.verify_and_consume(&issued[1], now), Ok(()));
        let refill = challenges.issue(now).expect("refill the freed slot");
        let newest = challenges
            .issue(now)
            .expect("a full pool evicts the oldest");
        assert_eq!(
            challenges.verify_and_consume(&issued[0], now),
            Err(PresenceError::UnknownChallenge),
            "issued[0] is the oldest unspent nonce"
        );
        assert_eq!(challenges.verify_and_consume(&refill, now), Ok(()));
        assert_eq!(challenges.verify_and_consume(&newest, now), Ok(()));
    }

    #[test]
    fn expired_challenges_are_pruned_before_a_fresh_one_is_evictable() {
        let now = Instant::now();
        let mut challenges = Challenges::new();
        for _ in 0..MAX_PENDING_CHALLENGES {
            challenges.issue(now).expect("issue within the cap");
        }

        // A minute later every old nonce is expired: they are pruned first, so
        // a nonce issued now is alone in the pool rather than competing with
        // sixteen dead entries.
        let later = now + CHALLENGE_LIFETIME;
        let fresh = challenges.issue(later).expect("issue after expiry");
        assert_eq!(challenges.pending(), 1);
        assert_eq!(challenges.verify_and_consume(&fresh, later), Ok(()));
    }

    #[test]
    fn debug_never_renders_the_proof() {
        let proof = Proof::compute(&[3u8; 32], &test_nonce(0), &test_digest(32)).expect("compute");
        let rendered = format!("{proof:?}");
        assert_eq!(rendered, "Proof(<redacted>)");
        assert!(!rendered.contains(proof.to_hex().as_str()));

        // Nonce and digest are public and may be shown, which keeps test
        // failures readable.
        let nonce = test_nonce(0);
        let digest = test_digest(32);
        assert!(format!("{nonce:?}").contains(&nonce.to_hex()));
        assert!(format!("{digest:?}").contains(&digest.to_hex()));
    }

    #[test]
    fn an_approval_is_bound_to_its_digest_and_spent_exactly_once() {
        let now = Instant::now();
        let approved = test_digest(0);
        let other = test_digest(64);
        let mut approvals = Approvals::new();
        approvals.record(approved, now);

        // A different request is refused and does not consume the human's
        // approval: the write for the approved digest still works.
        assert_eq!(approvals.take(&other, now), Err(PresenceError::NotApproved));
        assert_eq!(approvals.pending(), 1);
        assert_eq!(approvals.take(&approved, now), Ok(()));
        assert_eq!(approvals.pending(), 0);

        // The same approval cannot authorize a second write.
        assert_eq!(
            approvals.take(&approved, now),
            Err(PresenceError::NotApproved)
        );
    }

    #[test]
    fn an_approval_expires_after_sixty_seconds() {
        let now = Instant::now();
        let digest = test_digest(0);
        let mut approvals = Approvals::new();

        approvals.record(digest, now);
        assert_eq!(
            approvals.take(&digest, now + Duration::from_secs(59)),
            Ok(())
        );

        approvals.record(digest, now);
        assert_eq!(
            approvals.take(&digest, now + CHALLENGE_LIFETIME),
            Err(PresenceError::NotApproved)
        );
        assert_eq!(approvals.pending(), 0, "an expired approval is pruned");
    }

    #[test]
    fn approvals_are_bounded_and_the_oldest_makes_room() {
        let now = Instant::now();
        let mut approvals = Approvals::new();
        let oldest = test_digest(0);
        approvals.record(oldest, now);
        for index in 1..MAX_PENDING_APPROVALS {
            approvals.record(test_digest(index as u8), now);
        }
        let newest = test_digest(MAX_PENDING_APPROVALS as u8);
        approvals.record(newest, now);

        assert_eq!(approvals.pending(), MAX_PENDING_APPROVALS);
        assert_eq!(
            approvals.take(&oldest, now),
            Err(PresenceError::NotApproved),
            "the oldest approval made room",
        );
        assert_eq!(approvals.take(&newest, now), Ok(()));
    }
}
