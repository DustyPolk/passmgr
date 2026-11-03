//! Wire protocol between `pm` and the unlock daemon (`pmd`).
//!
//! The transport is a Unix socket (TODO 2.2), so the protocol has to frame
//! messages itself. Every frame is a 4-byte big-endian length followed by that
//! many bytes of UTF-8 JSON:
//!
//! ```text
//! u32 length | length bytes of JSON
//! ```
//!
//! The JSON envelope is `{"version":3,"token":"<64 hex>","request":{...}}`.
//! The `token` is the unlock session token (see [`crate::token`]) and is
//! required on every request; the daemon rejects a missing or mismatched one
//! with `unauthorized`. The `request` object always has a `"type"` field; the
//! types this version knows are `ping`, `lock`, `run`, `challenge` and
//! `prove`:
//!
//! ```json
//! {"version":3,"token":"...","request":{"type":"ping"}}
//! {"version":3,"token":"...","request":{"type":"lock"}}
//! {"version":3,"token":"...","request":{"type":"run","env":"API_KEY",
//!                         "ref":"pm://00112233445566778899aabbccddeeff",
//!                         "command":["/usr/bin/curl","-s","https://example.test"],
//!                         "cwd":"/home/alice/project"}}
//! {"version":3,"token":"...","request":{"type":"challenge"}}
//! {"version":3,"token":"...","request":{"type":"prove","nonce":"<64 hex>",
//!                         "digest":"<64 hex>","proof":"<64 hex>"}}
//! ```
//!
//! `challenge`/`prove` are the human-presence proof (TODO 3.3): the daemon
//! issues a single-use nonce and accepts a key-derived MAC over it exactly
//! once. Neither request carries a secret value; see [`crate::presence`].
//!
//! Version 2 added the required `token` field, so it is not backward
//! compatible with version 1 (a version-1 peer would be treated as an
//! unsigned request). Version 3 added the required `run.cwd` field and
//! requires `run.command[0]` to be an absolute path, so a version-2 daemon
//! would run the child in the wrong directory. Older versions are refused
//! with `unsupported_version`.
//!
//! # There is no plaintext request type
//!
//! The daemon holds the vault key, and any same-user process can connect to
//! the socket, so a client-side check would protect nothing. Consequently no
//! request type returns a secret value: the daemon injects the secret into a
//! child process for `run` and relays only redacted output. This module never
//! carries a secret in either direction; unknown request types are rejected.
//!
//! # The `run` response stream
//!
//! `run` is answered with a stream of [`RunFrame`]s rather than one response:
//! zero or more `stdout`/`stderr` chunks, then exactly one terminal frame —
//! either `exit` (`code` or `signal`) or `error` (`not_found`,
//! `spawn_failed`, `bad_request`). Chunk payloads are hex-encoded so arbitrary
//! child bytes survive JSON, and each chunk is capped at [`MAX_CHUNK_BYTES`]
//! so one frame always fits in [`MAX_MESSAGE_BYTES`].
//!
//! The stream is a **separate type** ([`RunFrame`]) from the one-shot
//! [`Response`]: a `ping` can never answer with child output, and a `run`
//! stream can never answer with `pong`. [`RunStream`] enforces the ordering
//! rule (nothing after a terminal frame) for the reader.
//!
//! What travels in `stdout`/`stderr` is ordinary child output that `pmd` has
//! already passed through [`crate::redact::Redactor`]; the daemon redacts
//! before encoding, and nothing in this module can tell whether a byte is a
//! secret. A chunk is therefore *not* zeroized or treated as secret here (it
//! is the redacted, agent-visible text), but it is still never rendered by
//! `Debug`.
//!
//! # Untrusted input
//!
//! Every function here is pure (it performs no I/O) and treats its input as
//! attacker-controlled: the declared length is range-checked *before* any
//! slice or allocation is made from it, the message body is capped at
//! [`MAX_MESSAGE_BYTES`], and JSON is parsed with a fixed schema. Malformed
//! input yields [`ProtocolError`], never a panic.
//!
//! # Forward compatibility
//!
//! Unknown *fields* are ignored (a later version may add a field without
//! breaking older peers). Unknown request *types* and unknown envelope
//! *versions* are hard errors, because guessing at semantics is not safe.
//! Adding the required `token` field bumped the version, so a version-1 peer
//! is refused instead of silently being served as if it were authenticated.

use std::fmt;

use crate::presence::{ChallengeNonce, Proof, RequestDigest};
use crate::store::EntryId;
use crate::token::SessionToken;

mod codec;
mod response;

/// Frame splitting is shared with [`response`], which decodes its own bodies.
use codec::split_frame;
pub use codec::{FrameDecoder, decode, encode};
pub use response::{
    Response, ResponseError, RunExit, RunFrame, RunStream, decode_response, decode_run_frame,
    encode_response, encode_run_frame,
};

/// The protocol version carried in every envelope. Bump it when a change is
/// not backward compatible.
///
/// Version 3 added the required `run.cwd` field and requires `run.command[0]`
/// to be an absolute path. A version-2 daemon would ignore `cwd` and execute
/// the program in its own working directory, so the bump turns a silent
/// mismatch into a refusal that tells the human to restart the daemon.
pub const PROTOCOL_VERSION: u32 = 3;

/// Largest accepted frame body. 64 KiB is far more than any request needs and
/// bounds the memory a peer can make the daemon allocate.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Size of the big-endian length prefix in bytes.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Upper bound on what a [`FrameDecoder`] will buffer before the caller drains
/// it: two maximum-size frames, so a read may legitimately contain more than
/// one frame.
pub const MAX_BUFFERED_BYTES: usize = 2 * (LENGTH_PREFIX_BYTES + MAX_MESSAGE_BYTES);

/// Longest accepted environment variable name.
pub const MAX_ENV_NAME_BYTES: usize = 128;
/// Longest accepted `pm://` reference.
pub const MAX_REFERENCE_BYTES: usize = 128;
/// Longest accepted single argument in a `run` command.
pub const MAX_ARG_BYTES: usize = 4096;
/// Longest accepted `run.cwd` (the caller's absolute working directory).
pub const MAX_PATH_BYTES: usize = 4096;
/// Most arguments accepted in a `run` command (including `argv[0]`).
pub const MAX_ARGS: usize = 256;
/// Largest raw payload carried by one `stdout`/`stderr` frame. Hex encoding
/// doubles it, and the JSON envelope adds only a few dozen bytes, so a
/// maximum chunk stays far below [`MAX_MESSAGE_BYTES`].
pub const MAX_CHUNK_BYTES: usize = 16 * 1024;
/// Largest signal number accepted in an `exit` frame. Real Unix signals are
/// below this on every supported platform; anything else is refused rather
/// than passed to a caller that may use it as an exit status.
pub const MAX_SIGNAL: u8 = 127;

/// How much of an unknown request type is echoed back in an error message.
pub(super) const MAX_TYPE_CHARS: usize = 32;

/// A request from a `pm` client to the daemon.
///
/// None of these variants carries a secret value; `run` names the reference to
/// inject and the command to run, and the daemon resolves the value itself.
/// `challenge`/`prove` carry only a public nonce, a public digest and a MAC;
/// see [`crate::presence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Liveness check. The daemon answers without touching the vault.
    Ping,
    /// Wipe the key and shut down.
    Lock,
    /// Spawn `command` with `env` set to the value of `reference`.
    Run(RunRequest),
    /// Issue a single-use nonce for a human-presence proof. Answer: [`Response::Challenge`](crate::protocol::Response::Challenge).
    Challenge,
    /// Present a proof of vault-key knowledge for a challenge.
    ///
    /// Answer: `proven` only after the daemon has recorded `digest` as a
    /// one-shot approval, or `denied` for every bad nonce or MAC. `proven`
    /// authorizes nothing by itself; the write for that request must present
    /// the same digest and consumes the approval exactly once.
    Prove(ProveRequest),
}

/// The `prove` payload: a MAC over a nonce and the digest of the request the
/// human is approving.
///
/// The proof is key-derived, so its `Debug` is redacted and equality is
/// constant-time (see [`crate::presence::Proof`]). The nonce and digest are
/// public values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveRequest {
    /// The nonce the daemon issued and has not yet spent.
    pub nonce: ChallengeNonce,
    /// Digest of the request the human is approving.
    pub digest: RequestDigest,
    /// `HMAC-SHA256(vault_key, DOMAIN || nonce || digest)`.
    pub proof: Proof,
}

/// The `run` payload: inject `reference`'s value as `env` for `command`.
///
/// `cwd` is the **caller's** working directory, not the daemon's. The daemon
/// runs the child there, so relative arguments mean what the caller meant.
/// `command[0]` must be an absolute path: the daemon never resolves a program
/// through its own `PATH`, which belongs to the shell that ran `unlock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    /// Environment variable name in the child process.
    pub env: String,
    /// `pm://<32 hex chars>` reference of the credential to inject.
    pub reference: String,
    /// Argument vector; `command[0]` is an absolute path to the program.
    pub command: Vec<String>,
    /// Absolute working directory the child starts in (the caller's cwd).
    pub cwd: String,
}

/// A request together with the session token that authorized it.
///
/// [`decode`] only produces this after the envelope's `token` field parsed as
/// a [`SessionToken`]; the daemon then compares it with its own token before
/// looking at the request. The token's `Debug` is redacted, so deriving
/// `Debug` here cannot leak it.
#[derive(Clone, Debug)]
pub struct AuthenticatedRequest {
    token: SessionToken,
    request: Request,
}

impl AuthenticatedRequest {
    /// Pair a token with a request (used by clients before encoding).
    pub fn new(token: SessionToken, request: Request) -> Self {
        Self { token, request }
    }

    /// The session token the peer presented.
    pub fn token(&self) -> &SessionToken {
        &self.token
    }

    /// The request the peer wants served.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Consume the pair, keeping only the request.
    pub fn into_request(self) -> Request {
        self.request
    }
}

/// Why a frame or request was rejected.
///
/// The messages contain only structural information (lengths, a truncated
/// request type), never request payload bytes, so they are safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The frame ended before the declared number of bytes arrived.
    TruncatedFrame { expected: usize, actual: usize },
    /// Bytes followed a complete frame; one call decodes exactly one frame.
    TrailingBytes { trailing: usize },
    /// The declared length exceeds [`MAX_MESSAGE_BYTES`].
    MessageTooLarge { length: usize, max: usize },
    /// A zero-length frame body.
    EmptyMessage,
    /// The body is not valid JSON, or not the expected JSON shape.
    MalformedJson(String),
    /// The envelope version is not [`PROTOCOL_VERSION`].
    UnsupportedVersion(u64),
    /// The `request.type` is not a request this version implements.
    UnknownRequest(String),
    /// The `response.type` (or its error code) is not one this version knows.
    UnknownResponse(String),
    /// The request is structurally valid JSON but fails validation.
    InvalidRequest(String),
    /// The envelope has no usable session token.
    InvalidToken,
    /// A [`FrameDecoder`] was given more bytes than it will buffer.
    BufferFull { buffered: usize, max: usize },
    /// A `stdout`/`stderr` chunk exceeds [`MAX_CHUNK_BYTES`].
    ChunkTooLarge { length: usize, max: usize },
    /// A response frame is valid JSON but its fields violate the protocol.
    InvalidResponse(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedFrame { expected, actual } => {
                write!(
                    f,
                    "truncated frame: expected {expected} bytes, got {actual}"
                )
            }
            Self::TrailingBytes { trailing } => {
                write!(f, "trailing bytes after frame: {trailing}")
            }
            Self::MessageTooLarge { length, max } => {
                write!(
                    f,
                    "message too large: {length} bytes exceeds the {max}-byte limit"
                )
            }
            Self::EmptyMessage => f.write_str("empty message"),
            Self::MalformedJson(detail) => write!(f, "malformed protocol message: {detail}"),
            Self::UnsupportedVersion(version) => write!(
                f,
                "unsupported protocol version {version} (this build speaks version {PROTOCOL_VERSION})"
            ),
            Self::UnknownRequest(kind) => write!(f, "unknown request type {kind:?}"),
            Self::UnknownResponse(kind) => write!(f, "unknown response type or code {kind:?}"),
            Self::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            Self::InvalidToken => write!(
                f,
                "invalid session token (expected {} lowercase hex characters)",
                crate::token::TOKEN_HEX_CHARS
            ),
            Self::BufferFull { buffered, max } => {
                write!(
                    f,
                    "protocol buffer full: {buffered} bytes buffered, limit {max}"
                )
            }
            Self::ChunkTooLarge { length, max } => {
                write!(
                    f,
                    "output chunk too large: {length} bytes exceeds the {max}-byte limit"
                )
            }
            Self::InvalidResponse(detail) => write!(f, "invalid response: {detail}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Validate field bounds for a request. Applied on both encode and decode:
/// locally generated requests and peer-supplied ones must meet the same
/// contract.
fn validate_request(request: &Request) -> Result<(), ProtocolError> {
    let Request::Run(run) = request else {
        return Ok(());
    };
    validate_env_name(&run.env)?;
    if run.reference.is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "run.ref must not be empty".into(),
        ));
    }
    if run.reference.len() > MAX_REFERENCE_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.ref exceeds {MAX_REFERENCE_BYTES} bytes"
        )));
    }
    // Reuse the canonical parser instead of duplicating the reference syntax.
    // The daemon still has to check that the entry exists and is in scope.
    if EntryId::parse_ref(&run.reference).is_err() {
        return Err(ProtocolError::InvalidRequest(
            "run.ref is not a valid pm:// reference".into(),
        ));
    }
    validate_absolute_path("run.cwd", &run.cwd)?;
    if run.command.is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "run.command must not be empty".into(),
        ));
    }
    if run.command.len() > MAX_ARGS {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.command has more than {MAX_ARGS} arguments"
        )));
    }
    for (index, argument) in run.command.iter().enumerate() {
        if argument.len() > MAX_ARG_BYTES {
            return Err(ProtocolError::InvalidRequest(format!(
                "run.command[{index}] exceeds {MAX_ARG_BYTES} bytes"
            )));
        }
        if index == 0 {
            // Never let the daemon resolve a program through its own PATH:
            // that PATH belongs to the shell that started `unlock`, not to the
            // caller that named the command.
            validate_absolute_path("run.command[0]", argument)?;
        }
    }
    Ok(())
}

/// Require a non-empty, NUL-free absolute path within [`MAX_PATH_BYTES`].
fn validate_absolute_path(field: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_PATH_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} exceeds {MAX_PATH_BYTES} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must not contain a NUL byte"
        )));
    }
    if !value.starts_with('/') {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must be an absolute path"
        )));
    }
    Ok(())
}

/// Whether `env` is a syntactically valid environment variable name.
///
/// This is syntax only: the daemon additionally refuses names that would let
/// an agent hijack the child (see [`crate::runner::denied_env_name`]). It is
/// public so the CLI can reject a malformed `--env` before it connects, with a
/// usage exit code instead of a daemon round-trip.
pub fn valid_env_name(env: &str) -> bool {
    if env.is_empty() || env.len() > MAX_ENV_NAME_BYTES {
        return false;
    }
    let mut bytes = env.bytes();
    let first = bytes.next().expect("checked non-empty");
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_env_name(env: &str) -> Result<(), ProtocolError> {
    if env.is_empty() {
        return Err(ProtocolError::InvalidRequest(
            "run.env must not be empty".into(),
        ));
    }
    if env.len() > MAX_ENV_NAME_BYTES {
        return Err(ProtocolError::InvalidRequest(format!(
            "run.env exceeds {MAX_ENV_NAME_BYTES} bytes"
        )));
    }
    let mut bytes = env.bytes();
    let first = bytes.next().expect("checked non-empty");
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(ProtocolError::InvalidRequest(
            "run.env must start with an ASCII letter or underscore".into(),
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err(ProtocolError::InvalidRequest(
            "run.env may contain only ASCII letters, digits and underscores".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
