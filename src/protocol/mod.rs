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
//! The JSON envelope is `{"version":2,"token":"<64 hex>","request":{...}}`.
//! The `token` is the unlock session token (see [`crate::token`]) and is
//! required on every request; the daemon rejects a missing or mismatched one
//! with `unauthorized`. The `request` object always has a `"type"` field; the
//! types this version knows are `ping`, `lock` and `run`:
//!
//! ```json
//! {"version":2,"token":"...","request":{"type":"ping"}}
//! {"version":2,"token":"...","request":{"type":"lock"}}
//! {"version":2,"token":"...","request":{"type":"run","env":"API_KEY",
//!                         "ref":"pm://00112233445566778899aabbccddeeff",
//!                         "command":["curl","-s","https://example.test"]}}
//! ```
//!
//! Version 2 added the required `token` field, so it is not backward
//! compatible with version 1 (a version-1 peer would be treated as an
//! unsigned request). Older versions are refused with `unsupported_version`.
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

use serde_json::{Map, Value, json};

use crate::store::EntryId;
use crate::token::SessionToken;

mod response;

pub use response::{
    Response, ResponseError, RunExit, RunFrame, RunStream, decode_response, decode_run_frame,
    encode_response, encode_run_frame,
};

/// The protocol version carried in every envelope. Bump it when a change is
/// not backward compatible.
pub const PROTOCOL_VERSION: u32 = 2;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Liveness check. The daemon answers without touching the vault.
    Ping,
    /// Wipe the key and shut down.
    Lock,
    /// Spawn `command` with `env` set to the value of `reference`.
    Run(RunRequest),
}

/// The `run` payload: inject `reference`'s value as `env` for `command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    /// Environment variable name in the child process.
    pub env: String,
    /// `pm://<32 hex chars>` reference of the credential to inject.
    pub reference: String,
    /// Argument vector; `command[0]` is the program.
    pub command: Vec<String>,
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

/// Encode one authenticated request as a complete length-prefixed frame.
///
/// Fails with [`ProtocolError::InvalidRequest`] if the request violates the
/// field bounds, and with [`ProtocolError::MessageTooLarge`] if the encoded
/// body would exceed [`MAX_MESSAGE_BYTES`].
pub fn encode(token: &SessionToken, request: &Request) -> Result<Vec<u8>, ProtocolError> {
    validate_request(request)?;
    let body = encode_body(token, request)?;
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            length: body.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode exactly one complete length-prefixed frame.
///
/// Rejects truncated frames, trailing bytes, oversized declared lengths (before
/// allocating anything based on them), malformed JSON, unknown versions,
/// missing or malformed session tokens, and unknown request types.
pub fn decode(frame: &[u8]) -> Result<AuthenticatedRequest, ProtocolError> {
    let (body, rest) = split_frame(frame)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes {
            trailing: rest.len(),
        });
    }
    decode_body(body)
}

/// Incremental frame reader for a byte stream (a socket read loop).
///
/// The decoder buffers bytes until a complete frame is available. It validates
/// the declared length as soon as the 4-byte prefix has arrived, so an
/// oversized frame is rejected without waiting for (or allocating) its body.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    /// Declared body length of the frame at the front of `buffer`, once the
    /// prefix has been seen and validated.
    expected: Option<usize>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes received from the peer.
    ///
    /// Returns an error if the prefix declares an invalid length, or if the
    /// peer sent more than [`MAX_BUFFERED_BYTES`] without the caller draining
    /// complete frames. After an error the decoder must not be reused.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let total = self.buffer.len().saturating_add(bytes.len());
        if total > MAX_BUFFERED_BYTES {
            return Err(ProtocolError::BufferFull {
                buffered: total,
                max: MAX_BUFFERED_BYTES,
            });
        }
        self.buffer.extend_from_slice(bytes);
        if self.expected.is_none() && self.buffer.len() >= LENGTH_PREFIX_BYTES {
            let length = read_length(&self.buffer);
            check_length(length)?;
            self.expected = Some(length);
        }
        Ok(())
    }

    /// The number of bytes currently buffered but not yet returned.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Take the next complete frame body, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        if self.buffer.len() < LENGTH_PREFIX_BYTES {
            return Ok(None);
        }
        let length = match self.expected {
            Some(length) => length,
            None => {
                let length = read_length(&self.buffer);
                check_length(length)?;
                self.expected = Some(length);
                length
            }
        };
        let end = LENGTH_PREFIX_BYTES + length;
        if self.buffer.len() < end {
            return Ok(None);
        }
        let body = self.buffer[LENGTH_PREFIX_BYTES..end].to_vec();
        self.buffer.drain(..end);
        self.expected = None;
        Ok(Some(body))
    }

    /// Take and decode the next complete authenticated request, if one is
    /// buffered.
    pub fn next_request(&mut self) -> Result<Option<AuthenticatedRequest>, ProtocolError> {
        match self.next_frame()? {
            Some(body) => decode_body(&body).map(Some),
            None => Ok(None),
        }
    }
}

/// Read the big-endian length prefix. The caller must pass at least
/// [`LENGTH_PREFIX_BYTES`] bytes.
fn read_length(prefix: &[u8]) -> usize {
    u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize
}

/// Validate a declared body length before it is used for slicing or
/// allocation.
fn check_length(length: usize) -> Result<(), ProtocolError> {
    if length == 0 {
        return Err(ProtocolError::EmptyMessage);
    }
    if length > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            length,
            max: MAX_MESSAGE_BYTES,
        });
    }
    Ok(())
}

/// Split one frame into its body and any bytes that follow it.
pub(super) fn split_frame(frame: &[u8]) -> Result<(&[u8], &[u8]), ProtocolError> {
    if frame.len() < LENGTH_PREFIX_BYTES {
        return Err(ProtocolError::TruncatedFrame {
            expected: LENGTH_PREFIX_BYTES,
            actual: frame.len(),
        });
    }
    let length = read_length(frame);
    check_length(length)?;
    let end = LENGTH_PREFIX_BYTES + length; // bounded by check_length
    if frame.len() < end {
        return Err(ProtocolError::TruncatedFrame {
            expected: end,
            actual: frame.len(),
        });
    }
    Ok((&frame[LENGTH_PREFIX_BYTES..end], &frame[end..]))
}

fn encode_body(token: &SessionToken, request: &Request) -> Result<Vec<u8>, ProtocolError> {
    let request = match request {
        Request::Ping => json!({ "type": "ping" }),
        Request::Lock => json!({ "type": "lock" }),
        Request::Run(run) => json!({
            "type": "run",
            "env": run.env,
            "ref": run.reference,
            "command": run.command,
        }),
    };
    let token = token.to_hex();
    let envelope = json!({
        "version": PROTOCOL_VERSION,
        "token": token.as_str(),
        "request": request,
    });
    serde_json::to_vec(&envelope).map_err(|err| ProtocolError::MalformedJson(err.to_string()))
}

fn decode_body(body: &[u8]) -> Result<AuthenticatedRequest, ProtocolError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| ProtocolError::MalformedJson(err.to_string()))?;
    let envelope = value
        .as_object()
        .ok_or_else(|| ProtocolError::MalformedJson("top-level value must be an object".into()))?;

    let version = envelope
        .get("version")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'version'".into()))?
        .as_u64()
        .ok_or_else(|| {
            ProtocolError::MalformedJson("'version' must be a non-negative integer".into())
        })?;
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(ProtocolError::UnsupportedVersion(version));
    }

    let token_text = envelope
        .get("token")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'token'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'token' must be a string".into()))?;
    let token = SessionToken::from_hex(token_text).map_err(|_| ProtocolError::InvalidToken)?;

    let request = envelope
        .get("request")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'request'".into()))?
        .as_object()
        .ok_or_else(|| ProtocolError::MalformedJson("'request' must be an object".into()))?;

    let kind = request
        .get("type")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'request.type'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'request.type' must be a string".into()))?;

    let decoded = match kind {
        "ping" => Request::Ping,
        "lock" => Request::Lock,
        "run" => Request::Run(RunRequest {
            env: required_string(request, "env")?,
            reference: required_string(request, "ref")?,
            command: required_string_array(request, "command")?,
        }),
        other => {
            return Err(ProtocolError::UnknownRequest(
                other.chars().take(MAX_TYPE_CHARS).collect(),
            ));
        }
    };
    validate_request(&decoded)?;
    Ok(AuthenticatedRequest::new(token, decoded))
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, ProtocolError> {
    object
        .get(key)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("missing '{key}'")))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("'{key}' must be a string")))
}

fn required_string_array(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, ProtocolError> {
    let values = object
        .get(key)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("missing '{key}'")))?
        .as_array()
        .ok_or_else(|| ProtocolError::MalformedJson(format!("'{key}' must be an array")))?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ProtocolError::MalformedJson(format!("'{key}' entries must be strings"))
            })
        })
        .collect()
}

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
        if index == 0 && argument.is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "run.command[0] must not be empty".into(),
            ));
        }
    }
    Ok(())
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
mod tests {
    use super::*;

    const REF: &str = "pm://00112233445566778899aabbccddeeff";
    /// A fixed token so exact-frame assertions stay readable.
    const TOKEN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn test_token() -> SessionToken {
        SessionToken::from_hex(TOKEN_HEX).expect("test token")
    }

    /// Request-only views of [`super::encode`]/[`super::decode`], so each
    /// transport test can assert on the request without restating the token.
    /// Tests that care about the token call `super::decode` directly.
    fn encode(request: &Request) -> Result<Vec<u8>, ProtocolError> {
        super::encode(&test_token(), request)
    }

    fn decode(frame: &[u8]) -> Result<Request, ProtocolError> {
        super::decode(frame).map(AuthenticatedRequest::into_request)
    }

    fn run_request() -> Request {
        Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: REF.into(),
            command: vec!["curl".into(), "-s".into(), "https://example.test".into()],
        })
    }

    /// Build a frame by hand, without going through `encode`.
    fn frame(body: &str) -> Vec<u8> {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body.as_bytes());
        frame
    }

    #[test]
    fn round_trips_every_request() {
        for request in [Request::Ping, Request::Lock, run_request()] {
            let encoded = encode(&request).expect("encode");
            assert_eq!(decode(&encoded).expect("decode"), request);
        }
    }

    #[test]
    fn frame_starts_with_a_big_endian_length_prefix() {
        let encoded = encode(&Request::Ping).expect("encode");
        let body = format!(
            r#"{{"request":{{"type":"ping"}},"token":"{TOKEN_HEX}","version":{PROTOCOL_VERSION}}}"#
        );
        assert_eq!(&encoded[..4], &(body.len() as u32).to_be_bytes());
        assert_eq!(&encoded[4..], body.as_bytes());
    }

    #[test]
    fn truncated_prefix_and_body_are_rejected() {
        for frame in [
            &b""[..],
            &b"\x00"[..],
            &b"\x00\x00"[..],
            &b"\x00\x00\x00"[..],
        ] {
            assert_eq!(
                decode(frame),
                Err(ProtocolError::TruncatedFrame {
                    expected: LENGTH_PREFIX_BYTES,
                    actual: frame.len(),
                })
            );
        }

        let truncated = [0, 0, 0, 10, b'{', b'}'];
        assert_eq!(
            decode(&truncated),
            Err(ProtocolError::TruncatedFrame {
                expected: 14,
                actual: 6,
            })
        );
    }

    #[test]
    fn oversized_declared_length_is_rejected_before_reading_the_body() {
        let prefix = u32::MAX.to_be_bytes();
        assert_eq!(
            decode(&prefix),
            Err(ProtocolError::MessageTooLarge {
                length: u32::MAX as usize,
                max: MAX_MESSAGE_BYTES,
            })
        );

        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decoder.push(&prefix),
            Err(ProtocolError::MessageTooLarge {
                length: u32::MAX as usize,
                max: MAX_MESSAGE_BYTES,
            })
        );
    }

    #[test]
    fn empty_and_trailing_bytes_are_rejected() {
        assert_eq!(decode(&[0, 0, 0, 0]), Err(ProtocolError::EmptyMessage));

        let mut encoded = encode(&Request::Ping).expect("encode");
        encoded.push(b'x');
        assert_eq!(
            decode(&encoded),
            Err(ProtocolError::TrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn oversized_encoded_message_is_rejected() {
        // Each argument is within MAX_ARG_BYTES, but the body is over 64 KiB.
        let mut command = vec!["prog".to_string()];
        for _ in 0..20 {
            command.push("x".repeat(4096));
        }
        let request = Request::Run(RunRequest {
            env: "API_KEY".into(),
            reference: REF.into(),
            command,
        });
        assert!(matches!(
            encode(&request),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn bad_versions_are_rejected() {
        for version in ["0", "1", "3", "99", "18446744073709551615"] {
            let body = format!(
                r#"{{"version":{version},"token":"{TOKEN_HEX}","request":{{"type":"ping"}}}}"#
            );
            let expected = version.parse::<u64>().expect("test version");
            assert_eq!(
                decode(&frame(&body)),
                Err(ProtocolError::UnsupportedVersion(expected))
            );
        }
    }

    #[test]
    fn missing_or_mistyped_envelope_fields_are_rejected() {
        let bodies: Vec<String> = vec![
            "not json".into(),
            "[]".into(),
            "null".into(),
            r#"{"request":{"type":"ping"}}"#.into(),
            r#"{"version":"2","token":"x","request":{"type":"ping"}}"#.into(),
            r#"{"version":-1,"token":"x","request":{"type":"ping"}}"#.into(),
            r#"{"version":2.5,"token":"x","request":{"type":"ping"}}"#.into(),
            r#"{"version":2}"#.into(),
            format!(r#"{{"version":2,"token":"{TOKEN_HEX}","request":[]}}"#),
            format!(r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{}}}}"#),
            format!(r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":42}}}}"#),
            format!(
                r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x"}}}}"#
            ),
            format!(
                r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x","command":"true"}}}}"#
            ),
            format!(
                r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x","command":[1]}}}}"#
            ),
        ];
        for body in bodies {
            assert!(
                matches!(
                    super::decode(&frame(&body)),
                    Err(ProtocolError::MalformedJson(_))
                ),
                "body should be malformed: {body}"
            );
        }
    }

    #[test]
    fn a_missing_or_malformed_token_is_rejected_on_every_request_type() {
        // No token at all.
        for request in [r#"{"type":"ping"}"#, r#"{"type":"lock"}"#] {
            let body = format!(r#"{{"version":2,"request":{request}}}"#);
            assert!(
                matches!(
                    super::decode(&frame(&body)),
                    Err(ProtocolError::MalformedJson(_))
                ),
                "missing token must be malformed: {body}"
            );
        }

        // A token field that is not a string.
        let body = r#"{"version":2,"token":7,"request":{"type":"ping"}}"#;
        assert!(matches!(
            super::decode(&frame(body)),
            Err(ProtocolError::MalformedJson(_))
        ));

        // Strings that are not exactly 64 lowercase hex characters.
        let uppercase = "A".repeat(crate::token::TOKEN_HEX_CHARS);
        let short = "a".repeat(crate::token::TOKEN_HEX_CHARS - 1);
        let long = "a".repeat(crate::token::TOKEN_HEX_CHARS + 1);
        let non_hex = "g".repeat(crate::token::TOKEN_HEX_CHARS);
        for token in [uppercase, short, long, non_hex, String::new()] {
            let body = format!(r#"{{"version":2,"token":"{token}","request":{{"type":"ping"}}}}"#);
            match super::decode(&frame(&body)) {
                Err(ProtocolError::InvalidToken) => {}
                other => panic!("token {token:?} should be invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_decoded_token_matches_what_was_encoded() {
        let token = test_token();
        let other = SessionToken::from_bytes(&[0xFFu8; crate::token::TOKEN_BYTES]).expect("token");
        for request in [Request::Ping, Request::Lock, run_request()] {
            let encoded = super::encode(&token, &request).expect("encode");
            let decoded = super::decode(&encoded).expect("decode");
            assert!(decoded.token().matches(&token));
            assert!(!decoded.token().matches(&other));
            assert_eq!(decoded.into_request(), request);
        }
    }

    #[test]
    fn the_token_never_appears_in_debug_output() {
        let token = test_token();
        let encoded = super::encode(&token, &Request::Ping).expect("encode");
        let decoded = super::decode(&encoded).expect("decode");
        let text = format!("{decoded:?} {decoded:?}");
        assert!(!text.contains(TOKEN_HEX), "Debug leaked the token: {text}");
    }

    #[test]
    fn unknown_request_types_are_rejected() {
        // Including the request types a plaintext-leaking protocol would have:
        // none of them exist here, and none may ever be added.
        for kind in ["reveal", "get", "password", "export", "run ", "PING", ""] {
            let body =
                format!(r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"{kind}"}}}}"#);
            assert!(
                matches!(decode(&frame(&body)), Err(ProtocolError::UnknownRequest(_))),
                "type {kind:?} should be unknown"
            );
        }

        // A huge type is echoed back only in truncated form.
        let long = "x".repeat(10_000);
        let body =
            format!(r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"{long}"}}}}"#);
        match decode(&frame(&body)) {
            Err(ProtocolError::UnknownRequest(kind)) => {
                assert_eq!(kind.chars().count(), MAX_TYPE_CHARS)
            }
            other => panic!("expected UnknownRequest, got {other:?}"),
        }
    }

    #[test]
    fn requests_have_no_plaintext_field() {
        // Structural proof: the only keys on the wire are these. A future
        // request type must not introduce a value field.
        let ping_frame = encode(&Request::Ping).expect("encode");
        let ping: Value = serde_json::from_slice(&ping_frame[4..]).expect("json");
        let keys: Vec<&str> = ping
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["request", "token", "version"]);
        // The token is the only envelope value, and it is the client's own
        // token, not anything read from the vault.
        let token = ping["token"].as_str().expect("token string");
        assert_eq!(token, TOKEN_HEX);
        let keys: Vec<&str> = ping["request"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["type"]);

        let run_frame = encode(&run_request()).expect("encode");
        let run: Value = serde_json::from_slice(&run_frame[4..]).expect("json");
        let keys: Vec<&str> = run["request"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["command", "env", "ref", "type"]);
    }

    #[test]
    fn run_fields_are_validated() {
        let cases = [
            RunRequest {
                env: String::new(),
                reference: REF.into(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "1BAD".into(),
                reference: REF.into(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "BAD-NAME".into(),
                reference: REF.into(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "A".repeat(MAX_ENV_NAME_BYTES + 1),
                reference: REF.into(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "OK".into(),
                reference: String::new(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "OK".into(),
                reference: "not-a-reference".into(),
                command: vec!["true".into()],
            },
            RunRequest {
                env: "OK".into(),
                reference: REF.into(),
                command: vec![],
            },
            RunRequest {
                env: "OK".into(),
                reference: REF.into(),
                command: vec![String::new()],
            },
            RunRequest {
                env: "OK".into(),
                reference: REF.into(),
                command: vec!["true".into(); MAX_ARGS + 1],
            },
            RunRequest {
                env: "OK".into(),
                reference: REF.into(),
                command: vec!["true".into(), "x".repeat(MAX_ARG_BYTES + 1)],
            },
        ];
        for run in cases {
            assert!(
                matches!(
                    encode(&Request::Run(run.clone())),
                    Err(ProtocolError::InvalidRequest(_))
                ),
                "should reject {run:?}"
            );
        }
    }

    #[test]
    fn decoder_reassembles_fragmented_frames() {
        let request = run_request();
        let encoded = encode(&request).expect("encode");
        let mut decoder = FrameDecoder::new();
        for (index, byte) in encoded.iter().enumerate() {
            decoder.push(std::slice::from_ref(byte)).expect("push");
            if index + 1 < encoded.len() {
                assert!(decoder.next_request().expect("decode").is_none());
            }
        }
        let decoded = decoder.next_request().expect("decode").expect("request");
        assert_eq!(decoded.into_request(), request);
        assert!(decoder.next_request().expect("decode").is_none());
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn decoder_reads_two_frames_from_one_push() {
        let mut bytes = encode(&Request::Ping).expect("encode");
        bytes.extend_from_slice(&encode(&Request::Lock).expect("encode"));
        let mut decoder = FrameDecoder::new();
        decoder.push(&bytes).expect("push");
        let first = decoder.next_request().expect("decode").expect("first");
        assert_eq!(first.into_request(), Request::Ping);
        let second = decoder.next_request().expect("decode").expect("second");
        assert_eq!(second.into_request(), Request::Lock);
        assert!(decoder.next_request().expect("decode").is_none());
    }

    #[test]
    fn decoder_rejects_a_buffer_flood() {
        let mut decoder = FrameDecoder::new();
        let mut flood = (MAX_MESSAGE_BYTES as u32).to_be_bytes().to_vec();
        flood.resize(MAX_MESSAGE_BYTES + 8, 0);
        decoder.push(&flood).expect("first push fits");
        assert!(matches!(
            decoder.push(&vec![0u8; MAX_BUFFERED_BYTES]),
            Err(ProtocolError::BufferFull { .. })
        ));
    }

    #[test]
    fn arbitrary_bytes_are_rejected_without_panicking() {
        // Deterministic xorshift; this is a smoke test for the parser, not a
        // substitute for the cargo-fuzz target in TODO 5.2.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for length in 0..=96 {
            for _ in 0..32 {
                let mut bytes = vec![0u8; length];
                for byte in &mut bytes {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                let _ = decode(&bytes);
                let mut decoder = FrameDecoder::new();
                let _ = decoder.push(&bytes);
                let _ = decoder.next_request();
            }
        }
    }

    #[test]
    fn errors_do_not_echo_request_field_values() {
        // Error text is loggable. It may name lengths and echo a truncated
        // request type, but must never repeat a field value from the body.
        let secret_like = "SUPER_SECRET_VALUE_123";
        let body = format!(
            r#"{{"version":2,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"{secret_like}","ref":"x","command":["true"]}}}}"#
        );
        let error = decode(&frame(&body)).expect_err("invalid ref");
        let text = error.to_string();
        assert!(text.contains("run.ref"), "unexpected message: {text}");
        assert!(!text.contains(secret_like));
    }
}
