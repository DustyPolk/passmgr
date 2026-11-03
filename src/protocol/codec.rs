//! Frame and body codec for the `pm`/`pmd` wire protocol.
//!
//! This is the transport half of [`crate::protocol`]: the 4-byte big-endian
//! length prefix, the JSON envelope, the incremental [`FrameDecoder`] and the
//! request body codec. The request types and their field validation live in
//! the parent module, which re-exports [`encode`], [`decode`] and
//! [`FrameDecoder`] so callers keep using `protocol::...` paths.
//!
//! Everything here is pure: no I/O, and every input is treated as
//! attacker-controlled (the declared length is range-checked before any slice
//! or allocation is made from it).

use serde_json::{Map, Value, json};

use super::{
    AuthenticatedRequest, LENGTH_PREFIX_BYTES, MAX_BUFFERED_BYTES, MAX_MESSAGE_BYTES,
    MAX_TYPE_CHARS, PROTOCOL_VERSION, ProtocolError, ProveRequest, Request, RunRequest,
    validate_request,
};
use crate::presence::{ChallengeNonce, Proof, RequestDigest};
use crate::token::SessionToken;

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
            "cwd": run.cwd,
        }),
        Request::Challenge => json!({ "type": "challenge" }),
        Request::Prove(prove) => json!({
            "type": "prove",
            "nonce": prove.nonce.to_hex(),
            "digest": prove.digest.to_hex(),
            "proof": prove.proof.to_hex().as_str(),
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
            cwd: required_string(request, "cwd")?,
        }),
        "challenge" => Request::Challenge,
        "prove" => Request::Prove(ProveRequest {
            nonce: ChallengeNonce::from_hex(&required_string(request, "nonce")?)
                .ok_or_else(|| invalid_presence_field("nonce"))?,
            digest: RequestDigest::from_hex(&required_string(request, "digest")?)
                .ok_or_else(|| invalid_presence_field("digest"))?,
            proof: Proof::from_hex(&required_string(request, "proof")?)
                .ok_or_else(|| invalid_presence_field("proof"))?,
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

fn invalid_presence_field(field: &str) -> ProtocolError {
    ProtocolError::InvalidRequest(format!(
        "prove.{field} must be {} lowercase hex characters",
        crate::presence::NONCE_BYTES * 2
    ))
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
