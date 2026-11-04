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
//!
//! # The frame bytes carry the session and grant tokens
//!
//! Every encoded request contains the session-token hex and some contain the
//! grant-token hex, so the buffers this module hands out are `Zeroizing` and
//! every copy it makes internally is overwritten before it is freed
//! (TODO R.50c). `pmd` is long-lived; a freed 200-byte frame would otherwise
//! leave a usable token in its allocator for the rest of the session.

use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{
    AuthenticatedRequest, DEFAULT_RUN_OUTPUT_BYTES, DEFAULT_RUN_TIMEOUT_SECS, DescribeRequest,
    EnvBinding, GrantCreateRequest, GrantRevokeRequest, LENGTH_PREFIX_BYTES, ListRequest,
    MAX_BUFFERED_BYTES, MAX_MESSAGE_BYTES, MAX_TYPE_CHARS, PROTOCOL_VERSION, ProtocolError,
    ProveRequest, Request, RunLimits, RunRequest, validate_request,
};
use crate::grant::{
    Capabilities, GRANT_ID_BYTES, GrantId, GrantToken, TOKEN_HASH_BYTES, TokenHash,
};
use crate::presence::{ChallengeNonce, Proof, RequestDigest};
use crate::store::EntryId;
use crate::token::SessionToken;

/// Encode one authenticated request as a complete length-prefixed frame.
///
/// Fails with [`ProtocolError::InvalidRequest`] if the request violates the
/// field bounds, and with [`ProtocolError::MessageTooLarge`] if the encoded
/// body would exceed [`MAX_MESSAGE_BYTES`].
pub fn encode(
    token: &SessionToken,
    request: &Request,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    validate_request(request)?;
    let body = encode_body(token, request)?;
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            length: body.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len()));
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
    /// Highest length `buffer` has ever had, so a test can read the bytes a
    /// taken frame left behind (they are outside `buffer`'s current length but
    /// were all written by `push`). Test-only: it is never needed at runtime.
    #[cfg(test)]
    written: usize,
}

impl Drop for FrameDecoder {
    fn drop(&mut self) {
        // The buffer holds whatever the peer sent, which includes the token
        // hex of every frame not yet taken.
        self.buffer.zeroize();
    }
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
        self.grow_for(bytes.len());
        // `grow_for` reserved `bytes.len()` more bytes, so this cannot
        // reallocate and cannot free a buffer that has held a token.
        self.buffer.extend_from_slice(bytes);
        #[cfg(test)]
        {
            self.written = self.written.max(self.buffer.len());
        }
        if self.expected.is_none() && self.buffer.len() >= LENGTH_PREFIX_BYTES {
            let length = read_length(&self.buffer);
            check_length(length)?;
            self.expected = Some(length);
        }
        Ok(())
    }

    /// Reserve room for `additional` more bytes without letting `Vec`
    /// reallocate a buffer whose front may already hold a token.
    ///
    /// `Vec::extend_from_slice` grows in place when it can, but otherwise
    /// frees the old allocation with every byte still in it. A request larger
    /// than the daemon's 4 KiB read chunk therefore used to leave several
    /// copies of the session-token hex (and, for `run`, the grant-token hex)
    /// in `pmd`'s heap for the rest of the session (TODO R.64). Allocate a
    /// fresh buffer, copy into it, wipe the old one, and only then drop it.
    /// The new capacity at least doubles, so growth stays amortized linear.
    fn grow_for(&mut self, additional: usize) {
        let needed = self.buffer.len() + additional;
        if needed <= self.buffer.capacity() {
            return;
        }
        grow_wiped(&mut self.buffer, needed);
        #[cfg(test)]
        {
            // The new allocation only holds the bytes just copied; the old
            // tail (which `written_bytes` could read) went with the wipe.
            self.written = self.buffer.len();
        }
    }

    /// The number of bytes currently buffered but not yet returned.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Take the next complete frame body, if one is buffered.
    ///
    /// The returned copy zeroizes on drop, and the frame's bytes are wiped out
    /// of the decoder's own buffer before the buffer is shrunk: `Vec::drain`
    /// would move the following frame down and leave the taken frame's tail in
    /// the allocation, reachable by nothing but a heap inspection. Growth in
    /// [`FrameDecoder::push`] is a wipe-and-swap for the same reason.
    pub fn next_frame(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ProtocolError> {
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
        let body = Zeroizing::new(self.buffer[LENGTH_PREFIX_BYTES..end].to_vec());
        let old_len = self.buffer.len();
        let remaining = old_len - end;
        self.buffer.copy_within(end..old_len, 0);
        self.buffer[remaining..old_len].zeroize();
        self.buffer.truncate(remaining);
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

    /// Every byte this decoder has ever written into its buffer, including the
    /// stale tail beyond the current length. Used only by the test that proves
    /// a taken frame is wiped.
    #[cfg(test)]
    pub(crate) fn written_bytes(&self) -> &[u8] {
        // SAFETY: `written <= capacity` (it is a maximum of past lengths) and
        // every byte in `0..written` was written by `push`, so the range is
        // initialized and inside the one allocation `buffer` owns.
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr(), self.written) }
    }
}

/// Replace `buffer` with a larger allocation, wiping the bytes of the old one
/// before it is freed.
///
/// `Vec`'s own growth frees the previous allocation with every byte still in
/// it, which for this module means a copy of a token hex surviving in `pmd`'s
/// heap for the rest of the session (TODO R.64). The new capacity at least
/// doubles, so repeated growth stays amortized linear.
fn grow_wiped(buffer: &mut Vec<u8>, needed: usize) {
    let capacity = needed.max(buffer.capacity().saturating_mul(2));
    let mut grown = Vec::with_capacity(capacity);
    // Fits by construction, so no second allocation happens here.
    grown.extend_from_slice(buffer);
    buffer.zeroize();
    *buffer = grown;
}

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

fn encode_body(
    token: &SessionToken,
    request: &Request,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let request = match request {
        Request::Ping => json!({ "type": "ping" }),
        Request::Lock => json!({ "type": "lock" }),
        Request::Run(run) => json!({
            "type": "run",
            "env": run.env.iter().map(|binding| json!({
                "name": binding.name,
                "ref": binding.reference,
            })).collect::<Vec<_>>(),
            "plain_env": run.plain_env.iter().map(|(name, value)| {
                (name.clone(), Value::String(value.clone()))
            }).collect::<Map<String, Value>>(),
            "command": run.command,
            "cwd": run.cwd,
            "timeout_secs": run.limits.timeout_secs,
            "max_output_bytes": run.limits.max_output_bytes,
            "grant": run.grant.to_hex().as_str(),
        }),
        Request::List(list) => json!({
            "type": "list",
            "tags": list.tags,
            "query": list.query,
            "grant": list.grant.to_hex().as_str(),
        }),
        Request::Describe(describe) => json!({
            "type": "describe",
            "ref": describe.reference,
            "grant": describe.grant.to_hex().as_str(),
        }),
        Request::Challenge => json!({ "type": "challenge" }),
        Request::Prove(prove) => json!({
            "type": "prove",
            "nonce": prove.nonce.to_hex(),
            "digest": prove.digest.to_hex(),
            "proof": prove.proof.to_hex().as_str(),
        }),
        Request::GrantCreate(create) => json!({
            "type": "grant_create",
            "label": create.label,
            "refs": create.references.iter().map(|id| id.to_ref()).collect::<Vec<_>>(),
            "tags": create.tags,
            "fields": create.fields,
            "commands": create.commands,
            "capabilities": create.capabilities.bits(),
            "expires_at": create.expires_at,
            "max_uses": create.max_uses,
            "token_hash": create.token_hash.to_hex(),
        }),
        Request::GrantRevoke(GrantRevokeRequest::Id(id)) => json!({
            "type": "grant_revoke",
            "id": id.to_hex(),
        }),
        Request::GrantRevoke(GrantRevokeRequest::All) => json!({
            "type": "grant_revoke",
            "all": true,
        }),
    };
    let token = token.to_hex();
    // Build the envelope by moving `request` in. `json!` on a `Value` variable
    // deep-copies it through `serde_json::to_value`, and the tree that was left
    // behind would be dropped with the grant-token hex still in it (TODO
    // R.64).
    let mut envelope = Map::new();
    envelope.insert("version".to_owned(), Value::from(PROTOCOL_VERSION));
    envelope.insert("token".to_owned(), Value::String(token.as_str().to_owned()));
    envelope.insert("request".to_owned(), request);
    let mut envelope = Value::Object(envelope);
    // `serde_json::to_vec` starts at 128 bytes and grows through `Vec`'s own
    // reallocation, so a request long enough to cross a capacity boundary
    // after the token hex was written used to leave a copy in freed memory.
    // `BodyWriter` grows with a wipe-and-swap instead.
    let mut body = BodyWriter::new();
    let serialized = serde_json::to_writer(&mut body, &envelope);
    // `serde_json` copies the token hex into the tree, and the tree outlives
    // the serialized bytes, so wipe it before it is freed.
    zeroize_json(&mut envelope);
    serialized.map_err(|err| ProtocolError::MalformedJson(err.to_string()))?;
    Ok(Zeroizing::new(body.into_inner()))
}

/// A body buffer for `serde_json` that grows with [`grow_wiped`].
///
/// `serde_json::to_vec` starts at 128 bytes and grows through `Vec`'s own
/// reallocation, so a request long enough to cross a capacity boundary after
/// the token hex was written used to leave a copy in freed memory (TODO R.64).
/// Serializing through this writer gives the encoder the same wipe-and-swap
/// guarantee as [`FrameDecoder::push`]. The writer also wipes its bytes on
/// drop, so a serialization error cannot leave them behind either.
struct BodyWriter {
    bytes: Vec<u8>,
}

impl BodyWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::io::Write for BodyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let needed = self.bytes.len() + buf.len();
        if needed > self.bytes.capacity() {
            grow_wiped(&mut self.bytes, needed);
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Owns the parsed envelope and wipes every string in it before it is freed.
///
/// A `serde_json::Value` has no `Zeroize` impl, and its strings are ordinary
/// heap allocations: dropping the tree frees the session-token hex (and the
/// grant-token hex for `run`) unwiped. A guard rather than a trailing call
/// means no error path can skip the wipe (TODO R.65).
struct WipingJson(Value);

impl Drop for WipingJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

/// Overwrite every string a JSON value owns.
///
/// `serde_json::Value` has no `Zeroize` impl: its strings are ordinary heap
/// allocations, freed unwiped if we simply drop the tree. Object *keys* are
/// left alone deliberately: they are protocol field names, never a secret, and
/// `Map` exposes no mutable access to them.
fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        Value::Object(map) => map.values_mut().for_each(zeroize_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn decode_body(body: &[u8]) -> Result<AuthenticatedRequest, ProtocolError> {
    let parsed: Value = serde_json::from_slice(body)
        .map_err(|err| ProtocolError::MalformedJson(err.to_string()))?;
    // Hold the tree in a guard so every exit wipes it, including each early
    // `return` below: the envelope holds a plain copy of the session-token hex
    // (and, for `run`, of the grant-token hex), and a rejected request used to
    // free it unwiped (TODO R.65).
    let value = WipingJson(parsed);
    let envelope = value
        .0
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
        "run" => {
            // The grant-token hex is a bearer credential even in its encoded
            // form: keep it zeroizing rather than in a plain `String`.
            let grant = Zeroizing::new(required_string(request, "grant")?);
            let (env, plain_env) = decode_run_env(request)?;
            Request::Run(RunRequest {
                env,
                limits: decode_run_limits(request)?,
                plain_env,
                command: required_string_array(request, "command")?,
                cwd: required_string(request, "cwd")?,
                grant: GrantToken::from_hex(&grant).map_err(|_| invalid_grant_field())?,
            })
        }
        "list" => {
            // The grant-token hex is a bearer credential even in its encoded
            // form: keep it zeroizing rather than in a plain `String`.
            let grant = Zeroizing::new(required_string(request, "grant")?);
            Request::List(ListRequest {
                tags: match request.get("tags") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(_) => required_string_array(request, "tags")?,
                },
                query: match request.get("query") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(required_string(request, "query")?),
                },
                grant: GrantToken::from_hex(&grant).map_err(|_| invalid_grant_field())?,
            })
        }
        "describe" => {
            // The grant-token hex is a bearer credential even in its encoded
            // form: keep it zeroizing rather than in a plain `String`.
            let grant = Zeroizing::new(required_string(request, "grant")?);
            Request::Describe(DescribeRequest {
                reference: required_string(request, "ref")?,
                grant: GrantToken::from_hex(&grant).map_err(|_| invalid_grant_field())?,
            })
        }
        "challenge" => Request::Challenge,
        "prove" => Request::Prove(ProveRequest {
            nonce: ChallengeNonce::from_hex(&required_string(request, "nonce")?)
                .ok_or_else(|| invalid_presence_field("nonce"))?,
            digest: RequestDigest::from_hex(&required_string(request, "digest")?)
                .ok_or_else(|| invalid_presence_field("digest"))?,
            proof: Proof::from_hex(&required_string(request, "proof")?)
                .ok_or_else(|| invalid_presence_field("proof"))?,
        }),
        "grant_create" => Request::GrantCreate(decode_grant_create(request)?),
        "grant_revoke" => Request::GrantRevoke(decode_grant_revoke(request)?),
        other => {
            return Err(ProtocolError::UnknownRequest(
                other.chars().take(MAX_TYPE_CHARS).collect(),
            ));
        }
    };
    // The decoded request owns zeroizing copies of anything secret; the parsed
    // tree still holds plain strings (the session-token hex among them) and is
    // wiped when `value` drops at the end of this function.
    validate_request(&decoded)?;
    Ok(AuthenticatedRequest::new(token, decoded))
}

/// Decode a `grant_revoke` body. Exactly one of `id` (a grant id in hex) or
/// `all: true` must be present; anything else is a malformed request, never a
/// guess at intent.
fn decode_grant_revoke(request: &Map<String, Value>) -> Result<GrantRevokeRequest, ProtocolError> {
    let id = match request.get("id") {
        None | Some(Value::Null) => None,
        Some(_) => Some(required_string(request, "id")?),
    };
    let all = match request.get("all") {
        None | Some(Value::Null) => false,
        Some(value) => match value.as_bool() {
            Some(true) => true,
            Some(false) => {
                return Err(ProtocolError::InvalidRequest(
                    "grant_revoke.all must be true when present".into(),
                ));
            }
            None => {
                return Err(ProtocolError::MalformedJson(
                    "'grant_revoke.all' must be a boolean".into(),
                ));
            }
        },
    };
    match (id, all) {
        (Some(id), false) => GrantId::from_hex(&id)
            .map(GrantRevokeRequest::Id)
            .map_err(|_| {
                ProtocolError::InvalidRequest(format!(
                    "grant_revoke.id must be {} hex characters",
                    GRANT_ID_BYTES * 2
                ))
            }),
        (None, true) => Ok(GrantRevokeRequest::All),
        (Some(_), true) => Err(ProtocolError::InvalidRequest(
            "grant_revoke must name one id or 'all', not both".into(),
        )),
        (None, false) => Err(ProtocolError::InvalidRequest(
            "grant_revoke must name an id or 'all'".into(),
        )),
    }
}

/// Decode the `run` environment: the current `env` array of `{name, ref}`
/// bindings, or the legacy `env: "NAME"` string plus top-level `ref` as one
/// binding. `plain_env` is an optional object of non-secret values.
///
/// A string `env` without `ref` is malformed rather than an empty binding; a
/// list is never silently reinterpreted as a single name.
type DecodedRunEnv = (Vec<EnvBinding>, Vec<(String, String)>);

fn decode_run_env(request: &Map<String, Value>) -> Result<DecodedRunEnv, ProtocolError> {
    let env = match request.get("env") {
        Some(Value::String(name)) => vec![EnvBinding {
            name: name.clone(),
            reference: required_string(request, "ref")?,
        }],
        Some(Value::Array(bindings)) => bindings
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let binding = value.as_object().ok_or_else(|| {
                    ProtocolError::MalformedJson(format!(
                        "'env[{index}]' must be an object with 'name' and 'ref'"
                    ))
                })?;
                Ok(EnvBinding {
                    name: required_string(binding, "name")?,
                    reference: required_string(binding, "ref")?,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        Some(_) => {
            return Err(ProtocolError::MalformedJson(
                "'env' must be a string or an array of bindings".into(),
            ));
        }
        None => return Err(ProtocolError::MalformedJson("missing 'env'".into())),
    };
    let plain_env = match request.get("plain_env") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(name, value)| {
                let value = value.as_str().ok_or_else(|| {
                    ProtocolError::MalformedJson(format!("'plain_env.{name}' must be a string"))
                })?;
                Ok((name.clone(), value.to_owned()))
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        Some(_) => {
            return Err(ProtocolError::MalformedJson(
                "'plain_env' must be an object".into(),
            ));
        }
    };
    Ok((env, plain_env))
}

/// Decode the optional `run` resource limits, applying the documented defaults
/// when a legacy client omits them. Bounds are checked by `validate_request`.
fn decode_run_limits(request: &Map<String, Value>) -> Result<RunLimits, ProtocolError> {
    Ok(RunLimits {
        timeout_secs: optional_u32(request, "timeout_secs", DEFAULT_RUN_TIMEOUT_SECS)?,
        max_output_bytes: optional_u32(request, "max_output_bytes", DEFAULT_RUN_OUTPUT_BYTES)?,
    })
}

fn optional_u32(
    object: &Map<String, Value>,
    key: &str,
    default: u32,
) -> Result<u32, ProtocolError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => {
            let number = value
                .as_u64()
                .ok_or_else(|| ProtocolError::MalformedJson(format!("'{key}' must be a number")))?;
            u32::try_from(number)
                .map_err(|_| ProtocolError::InvalidRequest(format!("'{key}' is too large")))
        }
    }
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, ProtocolError> {
    object
        .get(key)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("missing '{key}'")))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("'{key}' must be a string")))
}

fn invalid_grant_field() -> ProtocolError {
    ProtocolError::MalformedJson("'grant' must be 64 lowercase hex characters".into())
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

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, ProtocolError> {
    object
        .get(key)
        .ok_or_else(|| ProtocolError::MalformedJson(format!("missing '{key}'")))?
        .as_u64()
        .ok_or_else(|| {
            ProtocolError::MalformedJson(format!("'{key}' must be a non-negative integer"))
        })
}

/// Decode a `grant_create` body. The result is untrusted until
/// [`validate_request`] re-normalizes it through the same constructor the
/// approving CLI used.
fn decode_grant_create(request: &Map<String, Value>) -> Result<GrantCreateRequest, ProtocolError> {
    let references = required_string_array(request, "refs")?
        .iter()
        .enumerate()
        .map(|(index, text)| {
            EntryId::parse_ref(text).map_err(|_| {
                ProtocolError::InvalidRequest(format!(
                    "grant_create.refs[{index}] is not a valid pm:// reference"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fields = match request.get("fields") {
        None | Some(Value::Null) => None,
        Some(_) => Some(required_string_array(request, "fields")?),
    };
    let bits = required_u64(request, "capabilities")?;
    let capabilities = u8::try_from(bits)
        .ok()
        .and_then(|bits| Capabilities::from_bits(bits).ok())
        .ok_or_else(|| {
            ProtocolError::InvalidRequest(
                "grant_create.capabilities has bits this version does not know".into(),
            )
        })?;
    let max_uses = match request.get("max_uses") {
        None | Some(Value::Null) => None,
        Some(_) => {
            let max = required_u64(request, "max_uses")?;
            Some(u32::try_from(max).map_err(|_| {
                ProtocolError::InvalidRequest("grant_create.max_uses is too large".into())
            })?)
        }
    };
    let token_hash =
        TokenHash::from_hex(&required_string(request, "token_hash")?).ok_or_else(|| {
            ProtocolError::InvalidRequest(format!(
                "grant_create.token_hash must be {} lowercase hex characters",
                TOKEN_HASH_BYTES * 2
            ))
        })?;
    Ok(GrantCreateRequest {
        label: required_string(request, "label")?,
        references,
        tags: required_string_array(request, "tags")?,
        fields,
        commands: required_string_array(request, "commands")?,
        capabilities,
        expires_at: required_u64(request, "expires_at")?,
        max_uses,
        token_hash,
    })
}
