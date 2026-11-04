//! Daemon responses: one-shot statuses and the `run` output stream.
//!
//! These types live in their own module so the request and framing half of the
//! protocol stays readable. Both halves share [`ProtocolError`] and the frame
//! helpers in the parent module.

use std::fmt;

use serde_json::{Map, Value, json};

use super::entry::{Entry, decode_entries, decode_entry, entries_json};
use super::{
    LENGTH_PREFIX_BYTES, MAX_CHUNK_BYTES, MAX_MESSAGE_BYTES, MAX_SIGNAL, MAX_TYPE_CHARS,
    PROTOCOL_VERSION, ProtocolError, split_frame,
};
use crate::presence::ChallengeNonce;

/// A daemon response.
///
/// Responses carry status, the public challenge nonce, or credential metadata
/// (references, names, tags, field *names*, URLs and timestamps). There is
/// deliberately no field that can hold a secret value, and none may be added:
/// any same-user process can connect to the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The daemon is alive and the key is loaded.
    Pong,
    /// The daemon wiped its key and is shutting down.
    Locked,
    /// A fresh, single-use nonce for a human-presence proof.
    Challenge(ChallengeNonce),
    /// The presented proof was accepted and its nonce spent. The digest it
    /// covered is now a one-shot approval: the write for exactly that request
    /// may proceed once, and nothing else can use the answer as consent.
    Proven,
    /// A `grant_create` matched the one-shot approval the human proved and
    /// was accepted. Carries no token, hash or grant id: the CLI that holds
    /// the raw token assigns the id and writes the vault, so this answer is
    /// useless to anyone who did not already possess the token.
    GrantApproved,
    /// A `grant_revoke` marked grants revoked. `revoked` counts only grants
    /// that were active until now, so revoking an already-revoked id answers
    /// zero and changes nothing. Carries no id, label or hash.
    GrantRevoked { revoked: u32 },
    /// The metadata of the credentials a `list` grant covers, in vault order.
    /// Each entry is authorized individually, so an out-of-scope credential is
    /// simply absent. `truncated` is set when the rest would not fit one
    /// frame; the entries returned are always a prefix of the filtered list.
    Entries {
        entries: Vec<Entry>,
        truncated: bool,
    },
    /// The metadata of one credential a `describe` grant covers. The
    /// password is never read, and a reference outside the grant is reported
    /// as `not_found`, exactly like one that does not exist.
    Entry(Entry),
    /// The request was rejected. The error is a fixed code, never echo of the
    /// request or of vault data.
    Error(ResponseError),
}

/// Fixed, non-secret error codes a daemon may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// Malformed, truncated, oversized or unknown request.
    BadRequest,
    /// A well-formed request this build does not implement.
    Unsupported,
    /// The envelope did not carry this daemon's session token.
    Unauthorized,
    /// The requested credential or grant does not exist *or* the credential
    /// is outside the caller's grant scope. The cases are deliberately
    /// indistinguishable so the response is not an existence oracle.
    NotFound,
    /// The child process could not be started (missing program, permission).
    SpawnFailed,
    /// The daemon could not read its own vault (I/O, permissions, format).
    /// Deliberately fixed: the underlying error may name paths but never a
    /// value, and clients have nothing useful to do with it.
    Internal,
    /// The daemon is already serving its maximum number of concurrent `run`
    /// requests (or could not create a worker). Nothing was decrypted or
    /// spawned; the caller may retry once an earlier run finishes. Also the
    /// answer to `challenge` when the daemon cannot generate a nonce (a
    /// failing CSPRNG); the nonce pool itself never refuses (TODO R.16).
    Busy,
    /// A human-presence proof was refused: unknown or spent nonce, expired
    /// nonce, or a MAC that does not match the nonce and digest. All three
    /// cases are deliberately indistinguishable.
    Denied,
}

impl ResponseError {
    /// The stable wire code.
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unsupported => "unsupported",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::SpawnFailed => "spawn_failed",
            Self::Internal => "internal",
            Self::Busy => "busy",
            Self::Denied => "denied",
        }
    }

    fn from_code(code: &str) -> Result<Self, ProtocolError> {
        match code {
            "bad_request" => Ok(Self::BadRequest),
            "unsupported" => Ok(Self::Unsupported),
            "unauthorized" => Ok(Self::Unauthorized),
            "not_found" => Ok(Self::NotFound),
            "spawn_failed" => Ok(Self::SpawnFailed),
            "internal" => Ok(Self::Internal),
            "busy" => Ok(Self::Busy),
            "denied" => Ok(Self::Denied),
            other => Err(ProtocolError::UnknownResponse(
                other.chars().take(MAX_TYPE_CHARS).collect(),
            )),
        }
    }
}

/// One frame of a `run` response stream.
///
/// Chunks carry arbitrary child bytes (already redacted by the daemon); the
/// stream ends at exactly one [`RunFrame::Exit`] or [`RunFrame::Error`].
#[derive(Clone, PartialEq, Eq)]
pub enum RunFrame {
    /// A chunk of the child's standard output.
    Stdout(Vec<u8>),
    /// A chunk of the child's standard error.
    Stderr(Vec<u8>),
    /// The child finished; this is the last frame of a successful run.
    Exit(RunFinished),
    /// The run failed before or instead of producing a status.
    Error(ResponseError),
}

impl RunFrame {
    /// Whether this frame ends the stream.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exit(_) | Self::Error(_))
    }
}

impl fmt::Debug for RunFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Child output may contain fragments the redactor could not match
        // (or data a daemon bug failed to redact), so never render it.
        match self {
            Self::Stdout(data) => write!(f, "RunFrame::Stdout({} bytes)", data.len()),
            Self::Stderr(data) => write!(f, "RunFrame::Stderr({} bytes)", data.len()),
            Self::Exit(exit) => write!(f, "RunFrame::Exit({exit:?})"),
            Self::Error(error) => write!(f, "RunFrame::Error({error:?})"),
        }
    }
}

/// How a `run` child finished.
///
/// Exit codes and terminating signals stay distinct: collapsing a signal into
/// `128 + n` would make a signalled child indistinguishable from one that
/// chose that status, and the caller can decide how to render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
    /// The child exited normally with this status (0..=255).
    Code(u8),
    /// The child was killed by this signal (1..=[`MAX_SIGNAL`]).
    Signal(u8),
}

/// The terminal status of a `run`, plus the two limits that shaped it.
///
/// `timed_out` means the daemon's deadline fired and it killed the child's
/// process group; `exit` is then whatever signal the kill produced. The
/// truncation flags mean the relayed stream hit its cap: the cap is applied
/// to already-redacted bytes, so a truncated stream never ends in the middle
/// of a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunFinished {
    /// How the child exited, when it did.
    pub exit: RunExit,
    /// The run deadline fired and the child was killed.
    pub timed_out: bool,
    /// Standard output hit the per-stream cap and was cut short.
    pub stdout_truncated: bool,
    /// Standard error hit the per-stream cap and was cut short.
    pub stderr_truncated: bool,
}

impl RunFinished {
    /// A finished run that hit neither limit.
    pub const fn exited(exit: RunExit) -> Self {
        Self {
            exit,
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }
}

impl From<RunExit> for RunFinished {
    fn from(exit: RunExit) -> Self {
        Self::exited(exit)
    }
}

/// Ordering state for a `run` response stream.
///
/// The daemon sends exactly one terminal frame and then closes; a reader that
/// accepts a frame after `exit`/`error` would be mixing two runs (or letting a
/// broken peer append data to a finished one).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunStream {
    finished: bool,
}

impl RunStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a frame, rejecting anything after a terminal frame.
    pub fn accept(&mut self, frame: &RunFrame) -> Result<(), ProtocolError> {
        if self.finished {
            return Err(ProtocolError::InvalidResponse(
                "run frame after the stream ended".into(),
            ));
        }
        if frame.is_terminal() {
            self.finished = true;
        }
        Ok(())
    }

    /// Whether a terminal frame has been accepted.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Encode one response as a complete length-prefixed frame.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    let response = match response {
        Response::Pong => json!({ "type": "pong" }),
        Response::Locked => json!({ "type": "locked" }),
        Response::Challenge(nonce) => json!({ "type": "challenge", "nonce": nonce.to_hex() }),
        Response::Proven => json!({ "type": "proven" }),
        Response::GrantApproved => json!({ "type": "grant_approved" }),
        Response::GrantRevoked { revoked } => {
            json!({ "type": "grant_revoked", "revoked": revoked })
        }
        Response::Entries { entries, truncated } => json!({
            "type": "entries",
            "entries": entries_json(entries),
            "truncated": truncated,
        }),
        Response::Entry(entry) => json!({
            "type": "entry",
            "entry": entry.to_json(),
        }),
        Response::Error(error) => json!({ "type": "error", "code": error.code() }),
    };
    encode_value(&json!({ "version": PROTOCOL_VERSION, "response": response }))
}

/// Decode exactly one complete length-prefixed response frame.
///
/// Rejects the same structural problems as [`decode`] and unknown response
/// types or error codes. A `run` stream frame (`stdout`, `stderr`, `exit`) is
/// *not* a one-shot response and is rejected here; see [`decode_run_frame`].
/// Error messages never echo request or vault data.
pub fn decode_response(frame: &[u8]) -> Result<Response, ProtocolError> {
    let body = single_frame_body(frame)?;
    let value = response_value(body)?;
    let response = response_object(&value)?;

    match response_type(response)? {
        "pong" => Ok(Response::Pong),
        "locked" => Ok(Response::Locked),
        "challenge" => decode_challenge(response).map(Response::Challenge),
        "proven" => Ok(Response::Proven),
        "grant_approved" => Ok(Response::GrantApproved),
        "grant_revoked" => {
            decode_grant_revoked(response).map(|revoked| Response::GrantRevoked { revoked })
        }
        "entries" => decode_entries(response)
            .map(|(entries, truncated)| Response::Entries { entries, truncated }),
        "entry" => decode_entry(response).map(Response::Entry),
        "error" => decode_error_code(response).map(Response::Error),
        other => Err(ProtocolError::UnknownResponse(truncate_type(other))),
    }
}

/// Decode the count carried by a `grant_revoked` response.
fn decode_grant_revoked(response: &Map<String, Value>) -> Result<u32, ProtocolError> {
    let revoked = response
        .get("revoked")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response.revoked'".into()))?
        .as_u64()
        .ok_or_else(|| {
            ProtocolError::MalformedJson("'response.revoked' must be a non-negative integer".into())
        })?;
    u32::try_from(revoked)
        .map_err(|_| ProtocolError::InvalidResponse("'response.revoked' is too large".into()))
}

/// Decode the public nonce carried by a `challenge` response.
fn decode_challenge(response: &Map<String, Value>) -> Result<ChallengeNonce, ProtocolError> {
    let text = response
        .get("nonce")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response.nonce'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'response.nonce' must be a string".into()))?;
    ChallengeNonce::from_hex(text).ok_or_else(|| {
        ProtocolError::InvalidResponse(format!(
            "'response.nonce' must be {} lowercase hex characters",
            crate::presence::NONCE_BYTES * 2
        ))
    })
}

/// Encode one frame of a `run` response stream as a complete length-prefixed
/// frame.
///
/// Fails with [`ProtocolError::ChunkTooLarge`] if a `stdout`/`stderr` payload
/// exceeds [`MAX_CHUNK_BYTES`], so a caller cannot produce a chunk the peer
/// will refuse.
pub fn encode_run_frame(frame: &RunFrame) -> Result<Vec<u8>, ProtocolError> {
    let response = match frame {
        RunFrame::Stdout(data) => {
            check_chunk(data.len())?;
            json!({ "type": "stdout", "data": hex_encode(data) })
        }
        RunFrame::Stderr(data) => {
            check_chunk(data.len())?;
            json!({ "type": "stderr", "data": hex_encode(data) })
        }
        RunFrame::Exit(finished) => {
            let mut exit = Map::new();
            exit.insert("type".to_owned(), json!("exit"));
            match finished.exit {
                RunExit::Code(code) => {
                    exit.insert("code".to_owned(), json!(code));
                }
                RunExit::Signal(signal) => {
                    exit.insert("signal".to_owned(), json!(signal));
                }
            }
            exit.insert("timed_out".to_owned(), json!(finished.timed_out));
            exit.insert(
                "stdout_truncated".to_owned(),
                json!(finished.stdout_truncated),
            );
            exit.insert(
                "stderr_truncated".to_owned(),
                json!(finished.stderr_truncated),
            );
            Value::Object(exit)
        }
        RunFrame::Error(error) => json!({ "type": "error", "code": error.code() }),
    };
    encode_value(&json!({ "version": PROTOCOL_VERSION, "response": response }))
}

/// Decode exactly one complete length-prefixed `run` stream frame.
///
/// Rejects one-shot responses (`pong`, `locked`) as well as malformed hex, an
/// oversized chunk and an `exit` frame that does not carry exactly one of
/// `code`/`signal`. Never panics on attacker-supplied bytes.
pub fn decode_run_frame(frame: &[u8]) -> Result<RunFrame, ProtocolError> {
    let body = single_frame_body(frame)?;
    let value = response_value(body)?;
    let response = response_object(&value)?;

    match response_type(response)? {
        "stdout" => decode_chunk(response).map(RunFrame::Stdout),
        "stderr" => decode_chunk(response).map(RunFrame::Stderr),
        "exit" => decode_exit(response).map(RunFrame::Exit),
        "error" => decode_error_code(response).map(RunFrame::Error),
        other => Err(ProtocolError::UnknownResponse(truncate_type(other))),
    }
}

/// Serialize one response object with its length prefix.
fn encode_value(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let body =
        serde_json::to_vec(value).map_err(|err| ProtocolError::MalformedJson(err.to_string()))?;
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

/// Split one frame and reject anything that follows it.
fn single_frame_body(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    let (body, rest) = split_frame(frame)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes {
            trailing: rest.len(),
        });
    }
    Ok(body)
}

/// Parse a response envelope and check its version.
fn response_value(body: &[u8]) -> Result<Value, ProtocolError> {
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
    Ok(value)
}

fn response_object(value: &Value) -> Result<&Map<String, Value>, ProtocolError> {
    value
        .get("response")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response'".into()))?
        .as_object()
        .ok_or_else(|| ProtocolError::MalformedJson("'response' must be an object".into()))
}

fn response_type(response: &Map<String, Value>) -> Result<&str, ProtocolError> {
    response
        .get("type")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response.type'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'response.type' must be a string".into()))
}

fn decode_error_code(response: &Map<String, Value>) -> Result<ResponseError, ProtocolError> {
    let code = response
        .get("code")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response.code'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'response.code' must be a string".into()))?;
    ResponseError::from_code(code)
}

/// Decode a `stdout`/`stderr` payload. The length is checked before the hex is
/// decoded, so an oversized field is refused without allocating its bytes.
fn decode_chunk(response: &Map<String, Value>) -> Result<Vec<u8>, ProtocolError> {
    let text = response
        .get("data")
        .ok_or_else(|| ProtocolError::MalformedJson("missing 'response.data'".into()))?
        .as_str()
        .ok_or_else(|| ProtocolError::MalformedJson("'response.data' must be a string".into()))?;
    if text.len() % 2 != 0 {
        return Err(ProtocolError::InvalidResponse(
            "'response.data' must have an even number of hex digits".into(),
        ));
    }
    check_chunk(text.len() / 2)?;
    hex_decode(text).ok_or_else(|| {
        ProtocolError::InvalidResponse("'response.data' must be lowercase hex".into())
    })
}

fn decode_exit(response: &Map<String, Value>) -> Result<RunFinished, ProtocolError> {
    let exit = match (response.get("code"), response.get("signal")) {
        (Some(code), None) => {
            let code = code
                .as_u64()
                .ok_or_else(|| {
                    ProtocolError::InvalidResponse("'response.code' must be a number".into())
                })
                .and_then(|code| {
                    u8::try_from(code).map_err(|_| {
                        ProtocolError::InvalidResponse(
                            "'response.code' must be between 0 and 255".into(),
                        )
                    })
                })?;
            RunExit::Code(code)
        }
        (None, Some(signal)) => {
            let signal = signal
                .as_u64()
                .ok_or_else(|| {
                    ProtocolError::InvalidResponse("'response.signal' must be a number".into())
                })
                .and_then(|signal| {
                    u8::try_from(signal).map_err(|_| {
                        ProtocolError::InvalidResponse(
                            "'response.signal' must be between 1 and 127".into(),
                        )
                    })
                })?;
            if signal == 0 || signal > MAX_SIGNAL {
                return Err(ProtocolError::InvalidResponse(
                    "'response.signal' must be between 1 and 127".into(),
                ));
            }
            RunExit::Signal(signal)
        }
        _ => {
            return Err(ProtocolError::InvalidResponse(
                "an exit frame carries exactly one of 'code' and 'signal'".into(),
            ));
        }
    };
    Ok(RunFinished {
        exit,
        timed_out: optional_flag(response, "timed_out")?,
        stdout_truncated: optional_flag(response, "stdout_truncated")?,
        stderr_truncated: optional_flag(response, "stderr_truncated")?,
    })
}

/// Read an optional boolean flag from an exit frame. A peer that predates the
/// flags omits them; `null` or any other type is refused rather than guessed.
fn optional_flag(response: &Map<String, Value>, field: &str) -> Result<bool, ProtocolError> {
    match response.get(field) {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(|| {
            ProtocolError::InvalidResponse(format!("'response.{field}' must be a boolean"))
        }),
    }
}

fn check_chunk(length: usize) -> Result<(), ProtocolError> {
    if length > MAX_CHUNK_BYTES {
        return Err(ProtocolError::ChunkTooLarge {
            length,
            max: MAX_CHUNK_BYTES,
        });
    }
    Ok(())
}

fn truncate_type(kind: &str) -> String {
    kind.chars().take(MAX_TYPE_CHARS).collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Strict lowercase hex, like the session token. `None` on any other byte.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
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
mod tests;
