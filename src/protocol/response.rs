//! Daemon responses: one-shot statuses and the `run` output stream.
//!
//! These types live in their own module so the request and framing half of the
//! protocol stays readable. Both halves share [`ProtocolError`] and the frame
//! helpers in the parent module.

use std::fmt;

use serde_json::{Map, Value, json};

use super::{
    LENGTH_PREFIX_BYTES, MAX_CHUNK_BYTES, MAX_MESSAGE_BYTES, MAX_SIGNAL, MAX_TYPE_CHARS,
    PROTOCOL_VERSION, ProtocolError, split_frame,
};

/// A daemon response.
///
/// Responses carry status only. There is deliberately no field that can hold
/// a secret value, and none may be added: any same-user process can connect to
/// the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// The daemon is alive and the key is loaded.
    Pong,
    /// The daemon wiped its key and is shutting down.
    Locked,
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
    /// The requested credential does not exist *or* is outside the caller's
    /// grant scope. The two cases are deliberately indistinguishable so the
    /// response is not an existence oracle.
    NotFound,
    /// The child process could not be started (missing program, permission).
    SpawnFailed,
    /// The daemon could not read its own vault (I/O, permissions, format).
    /// Deliberately fixed: the underlying error may name paths but never a
    /// value, and clients have nothing useful to do with it.
    Internal,
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
    Exit(RunExit),
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
        "error" => decode_error_code(response).map(Response::Error),
        other => Err(ProtocolError::UnknownResponse(truncate_type(other))),
    }
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
        RunFrame::Exit(RunExit::Code(code)) => json!({ "type": "exit", "code": code }),
        RunFrame::Exit(RunExit::Signal(signal)) => json!({ "type": "exit", "signal": signal }),
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

fn decode_exit(response: &Map<String, Value>) -> Result<RunExit, ProtocolError> {
    match (response.get("code"), response.get("signal")) {
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
            Ok(RunExit::Code(code))
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
            Ok(RunExit::Signal(signal))
        }
        _ => Err(ProtocolError::InvalidResponse(
            "an exit frame carries exactly one of 'code' and 'signal'".into(),
        )),
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
mod tests {
    use super::*;

    /// Build a frame by hand, without going through `encode`.
    fn frame(body: &str) -> Vec<u8> {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body.as_bytes());
        frame
    }

    #[test]
    fn round_trips_every_response() {
        for response in [
            Response::Pong,
            Response::Locked,
            Response::Error(ResponseError::BadRequest),
            Response::Error(ResponseError::Unsupported),
            Response::Error(ResponseError::Unauthorized),
            Response::Error(ResponseError::NotFound),
            Response::Error(ResponseError::SpawnFailed),
            Response::Error(ResponseError::Internal),
        ] {
            let encoded = encode_response(&response).expect("encode response");
            assert_eq!(
                decode_response(&encoded).expect("decode response"),
                response
            );
        }
    }

    #[test]
    fn response_frames_have_a_fixed_shape_with_no_value_fields() {
        let pong = encode_response(&Response::Pong).expect("encode");
        let pong_body = br#"{"response":{"type":"pong"},"version":3}"#;
        assert_eq!(&pong[..4], &(pong_body.len() as u32).to_be_bytes());
        assert_eq!(&pong[4..], pong_body);

        let error = encode_response(&Response::Error(ResponseError::BadRequest)).expect("encode");
        assert_eq!(
            &error[4..],
            br#"{"response":{"code":"bad_request","type":"error"},"version":3}"#
        );
    }

    #[test]
    fn unknown_response_types_and_codes_are_rejected() {
        let long = "x".repeat(MAX_TYPE_CHARS * 4);
        let unknown_type = frame(&format!(
            r#"{{"version":3,"response":{{"type":"{long}"}}}}"#
        ));
        match decode_response(&unknown_type) {
            Err(ProtocolError::UnknownResponse(echoed)) => {
                assert_eq!(echoed.chars().count(), MAX_TYPE_CHARS);
            }
            other => panic!("expected unknown response type, got {other:?}"),
        }

        let unknown_code = frame(&format!(
            r#"{{"version":3,"response":{{"type":"error","code":"{long}"}}}}"#
        ));
        assert!(matches!(
            decode_response(&unknown_code),
            Err(ProtocolError::UnknownResponse(_))
        ));
    }

    #[test]
    fn malformed_response_frames_are_rejected() {
        let cases = [
            frame(r#"{"version":1,"response":{"type":"pong"}}"#),
            frame(r#"{"response":{"type":"pong"}}"#),
            frame(r#"{"version":3}"#),
            frame(r#"{"version":3,"response":"pong"}"#),
            frame(r#"{"version":3,"response":{}}"#),
            frame(r#"{"version":3,"response":{"type":7}}"#),
            frame(r#"{"version":3,"response":{"type":"error"}}"#),
            frame(r#"{"version":3,"response":{"type":"error","code":7}}"#),
            frame("not json"),
            vec![0, 0, 0, 10, b'{'],
        ];
        for bytes in cases {
            assert!(
                decode_response(&bytes).is_err(),
                "accepted malformed frame: {bytes:?}"
            );
        }

        let mut trailing = encode_response(&Response::Pong).expect("encode");
        trailing.push(b'x');
        assert_eq!(
            decode_response(&trailing),
            Err(ProtocolError::TrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn responses_never_repeat_a_body_field_value() {
        // A daemon bug that slipped a value into a response must not turn into
        // an echoed secret in logs: decoding ignores unknown fields and the
        // error text never repeats them.
        let secret_like = "SUPER_SECRET_VALUE_123";
        let body = format!(
            r#"{{"version":3,"response":{{"type":"error","code":"nope","value":"{secret_like}"}}}}"#
        );
        let error = decode_response(&frame(&body)).expect_err("unknown code");
        let text = error.to_string();
        assert!(!text.contains(secret_like), "unexpected message: {text}");
    }

    #[test]
    fn arbitrary_bytes_are_rejected_as_responses_without_panicking() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for length in 0..=96 {
            for _ in 0..32 {
                let mut bytes = vec![0u8; length];
                for byte in &mut bytes {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                let _ = decode_response(&bytes);
            }
        }
    }

    #[test]
    fn run_stream_frames_round_trip_arbitrary_bytes() {
        // Every byte value, NUL included, plus sequences that are not valid
        // UTF-8: JSON must not be allowed to mangle child output.
        let mut all_bytes = Vec::new();
        for byte in 0u8..=255 {
            all_bytes.push(byte);
        }
        let invalid_utf8 = vec![0xff, 0xfe, 0x80, b'a', 0x00, b'\n'];
        let cases = [
            Vec::new(),
            all_bytes,
            invalid_utf8,
            b"plain text\nwith a newline\n".to_vec(),
            vec![0u8; MAX_CHUNK_BYTES],
        ];
        let frames = [
            RunFrame::Stdout(cases[0].clone()),
            RunFrame::Stderr(cases[0].clone()),
            RunFrame::Stdout(cases[1].clone()),
            RunFrame::Stderr(cases[2].clone()),
            RunFrame::Stdout(cases[3].clone()),
            RunFrame::Stderr(cases[4].clone()),
        ];
        for frame in frames {
            let encoded = encode_run_frame(&frame).expect("encode run frame");
            assert_eq!(decode_run_frame(&encoded).expect("decode run frame"), frame);
        }
    }

    #[test]
    fn exit_frames_round_trip_and_validate_the_status() {
        for exit in [
            RunExit::Code(0),
            RunExit::Code(1),
            RunExit::Code(255),
            RunExit::Signal(1),
            RunExit::Signal(9),
            RunExit::Signal(127),
        ] {
            let encoded = encode_run_frame(&RunFrame::Exit(exit)).expect("encode exit");
            assert_eq!(
                decode_run_frame(&encoded).expect("decode exit"),
                RunFrame::Exit(exit)
            );
        }

        for body in [
            r#"{"version":3,"response":{"type":"exit"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":256}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":-1}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":1.5}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":"0"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","signal":0}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","signal":128}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","signal":-9}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":0,"signal":9}}"#.to_string(),
            r#"{"version":3,"response":{"type":"exit","code":null}}"#.to_string(),
        ] {
            assert!(
                decode_run_frame(&frame(&body)).is_err(),
                "accepted invalid exit frame: {body}"
            );
        }
    }

    #[test]
    fn output_chunks_are_capped_on_encode_and_decode() {
        let at_limit = RunFrame::Stdout(vec![b'x'; MAX_CHUNK_BYTES]);
        let encoded = encode_run_frame(&at_limit).expect("a maximum chunk must encode");
        assert!(encoded.len() <= MAX_MESSAGE_BYTES + LENGTH_PREFIX_BYTES);
        assert_eq!(decode_run_frame(&encoded).expect("decode"), at_limit);

        let over_limit = RunFrame::Stderr(vec![b'x'; MAX_CHUNK_BYTES + 1]);
        assert_eq!(
            encode_run_frame(&over_limit),
            Err(ProtocolError::ChunkTooLarge {
                length: MAX_CHUNK_BYTES + 1,
                max: MAX_CHUNK_BYTES,
            })
        );

        // The same bound applies to a peer-supplied frame, checked from the hex
        // text length before any decoding allocation.
        let body = format!(
            r#"{{"version":3,"response":{{"type":"stderr","data":"{}"}}}}"#,
            "00".repeat(MAX_CHUNK_BYTES + 1)
        );
        assert!(matches!(
            decode_run_frame(&frame(&body)),
            Err(ProtocolError::ChunkTooLarge { length, max })
                if length == MAX_CHUNK_BYTES + 1 && max == MAX_CHUNK_BYTES
        ));
    }

    #[test]
    fn malformed_run_frames_are_rejected() {
        let cases = [
            // One-shot responses are not stream frames.
            r#"{"version":3,"response":{"type":"pong"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"locked"}}"#.to_string(),
            // Output frames need a string of lowercase hex digits.
            r#"{"version":3,"response":{"type":"stdout"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"stdout","data":7}}"#.to_string(),
            r#"{"version":3,"response":{"type":"stdout","data":"0"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"stdout","data":"0g"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"stdout","data":"AB"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"stdout","data":null}}"#.to_string(),
            // Unknown frame types, and missing/mistyped envelopes.
            r#"{"version":3,"response":{"type":"password","data":"00"}}"#.to_string(),
            r#"{"version":1,"response":{"type":"stdout","data":"00"}}"#.to_string(),
            r#"{"response":{"type":"stdout","data":"00"}}"#.to_string(),
            r#"{"version":3,"response":[]}"#.to_string(),
            r#"{"version":3,"response":{"type":7}}"#.to_string(),
            "not json".to_string(),
            // An error frame still needs a known code.
            r#"{"version":3,"response":{"type":"error"}}"#.to_string(),
            r#"{"version":3,"response":{"type":"error","code":"nope"}}"#.to_string(),
        ];
        for body in cases {
            assert!(
                decode_run_frame(&frame(&body)).is_err(),
                "accepted malformed run frame: {body}"
            );
        }

        let mut trailing = encode_run_frame(&RunFrame::Stdout(b"hi".to_vec())).expect("encode");
        trailing.push(b'x');
        assert_eq!(
            decode_run_frame(&trailing),
            Err(ProtocolError::TrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn one_shot_and_stream_responses_cannot_be_confused() {
        let pong = encode_response(&Response::Pong).expect("encode pong");
        assert!(matches!(
            decode_run_frame(&pong),
            Err(ProtocolError::UnknownResponse(_))
        ));

        for frame in [
            RunFrame::Stdout(b"out".to_vec()),
            RunFrame::Stderr(b"err".to_vec()),
            RunFrame::Exit(RunExit::Code(0)),
        ] {
            let encoded = encode_run_frame(&frame).expect("encode run frame");
            assert!(matches!(
                decode_response(&encoded),
                Err(ProtocolError::UnknownResponse(_))
            ));
        }
    }

    #[test]
    fn run_error_codes_are_stable_and_round_trip() {
        let expected = [
            (ResponseError::BadRequest, "bad_request"),
            (ResponseError::Unsupported, "unsupported"),
            (ResponseError::Unauthorized, "unauthorized"),
            (ResponseError::NotFound, "not_found"),
            (ResponseError::SpawnFailed, "spawn_failed"),
            (ResponseError::Internal, "internal"),
        ];
        for (error, code) in expected {
            assert_eq!(error.code(), code);
            let encoded = encode_run_frame(&RunFrame::Error(error)).expect("encode error");
            assert_eq!(
                decode_run_frame(&encoded).expect("decode error"),
                RunFrame::Error(error)
            );
            let text = String::from_utf8(encoded[LENGTH_PREFIX_BYTES..].to_vec()).expect("json");
            assert!(text.contains(&format!("\"code\":\"{code}\"")));
        }
    }

    #[test]
    fn run_stream_accepts_nothing_after_a_terminal_frame() {
        for terminal in [
            RunFrame::Exit(RunExit::Code(0)),
            RunFrame::Exit(RunExit::Signal(9)),
            RunFrame::Error(ResponseError::NotFound),
        ] {
            let mut stream = RunStream::new();
            assert!(!stream.is_finished());
            stream
                .accept(&RunFrame::Stdout(b"out".to_vec()))
                .expect("chunk before the end is fine");
            stream
                .accept(&RunFrame::Stderr(b"err".to_vec()))
                .expect("chunk before the end is fine");
            assert!(!stream.is_finished());
            stream.accept(&terminal).expect("terminal frame is fine");
            assert!(stream.is_finished());
            for extra in [
                RunFrame::Stdout(b"late".to_vec()),
                RunFrame::Stderr(b"late".to_vec()),
                RunFrame::Exit(RunExit::Code(0)),
                RunFrame::Error(ResponseError::SpawnFailed),
            ] {
                assert!(
                    stream.accept(&extra).is_err(),
                    "accepted a frame after {terminal:?}"
                );
            }
        }
    }

    #[test]
    fn run_frame_debug_never_renders_child_output() {
        let canary = "CANARY_CHILD_OUTPUT_2f9a";
        for frame in [
            RunFrame::Stdout(canary.as_bytes().to_vec()),
            RunFrame::Stderr(canary.as_bytes().to_vec()),
        ] {
            let text = format!("{frame:?}");
            assert!(
                !text.contains(canary),
                "Debug rendered child output: {text}"
            );
        }
        assert_eq!(
            format!("{:?}", RunFrame::Stdout(b"abc".to_vec())),
            "RunFrame::Stdout(3 bytes)"
        );
    }

    #[test]
    fn arbitrary_bytes_are_rejected_as_run_frames_without_panicking() {
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for length in 0..=128 {
            for _ in 0..32 {
                let mut bytes = vec![0u8; length];
                for byte in &mut bytes {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                let _ = decode_run_frame(&bytes);
            }
        }
    }
}
