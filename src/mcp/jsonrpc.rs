//! The JSON-RPC 2.0 line codec for `pm mcp serve`.
//!
//! MCP runs over stdio as UTF-8 JSON-RPC 2.0 objects, one per line, delimited
//! by `\n` (see `MCP.md`, "Transport (stdio)"). This module is the whole of
//! that transport: it splits a byte stream into lines and parses or
//! serializes a single line. It performs no I/O, so the server loop and its
//! tests share the same code.
//!
//! ```text
//! {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n
//! ```
//!
//! # Rules enforced here
//!
//! - A line longer than [`MAX_LINE_BYTES`] is dropped as it is read and
//!   reported as [`LineEvent::TooLong`]; reading then resynchronizes on the
//!   next newline, so one hostile line cannot desynchronize the stream.
//! - The peer's JSON is parsed into [`Message`] and validated structurally:
//!   `jsonrpc` must be exactly `"2.0"`, a request needs a string or integer
//!   `id`, a notification has no `id` member, a response carries exactly one
//!   of `result`/`error`, and top-level batches (arrays) are refused. Unknown
//!   *members* are ignored, as JSON-RPC requires, so a later protocol revision
//!   can add fields without breaking this one.
//! - A rejection is a [`Rejected`]: the error object to send back plus the id
//!   to address it to when the frame carried a usable one (`"id": null`
//!   otherwise, as the spec requires when the id is unknown).
//!
//! # Untrusted input
//!
//! Every byte here comes from the agent host, so nothing is trusted: strings
//! are length-bounded before they are stored or echoed ([`MAX_ID_BYTES`],
//! [`MAX_METHOD_BYTES`], [`MAX_ERROR_MESSAGE_BYTES`]), and no rejection
//! message contains a value from the frame. A message's payload can name
//! references, argv and reasons, but by contract never a secret value; this
//! module neither creates nor accepts one, and no error it produces can carry
//! one.

use std::fmt;

use serde_json::{Map, Value, json};

/// The only JSON-RPC version string this build speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// Largest accepted line, excluding its trailing newline. `MCP.md` fixes this
/// at 1 MiB.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Longest accepted method name.
pub const MAX_METHOD_BYTES: usize = 128;

/// Longest accepted string request id. Real clients use numbers or short
/// strings; the bound stops a peer from making us echo a megabyte back.
pub const MAX_ID_BYTES: usize = 128;

/// Longest accepted `error.message` in a response we receive. It is peer text
/// that may reach a log, so it is bounded like any other agent-supplied text.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

/// One JSON-RPC 2.0 message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A call that expects an answer. MCP client → server.
    Request(Request),
    /// A call with no `id` member that must not be answered.
    Notification(Notification),
    /// An answer to a request this process sent.
    Response(Response),
}

/// A request: an `id`, a method name and optional structured params.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: Id,
    pub method: String,
    /// `params` exactly as sent; `None` when the member was absent or `null`.
    /// Interpreted by the protocol layer, never here.
    pub params: Option<Value>,
}

/// A notification: a method name and optional structured params, no `id`.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub method: String,
    pub params: Option<Value>,
}

/// A response to a request, carrying either a result or an error.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    /// `None` represents `"id": null`, which the spec allows when the peer
    /// could not determine which request the answer belongs to.
    pub id: Option<Id>,
    pub outcome: Outcome,
}

/// The payload of a [`Response`].
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Result(Value),
    Error(ErrorObject),
}

/// A JSON-RPC request id: a string or a signed 64-bit integer.
///
/// JSON-RPC also permits fractional numbers. They are refused: an MCP host
/// numbers its requests with integers, and accepting a float would mean
/// echoing a value this server cannot represent exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    Number(i64),
    String(String),
}

impl Id {
    fn to_json(&self) -> Value {
        match self {
            Self::Number(number) => json!(number),
            Self::String(text) => json!(text),
        }
    }
}

/// The error codes `MCP.md` defines. The wire value is the only thing that
/// matters; the variant names say what the code means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// `-32700`: the line was not UTF-8 or not valid JSON.
    Parse,
    /// `-32600`: valid JSON, but not a valid JSON-RPC message.
    InvalidRequest,
    /// `-32601`: a well-formed call to a method this server does not have.
    MethodNotFound,
    /// `-32602`: the method's params failed validation.
    InvalidParams,
    /// `-32603`: the server failed for a reason that is not the client's.
    Internal,
    /// `-32022`: a modern-era request named a protocol version we do not
    /// speak (see `MCP.md`, "Protocol eras").
    UnsupportedProtocolVersion,
}

impl ErrorCode {
    /// The stable numeric code sent on the wire.
    pub fn code(self) -> i32 {
        match self {
            Self::Parse => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::Internal => -32603,
            Self::UnsupportedProtocolVersion => -32022,
        }
    }
}

/// The `error` member of an error response.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorObject {
    /// The numeric code as it travels on the wire. Constructed from an
    /// [`ErrorCode`] locally; a code received from a peer is kept as it is so
    /// an unknown one is not rewritten into a wrong meaning.
    pub code: i32,
    /// Short, actionable text. Never contains a value from the vault.
    pub message: String,
    /// Optional structured detail (for `-32022`, the supported versions).
    pub data: Option<Value>,
}

impl ErrorObject {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// A line the server must answer with an error instead of acting on.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejected {
    /// The error object to send back.
    pub error: ErrorObject,
    /// The id to address it to, when the frame carried a usable one.
    pub id: Option<Id>,
}

impl Rejected {
    /// A `-32700`: the bytes were not UTF-8 or not JSON, so there is no id.
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self {
            error: ErrorObject::new(ErrorCode::Parse, message),
            id: None,
        }
    }

    /// A `-32600`: valid JSON, but not a valid JSON-RPC message. `id` is the
    /// request's id when it was readable, so the client can match the answer.
    pub fn invalid_request(id: Option<Id>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorObject::new(ErrorCode::InvalidRequest, message),
            id,
        }
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON-RPC code {}: {}",
            self.error.code, self.error.message
        )
    }
}

impl std::error::Error for Rejected {}

impl Message {
    pub fn request(id: Id, method: impl Into<String>, params: Option<Value>) -> Self {
        Self::Request(Request {
            id,
            method: method.into(),
            params,
        })
    }

    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self::Notification(Notification {
            method: method.into(),
            params,
        })
    }

    pub fn result(id: Id, result: Value) -> Self {
        Self::Response(Response {
            id: Some(id),
            outcome: Outcome::Result(result),
        })
    }

    pub fn error(id: Option<Id>, error: ErrorObject) -> Self {
        Self::Response(Response {
            id,
            outcome: Outcome::Error(error),
        })
    }
}

/// One unit of input produced by a [`LineReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvent {
    /// A complete line without its trailing newline. Never longer than
    /// [`MAX_LINE_BYTES`]; it may be empty (a bare `\n`), which
    /// [`parse_line`] rejects as a parse error like any other non-JSON line.
    Line(Vec<u8>),
    /// One line exceeded [`MAX_LINE_BYTES`] and was discarded up to and
    /// including its newline. `bytes` counts the discarded content (without
    /// the newline). Answer it with a parse error and carry on.
    TooLong { bytes: usize },
}

/// Turns a byte stream into newline-delimited lines without ever buffering
/// more than [`MAX_LINE_BYTES`].
///
/// Feed each read with [`LineReader::push`] and take the events it returns;
/// call [`LineReader::finish`] at end of input for a last line that arrived
/// without a trailing newline. An over-long line is dropped while it is
/// being read, and the reader resynchronizes on its newline, so a hostile
/// peer cannot make the server allocate without bound or lose the messages
/// that follow.
#[derive(Debug, Default)]
pub struct LineReader {
    pending: Vec<u8>,
    /// True while the tail of an over-long line is being skipped.
    discarding: bool,
    /// Content bytes discarded since the current line began.
    discarded: usize,
}

impl LineReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume bytes just read from the stream and return the lines they
    /// completed, in order.
    ///
    /// Never fails and never blocks. The returned vector is empty when the
    /// chunk held no newline. Callers should pass one read buffer at a time;
    /// the reader itself bounds what it retains to [`MAX_LINE_BYTES`].
    pub fn push(&mut self, bytes: &[u8]) -> Vec<LineEvent> {
        let mut events = Vec::new();
        let mut rest = bytes;
        while let Some(position) = rest.iter().position(|byte| *byte == b'\n') {
            let (content, tail) = rest.split_at(position);
            self.append(content);
            events.push(self.complete());
            rest = &tail[1..];
        }
        self.append(rest);
        events
    }

    /// Report the final line of a stream that ended without a newline.
    ///
    /// Returns `None` when nothing is pending (the last line ended with `\n`,
    /// or the input was empty). A trailing fragment of an over-long line is
    /// silently dropped: there is no complete line to report and the stream
    /// is over.
    pub fn finish(&mut self) -> Option<LineEvent> {
        if self.discarding {
            self.discarding = false;
            self.discarded = 0;
            return None;
        }
        if self.pending.is_empty() {
            return None;
        }
        Some(LineEvent::Line(std::mem::take(&mut self.pending)))
    }

    /// Add a piece of the current line, or drop it if the line is too long.
    fn append(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.discarding {
            self.discarded += bytes.len();
            return;
        }
        if self.pending.len().saturating_add(bytes.len()) <= MAX_LINE_BYTES {
            self.pending.extend_from_slice(bytes);
            return;
        }
        // The line is too long: forget what was buffered, keep only the count
        // so the caller can report how much was dropped.
        self.discarded = self.pending.len() + bytes.len();
        self.pending.clear();
        self.pending.shrink_to_fit();
        self.discarding = true;
    }

    /// Finish the current line at a newline boundary.
    fn complete(&mut self) -> LineEvent {
        if self.discarding {
            let bytes = self.discarded;
            self.discarded = 0;
            self.discarding = false;
            return LineEvent::TooLong { bytes };
        }
        LineEvent::Line(std::mem::take(&mut self.pending))
    }
}

/// Parse one line (without its newline) into a message.
///
/// Every structural rule in `MCP.md` is checked here; method and param
/// semantics belong to the layer above. Rejections carry the JSON-RPC error
/// to send and, when readable, the id it answers.
pub fn parse_line(line: &[u8]) -> Result<Message, Rejected> {
    let text = std::str::from_utf8(line)
        .map_err(|_| Rejected::parse_error("the line is not valid UTF-8"))?;
    let value: Value = serde_json::from_str(text)
        .map_err(|error| Rejected::parse_error(format!("the line is not valid JSON: {error}")))?;
    let object = match value {
        Value::Object(object) => object,
        Value::Array(_) => {
            return Err(Rejected::invalid_request(
                None,
                "JSON-RPC batches are not supported; send one request per line",
            ));
        }
        _ => {
            return Err(Rejected::invalid_request(
                None,
                "expected a JSON-RPC object",
            ));
        }
    };

    let id = id_field(&object);
    // A readable id is echoed in the error so the client can match it up.
    let usable = match &id {
        IdField::Valid(id) => Some(id.clone()),
        _ => None,
    };

    match object.get("jsonrpc") {
        Some(Value::String(version)) if version == JSONRPC_VERSION => {}
        Some(Value::String(_)) => {
            return Err(Rejected::invalid_request(
                usable,
                "unsupported JSON-RPC version (this server speaks 2.0)",
            ));
        }
        Some(_) => {
            return Err(Rejected::invalid_request(
                usable,
                "jsonrpc must be the string \"2.0\"",
            ));
        }
        None => {
            return Err(Rejected::invalid_request(
                usable,
                "missing the jsonrpc member",
            ));
        }
    }

    match object.get("method") {
        Some(Value::String(method)) => parse_call(&object, method, id),
        Some(_) => Err(Rejected::invalid_request(usable, "method must be a string")),
        None => parse_response(&object, id),
    }
}

/// The `id` member of a frame, distinguishing "absent" from "unusable".
enum IdField {
    Absent,
    Null,
    Valid(Id),
    Invalid,
}

fn id_field(object: &Map<String, Value>) -> IdField {
    match object.get("id") {
        None => IdField::Absent,
        Some(Value::Null) => IdField::Null,
        Some(Value::String(text)) if text.len() <= MAX_ID_BYTES => {
            IdField::Valid(Id::String(text.clone()))
        }
        Some(Value::Number(number)) => match number.as_i64() {
            Some(number) => IdField::Valid(Id::Number(number)),
            // An integer outside i64 or a fractional number: not something
            // this server can echo exactly, so the whole frame is refused.
            None => IdField::Invalid,
        },
        Some(_) => IdField::Invalid,
    }
}

/// Parse a frame that has a `method` member into a request or notification.
fn parse_call(object: &Map<String, Value>, method: &str, id: IdField) -> Result<Message, Rejected> {
    let usable = match &id {
        IdField::Valid(id) => Some(id.clone()),
        _ => None,
    };
    if method.is_empty() {
        return Err(Rejected::invalid_request(
            usable,
            "method must not be empty",
        ));
    }
    if method.len() > MAX_METHOD_BYTES {
        return Err(Rejected::invalid_request(
            usable,
            "method is longer than the supported limit",
        ));
    }
    let params = match object.get("params") {
        None | Some(Value::Null) => None,
        Some(value @ (Value::Object(_) | Value::Array(_))) => Some(value.clone()),
        Some(_) => {
            return Err(Rejected::invalid_request(
                usable,
                "params must be an object or an array",
            ));
        }
    };

    match id {
        IdField::Absent => Ok(Message::Notification(Notification {
            method: method.to_string(),
            params,
        })),
        IdField::Valid(id) => Ok(Message::Request(Request {
            id,
            method: method.to_string(),
            params,
        })),
        // `"id": null` is deliberately not treated as a notification: the
        // spec forbids it precisely because "call me back" and "don't call me
        // back" would then be indistinguishable.
        IdField::Null => Err(Rejected::invalid_request(
            None,
            "a request id must be a string or an integer, not null",
        )),
        IdField::Invalid => Err(Rejected::invalid_request(
            None,
            "a request id must be a string or a 64-bit integer",
        )),
    }
}

/// Parse a frame without a `method` member into a response.
fn parse_response(object: &Map<String, Value>, id: IdField) -> Result<Message, Rejected> {
    let id = match id {
        IdField::Valid(id) => Some(id),
        IdField::Null => None,
        IdField::Absent => {
            return Err(Rejected::invalid_request(
                None,
                "expected a request, a notification or a response",
            ));
        }
        IdField::Invalid => {
            return Err(Rejected::invalid_request(
                None,
                "a response id must be a string, an integer or null",
            ));
        }
    };

    let result = object.get("result");
    let error = object.get("error");
    match (result, error) {
        (Some(result), None) => Ok(Message::Response(Response {
            id,
            outcome: Outcome::Result(result.clone()),
        })),
        (None, Some(error)) => {
            let error = parse_error_object(error)
                .map_err(|message| Rejected::invalid_request(id.clone(), message))?;
            Ok(Message::Response(Response {
                id,
                outcome: Outcome::Error(error),
            }))
        }
        _ => Err(Rejected::invalid_request(
            id,
            "a response must carry exactly one of result and error",
        )),
    }
}

fn parse_error_object(value: &Value) -> Result<ErrorObject, &'static str> {
    let Value::Object(object) = value else {
        return Err("error must be an object");
    };
    let code = match object.get("code") {
        Some(Value::Number(number)) => number
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
            .ok_or("error.code must be a 32-bit integer")?,
        _ => return Err("error.code must be a 32-bit integer"),
    };
    let message = match object.get("message") {
        Some(Value::String(text)) if text.len() <= MAX_ERROR_MESSAGE_BYTES => text.clone(),
        Some(Value::String(_)) => return Err("error.message is longer than the supported limit"),
        _ => return Err("error.message must be a string"),
    };
    Ok(ErrorObject {
        code,
        message,
        data: object.get("data").cloned(),
    })
}

/// Serialize a message as exactly one line, including the trailing `\n`.
///
/// JSON encoding escapes every control character inside a string, so the
/// result contains no other newline. There is no size limit here:
/// [`MAX_LINE_BYTES`] bounds the lines this server reads, not the ones it
/// writes. A `run_with_credentials` result at the largest output caps, full of
/// escaped control bytes, encodes to roughly 12 MB.
pub fn encode_line(message: &Message) -> Vec<u8> {
    let value = match message {
        Message::Request(request) => {
            let mut object = Map::new();
            object.insert("jsonrpc".into(), json!(JSONRPC_VERSION));
            object.insert("id".into(), request.id.to_json());
            object.insert("method".into(), json!(request.method));
            if let Some(params) = &request.params {
                object.insert("params".into(), params.clone());
            }
            Value::Object(object)
        }
        Message::Notification(notification) => {
            let mut object = Map::new();
            object.insert("jsonrpc".into(), json!(JSONRPC_VERSION));
            object.insert("method".into(), json!(notification.method));
            if let Some(params) = &notification.params {
                object.insert("params".into(), params.clone());
            }
            Value::Object(object)
        }
        Message::Response(response) => {
            let mut object = Map::new();
            object.insert("jsonrpc".into(), json!(JSONRPC_VERSION));
            object.insert(
                "id".into(),
                match &response.id {
                    Some(id) => id.to_json(),
                    None => Value::Null,
                },
            );
            match &response.outcome {
                Outcome::Result(result) => {
                    object.insert("result".into(), result.clone());
                }
                Outcome::Error(error) => {
                    let mut body = Map::new();
                    body.insert("code".into(), json!(error.code));
                    body.insert("message".into(), json!(error.message));
                    if let Some(data) = &error.data {
                        body.insert("data".into(), data.clone());
                    }
                    object.insert("error".into(), Value::Object(body));
                }
            }
            Value::Object(object)
        }
    };

    let mut line = serde_json::to_vec(&value).expect("a JSON value always serializes");
    debug_assert!(!line.contains(&b'\n'));
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests;
