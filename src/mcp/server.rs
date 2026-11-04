//! The stdio server loop for `pm mcp serve`.
//!
//! The loop is deliberately small and sequential: read a line, decide its era
//! with [`era::Session::admit`], answer an era-owned method verbatim, or
//! dispatch the method and decorate the result. A notification and a peer's
//! response are consumed silently; nothing else is ever written to stdout.
//!
//! Every answer is one JSON-RPC line. A malformed or over-long line gets a
//! parse error and the loop resynchronizes on the next newline, so one bad
//! line cannot blind the session. Diagnostics (when there are any) belong on
//! stderr; no tool can make this module print a secret because no tool is
//! implemented here yet and the daemon has no plaintext request.

use std::io::{self, Read, Write};

use serde_json::{Value, json};

use super::era::{self, Admitted, Session};
use super::jsonrpc::{
    ErrorCode, ErrorObject, LineEvent, LineReader, MAX_LINE_BYTES, Message, encode_line, parse_line,
};
use super::tools;

/// `tools/list`: the catalogue. Implemented here because it needs no daemon.
pub const TOOLS_LIST_METHOD: &str = "tools/list";
/// `tools/call`: every tool call goes to the daemon (TODO 4.4).
pub const TOOLS_CALL_METHOD: &str = "tools/call";

/// One connection's protocol state.
///
/// The session currently holds only the legacy handshake state; the grant
/// binding, pending access requests and client name arrive with the tools that
/// need them (4.4 onwards).
#[derive(Debug, Default)]
pub struct Server {
    session: Session,
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one decoded message. Returns the answer to write, or `None`
    /// when the message needs no answer (a notification, or a response to a
    /// request this server never sends).
    pub fn handle(&mut self, message: Message) -> Option<Message> {
        match message {
            Message::Request(request) => Some(self.handle_request(request)),
            Message::Notification(_) | Message::Response(_) => None,
        }
    }

    fn handle_request(&mut self, request: super::jsonrpc::Request) -> Message {
        let admitted = match self.session.admit(&request) {
            Ok(admitted) => admitted,
            Err(rejected) => return Message::error(rejected.id, rejected.error),
        };
        let Admitted { era, reply } = admitted;
        if let Some(params) = &request.params {
            if !params.is_object() {
                return Message::error(
                    Some(request.id),
                    ErrorObject::new(ErrorCode::InvalidParams, "params must be an object"),
                );
            }
        }
        // An era-owned answer was built and decorated by `admit`; sending it
        // through `decorate` again would be harmless but hides which layer
        // owns it.
        if let Some(reply) = reply {
            return Message::result(request.id, reply);
        }
        match self.dispatch(&request) {
            Ok(result) => Message::result(request.id, era::decorate(era, result)),
            Err(error) => Message::error(Some(request.id), error),
        }
    }

    fn dispatch(&mut self, request: &super::jsonrpc::Request) -> Result<Value, ErrorObject> {
        match request.method.as_str() {
            era::PING_METHOD => Ok(json!({})),
            TOOLS_LIST_METHOD => Ok(tools::list_result()),
            // The catalogue is advertised now so `tools/list` can be tested
            // and an agent host can be pointed at the server; the dispatcher
            // that validates arguments and calls `pmd` lands with TODO 4.4.
            // Until then the honest answer is that the method is not
            // implemented, not a fabricated result.
            TOOLS_CALL_METHOD => Err(ErrorObject::new(
                ErrorCode::MethodNotFound,
                "tools/call is not available in this build",
            )),
            _ => Err(ErrorObject::new(
                ErrorCode::MethodNotFound,
                "unknown method: this server supports ping, tools/list, tools/call, \
                 initialize (legacy) and server/discover (modern)",
            )),
        }
    }
}

/// Run the server over a byte stream until end of input.
///
/// Reads are chunked, so a request larger than the read buffer is assembled by
/// [`LineReader`]; a line over [`MAX_LINE_BYTES`] is discarded and answered
/// with a parse error. Each batch of answers is flushed before the next read,
/// so a host that waits for a reply before sending the next request does not
/// deadlock behind a buffer.
///
/// The only errors returned are I/O errors. A closed output pipe ends the
/// command (the CLI maps `BrokenPipe` to exit 0); a failed read is reported to
/// the caller.
pub fn serve<R: Read, W: Write>(mut input: R, mut output: W) -> io::Result<()> {
    let mut server = Server::new();
    let mut reader = LineReader::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = input.read(&mut buffer)?;
        let at_eof = read == 0;
        let events: Vec<LineEvent> = if at_eof {
            reader.finish().into_iter().collect()
        } else {
            reader.push(&buffer[..read])
        };
        for event in events {
            if let Some(answer) = answer_for(&mut server, event) {
                output.write_all(&encode_line(&answer))?;
            }
        }
        output.flush()?;
        if at_eof {
            return Ok(());
        }
    }
}

/// Turn one line event into the answer to send, if any.
fn answer_for(server: &mut Server, event: LineEvent) -> Option<Message> {
    match event {
        LineEvent::Line(line) => match parse_line(&line) {
            Ok(message) => server.handle(message),
            Err(rejected) => Some(Message::error(rejected.id, rejected.error)),
        },
        LineEvent::TooLong { bytes } => Some(Message::error(
            None,
            ErrorObject::new(
                ErrorCode::Parse,
                format!(
                    "line of {bytes} bytes exceeds the {MAX_LINE_BYTES}-byte limit and was discarded"
                ),
            ),
        )),
    }
}

#[cfg(test)]
mod tests;
