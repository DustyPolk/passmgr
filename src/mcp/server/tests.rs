//! Tests for the stdio loop: era dispatch, answer hygiene and resynchronizing.

use std::io::Cursor;

use serde_json::{Value, json};

use super::*;
use crate::mcp::era::{INITIALIZE_METHOD, INSTRUCTIONS, LEGACY_VERSION, MODERN_VERSION};
use crate::mcp::jsonrpc::{Id, Notification, Outcome, Request, Response};

fn initialize_params() -> Value {
    json!({
        "protocolVersion": LEGACY_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "test-host", "version": "1.0"},
    })
}

fn modern_params() -> Value {
    json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    })
}

/// One complete input line, including its newline.
fn request(id: i64, method: &str, params: Option<Value>) -> Vec<u8> {
    encode_line(&Message::request(Id::Number(id), method, params))
}

fn initialize(server: &mut Server) -> Value {
    let answer = server
        .handle(Message::request(
            Id::Number(1),
            INITIALIZE_METHOD,
            Some(initialize_params()),
        ))
        .expect("initialize is a request");
    result(&answer).clone()
}

/// Feed `input` to a fresh server and parse every stdout line.
fn serve_lines(input: &[u8]) -> Vec<Message> {
    let mut output = Vec::new();
    serve(Cursor::new(input.to_vec()), &mut output).expect("serve returns at end of input");
    assert!(
        output.is_empty() || output.ends_with(b"\n"),
        "every message must end with a newline"
    );
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| parse_line(line).expect("stdout must be JSON-RPC"))
        .collect()
}

fn result(message: &Message) -> &Value {
    match message {
        Message::Response(Response {
            outcome: Outcome::Result(value),
            ..
        }) => value,
        other => panic!("expected a result, got {other:?}"),
    }
}

fn error(message: &Message) -> &ErrorObject {
    match message {
        Message::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => error,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn id(message: &Message) -> Option<&Id> {
    match message {
        Message::Response(response) => response.id.as_ref(),
        other => panic!("expected a response, got {other:?}"),
    }
}

#[test]
fn a_legacy_session_initializes_and_lists_the_catalogue() {
    let mut input = request(1, INITIALIZE_METHOD, Some(initialize_params()));
    input.extend(encode_line(&Message::notification(
        "notifications/initialized",
        None,
    )));
    input.extend(request(2, TOOLS_LIST_METHOD, None));
    input.extend(request(3, era::PING_METHOD, None));

    let answer_lines = serve_lines(&input);
    assert_eq!(answer_lines.len(), 3, "the notification is not answered");
    assert_eq!(id(&answer_lines[0]), Some(&Id::Number(1)));
    assert_eq!(id(&answer_lines[1]), Some(&Id::Number(2)));
    assert_eq!(id(&answer_lines[2]), Some(&Id::Number(3)));

    let handshake = result(&answer_lines[0]);
    assert_eq!(handshake["protocolVersion"], LEGACY_VERSION);
    assert_eq!(handshake["serverInfo"]["name"], "passmgr");
    assert_eq!(handshake["instructions"], json!(INSTRUCTIONS));
    assert_eq!(handshake["capabilities"]["tools"]["listChanged"], false);
    assert!(
        handshake["instructions"]
            .as_str()
            .expect("instructions is a string")
            .contains("run_with_credentials"),
        "the instructions must point at the workflow"
    );

    let list = result(&answer_lines[1]);
    let tools = list["tools"].as_array().expect("a tools array");
    assert_eq!(tools.len(), 5);
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        [
            "access_status",
            "list_credentials",
            "describe_credential",
            "run_with_credentials",
            "request_access"
        ]
    );

    assert_eq!(result(&answer_lines[2]), &json!({}));
}

#[test]
fn a_modern_request_needs_no_handshake_and_is_decorated() {
    let mut input = request(1, TOOLS_LIST_METHOD, Some(modern_params()));
    input.extend(request(2, era::PING_METHOD, Some(modern_params())));
    input.extend(request(3, era::DISCOVER_METHOD, Some(modern_params())));

    let answer_lines = serve_lines(&input);
    assert_eq!(answer_lines.len(), 3);
    for answer in &answer_lines {
        assert_eq!(result(answer)["resultType"], "complete");
        assert_eq!(
            result(answer)["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "passmgr"
        );
    }
    assert_eq!(
        result(&answer_lines[1]),
        &json!({
            "resultType": "complete",
            "_meta": {"io.modelcontextprotocol/serverInfo": {
                "name": "passmgr",
                "version": env!("CARGO_PKG_VERSION"),
            }},
        })
    );
    assert_eq!(
        result(&answer_lines[2])["supportedVersions"],
        json!([MODERN_VERSION, LEGACY_VERSION])
    );
}

#[test]
fn a_legacy_request_before_initialize_is_rejected_but_ping_is_not() {
    let mut server = Server::new();
    let refused = server
        .handle(Message::request(Id::Number(1), TOOLS_LIST_METHOD, None))
        .expect("a request");
    assert_eq!(error(&refused).code, ErrorCode::InvalidRequest.code());
    assert!(error(&refused).message.contains("not initialized"));

    let ping = server
        .handle(Message::request(Id::Number(2), era::PING_METHOD, None))
        .expect("a request");
    assert_eq!(result(&ping), &json!({}));

    // The refusal did not consume the handshake.
    let handshake = initialize(&mut server);
    assert_eq!(handshake["protocolVersion"], LEGACY_VERSION);
}

#[test]
fn a_second_legacy_initialize_is_rejected() {
    let mut server = Server::new();
    initialize(&mut server);
    let refused = server
        .handle(Message::request(
            Id::Number(2),
            INITIALIZE_METHOD,
            Some(initialize_params()),
        ))
        .expect("a request");
    assert_eq!(error(&refused).code, ErrorCode::InvalidRequest.code());
    assert!(error(&refused).message.contains("already initialized"));
}

#[test]
fn unknown_methods_are_method_not_found() {
    let mut server = Server::new();
    initialize(&mut server);
    let refused = server
        .handle(Message::request(Id::Number(2), "vault/reveal", None))
        .expect("a request");
    assert_eq!(error(&refused).code, ErrorCode::MethodNotFound.code());
    assert!(error(&refused).message.contains("unknown method"));
}

#[test]
fn tools_call_reports_that_it_is_not_available_yet() {
    // TODO 4.4 replaces this branch with the dispatcher. The test is here so
    // the change cannot silently turn a missing implementation into a fake
    // success: the answer must be an error, and the answer must change when
    // the dispatcher lands.
    let mut server = Server::new();
    initialize(&mut server);
    let refused = server
        .handle(Message::request(
            Id::Number(2),
            TOOLS_CALL_METHOD,
            Some(json!({"name": "list_credentials", "arguments": {}})),
        ))
        .expect("a request");
    assert_eq!(error(&refused).code, ErrorCode::MethodNotFound.code());
    assert_eq!(
        error(&refused).message,
        "tools/call is not available in this build"
    );
}

#[test]
fn malformed_lines_get_a_parse_error_and_the_loop_recovers() {
    let mut input = b"not json\n".to_vec();
    input.extend(b"[]\n");
    input.extend(vec![b'x'; MAX_LINE_BYTES + 1]);
    input.extend(b"\n");
    input.extend(request(9, era::PING_METHOD, None));

    let answer_lines = serve_lines(&input);
    assert_eq!(
        answer_lines.len(),
        4,
        "one answer per bad line, then the ping"
    );
    assert_eq!(error(&answer_lines[0]).code, ErrorCode::Parse.code());
    assert_eq!(
        error(&answer_lines[1]).code,
        ErrorCode::InvalidRequest.code()
    );
    assert_eq!(error(&answer_lines[2]).code, ErrorCode::Parse.code());
    for answer in &answer_lines[..3] {
        assert_eq!(id(answer), None, "a line with no usable id gets null");
    }
    let parse = error(&answer_lines[0]);
    assert!(parse.message.contains("JSON"));
    let oversized = error(&answer_lines[2]);
    assert!(oversized.message.contains("exceeds the"));
    assert!(oversized.message.contains(&MAX_LINE_BYTES.to_string()));
    assert_eq!(result(&answer_lines[3]), &json!({}));
    assert_eq!(id(&answer_lines[3]), Some(&Id::Number(9)));
}

#[test]
fn notifications_and_peer_responses_get_no_answer() {
    let mut input = encode_line(&Message::notification(
        "notifications/cancelled",
        Some(json!({"requestId": 1})),
    ));
    input.extend(encode_line(&Message::Response(Response {
        id: Some(Id::Number(4)),
        outcome: Outcome::Result(json!({})),
    })));
    input.extend(request(5, era::PING_METHOD, None));

    let answer_lines = serve_lines(&input);
    assert_eq!(answer_lines.len(), 1, "only the ping is answered");
    assert_eq!(id(&answer_lines[0]), Some(&Id::Number(5)));
}

#[test]
fn non_object_params_are_invalid_params() {
    let mut server = Server::new();
    initialize(&mut server);
    let refused = server
        .handle(Message::request(
            Id::Number(2),
            era::PING_METHOD,
            Some(json!([])),
        ))
        .expect("a request");
    assert_eq!(error(&refused).code, ErrorCode::InvalidParams.code());
    assert_eq!(error(&refused).message, "params must be an object");
}

#[test]
fn a_final_line_without_a_newline_is_served() {
    let mut input = request(7, era::PING_METHOD, None);
    input.pop(); // the last line arrives without its newline
    let answer_lines = serve_lines(&input);
    assert_eq!(answer_lines.len(), 1);
    assert_eq!(id(&answer_lines[0]), Some(&Id::Number(7)));

    // A trailing over-long fragment with no newline is dropped silently: the
    // stream is over and there is no complete line to report.
    let fragment = vec![b'x'; MAX_LINE_BYTES + 1];
    assert!(serve_lines(&fragment).is_empty());

    // The same fragment followed by a newline is one complete over-long line,
    // and gets exactly one parse error.
    let mut terminated = fragment;
    terminated.push(b'\n');
    let over_long = serve_lines(&terminated);
    assert_eq!(over_long.len(), 1);
    assert_eq!(error(&over_long[0]).code, ErrorCode::Parse.code());
    assert!(error(&over_long[0]).message.contains("exceeds the"));
}

#[test]
fn stdout_is_only_json_rpc_lines() {
    let mut input = request(1, INITIALIZE_METHOD, Some(initialize_params()));
    input.extend(request(2, TOOLS_LIST_METHOD, None));
    input.extend(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"}\n");

    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output).expect("serve");
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let text = std::str::from_utf8(line).expect("stdout is UTF-8");
        assert!(text.starts_with('{') && text.ends_with('}'), "{text}");
        parse_line(line).expect("every stdout line is a JSON-RPC message");
    }
}

#[test]
fn the_server_never_answers_a_notification_even_in_the_modern_era() {
    let mut server = Server::new();
    let answer = server.handle(Message::Notification(Notification {
        method: "notifications/progress".into(),
        params: Some(modern_params()),
    }));
    assert!(answer.is_none());
}

#[test]
fn a_peer_request_cannot_reach_a_tool_yet() {
    // A request *from* the peer (as opposed to an answer to one of ours) is
    // dispatched like any other; it is the dispatcher's job to say no.
    let mut server = Server::new();
    initialize(&mut server);
    let request = Request {
        id: Id::String("x".into()),
        method: TOOLS_CALL_METHOD.into(),
        params: Some(json!({"name": "run_with_credentials"})),
    };
    let answer = server.handle(Message::Request(request)).expect("a request");
    assert_eq!(error(&answer).code, ErrorCode::MethodNotFound.code());
}
