use super::*;
use serde_json::json;

fn parse(text: &str) -> Result<Message, Rejected> {
    parse_line(text.as_bytes())
}

fn rejection(text: &str) -> Rejected {
    match parse(text) {
        Ok(message) => panic!("expected a rejection, got {message:?}"),
        Err(rejected) => rejected,
    }
}

fn code(text: &str) -> i32 {
    rejection(text).error.code
}

fn encoded(message: &Message) -> String {
    String::from_utf8(encode_line(message)).expect("encoding produces UTF-8")
}

fn line(bytes: &[u8]) -> LineEvent {
    LineEvent::Line(bytes.to_vec())
}

// --- parsing well-formed messages -------------------------------------------

#[test]
fn a_request_with_a_number_id_parses() {
    let message = parse(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#)
        .expect("valid request");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.id, Id::Number(7));
    assert_eq!(request.method, "tools/list");
    assert_eq!(request.params, Some(json!({})));
}

#[test]
fn a_request_with_a_string_id_and_no_params_parses() {
    let message =
        parse(r#"{"jsonrpc":"2.0","id":"call-1","method":"ping"}"#).expect("valid request");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.id, Id::String("call-1".into()));
    assert_eq!(request.method, "ping");
    assert_eq!(request.params, None);
}

#[test]
fn a_null_params_member_is_treated_as_absent() {
    let message =
        parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#).expect("valid request");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.params, None);
}

#[test]
fn array_params_are_preserved() {
    let message =
        parse(r#"{"jsonrpc":"2.0","id":1,"method":"m","params":[1,2]}"#).expect("valid request");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.params, Some(json!([1, 2])));
}

#[test]
fn unknown_members_are_ignored() {
    let message = parse(
        r#"{"jsonrpc":"2.0","id":1,"method":"m","params":{"_meta":{}},"extra":true,"result":null}"#,
    )
    .expect("valid request");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.id, Id::Number(1));
}

#[test]
fn a_notification_has_no_id() {
    let message = parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .expect("valid notification");
    assert_eq!(
        message,
        Message::notification("notifications/initialized", None)
    );
}

#[test]
fn a_result_response_parses() {
    let message =
        parse(r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#).expect("valid response");
    assert_eq!(
        message,
        Message::result(Id::Number(3), json!({"tools": []}))
    );
}

#[test]
fn a_response_may_carry_a_null_id() {
    let message = parse(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#).expect("valid response");
    let Message::Response(response) = message else {
        panic!("expected a response");
    };
    assert_eq!(response.id, None);
    assert_eq!(response.outcome, Outcome::Result(json!({})));
}

#[test]
fn an_error_response_parses_with_its_data() {
    let message = parse(
        r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32022,"message":"bad version","data":{"supported":["2026-07-28"]}}}"#,
    )
    .expect("valid error response");
    let Message::Response(response) = message else {
        panic!("expected a response");
    };
    assert_eq!(response.id, Some(Id::Number(4)));
    let Outcome::Error(error) = response.outcome else {
        panic!("expected an error");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedProtocolVersion.code());
    assert_eq!(error.message, "bad version");
    assert_eq!(error.data, Some(json!({"supported": ["2026-07-28"]})));
}

#[test]
fn an_unknown_peer_error_code_is_preserved_verbatim() {
    let message = parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nope"}}"#)
        .expect("valid error response");
    let Message::Response(Response {
        outcome: Outcome::Error(error),
        ..
    }) = message
    else {
        panic!("expected an error response");
    };
    assert_eq!(error.code, -32000);
}

// --- the documented error codes ---------------------------------------------

#[test]
fn the_error_codes_match_the_mcp_contract() {
    let table = [
        (ErrorCode::Parse, -32700),
        (ErrorCode::InvalidRequest, -32600),
        (ErrorCode::MethodNotFound, -32601),
        (ErrorCode::InvalidParams, -32602),
        (ErrorCode::Internal, -32603),
        (ErrorCode::UnsupportedProtocolVersion, -32022),
    ];
    for (variant, number) in table {
        assert_eq!(variant.code(), number, "{variant:?}");
    }
}

// --- rejected input ---------------------------------------------------------

#[test]
fn truncated_json_is_a_parse_error_without_an_id() {
    let rejected = rejection(r#"{"jsonrpc":"2.0","id":1,"method":"ping""#);
    assert_eq!(rejected.error.code, ErrorCode::Parse.code());
    assert_eq!(rejected.id, None);
    assert!(!rejected.error.message.is_empty());
}

#[test]
fn invalid_utf8_is_a_parse_error() {
    let rejected = parse_line(&[0xff, 0xfe, b'{', b'}']).expect_err("not UTF-8");
    assert_eq!(rejected.error.code, ErrorCode::Parse.code());
    assert_eq!(rejected.id, None);
}

#[test]
fn a_parse_error_never_echoes_the_input() {
    let rejected = rejection(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":"CANARY"#);
    assert!(
        !rejected.error.message.contains("CANARY"),
        "{}",
        rejected.error.message
    );
}

#[test]
fn every_prefix_of_a_valid_line_is_rejected_without_a_panic() {
    let text = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
    for end in 0..text.len() {
        assert!(
            parse_line(&text.as_bytes()[..end]).is_err(),
            "prefix of length {end} parsed"
        );
    }
    assert!(parse(text).is_ok());
}

#[test]
fn a_batch_is_rejected() {
    for text in [
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]"#,
        "[]",
    ] {
        let rejected = rejection(text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, None);
    }
}

#[test]
fn a_non_object_toplevel_is_an_invalid_request() {
    for text in [r#""ping""#, "1", "true", "null"] {
        assert_eq!(code(text), ErrorCode::InvalidRequest.code(), "{text}");
    }
}

#[test]
fn a_missing_jsonrpc_member_is_an_invalid_request() {
    let rejected = rejection(r#"{"id":1,"method":"ping"}"#);
    assert_eq!(rejected.error.code, ErrorCode::InvalidRequest.code());
    assert_eq!(rejected.id, Some(Id::Number(1)));
}

#[test]
fn the_jsonrpc_member_must_be_the_string_2_0() {
    for text in [
        r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":2.0,"id":1,"method":"ping"}"#,
        r#"{"jsonrpc":null,"id":1,"method":"ping"}"#,
    ] {
        let rejected = rejection(text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, Some(Id::Number(1)), "{text}");
    }
}

#[test]
fn a_null_id_is_neither_a_request_nor_a_notification() {
    let rejected = rejection(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#);
    assert_eq!(rejected.error.code, ErrorCode::InvalidRequest.code());
    assert_eq!(rejected.id, None);
}

#[test]
fn only_string_and_integer_ids_are_accepted() {
    for id in ["1.5", "true", "{}", "[]"] {
        let text = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
        let rejected = rejection(&text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, None, "{text}");
    }
    // A number JSON itself cannot represent is a parse error, not a shape
    // error: serde_json refuses it before any structural check happens.
    assert_eq!(
        code(r#"{"jsonrpc":"2.0","id":1e400,"method":"ping"}"#),
        ErrorCode::Parse.code()
    );
}

#[test]
fn an_oversized_string_id_is_refused() {
    let id = "x".repeat(MAX_ID_BYTES + 1);
    let text = format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"ping"}}"#);
    let rejected = rejection(&text);
    assert_eq!(rejected.error.code, ErrorCode::InvalidRequest.code());
    assert_eq!(rejected.id, None);

    let id = "x".repeat(MAX_ID_BYTES);
    let text = format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"ping"}}"#);
    assert!(parse(&text).is_ok(), "an id at the cap is still accepted");
}

#[test]
fn a_negative_integer_id_round_trips() {
    let message = parse(r#"{"jsonrpc":"2.0","id":-12,"method":"m"}"#).expect("valid");
    let Message::Request(request) = message else {
        panic!("expected a request");
    };
    assert_eq!(request.id, Id::Number(-12));
}

#[test]
fn the_method_must_be_a_short_non_empty_string() {
    for text in [
        r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":null}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":""}"#,
    ] {
        let rejected = rejection(text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, Some(Id::Number(1)), "{text}");
    }

    let long = "m".repeat(MAX_METHOD_BYTES + 1);
    let text = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{long}"}}"#);
    let rejected = rejection(&text);
    assert_eq!(rejected.error.code, ErrorCode::InvalidRequest.code());
    assert_eq!(rejected.id, Some(Id::Number(1)));
}

#[test]
fn params_must_be_structured_when_present() {
    for params in [r#""x""#, "1", "true"] {
        let text = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"m","params":{params}}}"#);
        let rejected = rejection(&text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, Some(Id::Number(1)), "{text}");
    }
}

#[test]
fn a_response_without_an_id_is_refused() {
    for text in [r#"{"jsonrpc":"2.0","result":{}}"#, r#"{"jsonrpc":"2.0"}"#] {
        assert_eq!(code(text), ErrorCode::InvalidRequest.code(), "{text}");
    }
}

#[test]
fn a_response_needs_exactly_one_of_result_and_error() {
    for text in [
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
    ] {
        let rejected = rejection(text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, Some(Id::Number(1)), "{text}");
    }
}

#[test]
fn a_malformed_error_object_is_an_invalid_request() {
    let message = "m".repeat(MAX_ERROR_MESSAGE_BYTES + 1);
    let cases = [
        r#""not an object""#.to_string(),
        r#"{"message":"x"}"#.to_string(),
        r#"{"code":"-32603","message":"x"}"#.to_string(),
        r#"{"code":-32603.5,"message":"x"}"#.to_string(),
        r#"{"code":4294967296,"message":"x"}"#.to_string(),
        r#"{"code":-32603}"#.to_string(),
        r#"{"code":-32603,"message":7}"#.to_string(),
        format!(r#"{{"code":-32603,"message":"{message}"}}"#),
    ];
    for error in cases {
        let text = format!(r#"{{"jsonrpc":"2.0","id":1,"error":{error}}}"#);
        let rejected = rejection(&text);
        assert_eq!(
            rejected.error.code,
            ErrorCode::InvalidRequest.code(),
            "{text}"
        );
        assert_eq!(rejected.id, Some(Id::Number(1)), "{text}");
    }
}

// --- encoding ---------------------------------------------------------------

#[test]
fn every_message_kind_round_trips_through_the_wire() {
    let messages = [
        Message::request(Id::Number(1), "tools/list", Some(json!({"tags": ["prod"]}))),
        Message::request(Id::String("a b".into()), "ping", None),
        Message::notification("notifications/cancelled", Some(json!({"requestId": 2}))),
        Message::result(Id::Number(3), json!({"content": []})),
        Message::error(
            Some(Id::Number(4)),
            ErrorObject::new(ErrorCode::InvalidParams, "bad params")
                .with_data(json!({"field": "reason"})),
        ),
        Message::error(None, ErrorObject::new(ErrorCode::Parse, "not JSON")),
    ];
    for message in messages {
        let line = encoded(&message);
        assert!(line.ends_with('\n'), "{line:?}");
        let parsed = parse(line.trim_end_matches('\n')).expect("round trip");
        assert_eq!(parsed, message, "round trip of {line:?}");
    }
}

#[test]
fn an_encoded_message_is_exactly_one_line() {
    let message = Message::request(
        Id::Number(1),
        "tools/call",
        Some(json!({"text": "a\nb\r\nc\u{0000}d"})),
    );
    let bytes = encode_line(&message);
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(
        bytes.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "only the trailing newline may be a raw newline"
    );
    assert_eq!(
        bytes.iter().filter(|byte| **byte == b'\r').count(),
        0,
        "carriage returns are escaped too"
    );
    assert_eq!(
        parse_line(&bytes[..bytes.len() - 1]).expect("re-parse"),
        message
    );
}

#[test]
fn an_error_response_without_an_id_encodes_a_null_id() {
    let line = encoded(&Message::error(
        None,
        ErrorObject::new(ErrorCode::Parse, "no"),
    ));
    let value: Value = serde_json::from_str(line.trim_end()).expect("JSON");
    assert_eq!(value["id"], Value::Null);
    assert!(value.get("result").is_none());
}

// --- the line reader --------------------------------------------------------

#[test]
fn one_push_with_several_lines_yields_them_all() {
    let mut reader = LineReader::new();
    assert_eq!(reader.push(b"one\ntwo\n"), vec![line(b"one"), line(b"two")]);
    assert_eq!(reader.finish(), None);
}

#[test]
fn a_line_split_across_pushes_is_joined() {
    let mut reader = LineReader::new();
    let mut events = Vec::new();
    for byte in b"{\"a\":1}\n{\"b\":2}\n" {
        events.extend(reader.push(&[*byte]));
    }
    assert_eq!(events, vec![line(b"{\"a\":1}"), line(b"{\"b\":2}")]);
    assert_eq!(reader.finish(), None);
}

#[test]
fn a_chunk_without_a_newline_yields_nothing() {
    let mut reader = LineReader::new();
    assert!(reader.push(b"partial").is_empty());
    assert!(reader.push(b"-more").is_empty());
    assert_eq!(reader.finish(), Some(line(b"partial-more")));
}

#[test]
fn an_empty_line_is_a_line() {
    let mut reader = LineReader::new();
    assert_eq!(reader.push(b"\n"), vec![line(b"")]);
    assert_eq!(code(""), ErrorCode::Parse.code());
}

#[test]
fn a_crlf_line_keeps_its_carriage_return_and_still_parses() {
    let mut reader = LineReader::new();
    let events = reader.push(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n");
    let [LineEvent::Line(bytes)] = events.as_slice() else {
        panic!("expected one line, got {events:?}");
    };
    assert!(bytes.ends_with(b"\r"), "the reader does not edit content");
    parse_line(bytes).expect("trailing whitespace is not part of the JSON value");
}

#[test]
fn a_line_at_the_cap_is_accepted_and_one_byte_more_is_dropped() {
    let mut reader = LineReader::new();
    let at_cap = vec![b'a'; MAX_LINE_BYTES];
    assert!(reader.push(&at_cap).is_empty());
    assert_eq!(reader.push(b"\n"), vec![line(&at_cap)]);

    let over = vec![b'a'; MAX_LINE_BYTES + 1];
    assert!(reader.push(&over).is_empty());
    assert_eq!(
        reader.push(b"\n"),
        vec![LineEvent::TooLong {
            bytes: MAX_LINE_BYTES + 1
        }]
    );
}

#[test]
fn an_oversized_line_is_dropped_and_the_next_line_survives() {
    let mut reader = LineReader::new();
    let mut bytes = vec![b'a'; 2 * MAX_LINE_BYTES + 7];
    bytes.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    let events = reader.push(&bytes);
    assert_eq!(
        events,
        vec![
            LineEvent::TooLong {
                bytes: 2 * MAX_LINE_BYTES + 7
            },
            line(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
        ]
    );
    assert_eq!(reader.finish(), None);
}

#[test]
fn an_oversized_line_is_counted_across_pushes() {
    let mut reader = LineReader::new();
    assert!(reader.push(&vec![b'a'; MAX_LINE_BYTES]).is_empty());
    assert!(reader.push(&[b'a'; 10]).is_empty());
    assert_eq!(
        reader.push(b"\n"),
        vec![LineEvent::TooLong {
            bytes: MAX_LINE_BYTES + 10
        }]
    );
    assert_eq!(reader.push(b"ok\n"), vec![line(b"ok")]);
}

#[test]
fn the_reader_never_retains_more_than_the_cap() {
    let mut reader = LineReader::new();
    for _ in 0..4 {
        reader.push(&vec![b'a'; MAX_LINE_BYTES]);
        assert!(
            reader.pending.len() <= MAX_LINE_BYTES,
            "retained {} bytes",
            reader.pending.len()
        );
    }
    assert!(reader.discarding);
    assert_eq!(
        reader.push(b"\n"),
        vec![LineEvent::TooLong {
            bytes: 4 * MAX_LINE_BYTES
        }]
    );
}

#[test]
fn finish_reports_a_final_line_without_a_newline() {
    let mut reader = LineReader::new();
    assert!(reader.push(b"{\"jsonrpc\":\"2.0\"}").is_empty());
    assert_eq!(reader.finish(), Some(line(b"{\"jsonrpc\":\"2.0\"}")));
    assert_eq!(reader.finish(), None, "finish is idempotent");
}

#[test]
fn finish_drops_a_truncated_oversized_line() {
    let mut reader = LineReader::new();
    assert!(reader.push(&vec![b'a'; MAX_LINE_BYTES + 1]).is_empty());
    assert_eq!(reader.finish(), None);
    assert_eq!(
        reader.push(b"ok\n"),
        vec![line(b"ok")],
        "reader is reusable"
    );
}
