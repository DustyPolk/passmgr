//! End-to-end tests for `passmgr mcp serve` (TODO 4.3).
//!
//! The binary is driven over real pipes: the whole scripted session is written,
//! stdin is closed, and the process is waited for. Every stdout line must be a
//! JSON-RPC message, stderr must stay empty, and each era must answer the
//! handshake its own way.

mod cli_support;

use cli_support::*;
use serde_json::{Value, json};

use passmgr::mcp::jsonrpc::{Message, parse_line};

/// Parse a line with the crate's own codec, then return its JSON for asserts.
fn line_value(line: &str) -> Value {
    parse_line(line.as_bytes()).unwrap_or_else(|error| panic!("{line}: {error}"));
    serde_json::from_str(line).expect("a JSON line")
}

fn lines(output: &std::process::Output) -> Vec<Value> {
    stdout(output).lines().map(line_value).collect()
}

fn legacy_session() -> &'static str {
    concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
        "\n",
    )
}

const MODERN_META: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;

#[test]
fn a_legacy_session_initializes_and_lists_five_tools() {
    let _guard = serial();
    let output = run_with_env(
        &["mcp", "serve"],
        legacy_session(),
        &[("PASSMGR_AGENT", "1")],
    );
    assert_success(&output);
    assert_eq!(
        stderr(&output),
        "",
        "diagnostics must not pollute stderr here"
    );

    let answers = lines(&output);
    assert_eq!(
        answers.len(),
        3,
        "the notification is not answered: {answers:?}"
    );

    let handshake = &answers[0];
    assert_eq!(handshake["id"], 1);
    assert_eq!(handshake["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(handshake["result"]["serverInfo"]["name"], "passmgr");
    assert_eq!(
        handshake["result"]["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    let instructions = handshake["result"]["instructions"]
        .as_str()
        .expect("instructions is a string");
    assert!(instructions.len() < 1200);
    assert!(instructions.contains("run_with_credentials"));

    let list = &answers[1];
    assert_eq!(list["id"], 2);
    let tools = list["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 5);
    assert_eq!(tools[0]["name"], "access_status");
    assert_eq!(tools[4]["name"], "request_access");
    for tool in tools {
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }

    assert_eq!(answers[2], json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
}

#[test]
fn a_modern_session_needs_no_handshake_and_every_result_is_decorated() {
    let _guard = serial();
    let input = format!(
        concat!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{{}}}}}"#,
            "\n",
            r#"{{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{{{}}}}}"#,
            "\n",
        ),
        MODERN_META, MODERN_META
    );
    let output = run_with_env(&["mcp", "serve"], &input, &[("PASSMGR_AGENT", "1")]);
    assert_success(&output);
    assert_eq!(stderr(&output), "");

    let answers = lines(&output);
    assert_eq!(answers.len(), 2);
    for answer in &answers {
        assert_eq!(answer["result"]["resultType"], "complete");
        assert_eq!(
            answer["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "passmgr"
        );
        assert_eq!(
            answer["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }
    assert_eq!(
        answers[0]["result"]["tools"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(
        answers[1]["result"]["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
}

#[test]
fn a_bad_line_gets_one_error_and_the_session_continues() {
    let _guard = serial();
    let input = concat!(
        "this is not json\n",
        r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
        "\n",
    );
    let output = run_with_env(&["mcp", "serve"], input, &[("PASSMGR_AGENT", "1")]);
    assert_success(&output);
    let answers = lines(&output);
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["error"]["code"], -32700);
    assert_eq!(answers[0]["id"], Value::Null);
    assert_eq!(answers[1], json!({"jsonrpc": "2.0", "id": 7, "result": {}}));
}

#[test]
fn mcp_serve_refuses_a_vault_selection() {
    let _guard = serial();
    // `--db` is a global option; before the command it must be refused with a
    // reason, and the same exported variable must be refused too.
    for (args, env) in [
        (vec!["--db", "elsewhere.dat", "mcp", "serve"], vec![]),
        (vec!["mcp", "serve"], vec![("PASSMGR_DB", "elsewhere.dat")]),
    ] {
        let output = run_with_env(&args, "", &env);
        assert_eq!(
            output.status.code(),
            Some(2),
            "usage error for {args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("mcp serve")
                && stderr(&output).contains("vault")
                && stderr(&output).contains("does not accept"),
            "the refusal must name the command and the reason: {}",
            stderr(&output)
        );
    }

    // After the subcommand `--db` is not a global option any more, so the
    // generic "takes no arguments" error wins. Either way it is refused.
    let output = run(&["mcp", "serve", "--db", "elsewhere.dat"], "");
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("takes no arguments"));
}

#[test]
fn an_unknown_mcp_subcommand_is_a_usage_error() {
    let _guard = serial();
    let output = run(&["mcp", "reveal"], "");
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown 'mcp' subcommand 'reveal'"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn an_agent_marker_neither_widens_nor_narrows_the_server() {
    // The server is always in agent context; a marker variable must not change
    // what it answers. This is the canary for a future "human mode" branch.
    let _guard = serial();
    let without = run(&["mcp", "serve"], legacy_session());
    let with = run_with_env(
        &["mcp", "serve"],
        legacy_session(),
        &[("CLAUDE_CODE", "1"), ("CURSOR_AGENT", "1")],
    );
    assert_success(&with);
    assert_eq!(stdout(&with), stdout(&without));
    assert_eq!(stderr(&with), stderr(&without));
    assert_eq!(with.status.code(), without.status.code());
}

#[test]
fn a_peer_response_is_never_answered() {
    let _guard = serial();
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        "\n",
    );
    let output = run(&["mcp", "serve"], input);
    assert_success(&output);
    let answers = lines(&output);
    assert_eq!(answers.len(), 1, "only the ping is answered");

    // `Message` is public so the check above can use it; this keeps the import
    // meaningful if the helper ever stops parsing.
    assert!(matches!(
        parse_line(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).expect("valid"),
        Message::Response(_)
    ));
}
