//! The wire shape carries references and policy numbers, never values.
//! Split out of `src/protocol/tests.rs` for the line limit.

use super::*;

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
    // `timeout_secs` and `max_output_bytes` are policy numbers, never values.
    assert_eq!(
        keys,
        [
            "command",
            "cwd",
            "env",
            "grant",
            "max_output_bytes",
            "plain_env",
            "timeout_secs",
            "type",
        ]
    );
}
