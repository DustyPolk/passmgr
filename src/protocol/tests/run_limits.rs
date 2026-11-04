//! Timeout and output-cap fields on a `run` request (TODO 4.5c).
//! Split out of `src/protocol/tests.rs` to keep it under the line limit.

use super::*;

fn with_limits(limits: RunLimits) -> Request {
    let Request::Run(mut run) = run_request() else {
        panic!("expected a run request");
    };
    run.limits = limits;
    Request::Run(run)
}

/// A valid run body with the limits spliced in as raw JSON.
fn body_with(timeout: &str, cap: &str) -> String {
    format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":[{{"name":"API_KEY","ref":"{REF}"}}],"command":["/bin/true"],"cwd":"/tmp","grant":"{}","timeout_secs":{timeout},"max_output_bytes":{cap}}}}}"#,
        "11".repeat(32)
    )
}

#[test]
fn run_limits_round_trip() {
    let request = with_limits(RunLimits {
        timeout_secs: 5,
        max_output_bytes: 1024,
    });
    let encoded = encode(&request).expect("encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert_eq!(value["request"]["timeout_secs"], 5);
    assert_eq!(value["request"]["max_output_bytes"], 1024);
    assert_eq!(decode(&encoded).expect("decode"), request);
}

#[test]
fn a_legacy_run_without_limits_gets_the_defaults() {
    // Old clients predate the fields entirely; their runs must keep working
    // with the safe daemon-side defaults, and a re-encode states them.
    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":[{{"name":"API_KEY","ref":"{REF}"}}],"command":["/bin/true"],"cwd":"/tmp","grant":"{}"}}}}"#,
        "11".repeat(32)
    );
    let Request::Run(run) = decode(&frame(&body)).expect("legacy run") else {
        panic!("expected run");
    };
    assert_eq!(run.limits.timeout_secs, DEFAULT_RUN_TIMEOUT_SECS);
    assert_eq!(run.limits.max_output_bytes, DEFAULT_RUN_OUTPUT_BYTES);

    let encoded = encode(&Request::Run(run)).expect("re-encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert_eq!(value["request"]["timeout_secs"], DEFAULT_RUN_TIMEOUT_SECS);
    assert_eq!(
        value["request"]["max_output_bytes"],
        DEFAULT_RUN_OUTPUT_BYTES
    );
}

#[test]
fn a_null_limit_is_treated_as_absent() {
    let Request::Run(run) =
        decode(&frame(&body_with("null", "null"))).expect("null limits mean defaults")
    else {
        panic!("expected run");
    };
    assert_eq!(run.limits, RunLimits::default());
}

#[test]
fn run_limits_are_bounded_at_the_boundary() {
    for (timeout, cap) in [
        ("0", "1024"),
        ("601", "1024"),
        ("5", "0"),
        ("5", "1048577"),
        // Larger than u32: rejected while decoding the number.
        ("4294967296", "1024"),
    ] {
        let error = decode(&frame(&body_with(timeout, cap)))
            .expect_err(&format!("timeout={timeout} cap={cap} must be rejected"));
        assert!(
            matches!(error, ProtocolError::InvalidRequest(_)),
            "timeout={timeout} cap={cap}: {error:?}"
        );
    }

    // The widest accepted values decode and survive validation.
    for (timeout, cap) in [
        ("1", "1"),
        ("600", "1048576"),
        ("null", "1024"),
        ("5", "null"),
    ] {
        decode(&frame(&body_with(timeout, cap)))
            .unwrap_or_else(|error| panic!("timeout={timeout} cap={cap}: {error:?}"));
    }
}

#[test]
fn a_non_numeric_limit_is_malformed() {
    for (timeout, cap) in [("1.5", "1024"), ("\"5\"", "1024"), ("5", "true")] {
        let error = decode(&frame(&body_with(timeout, cap)))
            .expect_err(&format!("timeout={timeout} cap={cap} must be rejected"));
        assert!(
            matches!(error, ProtocolError::MalformedJson(_)),
            "timeout={timeout} cap={cap}: {error:?}"
        );
    }
}
