//! `describe` request codec (TODO 4.4c): one reference plus a grant token,
//! bounded and canonical at the boundary. Split out of `src/protocol/tests.rs`
//! to keep it under the ~1,000-line limit.

use super::*;

#[test]
fn describe_carries_the_reference_and_grant_token_but_no_secret() {
    let encoded = encode(&describe_request()).expect("encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert_eq!(value["request"]["type"], "describe");
    assert_eq!(value["request"]["ref"], REF);
    assert_eq!(
        value["request"]["grant"].as_str().expect("grant hex"),
        grant_token().to_hex().as_str(),
        "describe carries the grant token, never its hash or a secret"
    );
}

#[test]
fn describe_rejects_references_no_entry_could_have() {
    for reference in [
        "",
        "pm://",
        "pm://zz",
        "pm://00112233445566778899aabbccddee",
        "https://example.test/credential",
        // Valid hex but a nested reference, not the canonical form.
        "pm://pm://00112233445566778899aabbccddeeff",
    ] {
        let request = Request::Describe(DescribeRequest {
            reference: reference.into(),
            grant: grant_token(),
        });
        assert!(
            matches!(encode(&request), Err(ProtocolError::InvalidRequest(_))),
            "{reference:?} must not be accepted as a reference"
        );
    }

    let too_long = Request::Describe(DescribeRequest {
        reference: format!("pm://{}", "a".repeat(MAX_REFERENCE_BYTES)),
        grant: grant_token(),
    });
    assert!(matches!(
        encode(&too_long),
        Err(ProtocolError::InvalidRequest(_))
    ));

    // The decoder applies the same rule to an untrusted body.
    let body = format!(
        r#"{{"type":"describe","ref":"not-a-ref","grant":"{}"}}"#,
        grant_token().to_hex().as_str()
    );
    assert!(matches!(
        decode(&request_frame(&body)),
        Err(ProtocolError::InvalidRequest(_))
    ));
}

#[test]
fn describe_requires_a_grant_token() {
    let body = format!(r#"{{"type":"describe","ref":"{REF}"}}"#);
    assert!(decode(&request_frame(&body)).is_err());
}
