//! Unit tests for the `tools/call` boundary: bounds, pass-through and mapping.

use serde_json::json;

use super::*;
use crate::protocol::ResponseError;

fn entry() -> Entry {
    Entry {
        reference: "pm://00112233445566778899aabbccddeeff".to_owned(),
        service: "example.test".to_owned(),
        username: Some("alice".to_owned()),
        tags: vec!["prod".to_owned()],
        fields: vec!["token".to_owned()],
        url: Some("https://example.test".to_owned()),
        created: Some(1_700_000_000),
        last_rotated: None,
    }
}

#[test]
fn call_parts_requires_a_bounded_name_and_an_object_arguments_member() {
    let params = json!({"name": "list_credentials", "arguments": {"query": "git"}});
    let (name, arguments) = call_parts(Some(&params)).expect("valid params");
    assert_eq!(name, "list_credentials");
    assert_eq!(arguments, Some(&json!({"query": "git"})));

    // The modern era attaches `_meta` to every params object; it is not a
    // tool argument and must not be forwarded.
    let params = json!({
        "name": "list_credentials",
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
    });
    assert_eq!(call_parts(Some(&params)).expect("valid params").1, None);

    for (params, needle) in [
        (None, "requires params"),
        (Some(json!([])), "must be an object"),
        (Some(json!({})), "string 'name'"),
        (Some(json!({"name": 3})), "string 'name'"),
        (Some(json!({"name": ""})), "must not be empty"),
        (Some(json!({"name": "x".repeat(65)})), "'name' is too long"),
        (
            Some(json!({"name": "list_credentials", "arguments": []})),
            "arguments' must be an object",
        ),
        (
            Some(json!({"name": "list_credentials", "extra": 1})),
            "unknown tools/call parameter",
        ),
    ] {
        let error = call_parts(params.as_ref()).expect_err("must be refused");
        assert!(
            error.contains(needle),
            "{error:?} does not contain {needle:?}"
        );
    }

    // An unknown member name is bounded and non-ASCII/control characters
    // are removed, so it cannot reorder or erase the error line.
    let params =
        json!({"name": "list_credentials", format!("x{}\u{7}\u{202e}", "y".repeat(40)): 1});
    let error = call_parts(Some(&params)).expect_err("must be refused");
    assert!(error.len() < 100, "the error must stay short: {error}");
    assert!(
        !error.contains('\u{7}'),
        "control characters leaked: {error:?}"
    );
    assert!(
        !error.contains('\u{202e}'),
        "bidi characters leaked: {error:?}"
    );
}

#[test]
fn list_filters_are_bounded_and_preserve_their_order() {
    let arguments = json!({"tags": ["prod", "git"], "query": "GitHub"});
    assert_eq!(
        list_filters(Some(&arguments)).expect("valid"),
        ListFilters {
            tags: vec!["prod".to_owned(), "git".to_owned()],
            query: Some("GitHub".to_owned()),
        }
    );
    assert_eq!(list_filters(None).expect("absent"), ListFilters::default());
    assert_eq!(
        list_filters(Some(&json!({}))).expect("empty"),
        ListFilters::default()
    );

    for (arguments, needle) in [
        (json!({"unknown": 1}), "unknown list_credentials argument"),
        (json!({"tags": "prod"}), "'tags' must be an array"),
        (json!({"tags": [1]}), "must be a string"),
        (json!({"tags": ["PROD"]}), "not a valid tag"),
        (json!({"query": 1}), "'query' must be a string"),
        (json!({"query": ""}), "must not be empty"),
        (json!({"query": "x".repeat(MAX_QUERY_BYTES + 1)}), "exceeds"),
        (json!({"query": "git\nhub"}), "control characters"),
    ] {
        let error = list_filters(Some(&arguments)).expect_err("must be refused");
        assert!(
            error.contains(needle),
            "{error:?} does not contain {needle:?}"
        );
    }

    let too_many: Vec<String> = (0..=MAX_TAGS_PER_CREDENTIAL)
        .map(|index| format!("tag{index}"))
        .collect();
    let error = list_filters(Some(&json!({"tags": too_many}))).expect_err("too many");
    assert!(error.contains("at most"), "{error}");
}

#[test]
fn a_validated_filter_becomes_the_daemon_request_verbatim() {
    let token = GrantToken::generate().expect("token");
    let expected = token.hash();
    let functions = ListFilters {
        tags: vec!["prod".to_owned(), "git".to_owned()],
        query: Some("GitHub".to_owned()),
    };
    let Request::List(list) = list_request(token, functions.clone()) else {
        panic!("expected a list request");
    };
    assert_eq!(list.tags, functions.tags);
    assert_eq!(list.query, functions.query);
    assert!(list.grant.hash().matches(&expected));
}

#[test]
fn entries_are_metadata_only_with_rfc3339_timestamps() {
    let rendered = entry_json(&entry());
    assert_eq!(rendered["ref"], "pm://00112233445566778899aabbccddeeff");
    assert_eq!(rendered["service"], "example.test");
    assert_eq!(rendered["username"], "alice");
    assert_eq!(rendered["tags"], json!(["prod"]));
    assert_eq!(rendered["fields"], json!(["token"]));
    assert_eq!(rendered["url"], "https://example.test");
    assert_eq!(rendered["created"], "2023-11-14T22:13:20Z");
    assert_eq!(rendered["last_rotated"], Value::Null);
}

#[test]
fn list_output_has_the_declared_shape_and_reports_truncation() {
    let output = list_output(&[entry()], false);
    assert_eq!(output["isError"], false);
    let structured = output["structuredContent"].as_object().expect("object");
    assert_eq!(structured.len(), 2, "entries and truncated only");
    assert_eq!(structured["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(structured["truncated"], false);
    assert_eq!(output["content"][0]["type"], "text");
    assert!(
        !output["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("truncated"),
        "a complete answer must not claim truncation"
    );

    let truncated = list_output(&[], true);
    assert_eq!(truncated["structuredContent"]["truncated"], true);
    assert_eq!(truncated["structuredContent"]["entries"], json!([]));
    assert!(
        truncated["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("narrow"),
        "a truncated answer must tell the agent how to narrow it"
    );
}

#[test]
fn every_daemon_refusal_maps_to_a_short_is_error_result() {
    let canary = "canary-1a2b3c-should-never-be-in-an-error";
    for error in [
        ResponseError::Denied,
        ResponseError::NotFound,
        ResponseError::Unauthorized,
        ResponseError::Busy,
        ResponseError::Internal,
        ResponseError::BadRequest,
        ResponseError::Unsupported,
        ResponseError::SpawnFailed,
    ] {
        let result = list_response(Response::Error(error));
        assert_eq!(result["isError"], true, "{error:?} must be an error");
        assert!(result.get("structuredContent").is_none());
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(!text.is_empty());
        assert!(!text.contains(canary));
        assert!(
            !text.to_ascii_lowercase().contains("debug"),
            "a daemon error must not be rendered with Debug: {text}"
        );
    }

    let denied = list_response(Response::Error(ResponseError::Denied));
    let text = denied["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("denied") && text.contains("grant"), "{text}");
}

#[test]
fn an_unexpected_daemon_answer_is_never_a_success() {
    let result = list_response(Response::Pong);
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
    assert!(
        result["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("unexpected")
    );
}

#[test]
fn describe_ref_accepts_only_the_canonical_reference_form() {
    let reference = "pm://00112233445566778899aabbccddeeff";
    assert_eq!(
        describe_ref(Some(&json!({"ref": reference}))).expect("valid"),
        reference
    );

    for (arguments, needle) in [
        (None, "requires a 'ref'"),
        (Some(json!({})), "'ref' is required"),
        (Some(json!({"ref": 1})), "must be a string"),
        (
            Some(json!({"ref": "pm://00112233445566778899AABBCCDDEEFF"})),
            "canonical",
        ),
        (
            Some(json!({"ref": "pm://00112233445566778899aabbccddeeff/token"})),
            "canonical",
        ),
        (
            Some(json!({"ref": "00112233445566778899aabbccddeeff"})),
            "canonical",
        ),
        (Some(json!({"ref": ""})), "canonical"),
        (
            Some(json!({"ref": "pm://00112233445566778899aabbccddeefg"})),
            "canonical",
        ),
        (
            Some(json!({"ref": " pm://00112233445566778899aabbccddeeff"})),
            "canonical",
        ),
        (
            Some(json!({"extra": 1})),
            "unknown describe_credential argument",
        ),
    ] {
        let error = describe_ref(arguments.as_ref()).expect_err("must be refused");
        assert!(
            error.contains(needle),
            "{error:?} does not contain {needle:?}"
        );
    }

    // A non-canonical reference is agent-supplied text: it must never be
    // quoted back, and the error must stay short.
    let canary = "canary-ref-that-must-not-be-echoed";
    let error = describe_ref(Some(&json!({"ref": canary}))).expect_err("refused");
    assert!(!error.contains(canary), "the reference leaked: {error:?}");
    assert!(error.len() < 120, "the error must stay short: {error}");

    let long = format!("pm://{}", "a".repeat(MAX_REFERENCE_BYTES));
    let error = describe_ref(Some(&json!({"ref": long}))).expect_err("too long");
    assert!(error.contains("exceeds"), "{error}");
}

#[test]
fn a_validated_reference_becomes_the_describe_request_verbatim() {
    let token = GrantToken::generate().expect("token");
    let expected = token.hash();
    let reference = entry().reference;
    let Request::Describe(describe) = describe_request(token, reference.clone()) else {
        panic!("expected a describe request");
    };
    assert_eq!(describe.reference, reference);
    assert!(describe.grant.hash().matches(&expected));
}

#[test]
fn describe_output_is_the_entry_object_with_no_value() {
    let output = describe_output(&entry());
    assert_eq!(output["isError"], false);
    assert_eq!(output["content"][0]["type"], "text");
    assert!(
        !output["content"][0]["text"]
            .as_str()
            .expect("text")
            .is_empty()
    );
    let structured = output["structuredContent"].as_object().expect("object");
    assert_eq!(structured.len(), 8, "exactly the Entry properties");
    assert_eq!(structured["ref"], "pm://00112233445566778899aabbccddeeff");
    assert_eq!(structured["service"], "example.test");
    assert_eq!(structured["fields"], json!(["token"]));
    assert_eq!(structured["created"], "2023-11-14T22:13:20Z");
}

#[test]
fn describe_response_maps_one_entry_and_collapses_not_found() {
    let result = describe_response(Response::Entry(entry()));
    assert_eq!(result["isError"], false);
    assert_eq!(
        result["structuredContent"]["ref"],
        "pm://00112233445566778899aabbccddeeff"
    );

    // The daemon uses one `NotFound` for a missing reference and for one its
    // grant does not cover; this layer must keep them indistinguishable.
    let missing = describe_response(Response::Error(ResponseError::NotFound));
    assert_eq!(missing["isError"], true);
    assert!(missing.get("structuredContent").is_none());
    assert_eq!(missing["content"][0]["text"], "not found or not granted");

    let unexpected = describe_response(Response::Pong);
    assert_eq!(unexpected["isError"], true);
    assert!(unexpected.get("structuredContent").is_none());
    assert!(
        unexpected["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("unexpected")
    );
}

#[test]
fn the_no_grant_message_is_exactly_the_contract_message() {
    assert_eq!(NO_GRANT, "no active grant; call request_access");
    let result = error_result(NO_GRANT);
    assert_eq!(result["isError"], true);
    assert_eq!(result["content"][0]["text"], NO_GRANT);
    assert!(result.get("structuredContent").is_none());
}
