//! `list` request filters (TODO 4.4b): bounded, tag-validated and free of
//! secrets. Split out of `src/protocol/tests.rs` to keep it under the
//! ~1,000-line limit.

use super::*;

#[test]
fn list_filters_are_bounded_and_carry_no_secret() {
    let encoded = encode(&list_request()).expect("encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert_eq!(value["request"]["type"], "list");
    assert_eq!(value["request"]["tags"], serde_json::json!(["prod"]));
    assert_eq!(value["request"]["query"], "gh");
    assert_eq!(
        value["request"]["grant"].as_str().expect("grant hex"),
        grant_token().to_hex().as_str(),
        "list carries the grant token, never its hash or a secret"
    );

    // Absent filters mean "no filter", so a hand-written client may omit them.
    let bare = r#"{"type":"list","grant":""#.to_owned() + grant_token().to_hex().as_str() + r#""}"#;
    assert_eq!(
        decode(&request_frame(&bare)).expect("absent filters decode"),
        Request::List(ListRequest {
            tags: Vec::new(),
            query: None,
            grant: grant_token(),
        })
    );
}

#[test]
fn list_rejects_filters_that_are_not_tags_or_bounded_text() {
    let bad_tags = [
        "Prod",          // tags are lowercase
        "two words",     // no spaces
        "-leading",      // must start with a letter or digit
        "",              // empty
        &"a".repeat(33), // longer than MAX_TAG_BYTES
    ];
    for tag in bad_tags {
        let request = Request::List(ListRequest {
            tags: vec![tag.into()],
            query: None,
            grant: grant_token(),
        });
        assert!(
            matches!(encode(&request), Err(ProtocolError::InvalidRequest(_))),
            "{tag:?} must not be accepted as a tag"
        );
    }

    let too_many = Request::List(ListRequest {
        tags: vec!["prod".into(); crate::store::MAX_TAGS_PER_CREDENTIAL + 1],
        query: None,
        grant: grant_token(),
    });
    assert!(matches!(
        encode(&too_many),
        Err(ProtocolError::InvalidRequest(_))
    ));

    let too_long = Request::List(ListRequest {
        tags: Vec::new(),
        query: Some("q".repeat(MAX_QUERY_BYTES + 1)),
        grant: grant_token(),
    });
    assert!(matches!(
        encode(&too_long),
        Err(ProtocolError::InvalidRequest(_))
    ));

    let control = Request::List(ListRequest {
        tags: Vec::new(),
        query: Some("gh\u{1b}[31m".into()),
        grant: grant_token(),
    });
    assert!(matches!(
        encode(&control),
        Err(ProtocolError::InvalidRequest(_))
    ));

    // The decoder applies the same rules to an untrusted body.
    let body = format!(
        r#"{{"type":"list","tags":["Prod"],"grant":"{}"}}"#,
        grant_token().to_hex().as_str()
    );
    assert!(matches!(
        decode(&request_frame(&body)),
        Err(ProtocolError::InvalidRequest(_))
    ));
}
