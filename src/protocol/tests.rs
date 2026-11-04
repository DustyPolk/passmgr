//! Unit tests for the protocol request codec and field validation.
//!
//! Moved out of `src/protocol/mod.rs` by TODO R.20c to keep the module under
//! the line limit. The tests are unchanged apart from the module wrapper.

use super::*;
use serde_json::Value;

const REF: &str = "pm://00112233445566778899aabbccddeeff";
/// A fixed token so exact-frame assertions stay readable.
const TOKEN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn test_token() -> SessionToken {
    SessionToken::from_hex(TOKEN_HEX).expect("test token")
}

/// Request-only views of [`super::encode`]/[`super::decode`], so each
/// transport test can assert on the request without restating the token.
/// Tests that care about the token call `super::decode` directly.
fn encode(request: &Request) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtocolError> {
    super::encode(&test_token(), request)
}

fn decode(frame: &[u8]) -> Result<Request, ProtocolError> {
    super::decode(frame).map(AuthenticatedRequest::into_request)
}

/// A fixed grant token, so the wire form and its hash stay pinned.
fn grant_token() -> GrantToken {
    GrantToken::from_hex(&"11".repeat(32)).expect("fixed token")
}

fn describe_request() -> Request {
    Request::Describe(DescribeRequest {
        reference: REF.into(),
        grant: grant_token(),
    })
}
fn binding(name: &str) -> EnvBinding {
    EnvBinding {
        name: name.into(),
        reference: REF.into(),
    }
}

fn run_request() -> Request {
    Request::Run(RunRequest {
        limits: Default::default(),
        env: vec![binding("API_KEY")],
        plain_env: Vec::new(),
        command: vec![
            "/usr/bin/curl".into(),
            "-s".into(),
            "https://example.test".into(),
        ],
        cwd: "/tmp".into(),
        grant: grant_token(),
    })
}

fn list_request() -> Request {
    Request::List(ListRequest {
        tags: vec!["prod".into()],
        query: Some("gh".into()),
        grant: grant_token(),
    })
}

const PROVE_NONCE_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PROVE_DIGEST_HEX: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
/// HMAC-SHA256(0x0b * 32, "passmgr-approve-v1" || nonce || digest).
const PROVE_PROOF_HEX: &str = "3596124510e1fbd47cc55655696b177e71c511593ca8dde627eacf964a1e3f4c";

fn prove_request() -> Request {
    Request::Prove(ProveRequest {
        nonce: ChallengeNonce::from_hex(PROVE_NONCE_HEX).expect("nonce"),
        digest: RequestDigest::from_hex(PROVE_DIGEST_HEX).expect("digest"),
        proof: Proof::from_hex(PROVE_PROOF_HEX).expect("proof"),
    })
}

fn grant_request() -> crate::grant::GrantRequest {
    use crate::grant::{Capabilities, GrantRequest, GrantSpec, Scope};

    GrantRequest::new(
        GrantSpec {
            label: "deploy prod".into(),
            scope: Scope::new(
                Vec::new(),
                vec!["prod".into()],
                Some(vec!["password".into()]),
            )
            .expect("scope"),
            commands: vec!["/usr/bin/gh".into()],
            capabilities: Capabilities::RUN,
            expires_at: 1_700_003_600,
            max_uses: Some(2),
        },
        crate::grant::TokenHash::of(b"grant-token"),
    )
    .expect("grant request")
}

fn grant_create() -> Request {
    Request::GrantCreate(GrantCreateRequest::from_grant_request(&grant_request()))
}

fn grant_id() -> crate::grant::GrantId {
    crate::grant::GrantId::from_hex("00112233445566778899aabbccddeeff").expect("grant id")
}

/// Build a frame by hand, without going through `encode`.
fn frame(body: &str) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    frame
}

#[test]
fn round_trips_every_request() {
    for request in [
        Request::Ping,
        Request::Lock,
        Request::Challenge,
        prove_request(),
        run_request(),
        list_request(),
        describe_request(),
        grant_create(),
        Request::GrantRevoke(GrantRevokeRequest::Id(grant_id())),
        Request::GrantRevoke(GrantRevokeRequest::All),
    ] {
        let encoded = encode(&request).expect("encode");
        assert_eq!(decode(&encoded).expect("decode"), request);
    }
}

/// TODO R.51: the published list must match the encoder, so documentation can
/// derive the request types instead of repeating them. Each `"type"` is read
/// back from the encoded frame, so a rename cannot pass by updating only
/// [`Request::wire_name`].
#[test]
fn request_wire_names_match_the_encoder_for_every_variant() {
    let requests = [
        Request::Ping,
        Request::Lock,
        Request::Challenge,
        prove_request(),
        run_request(),
        list_request(),
        describe_request(),
        grant_create(),
        Request::GrantRevoke(GrantRevokeRequest::Id(grant_id())),
        Request::GrantRevoke(GrantRevokeRequest::All),
    ];
    let mut encoded_names = Vec::new();
    for request in &requests {
        let frame = encode(request).expect("encode");
        let value: Value = serde_json::from_slice(&frame[4..]).expect("json");
        let encoded = value["request"]["type"]
            .as_str()
            .expect("every request has a string type");
        assert_eq!(encoded, request.wire_name(), "{request:?}");
        encoded_names.push(encoded.to_owned());
    }
    encoded_names.sort_unstable();
    encoded_names.dedup();
    let mut published = REQUEST_WIRE_NAMES.to_vec();
    published.sort_unstable();
    assert_eq!(
        encoded_names, published,
        "REQUEST_WIRE_NAMES must name exactly the types the encoder emits"
    );
}

#[test]
fn grant_revoke_frames_name_exactly_one_target() {
    let by_id = encode(&Request::GrantRevoke(GrantRevokeRequest::Id(grant_id()))).expect("encode");
    let value: Value = serde_json::from_slice(&by_id[4..]).expect("json");
    assert_eq!(
        value["request"],
        serde_json::json!({
            "type": "grant_revoke",
            "id": "00112233445566778899aabbccddeeff",
        })
    );

    let all = encode(&Request::GrantRevoke(GrantRevokeRequest::All)).expect("encode");
    let value: Value = serde_json::from_slice(&all[4..]).expect("json");
    assert_eq!(
        value["request"],
        serde_json::json!({ "type": "grant_revoke", "all": true })
    );
}

/// Wrap a request body in the full envelope `decode` expects, without going
/// through `encode`, so a rejection is about the body and nothing else.
fn request_frame(request: &str) -> Vec<u8> {
    frame(&format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{request}}}"#
    ))
}

#[test]
fn grant_revoke_rejects_ambiguous_or_malformed_targets() {
    for body in [
        r#"{"type":"grant_revoke"}"#,
        r#"{"type":"grant_revoke","all":false}"#,
        r#"{"type":"grant_revoke","all":"true"}"#,
        r#"{"type":"grant_revoke","id":"00112233445566778899aabbccddeeff","all":true}"#,
        r#"{"type":"grant_revoke","id":"0011"}"#,
        r#"{"type":"grant_revoke","id":"zzzz2233445566778899aabbccddeeff"}"#,
        r#"{"type":"grant_revoke","id":null}"#,
    ] {
        assert!(
            matches!(
                decode(&request_frame(body)),
                Err(ProtocolError::InvalidRequest(_) | ProtocolError::MalformedJson(_))
            ),
            "{body} must be rejected as a bad request, not accepted or ignored"
        );
    }

    let accepted = r#"{"type":"grant_revoke","id":"00112233445566778899aabbccddeeff","all":null}"#;
    assert_eq!(
        decode(&request_frame(accepted)).expect("null all is absent"),
        Request::GrantRevoke(GrantRevokeRequest::Id(grant_id()))
    );
}

#[test]
fn grant_create_frames_carry_only_the_approved_fields() {
    let encoded = encode(&grant_create()).expect("encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    let hash_hex = crate::grant::TokenHash::of(b"grant-token").to_hex();
    assert_eq!(
        value["request"],
        serde_json::json!({
            "type": "grant_create",
            "label": "deploy prod",
            "refs": [],
            "tags": ["prod"],
            "fields": ["password"],
            "commands": ["/usr/bin/gh"],
            "capabilities": crate::grant::Capabilities::RUN.bits(),
            "expires_at": 1_700_003_600u64,
            "max_uses": 2,
            "token_hash": hash_hex,
        })
    );
    // The token hash is derived from the raw token, so Debug must redact it.
    let debug = format!("{:?}", grant_create());
    assert!(!debug.contains(&hash_hex), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

/// The exact `grant_create` frame body published in `MCP.md` ("The daemon
/// never writes a grant"), pinned as a literal (TODO R.24). It is one wire
/// line; the `concat!` splits are only for readability.
///
/// The fields are flat on the request object, like `run`. Nesting them under
/// a `request` key -- the shape TODO 3.4c once documented -- fails to decode
/// here, and `tests/docs.rs` fails if the document stops matching this shape.
const MCP_GRANT_CREATE_BODY: &str = concat!(
    r#"{"request":{"capabilities":2,"commands":["/usr/bin/gh"],"#,
    r#""expires_at":1700003600,"fields":["password"],"label":"deploy prod","#,
    r#""max_uses":2,"refs":[],"tags":["prod"],"#,
    r#""token_hash":"6d2bfc0147054b3d0ad9dac8d06b6f65bf79270378498f8a20cb87db6f07e3b6","#,
    r#""type":"grant_create"},"#,
    r#""token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","#,
    r#""version":4}"#,
);

#[test]
fn mcp_documented_grant_create_body_is_the_wire_format() {
    let decoded = decode(&frame(MCP_GRANT_CREATE_BODY)).expect("MCP.md example must decode");
    assert_eq!(decoded, grant_create());

    let encoded = encode(&grant_create()).expect("encode");
    assert_eq!(
        std::str::from_utf8(&encoded[4..]).expect("frame body is UTF-8"),
        MCP_GRANT_CREATE_BODY,
        "MCP.md's example must be the encoder's body byte for byte"
    );
}

/// A decoded payload is re-normalized through the same constructor the
/// approving CLI used, so a corrupted body cannot reach the approval store as
/// a digest for something the human never saw.
#[test]
fn grant_create_rejects_payloads_the_vault_writer_would_refuse() {
    let refused = |mutate: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let encoded = encode(&grant_create()).expect("encode");
        let mut value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
        mutate(value["request"].as_object_mut().expect("request"));
        assert!(
            matches!(
                decode(&frame(&value.to_string())),
                Err(ProtocolError::InvalidRequest(_))
            ),
            "payload must be refused"
        );
    };

    refused(&|request| {
        request.insert("token_hash".into(), "AA".repeat(32).into());
    });
    refused(&|request| {
        request.insert("token_hash".into(), "00".repeat(31).into());
    });
    refused(&|request| {
        request.insert("token_hash".into(), "zz".repeat(32).into());
    });
    refused(&|request| {
        request.insert("label".into(), "".into());
    });
    refused(&|request| {
        request.insert("refs".into(), serde_json::json!(["not-a-ref"]));
    });
    refused(&|request| {
        request.insert("capabilities".into(), serde_json::json!(0));
    });
    refused(&|request| {
        request.insert("capabilities".into(), serde_json::json!(8));
    });
    refused(&|request| {
        request.insert("max_uses".into(), serde_json::json!(0));
    });
    refused(&|request| {
        request.insert(
            "expires_at".into(),
            serde_json::json!(crate::store::MAX_TIMESTAMP_UNIX + 1),
        );
    });
    // TODO R.21: a command path is untrusted text a human will be shown.
    for command in [
        "/usr/bin/gh\u{1b}[2K\r/usr/bin/true",
        "/usr/bin/gh\ntrue",
        "/tmp/\u{202e}bin",
        "/tmp/a\u{200b}b",
    ] {
        refused(&|request| {
            request.insert("commands".into(), serde_json::json!([command]));
        });
    }
}

#[test]
fn challenge_and_prove_frames_have_a_fixed_shape() {
    let challenge = encode(&Request::Challenge).expect("encode");
    let body = format!(
        r#"{{"request":{{"type":"challenge"}},"token":"{TOKEN_HEX}","version":{PROTOCOL_VERSION}}}"#
    );
    assert_eq!(&challenge[4..], body.as_bytes());

    let prove = encode(&prove_request()).expect("encode");
    let body = format!(
        r#"{{"request":{{"digest":"{PROVE_DIGEST_HEX}","nonce":"{PROVE_NONCE_HEX}","proof":"{PROVE_PROOF_HEX}","type":"prove"}},"token":"{TOKEN_HEX}","version":{PROTOCOL_VERSION}}}"#
    );
    assert_eq!(&prove[4..], body.as_bytes());
}

#[test]
fn malformed_presence_fields_are_rejected() {
    let request = |fields: &str| {
        format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"prove",{fields}}}}}"#)
    };
    let valid = format!(
        r#""nonce":"{PROVE_NONCE_HEX}","digest":"{PROVE_DIGEST_HEX}","proof":"{PROVE_PROOF_HEX}""#
    );
    assert!(super::decode(&frame(&request(&valid))).is_ok());

    let cases = [
        String::new(),
        format!(r#""nonce":"{PROVE_NONCE_HEX}","digest":"{PROVE_DIGEST_HEX}""#),
        format!(r#""digest":"{PROVE_DIGEST_HEX}","proof":"{PROVE_PROOF_HEX}""#),
        format!(r#""nonce":"{PROVE_NONCE_HEX}","proof":"{PROVE_PROOF_HEX}""#),
        format!(
            r#""nonce":"{}","digest":"{PROVE_DIGEST_HEX}","proof":"{PROVE_PROOF_HEX}""#,
            PROVE_NONCE_HEX.to_uppercase()
        ),
        format!(
            r#""nonce":"{PROVE_NONCE_HEX}","digest":"{PROVE_DIGEST_HEX}","proof":"{}""#,
            &PROVE_PROOF_HEX[..62]
        ),
        format!(
            r#""nonce":"{PROVE_NONCE_HEX}","digest":"{PROVE_DIGEST_HEX}","proof":"zz{}""#,
            &PROVE_PROOF_HEX[2..]
        ),
        format!(r#""nonce":"{PROVE_NONCE_HEX}","digest":"{PROVE_DIGEST_HEX}","proof":7""#),
    ];
    for fields in cases {
        match super::decode(&frame(&request(&fields))) {
            Err(ProtocolError::MalformedJson(_) | ProtocolError::InvalidRequest(_)) => {}
            other => panic!("expected a malformed prove request for {fields:?}, got {other:?}"),
        }
    }
}

#[test]
fn a_prove_request_never_renders_its_proof_in_debug() {
    let rendered = format!("{:?}", prove_request());
    assert!(!rendered.contains(PROVE_PROOF_HEX), "{rendered}");
    assert!(rendered.contains(PROVE_NONCE_HEX), "{rendered}");
    assert!(rendered.contains(PROVE_DIGEST_HEX), "{rendered}");
    assert!(rendered.contains("Proof(<redacted>)"), "{rendered}");
}

#[test]
fn frame_starts_with_a_big_endian_length_prefix() {
    let encoded = encode(&Request::Ping).expect("encode");
    let body = format!(
        r#"{{"request":{{"type":"ping"}},"token":"{TOKEN_HEX}","version":{PROTOCOL_VERSION}}}"#
    );
    assert_eq!(&encoded[..4], &(body.len() as u32).to_be_bytes());
    assert_eq!(&encoded[4..], body.as_bytes());
}

#[test]
fn truncated_prefix_and_body_are_rejected() {
    for frame in [
        &b""[..],
        &b"\x00"[..],
        &b"\x00\x00"[..],
        &b"\x00\x00\x00"[..],
    ] {
        assert_eq!(
            decode(frame),
            Err(ProtocolError::TruncatedFrame {
                expected: LENGTH_PREFIX_BYTES,
                actual: frame.len(),
            })
        );
    }

    let truncated = [0, 0, 0, 10, b'{', b'}'];
    assert_eq!(
        decode(&truncated),
        Err(ProtocolError::TruncatedFrame {
            expected: 14,
            actual: 6,
        })
    );
}

#[test]
fn oversized_declared_length_is_rejected_before_reading_the_body() {
    let prefix = u32::MAX.to_be_bytes();
    assert_eq!(
        decode(&prefix),
        Err(ProtocolError::MessageTooLarge {
            length: u32::MAX as usize,
            max: MAX_MESSAGE_BYTES,
        })
    );

    let mut decoder = FrameDecoder::new();
    assert_eq!(
        decoder.push(&prefix),
        Err(ProtocolError::MessageTooLarge {
            length: u32::MAX as usize,
            max: MAX_MESSAGE_BYTES,
        })
    );
}

#[test]
fn empty_and_trailing_bytes_are_rejected() {
    assert_eq!(decode(&[0, 0, 0, 0]), Err(ProtocolError::EmptyMessage));

    let mut encoded = encode(&Request::Ping).expect("encode");
    encoded.push(b'x');
    assert_eq!(
        decode(&encoded),
        Err(ProtocolError::TrailingBytes { trailing: 1 })
    );
}

#[test]
fn oversized_encoded_message_is_rejected() {
    // Each argument is within MAX_ARG_BYTES, but the body is over 64 KiB.
    let mut command = vec!["/bin/prog".to_string()];
    for _ in 0..20 {
        command.push("x".repeat(4096));
    }
    let request = Request::Run(RunRequest {
        limits: Default::default(),
        env: vec![binding("API_KEY")],
        plain_env: Vec::new(),
        command,
        cwd: "/tmp".into(),
        grant: grant_token(),
    });
    assert!(matches!(
        encode(&request),
        Err(ProtocolError::MessageTooLarge { .. })
    ));
}

#[test]
fn bad_versions_are_rejected() {
    for version in ["0", "1", "2", "3", "5", "99", "18446744073709551615"] {
        let body =
            format!(r#"{{"version":{version},"token":"{TOKEN_HEX}","request":{{"type":"ping"}}}}"#);
        let expected = version.parse::<u64>().expect("test version");
        assert_eq!(
            decode(&frame(&body)),
            Err(ProtocolError::UnsupportedVersion(expected))
        );
    }
}

#[test]
fn missing_or_mistyped_envelope_fields_are_rejected() {
    let bodies: Vec<String> = vec![
        "not json".into(),
        "[]".into(),
        "null".into(),
        r#"{"request":{"type":"ping"}}"#.into(),
        r#"{"version":"2","token":"x","request":{"type":"ping"}}"#.into(),
        r#"{"version":-1,"token":"x","request":{"type":"ping"}}"#.into(),
        r#"{"version":3.5,"token":"x","request":{"type":"ping"}}"#.into(),
        r#"{"version":4}"#.into(),
        format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":[]}}"#),
        format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{}}}}"#),
        format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":42}}}}"#),
        format!(
            r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x"}}}}"#
        ),
        format!(
            r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x","command":"true"}}}}"#
        ),
        format!(
            r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"A","ref":"x","command":[1]}}}}"#
        ),
    ];
    for body in bodies {
        assert!(
            matches!(
                super::decode(&frame(&body)),
                Err(ProtocolError::MalformedJson(_))
            ),
            "body should be malformed: {body}"
        );
    }
}

#[test]
fn a_missing_or_malformed_token_is_rejected_on_every_request_type() {
    // No token at all.
    for request in [r#"{"type":"ping"}"#, r#"{"type":"lock"}"#] {
        let body = format!(r#"{{"version":4,"request":{request}}}"#);
        assert!(
            matches!(
                super::decode(&frame(&body)),
                Err(ProtocolError::MalformedJson(_))
            ),
            "missing token must be malformed: {body}"
        );
    }

    // A token field that is not a string.
    let body = r#"{"version":4,"token":7,"request":{"type":"ping"}}"#;
    assert!(matches!(
        super::decode(&frame(body)),
        Err(ProtocolError::MalformedJson(_))
    ));

    // Strings that are not exactly 64 lowercase hex characters.
    let uppercase = "A".repeat(crate::token::TOKEN_HEX_CHARS);
    let short = "a".repeat(crate::token::TOKEN_HEX_CHARS - 1);
    let long = "a".repeat(crate::token::TOKEN_HEX_CHARS + 1);
    let non_hex = "g".repeat(crate::token::TOKEN_HEX_CHARS);
    for token in [uppercase, short, long, non_hex, String::new()] {
        let body = format!(r#"{{"version":4,"token":"{token}","request":{{"type":"ping"}}}}"#);
        match super::decode(&frame(&body)) {
            Err(ProtocolError::InvalidToken) => {}
            other => panic!("token {token:?} should be invalid, got {other:?}"),
        }
    }
}

#[test]
fn the_decoded_token_matches_what_was_encoded() {
    let token = test_token();
    let other = SessionToken::from_bytes(&[0xFFu8; crate::token::TOKEN_BYTES]).expect("token");
    for request in [Request::Ping, Request::Lock, run_request()] {
        let encoded = super::encode(&token, &request).expect("encode");
        let decoded = super::decode(&encoded).expect("decode");
        assert!(decoded.token().matches(&token));
        assert!(!decoded.token().matches(&other));
        assert_eq!(decoded.into_request(), request);
    }
}

#[test]
fn the_token_never_appears_in_debug_output() {
    let token = test_token();
    let encoded = super::encode(&token, &Request::Ping).expect("encode");
    let decoded = super::decode(&encoded).expect("decode");
    let text = format!("{decoded:?} {decoded:?}");
    assert!(!text.contains(TOKEN_HEX), "Debug leaked the token: {text}");
}

#[test]
fn unknown_request_types_are_rejected() {
    // Including the request types a plaintext-leaking protocol would have:
    // none of them exist here, and none may ever be added.
    for kind in ["reveal", "get", "password", "export", "run ", "PING", ""] {
        let body =
            format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"{kind}"}}}}"#);
        assert!(
            matches!(decode(&frame(&body)), Err(ProtocolError::UnknownRequest(_))),
            "type {kind:?} should be unknown"
        );
    }

    // A huge type is echoed back only in truncated form.
    let long = "x".repeat(10_000);
    let body = format!(r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"{long}"}}}}"#);
    match decode(&frame(&body)) {
        Err(ProtocolError::UnknownRequest(kind)) => {
            assert_eq!(kind.chars().count(), MAX_TYPE_CHARS)
        }
        other => panic!("expected UnknownRequest, got {other:?}"),
    }
}

#[test]
fn env_name_syntax_is_shared_with_the_cli() {
    // The CLI pre-checks with `valid_env_name`; both paths must agree so a
    // name can never pass the client and fail at the daemon (or vice
    // versa) because the two grammars drifted.
    for name in ["A", "_", "A_B9", "a", "_0"] {
        assert!(valid_env_name(name), "{name}");
        assert!(validate_env_name(name).is_ok(), "{name}");
    }
    for name in ["", "1BAD", "BAD-NAME", "A B", "A.B", "é", "_é"] {
        assert!(!valid_env_name(name), "{name}");
        assert!(validate_env_name(name).is_err(), "{name}");
    }
    let long = "A".repeat(MAX_ENV_NAME_BYTES + 1);
    assert!(!valid_env_name(&long));
    assert!(validate_env_name(&long).is_err());
    assert!(valid_env_name(&"A".repeat(MAX_ENV_NAME_BYTES)));
}

#[test]
fn run_fields_are_validated() {
    let base = RunRequest {
        limits: Default::default(),
        env: vec![binding("OK")],
        plain_env: Vec::new(),
        command: vec!["/bin/true".into()],
        cwd: "/tmp".into(),
        grant: grant_token(),
    };
    let cases = [
        RunRequest {
            limits: Default::default(),
            env: Vec::new(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![binding("")],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![binding("1BAD")],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![binding("BAD-NAME")],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![binding(&"A".repeat(MAX_ENV_NAME_BYTES + 1))],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![
                EnvBinding {
                    name: "DUP".into(),
                    reference: REF.into(),
                },
                EnvBinding {
                    name: "DUP".into(),
                    reference: REF.into(),
                },
            ],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![binding("OK")],
            plain_env: vec![("OK".into(), "plain".into())],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![EnvBinding {
                name: "OK".into(),
                reference: String::new(),
            }],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: vec![EnvBinding {
                name: "OK".into(),
                reference: "not-a-reference".into(),
            }],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            env: (0..=MAX_ENV_BINDINGS)
                .map(|index| EnvBinding {
                    name: format!("V{index}"),
                    reference: REF.into(),
                })
                .collect(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            plain_env: vec![("1BAD".into(), "x".into())],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            plain_env: vec![("OK_PLAIN".into(), "x".repeat(MAX_ENV_VALUE_BYTES + 1))],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            plain_env: vec![("OK_PLAIN".into(), "x\0y".into())],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            command: vec![],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            command: vec![String::new()],
            ..base.clone()
        },
        // A bare program name would be resolved through the daemon's own
        // PATH, which belongs to the shell that ran `unlock`.
        RunRequest {
            limits: Default::default(),
            command: vec!["true".into()],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            command: vec!["bin/true".into()],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            command: vec!["/bin/true".into(); MAX_ARGS + 1],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            command: vec!["/bin/true".into(), "x".repeat(MAX_ARG_BYTES + 1)],
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            cwd: String::new(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            cwd: "tmp".into(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            cwd: "./tmp".into(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            cwd: "/tmp/\0/x".into(),
            ..base.clone()
        },
        RunRequest {
            limits: Default::default(),
            cwd: format!("/{}", "x".repeat(MAX_PATH_BYTES)),
            ..base.clone()
        },
    ];
    for run in cases {
        assert!(
            matches!(
                encode(&Request::Run(run.clone())),
                Err(ProtocolError::InvalidRequest(_))
            ),
            "should reject {run:?}"
        );
    }
    // The baseline itself is valid, so the cases above fail for the
    // intended reason rather than a mistake in the fixture.
    assert!(encode(&Request::Run(base)).is_ok());
}

#[test]
fn run_without_cwd_is_rejected_on_decode() {
    let body = format!(
        r#"{{"version":{PROTOCOL_VERSION},"token":"{TOKEN_HEX}","request":{{"type":"run","env":"K","ref":"{REF}","command":["/bin/true"]}}}}"#
    );
    assert!(matches!(
        decode(&frame(&body)),
        Err(ProtocolError::MalformedJson(_))
    ));
}

#[test]
fn run_without_a_grant_is_rejected_on_decode() {
    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"K","ref":"{REF}","command":["/bin/true"],"cwd":"/tmp"}}}}"#
    );
    assert!(matches!(
        decode(&frame(&body)),
        Err(ProtocolError::MalformedJson(message)) if message.contains("grant")
    ));
}

#[test]
fn a_malformed_grant_is_rejected_without_echoing_it() {
    // Uppercase hex is a different encoding of the same bytes, so it is not
    // accepted; the error must not repeat the token.
    let canary = "A".repeat(64);
    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"K","ref":"{REF}","command":["/bin/true"],"cwd":"/tmp","grant":"{canary}"}}}}"#
    );
    let error = decode(&frame(&body)).expect_err("must reject uppercase grant");
    let text = error.to_string();
    assert!(!text.contains(&canary), "error echoed the grant: {text}");
}

#[test]
fn decoder_reassembles_fragmented_frames() {
    let request = run_request();
    let encoded = encode(&request).expect("encode");
    let mut decoder = FrameDecoder::new();
    for (index, byte) in encoded.iter().enumerate() {
        decoder.push(std::slice::from_ref(byte)).expect("push");
        if index + 1 < encoded.len() {
            assert!(decoder.next_request().expect("decode").is_none());
        }
    }
    let decoded = decoder.next_request().expect("decode").expect("request");
    assert_eq!(decoded.into_request(), request);
    assert!(decoder.next_request().expect("decode").is_none());
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn decoder_reads_two_frames_from_one_push() {
    let mut bytes = encode(&Request::Ping).expect("encode");
    bytes.extend_from_slice(&encode(&Request::Lock).expect("encode"));
    let mut decoder = FrameDecoder::new();
    decoder.push(&bytes).expect("push");
    let first = decoder.next_request().expect("decode").expect("first");
    assert_eq!(first.into_request(), Request::Ping);
    let second = decoder.next_request().expect("decode").expect("second");
    assert_eq!(second.into_request(), Request::Lock);
    assert!(decoder.next_request().expect("decode").is_none());
}

#[test]
fn decoder_rejects_a_buffer_flood() {
    let mut decoder = FrameDecoder::new();
    let mut flood = (MAX_MESSAGE_BYTES as u32).to_be_bytes().to_vec();
    flood.resize(MAX_MESSAGE_BYTES + 8, 0);
    decoder.push(&flood).expect("first push fits");
    assert!(matches!(
        decoder.push(&vec![0u8; MAX_BUFFERED_BYTES]),
        Err(ProtocolError::BufferFull { .. })
    ));
}

#[test]
fn arbitrary_bytes_are_rejected_without_panicking() {
    // Deterministic xorshift; this is a smoke test for the parser, not a
    // substitute for the cargo-fuzz target in TODO 5.2.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for length in 0..=96 {
        for _ in 0..32 {
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = decode(&bytes);
            let mut decoder = FrameDecoder::new();
            let _ = decoder.push(&bytes);
            let _ = decoder.next_request();
        }
    }
}

#[test]
fn errors_do_not_echo_request_field_values() {
    // Error text is loggable. It may name lengths and echo a truncated
    // request type, but must never repeat a field value from the body.
    let secret_like = "SUPER_SECRET_VALUE_123";
    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"{secret_like}","ref":"x","command":["/bin/true"],"cwd":"/tmp","grant":"{}"}}}}"#,
        "11".repeat(32)
    );
    let error = decode(&frame(&body)).expect_err("invalid ref");
    let text = error.to_string();
    assert!(
        text.contains("run.env[0].ref"),
        "unexpected message: {text}"
    );
    assert!(!text.contains(secret_like));
}

#[test]
fn a_taken_frame_is_wiped_from_the_decoder_buffer() {
    // The decoder's buffer holds the session-token hex until the frame is
    // taken; `Vec::drain` would leave the consumed bytes in the allocation.
    // (TODO R.50c)
    let frame = encode(&run_request()).expect("encode");
    let mut decoder = FrameDecoder::new();
    decoder.push(&frame).expect("push");
    let taken = decoder.next_frame().expect("frame").expect("body");
    assert_eq!(
        taken.len() + crate::protocol::LENGTH_PREFIX_BYTES,
        frame.len()
    );
    assert_eq!(decoder.buffered(), 0);
    assert!(
        decoder.written_bytes().iter().all(|&byte| byte == 0),
        "the taken frame is still in the decoder buffer"
    );
}

#[test]
fn taking_a_frame_zeroes_the_stale_tail_behind_the_next_one() {
    // A second frame keeps its bytes live, but the tail the first frame left
    // past the new length must be zero: that is exactly the region `drain`
    // used to leave the taken frame in.
    let first = encode(&run_request()).expect("encode");
    let second = encode(&Request::Ping).expect("encode");
    let mut decoder = FrameDecoder::new();
    decoder.push(&first).expect("push first");
    decoder.push(&second).expect("push second");
    decoder.next_frame().expect("frame").expect("body");
    let live = decoder.buffered();
    assert_eq!(live, second.len());
    assert_eq!(&decoder.written_bytes()[..live], &second[..]);
    assert!(
        decoder.written_bytes()[live..]
            .iter()
            .all(|&byte| byte == 0),
        "the taken frame's tail is still in the decoder buffer"
    );
}

mod describe;
mod list;
mod run_env;
mod run_limits;
mod wire;
