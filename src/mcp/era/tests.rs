use super::super::jsonrpc::Id;
use super::*;
use serde_json::json;

fn request(method: &str, params: Option<Value>) -> Request {
    Request {
        id: Id::Number(1),
        method: method.to_string(),
        params,
    }
}

fn admit(session: &mut Session, method: &str, params: Option<Value>) -> Result<Admitted, Rejected> {
    session.admit(&request(method, params))
}

fn rejected(result: Result<Admitted, Rejected>) -> Rejected {
    match result {
        Ok(admitted) => panic!("expected a rejection, got {admitted:?}"),
        Err(rejected) => rejected,
    }
}

fn code(result: Result<Admitted, Rejected>) -> i32 {
    rejected(result).error.code
}

/// A modern `params` object whose `_meta` holds the three documented keys.
fn meta(version: &str) -> Value {
    let mut meta = Map::new();
    meta.insert(META_PROTOCOL_VERSION.into(), json!(version));
    meta.insert(META_CLIENT_CAPABILITIES.into(), json!({}));
    let mut params = Map::new();
    params.insert("_meta".into(), Value::Object(meta));
    Value::Object(params)
}

/// Legacy `initialize` params for one requested version.
fn initialize_params(version: &str) -> Value {
    json!({
        "protocolVersion": version,
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0"},
    })
}

// --- legacy era -------------------------------------------------------------

#[test]
fn initialize_answers_the_legacy_version_for_every_requested_version() {
    // Supported legacy versions, plus a modern one and nonsense: `MCP.md`
    // says the answer is always 2025-11-25 and the client decides.
    let requested =
        LEGACY_ACCEPTED_VERSIONS
            .iter()
            .copied()
            .chain([MODERN_VERSION, "1999-01-01", ""]);

    for version in requested {
        let mut session = Session::new();
        let admitted = admit(
            &mut session,
            INITIALIZE_METHOD,
            Some(initialize_params(version)),
        )
        .expect("initialize is accepted");
        assert_eq!(admitted.era, Era::Legacy, "requested {version:?}");
        let result = admitted.reply.expect("initialize answers");
        assert_eq!(result["protocolVersion"], json!(LEGACY_VERSION));
        assert_eq!(session.client_name(), Some("test-client"));
        assert!(session.legacy_initialized());
    }
}

#[test]
fn the_initialize_result_is_legacy_shaped() {
    let result = initialize_result();
    assert_eq!(result["protocolVersion"], json!(LEGACY_VERSION));
    assert_eq!(
        result["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(result["serverInfo"]["name"], json!(SERVER_NAME));
    assert_eq!(
        result["serverInfo"]["version"],
        json!(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(result["instructions"], json!(INSTRUCTIONS));
    // Legacy results carry neither modern member.
    assert!(result.get("resultType").is_none());
    assert!(result.get("_meta").is_none());
}

#[test]
fn instructions_stay_within_the_contract() {
    assert!(INSTRUCTIONS.len() <= 1_200, "{} bytes", INSTRUCTIONS.len());
    for phrase in [
        "without ever seeing their values",
        "redacted",
        "audited",
        "access_status",
        "request_access",
        "list_credentials",
        "run_with_credentials",
        "pm://",
        "ask the human",
    ] {
        assert!(
            INSTRUCTIONS.contains(phrase),
            "instructions must mention {phrase:?}"
        );
    }
    for injection in ["stdin_ref", "files"] {
        assert!(
            !INSTRUCTIONS.contains(injection),
            "instructions must not recommend {injection:?}"
        );
    }
}

#[test]
fn a_legacy_request_before_initialize_is_invalid_but_ping_is_allowed() {
    let mut session = Session::new();
    assert_eq!(
        code(admit(&mut session, "tools/list", None)),
        ErrorCode::InvalidRequest.code()
    );

    let ping = admit(&mut session, PING_METHOD, None).expect("ping works before initialize");
    assert_eq!(ping.era, Era::Legacy);
    assert!(ping.reply.is_none());
    assert!(!session.legacy_initialized());

    admit(
        &mut session,
        INITIALIZE_METHOD,
        Some(initialize_params(LEGACY_VERSION)),
    )
    .expect("initialize is accepted");
    let listed = admit(&mut session, "tools/list", None).expect("initialized");
    assert_eq!(listed.era, Era::Legacy);
    assert!(listed.reply.is_none());
}

#[test]
fn initialize_is_refused_twice() {
    let mut session = Session::new();
    admit(
        &mut session,
        INITIALIZE_METHOD,
        Some(initialize_params(LEGACY_VERSION)),
    )
    .expect("first initialize is accepted");

    let mut second = initialize_params(LEGACY_VERSION);
    second["clientInfo"]["name"] = json!("someone-else");
    let refused = rejected(admit(&mut session, INITIALIZE_METHOD, Some(second)));
    assert_eq!(refused.error.code, ErrorCode::InvalidRequest.code());
    // The first handshake still owns the session.
    assert_eq!(session.client_name(), Some("test-client"));
    assert!(session.legacy_initialized());
}

#[test]
fn initialize_requires_the_documented_params() {
    let cases: [(Option<Value>, &str); 7] = [
        (None, "no params"),
        (Some(Value::Null), "null params"),
        (
            Some(json!({"capabilities": {}, "clientInfo": {"name": "x"}})),
            "no protocolVersion",
        ),
        (
            Some(json!({"protocolVersion": 3, "capabilities": {}, "clientInfo": {"name": "x"}})),
            "non-string protocolVersion",
        ),
        (
            Some(json!({"protocolVersion": LEGACY_VERSION, "clientInfo": {"name": "x"}})),
            "no capabilities",
        ),
        (
            Some(json!({"protocolVersion": LEGACY_VERSION, "capabilities": {}})),
            "no clientInfo",
        ),
        (
            Some(json!({"protocolVersion": LEGACY_VERSION, "capabilities": {}, "clientInfo": {}})),
            "clientInfo without a name",
        ),
    ];

    for (params, label) in cases {
        let mut session = Session::new();
        assert_eq!(
            code(admit(&mut session, INITIALIZE_METHOD, params)),
            ErrorCode::InvalidParams.code(),
            "{label}"
        );
        assert!(!session.legacy_initialized(), "{label}");
        assert_eq!(session.client_name(), None, "{label}");
    }
}

#[test]
fn a_rejected_initialize_leaves_the_session_uninitialized() {
    let mut session = Session::new();
    rejected(admit(&mut session, INITIALIZE_METHOD, Some(json!({}))));
    assert_eq!(
        code(admit(&mut session, "tools/list", None)),
        ErrorCode::InvalidRequest.code()
    );
}

// --- modern era -------------------------------------------------------------

#[test]
fn a_modern_request_is_served_without_a_handshake() {
    let mut session = Session::new();
    let admitted = admit(&mut session, "tools/list", Some(meta(MODERN_VERSION)))
        .expect("a modern request needs no initialize");
    assert_eq!(admitted.era, Era::Modern);
    assert!(admitted.reply.is_none());
    assert!(!session.legacy_initialized());
}

#[test]
fn decorate_adds_the_modern_members_only() {
    let decorated = decorate(Era::Modern, json!({"entries": []}));
    assert_eq!(decorated["resultType"], json!("complete"));
    assert_eq!(decorated["entries"], json!([]));
    assert_eq!(
        decorated["_meta"][META_SERVER_INFO],
        json!({"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")})
    );

    let untouched = json!({"entries": []});
    assert_eq!(decorate(Era::Legacy, untouched.clone()), untouched);
}

#[test]
fn modern_meta_requires_its_keys() {
    let mut params = Map::new();
    params.insert("_meta".into(), Value::Null);
    let cases: [Value; 5] = [
        Value::Object(params),
        json!({"_meta": {}}),
        json!({"_meta": {META_PROTOCOL_VERSION: MODERN_VERSION}}),
        json!({"_meta": {
            META_PROTOCOL_VERSION: 20260728,
            META_CLIENT_CAPABILITIES: {},
        }}),
        json!({"_meta": {
            META_PROTOCOL_VERSION: MODERN_VERSION,
            META_CLIENT_CAPABILITIES: "yes",
        }}),
    ];

    for params in cases {
        let mut session = Session::new();
        assert_eq!(
            code(admit(&mut session, "tools/list", Some(params.clone()))),
            ErrorCode::InvalidParams.code(),
            "{params}"
        );
        assert_eq!(session.client_name(), None);
    }
}

#[test]
fn an_unknown_modern_version_is_32022_with_the_supported_list() {
    let mut session = Session::new();
    let refused = rejected(admit(&mut session, "tools/list", Some(meta("2027-01-01"))));
    assert_eq!(
        refused.error.code,
        ErrorCode::UnsupportedProtocolVersion.code()
    );
    assert_eq!(
        refused.error.data,
        Some(json!({
            "supported": ["2026-07-28", "2025-11-25"],
            "requested": "2027-01-01",
        }))
    );
    // The version appears only in the structured field, never the message.
    assert!(!refused.error.message.contains("2027-01-01"));
    assert!(!session.legacy_initialized());
}

#[test]
fn a_legacy_version_in_a_modern_meta_is_32022_too() {
    // Stateless serving exists only for the modern version; a legacy client
    // must use `initialize`, not `_meta`.
    for version in LEGACY_ACCEPTED_VERSIONS {
        let mut session = Session::new();
        let refused = rejected(admit(&mut session, "tools/list", Some(meta(version))));
        assert_eq!(
            refused.error.code,
            ErrorCode::UnsupportedProtocolVersion.code()
        );
        assert_eq!(
            refused.error.data,
            Some(json!({"supported": SUPPORTED_VERSIONS, "requested": version}))
        );
        assert!(!session.legacy_initialized());
    }
}

#[test]
fn an_over_long_version_is_refused_before_it_is_echoed() {
    let version = "9".repeat(MAX_VERSION_BYTES + 1);
    let mut session = Session::new();
    let refused = rejected(admit(&mut session, "tools/list", Some(meta(&version))));
    assert_eq!(refused.error.code, ErrorCode::InvalidParams.code());
    assert!(refused.error.data.is_none());
    assert!(!refused.error.message.contains(&version));
    assert!(!refused.error.message.contains('9'));
}

#[test]
fn client_info_is_recorded_from_both_eras_and_bounded() {
    let mut modern = meta(MODERN_VERSION);
    modern["_meta"][META_CLIENT_INFO] = json!({"name": "cursor", "version": "0.9"});
    let mut session = Session::new();
    admit(&mut session, "tools/list", Some(modern)).expect("modern request");
    assert_eq!(session.client_name(), Some("cursor"));

    let mut legacy = initialize_params(LEGACY_VERSION);
    legacy["clientInfo"]["name"] = json!("claude-code");
    let mut session = Session::new();
    admit(&mut session, INITIALIZE_METHOD, Some(legacy)).expect("initialize");
    assert_eq!(session.client_name(), Some("claude-code"));

    let mut bad = meta(MODERN_VERSION);
    bad["_meta"][META_CLIENT_INFO] = json!({"version": "0.9"});
    let mut session = Session::new();
    assert_eq!(
        code(admit(&mut session, "tools/list", Some(bad))),
        ErrorCode::InvalidParams.code()
    );

    let mut too_long = meta(MODERN_VERSION);
    too_long["_meta"][META_CLIENT_INFO] = json!({"name": "c".repeat(MAX_CLIENT_NAME_BYTES + 1)});
    let mut session = Session::new();
    assert_eq!(
        code(admit(&mut session, "tools/list", Some(too_long))),
        ErrorCode::InvalidParams.code()
    );

    let mut empty = meta(MODERN_VERSION);
    empty["_meta"][META_CLIENT_INFO] = json!({"name": ""});
    let mut session = Session::new();
    assert_eq!(
        code(admit(&mut session, "tools/list", Some(empty))),
        ErrorCode::InvalidParams.code()
    );
}

// --- era switching ----------------------------------------------------------

#[test]
fn a_modern_initialize_does_not_select_the_legacy_era() {
    let mut session = Session::new();
    let admitted = admit(&mut session, INITIALIZE_METHOD, Some(meta(MODERN_VERSION)))
        .expect("served statelessly");
    assert_eq!(admitted.era, Era::Modern);
    assert!(admitted.reply.is_none(), "the modern era has no handshake");
    assert!(!session.legacy_initialized());
    assert_eq!(
        code(admit(&mut session, "tools/list", None)),
        ErrorCode::InvalidRequest.code()
    );
}

#[test]
fn initialize_after_modern_traffic_is_honoured() {
    let mut session = Session::new();
    admit(&mut session, "tools/list", Some(meta(MODERN_VERSION))).expect("modern request");
    let admitted = admit(
        &mut session,
        INITIALIZE_METHOD,
        Some(initialize_params(LEGACY_VERSION)),
    )
    .expect("initialize is honoured after modern traffic");
    assert_eq!(admitted.era, Era::Legacy);
    assert!(admitted.reply.is_some());
    assert!(session.legacy_initialized());
}

#[test]
fn eras_interleave_after_the_handshake() {
    let mut session = Session::new();
    admit(
        &mut session,
        INITIALIZE_METHOD,
        Some(initialize_params(LEGACY_VERSION)),
    )
    .expect("initialize");

    let modern = admit(&mut session, "tools/list", Some(meta(MODERN_VERSION))).expect("modern");
    assert_eq!(modern.era, Era::Modern);
    let legacy = admit(&mut session, "tools/list", None).expect("legacy");
    assert_eq!(legacy.era, Era::Legacy);
}

// --- server/discover --------------------------------------------------------

#[test]
fn discover_result_is_complete() {
    let result = discover();
    assert_eq!(result["resultType"], json!("complete"));
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
    assert_eq!(
        result["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(result["instructions"], json!(INSTRUCTIONS));
    assert_eq!(result["ttlMs"], json!(0));
    assert_eq!(result["cacheScope"], json!("private"));
    assert_eq!(
        result["_meta"][META_SERVER_INFO],
        json!({"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")})
    );
}

#[test]
fn discover_is_modern_only() {
    let mut session = Session::new();
    assert_eq!(
        code(admit(&mut session, DISCOVER_METHOD, None)),
        ErrorCode::InvalidRequest.code()
    );

    admit(
        &mut session,
        INITIALIZE_METHOD,
        Some(initialize_params(LEGACY_VERSION)),
    )
    .expect("initialize");
    // In the legacy era the method simply does not exist; the dispatcher
    // answers -32601.
    let legacy = admit(&mut session, DISCOVER_METHOD, None).expect("legacy request");
    assert_eq!(legacy.era, Era::Legacy);
    assert!(legacy.reply.is_none());

    let mut session = Session::new();
    let modern =
        admit(&mut session, DISCOVER_METHOD, Some(meta(MODERN_VERSION))).expect("modern discover");
    assert_eq!(modern.era, Era::Modern);
    assert_eq!(modern.reply, Some(discover()));
}

// --- rejections -------------------------------------------------------------

#[test]
fn rejections_carry_the_request_id() {
    let mut session = Session::new();
    let request = Request {
        id: Id::String("call-7".into()),
        method: "tools/list".to_string(),
        params: Some(meta("2027-01-01")),
    };
    let refused = session.admit(&request).expect_err("unknown version");
    assert_eq!(refused.id, Some(Id::String("call-7".into())));

    let mut session = Session::new();
    let refused = session
        .admit(&Request {
            id: Id::Number(42),
            method: "tools/list".to_string(),
            params: None,
        })
        .expect_err("not initialized");
    assert_eq!(refused.id, Some(Id::Number(42)));
    assert_eq!(refused.error.code, ErrorCode::InvalidRequest.code());
}
