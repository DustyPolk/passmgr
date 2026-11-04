//! Multiple secret bindings and `plain_env` in a `run` request (TODO 4.5b).
//! Split out of `src/protocol/tests.rs` to keep it under the line limit.

use super::*;

#[test]
fn a_legacy_single_env_run_decodes_as_one_binding() {
    // An old client sends `env` as a string and `ref` at the top level. It
    // must keep working, but re-encoding uses the new binding list.
    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":"LEGACY","ref":"{REF}","command":["/bin/true"],"cwd":"/tmp","grant":"{}"}}}}"#,
        "11".repeat(32)
    );
    let decoded = decode(&frame(&body)).expect("legacy run");
    let Request::Run(run) = decoded else {
        panic!("expected run");
    };
    assert_eq!(
        run.env,
        vec![EnvBinding {
            name: "LEGACY".into(),
            reference: REF.into(),
        }]
    );
    assert!(run.plain_env.is_empty());

    let encoded = encode(&Request::Run(run.clone())).expect("re-encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    assert!(value["request"]["env"].is_array());
    assert!(value["request"].get("ref").is_none());
}

#[test]
fn several_bindings_and_plain_env_round_trip_in_order() {
    let request = Request::Run(RunRequest {
        limits: Default::default(),
        env: vec![
            EnvBinding {
                name: "FIRST".into(),
                reference: "pm://00000000000000000000000000000001".into(),
            },
            EnvBinding {
                name: "SECOND".into(),
                reference: "pm://00000000000000000000000000000002".into(),
            },
        ],
        plain_env: vec![
            ("GH_HOST".into(), "github.com".into()),
            ("NO_COLOR".into(), "1".into()),
        ],
        command: vec!["/bin/true".into()],
        cwd: "/tmp".into(),
        grant: grant_token(),
    });
    let encoded = encode(&request).expect("encode");
    let value: Value = serde_json::from_slice(&encoded[4..]).expect("json");
    let bindings = value["request"]["env"].as_array().expect("env array");
    assert_eq!(bindings[0]["name"], "FIRST");
    assert_eq!(bindings[1]["name"], "SECOND");
    assert_eq!(value["request"]["plain_env"]["GH_HOST"], "github.com");
    assert_eq!(decode(&encoded).expect("decode"), request);
}

#[test]
fn malformed_env_shapes_are_rejected() {
    let cases = [
        // A list entry without a reference.
        r#"["name-only"]"#.to_owned(),
        r#"[{"name":"A"}]"#.to_owned(),
        r#"[{"ref":"pm://00000000000000000000000000000001"}]"#.to_owned(),
        r#"[{"name":1,"ref":"pm://00000000000000000000000000000001"}]"#.to_owned(),
        // A legacy string without `ref`.
        r#""NAME_ONLY""#.to_owned(),
        // A plain_env array instead of an object.
        r#"[]"#.to_owned(),
    ];
    for env in cases {
        let plain_env = "{}";
        let body = format!(
            r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":{env},"plain_env":{plain_env},"command":["/bin/true"],"cwd":"/tmp","grant":"{}"}}}}"#,
            "11".repeat(32)
        );
        assert!(
            decode(&frame(&body)).is_err(),
            "env {env} should be rejected"
        );
    }

    let body = format!(
        r#"{{"version":4,"token":"{TOKEN_HEX}","request":{{"type":"run","env":[{{"name":"A","ref":"{REF}"}}],"plain_env":[],"command":["/bin/true"],"cwd":"/tmp","grant":"{}"}}}}"#,
        "11".repeat(32)
    );
    assert!(decode(&frame(&body)).is_err());
}
