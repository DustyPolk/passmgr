//! Tests for the tool catalogue: shape, naming and the no-secret invariant.

use serde_json::{Map, Value, json};

use super::*;
use crate::mcp::jsonrpc::MAX_LINE_BYTES;

fn definitions() -> Vec<Value> {
    ALL.iter().map(|tool| tool.definition()).collect()
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("a schema object")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

/// Visit every JSON object in `value`, depth first.
fn walk(value: &Value, visit: &mut impl FnMut(&Map<String, Value>)) {
    match value {
        Value::Object(map) => {
            visit(map);
            for member in map.values() {
                walk(member, visit);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, visit);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn names_are_unique_and_lookup_round_trips() {
    let mut names: Vec<&str> = Vec::new();
    for tool in ALL {
        let name = tool.as_str();
        assert!(!names.contains(&name), "duplicate tool name {name}");
        names.push(name);
        assert_eq!(Tool::from_name(name), Some(tool));
        let definition = tool.definition();
        assert_eq!(text(&definition, "name"), name);
    }
    assert_eq!(names.len(), 5, "MCP.md defines five tools");
    assert_eq!(Tool::from_name("reveal_secret"), None);
    assert_eq!(Tool::from_name("LIST_CREDENTIALS"), None);
    assert_eq!(Tool::from_name(""), None);
    // A tool name is a stable audit label: keep it short and snake_case.
    for name in names {
        assert!(name.len() <= 32);
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
    }
}

#[test]
fn every_definition_has_the_mcp_shape() {
    for definition in definitions() {
        let tool = text(&definition, "name").to_owned();
        assert!(!text(&definition, "title").is_empty(), "{tool} title");
        assert!(
            text(&definition, "title").len() <= 80,
            "{tool} title is too long"
        );
        assert!(
            !text(&definition, "description").is_empty(),
            "{tool} description"
        );
        assert!(
            text(&definition, "description").len() <= 1600,
            "{tool} description is too long for a tool listing"
        );

        let input = definition.get("inputSchema").expect("inputSchema");
        assert_eq!(text(input, "type"), "object", "{tool} input type");
        // The catalogue is also readable by a human and by `MCP.md`; a
        // definition must not depend on a remote `$ref`.
        walk(&definition, &mut |map| {
            assert!(
                !map.contains_key("$ref"),
                "{tool} must not use a remote schema reference"
            );
        });

        let output = definition.get("outputSchema").expect("outputSchema");
        assert_eq!(text(output, "type"), "object", "{tool} output type");
        assert_eq!(
            object(output).get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{tool} outputSchema must close its object"
        );
        let output_properties = output
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{tool} output properties"));
        let required = array(output, "required");
        assert_eq!(
            required.len(),
            output_properties.len(),
            "{tool} outputSchema must require every property"
        );
        for name in output_properties.keys() {
            assert!(
                required.iter().any(|value| value.as_str() == Some(name)),
                "{tool} output property {name} is not required"
            );
        }

        let annotations = definition.get("annotations").expect("annotations");
        for hint in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(
                annotations.get(hint).and_then(Value::as_bool).is_some(),
                "{tool} must carry the {hint} boolean"
            );
        }
    }
}

#[test]
fn every_object_schema_closes_itself() {
    for definition in definitions() {
        let tool = text(&definition, "name").to_owned();
        walk(&definition, &mut |map| {
            if map.contains_key("properties") {
                assert_eq!(
                    map.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "{tool}: a schema with properties must set additionalProperties: false"
                );
            }
        });
    }
}

#[test]
fn no_schema_property_can_carry_a_secret() {
    // A property *name* that reads like a secret is a design smell even when
    // its schema says "string": a later handler could fill it. The catalogue
    // uses references and field names instead.
    const BANNED: [&str; 11] = [
        "password",
        "passwords",
        "secret",
        "secrets",
        "token",
        "tokens",
        "value",
        "values",
        "plaintext",
        "credential",
        "credential_value",
    ];
    for definition in definitions() {
        let tool = text(&definition, "name").to_owned();
        walk(&definition, &mut |map| {
            if let Some(properties) = map.get("properties").and_then(Value::as_object) {
                for name in properties.keys() {
                    assert!(
                        !BANNED.contains(&name.as_str()),
                        "{tool} exposes a property named {name}"
                    );
                }
            }
        });
    }
}

#[test]
fn annotations_match_the_contract() {
    let by_name = |name: &str| Tool::from_name(name).expect("the tool exists").definition();
    for name in ["list_credentials", "describe_credential", "access_status"] {
        let definition = by_name(name);
        let annotations = definition.get("annotations").expect("annotations");
        assert_eq!(
            annotations.get("readOnlyHint"),
            Some(&Value::Bool(true)),
            "{name} only reads metadata"
        );
        assert_eq!(
            annotations.get("openWorldHint"),
            Some(&Value::Bool(false)),
            "{name} reaches nothing outside the vault"
        );
    }

    let run = by_name("run_with_credentials");
    let annotations = run.get("annotations").expect("annotations");
    assert_eq!(annotations.get("readOnlyHint"), Some(&Value::Bool(false)));
    assert_eq!(
        annotations.get("destructiveHint"),
        Some(&Value::Bool(true)),
        "a command can change the world"
    );
    assert_eq!(
        annotations.get("openWorldHint"),
        Some(&Value::Bool(true)),
        "a child process can reach the network and more"
    );
    assert_eq!(
        annotations.get("idempotentHint"),
        Some(&Value::Bool(false)),
        "running twice can have two effects"
    );

    let request = by_name("request_access");
    let annotations = request.get("annotations").expect("annotations");
    assert_eq!(annotations.get("readOnlyHint"), Some(&Value::Bool(false)));
    assert_eq!(
        annotations.get("destructiveHint"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        annotations.get("openWorldHint"),
        Some(&Value::Bool(false)),
        "a pending request reaches only the local daemon"
    );
}

#[test]
fn request_access_cannot_approve_itself() {
    let definition = Tool::RequestAccess.definition();
    let output = definition.get("outputSchema").expect("outputSchema");
    let status = output
        .get("properties")
        .and_then(|properties| properties.get("status"))
        .expect("a status property");
    assert_eq!(
        status.get("enum"),
        Some(&json!(["pending"])),
        "the only possible result of request_access is a pending request"
    );
    let description = text(&definition, "description");
    assert!(
        description.contains("human must approve"),
        "the model must be told a human approves"
    );
}

#[test]
fn input_schemas_accept_references_not_values() {
    let run = Tool::RunWithCredentials.definition();
    let schema = run.get("inputSchema").expect("inputSchema");
    let properties = schema.get("properties").expect("properties");
    for map in ["env", "files"] {
        let member = properties.get(map).expect(map);
        assert_eq!(text(member, "type"), "object");
        let additional = member
            .get("additionalProperties")
            .expect("additionalProperties");
        assert_eq!(
            text(additional, "pattern"),
            "^pm://[0-9a-f]{32}(/[a-z0-9_-]{1,32})?$",
            "{map} must map names to references, never to literal values"
        );
    }
    let stdin = properties.get("stdin_ref").expect("stdin_ref");
    assert_eq!(text(stdin, "type"), "string");
    assert!(text(stdin, "pattern").starts_with("^pm://"));

    let entry = Tool::ListCredentials.definition();
    let entry = entry
        .get("outputSchema")
        .and_then(|output| output.get("properties"))
        .and_then(|properties| properties.get("entries"))
        .and_then(|entries| entries.get("items"))
        .expect("the entry schema");
    let fields = entry
        .get("properties")
        .and_then(|p| p.get("fields"))
        .expect("fields");
    assert!(
        text(fields, "description").contains("Values are never returned"),
        "fields documents that only names leave the daemon"
    );
}

#[test]
fn the_whole_catalogue_fits_one_response_line() {
    let result = list_result();
    let entries = array(&result, "tools");
    assert_eq!(entries.len(), ALL.len());
    let names: Vec<&str> = entries.iter().map(|entry| text(entry, "name")).collect();
    let expected: Vec<&str> = ALL.iter().map(|tool| tool.as_str()).collect();
    assert_eq!(names, expected);

    let encoded = serde_json::to_vec(&result).expect("the catalogue serializes");
    assert!(
        encoded.len() < MAX_LINE_BYTES,
        "tools/list must fit one JSON-RPC line ({} bytes)",
        encoded.len()
    );
}
