//! Unit tests for the `tools/call` boundary: bounds, pass-through and mapping.

use serde_json::json;

use super::*;
use crate::client::RunOutcome;
use crate::protocol::{ResponseError, RunExit, RunFinished, RunFrame};

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

// --- run_with_credentials (TODO 4.5d) -------------------------------------

fn reference() -> String {
    "pm://00112233445566778899aabbccddeeff".to_owned()
}

fn run_object(extra: serde_json::Value) -> serde_json::Value {
    let mut object = json!({
        "command": ["/bin/echo", "hello"],
        "env": {"TOKEN": reference()},
    });
    let extra = extra.as_object().expect("extra is an object").clone();
    for (key, value) in extra {
        object.as_object_mut().expect("object").insert(key, value);
    }
    object
}

fn args(extra: serde_json::Value) -> Result<RunArgs, String> {
    run_args(Some(&run_object(extra)), Some(std::path::Path::new("/")))
}

#[test]
fn run_args_defaults_the_limits_and_the_working_directory() {
    let defaults = args(json!({})).expect("valid run");
    assert_eq!(
        defaults.command,
        vec!["/bin/echo".to_owned(), "hello".to_owned()]
    );
    assert_eq!(defaults.env.len(), 1);
    assert_eq!(defaults.env[0].name, "TOKEN");
    assert_eq!(defaults.env[0].reference, reference());
    assert!(defaults.plain_env.is_empty());
    assert_eq!(defaults.cwd, "/");
    assert_eq!(defaults.limits.timeout_secs, 600);
    assert_eq!(defaults.limits.max_output_bytes, 262_144);

    let explicit = args(json!({"timeout_secs": 5, "max_output_bytes": 1024, "cwd": "/tmp"}))
        .expect("valid run");
    assert_eq!(explicit.limits.timeout_secs, 5);
    assert_eq!(explicit.limits.max_output_bytes, 1024);
    assert_eq!(explicit.cwd, "/tmp");
}

#[test]
fn run_args_requires_a_command_and_a_secret_binding() {
    assert!(
        run_args(None, Some(std::path::Path::new("/")))
            .expect_err("no arguments")
            .contains("requires 'command'")
    );
    let without_env = json!({"command": ["/bin/echo"]});
    assert!(
        run_args(Some(&without_env), Some(std::path::Path::new("/")))
            .expect_err("no env")
            .contains("at least one credential reference")
    );
    // A run without a usable working directory has no absolute cwd to send.
    let object = run_object(json!({}));
    assert!(
        run_args(Some(&object), None)
            .expect_err("no cwd")
            .contains("pass an absolute 'cwd'")
    );
}

#[test]
fn run_args_rejects_unknown_members_and_bad_argv() {
    for (extra, needle) in [
        (
            json!({"shell": "/bin/sh"}),
            "unknown run_with_credentials argument 'shell'",
        ),
        (json!({"command": "echo"}), "must be an array"),
        (json!({"command": []}), "at least one program"),
        (json!({"command": [""]}), "command[0]' must not be empty"),
        (json!({"command": [3]}), "command[0]' must be a string"),
        (
            json!({"command": ["/bin/echo", "a\0b"]}),
            "must not contain a NUL byte",
        ),
        (
            json!({"command": ["/bin/echo", "x".repeat(4097)]}),
            "command[1]' exceeds 4096 bytes",
        ),
    ] {
        let message = args(extra).expect_err("rejected");
        assert!(message.contains(needle), "unexpected message: {message}");
    }
}

#[test]
fn run_args_refuses_the_unimplemented_injections() {
    let stdin = args(json!({"stdin_ref": reference()})).expect_err("stdin_ref");
    assert!(stdin.contains("'stdin_ref' is not available"), "{stdin}");
    assert!(stdin.contains("'env'"), "{stdin}");

    let files = args(json!({"files": {"CONFIG": reference()}})).expect_err("files");
    assert!(files.contains("'files' is not available"), "{files}");
    assert!(files.contains("'env'"), "{files}");

    // An absent member, `null` and `{}` all mean "no files".
    for extra in [json!({}), json!({"files": null}), json!({"files": {}})] {
        assert!(args(extra).is_ok());
    }

    // Any other type is a malformed argument, not "no files": running
    // without the file the caller asked for would spend a grant use.
    for files in [json!("X=pm://x"), json!(["x"]), json!(true), json!(5)] {
        let message = args(json!({ "files": files })).expect_err("wrong type");
        assert_eq!(message, "'files' must be an object", "for {files}");
    }
}

#[test]
fn run_args_validates_env_and_plain_env_without_echoing_values() {
    let canary = "canary-run-literal-7f2c";
    let literal = args(json!({"env": {"TOKEN": canary}})).expect_err("literal secret");
    assert!(literal.contains("'env.TOKEN'"), "{literal}");
    assert!(
        !literal.contains(canary),
        "the literal was echoed: {literal}"
    );

    let name = args(json!({"env": {"lower": reference()}})).expect_err("bad name");
    assert!(
        name.contains("not a valid environment variable name"),
        "{name}"
    );
    assert!(
        name.contains("\"lower\"") || name.contains("lower"),
        "{name}"
    );

    let upper = args(json!({"env": {"TOKEN": "pm://00112233445566778899AABBCCDDEEFF"}}))
        .expect_err("non-canonical reference");
    assert!(
        upper.contains("canonical pm:// references from list_credentials"),
        "{upper}"
    );

    let duplicate = args(json!({"plain_env": {"TOKEN": "x"}})).expect_err("duplicate");
    assert!(duplicate.contains("more than once"), "{duplicate}");

    let too_many: serde_json::Map<String, serde_json::Value> = (0..33)
        .map(|index| (format!("NAME_{index}"), json!(reference())))
        .collect();
    let many = args(json!({"env": too_many})).expect_err("too many");
    assert!(many.contains("at most 32"), "{many}");

    let plain = args(json!({"plain_env": {"CI": "1"}})).expect("plain env");
    assert_eq!(plain.plain_env, vec![("CI".to_owned(), "1".to_owned())]);
    // A field path is a form the schema mentions, but the daemon's parser
    // rejects it everywhere (`describe_ref` does too), so the boundary does
    // the same rather than sending something `pmd` would refuse.
    let field = args(json!({"env": {"TOKEN": format!("{}/password", reference())}}))
        .expect_err("field path");
    assert!(field.contains("canonical pm:// references"), "{field}");
}

#[test]
fn run_args_bounds_the_working_directory_and_the_limits() {
    for (extra, needle) in [
        (json!({"cwd": "relative"}), "must be an absolute path"),
        (json!({"cwd": ""}), "must not be empty"),
        (json!({"cwd": "/a\0b"}), "must not contain a NUL byte"),
        (json!({"timeout_secs": 0}), "between 1 and 600"),
        (json!({"timeout_secs": 601}), "between 1 and 600"),
        (json!({"timeout_secs": 1.5}), "must be an integer"),
        (json!({"timeout_secs": "60"}), "must be an integer"),
        (json!({"max_output_bytes": 0}), "between 1 and 1048576"),
        (
            json!({"max_output_bytes": 1_048_577}),
            "between 1 and 1048576",
        ),
    ] {
        let message = args(extra).expect_err("rejected");
        assert!(message.contains(needle), "unexpected message: {message}");
    }
}

#[test]
fn resolve_command_makes_the_program_absolute() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp dir");
    let program = directory.path().join("fixture-run");
    std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("write");
    let mut permissions = std::fs::metadata(&program).expect("metadata").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&program, permissions).expect("chmod");

    let run = args(json!({"command": ["fixture-run", "--flag"]})).expect("valid run");
    let resolved = resolve_command(run, directory.path().as_os_str()).expect("resolved");
    assert_eq!(resolved.command[0], program.to_str().expect("utf-8 path"));
    assert_eq!(resolved.command[1], "--flag");

    let missing = args(json!({"command": ["canary-missing-program-5b1d"]})).expect("valid run");
    let message = resolve_command(missing, directory.path().as_os_str()).expect_err("missing");
    assert_eq!(
        message,
        "the program in 'command[0]' was not found: use an absolute path or a name on PATH"
    );
    assert!(!message.contains("canary-missing-program-5b1d"));
}

#[test]
fn run_output_maps_the_exit_signal_and_daemon_statistics() {
    let mut sink = RunSink::new(1024);
    sink.push(&RunFrame::Stdout(b"out\n".to_vec()));
    sink.push(&RunFrame::Stderr(b"err\n".to_vec()));

    let finished = RunFinished {
        exit: RunExit::Code(3),
        timed_out: false,
        stdout_truncated: true,
        stderr_truncated: false,
        redactions: 2,
        duration_ms: 987,
    };
    let result = run_output(&finished, &sink);
    assert_eq!(result["isError"], false);
    let structured = &result["structuredContent"];
    assert_eq!(structured["exit_code"], 3);
    assert_eq!(structured["signal"], serde_json::Value::Null);
    assert_eq!(structured["timed_out"], false);
    assert_eq!(structured["stdout"], "out\n");
    assert_eq!(structured["stderr"], "err\n");
    assert_eq!(structured["stdout_truncated"], true);
    assert_eq!(structured["stderr_truncated"], false);
    assert_eq!(structured["redactions"], 2);
    assert_eq!(structured["duration_ms"], 987);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("truncated")
    );

    let signalled = RunFinished {
        exit: RunExit::Signal(9),
        timed_out: true,
        ..finished
    };
    let result = run_output(&signalled, &sink);
    assert_eq!(
        result["structuredContent"]["exit_code"],
        serde_json::Value::Null
    );
    assert_eq!(result["structuredContent"]["signal"], "SIGKILL");
    assert_eq!(result["structuredContent"]["timed_out"], true);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("timed out")
    );
}

#[test]
fn run_output_replaces_bytes_that_are_not_utf8() {
    let mut sink = RunSink::new(16);
    sink.push(&RunFrame::Stdout(vec![0x66, 0xff, 0x6f]));
    let result = run_output(&RunFinished::exited(RunExit::Code(0)), &sink);
    let stdout = result["structuredContent"]["stdout"]
        .as_str()
        .expect("string");
    assert!(stdout.starts_with('f'), "{stdout:?}");
    assert!(stdout.ends_with('o'), "{stdout:?}");
}

#[test]
fn run_sink_caps_each_stream_and_ignores_terminal_frames() {
    let mut sink = RunSink::new(4);
    sink.push(&RunFrame::Stdout(b"hello world".to_vec()));
    sink.push(&RunFrame::Stdout(b"more".to_vec()));
    sink.push(&RunFrame::Stderr(b"error".to_vec()));
    sink.push(&RunFrame::Exit(RunFinished::exited(RunExit::Code(0))));
    assert_eq!(sink.stdout(), b"hell");
    assert_eq!(sink.stderr(), b"erro");
}

#[test]
fn a_refused_run_is_an_error_result_with_the_daemon_message() {
    let sink = RunSink::new(16);
    let refused = run_response(RunOutcome::Refused(ResponseError::Denied), &sink);
    assert_eq!(refused["isError"], true);
    assert!(refused.get("structuredContent").is_none());
    let text = refused["content"][0]["text"].as_str().expect("text");
    assert_eq!(text, daemon_error(ResponseError::Denied));
}

#[test]
fn signal_names_are_conventional_and_fall_back_to_the_number() {
    assert_eq!(super::run::signal_name(9), "SIGKILL");
    assert_eq!(super::run::signal_name(15), "SIGTERM");
    assert_eq!(super::run::signal_name(77), "SIG77");
}

#[test]
fn run_args_debug_names_variables_but_not_plain_env_values() {
    let canary = "canary-debug-plain-env-1c9e";
    let args = args(json!({"plain_env": {"CI_TOKEN": canary}})).expect("valid run");
    let debug = format!("{args:?}");
    assert!(debug.contains("CI_TOKEN"), "{debug}");
    assert!(
        !debug.contains(canary),
        "the plain_env value was printed: {debug}"
    );
    assert!(debug.contains("RunArgs"), "{debug}");
}
