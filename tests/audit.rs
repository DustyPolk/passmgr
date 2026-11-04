//! End-to-end tests for the hash-chained audit log (TODO 3.8).
//!
//! Every run that reaches `pmd` must leave exactly one metadata record, and
//! neither the injected secret nor a grant/session token may appear in it.
//! These tests use the real daemon and the real socket, because the point is
//! that the *served* request is what gets recorded.

#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use passmgr::audit::{self, GENESIS_PREV};
use passmgr::grant::GrantToken;
use passmgr::protocol::{Request, ResponseError, RunFrame, RunRequest};
use serde_json::Value;
use support::*;

fn audit_file(fixture: &Fixture) -> PathBuf {
    fixture
        ._directory
        .path()
        .join("state")
        .join("passmgr")
        .join("audit.jsonl")
}

fn records(fixture: &Fixture) -> (String, Vec<Value>) {
    let path = audit_file(fixture);
    let text = fs::read_to_string(&path).expect("read the audit log");
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("every audit line is JSON"))
        .collect();
    (text, lines)
}

fn token_text(token: &GrantToken) -> String {
    token.to_hex().as_str().to_owned()
}

#[test]
fn an_allowed_run_appends_one_record_without_the_secret_or_any_token() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let request = fixture.run_request("TOKEN", &["/bin/sh", "-c", "printf '%s' \"$TOKEN\""]);

    let (frames, raw) = read_run(&fixture.socket(), &fixture.token, &request);
    assert_exited(&frames, 0);
    assert!(frames.len() > 1, "the run must finish: {frames:?}");
    let stdout = stdout_bytes(&frames);
    assert!(
        String::from_utf8_lossy(&stdout).contains("[REDACTED]"),
        "the child ran and its output was redacted: {frames:?}"
    );
    assert!(!String::from_utf8_lossy(&raw).contains(SECRET));

    let (text, lines) = records(&fixture);
    assert_eq!(lines.len(), 1, "one run, one record: {text}");
    let record = &lines[0];
    assert_eq!(record["v"], 1);
    assert_eq!(record["source"], "daemon");
    assert_eq!(record["event"], "run");
    assert_eq!(record["outcome"], "allowed");
    assert_eq!(record["ref"], fixture.reference);
    assert_eq!(record["exit"], 0);
    assert!(record["signal"].is_null());
    assert_eq!(record["prev"], GENESIS_PREV);
    assert_eq!(
        record["command"],
        fs::canonicalize("/bin/sh")
            .expect("canonical /bin/sh")
            .to_str()
            .expect("UTF-8 path"),
        "the canonical program is recorded: {record}"
    );
    assert_eq!(record["args"][0], "-c");
    assert!(
        record["grant"].as_str().is_some_and(|id| id.len() == 32),
        "the authorizing grant id is recorded: {record}"
    );

    assert!(!text.contains(SECRET), "the secret must never be audited");
    assert!(
        !text.contains(&token_text(&fixture.grant)),
        "the grant token must never be audited"
    );
    assert!(
        !text.contains(fixture.token.to_hex().as_str()),
        "the session token must never be audited"
    );

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn a_denied_run_is_recorded_without_a_grant_or_any_token() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let forged = GrantToken::generate().expect("forged token");
    let request = Request::Run(RunRequest {
        limits: Default::default(),
        env: vec![passmgr::protocol::EnvBinding {
            name: "TOKEN".into(),
            reference: fixture.reference.clone(),
        }],
        plain_env: Vec::new(),
        command: vec!["/bin/true".into()],
        cwd: "/".into(),
        grant: forged.clone(),
    });

    let (frames, raw) = read_run(&fixture.socket(), &fixture.token, &request);
    assert_eq!(
        frames.last(),
        Some(&RunFrame::Error(ResponseError::Denied)),
        "an unknown grant is denied: {frames:?}"
    );

    let (text, lines) = records(&fixture);
    assert_eq!(lines.len(), 1, "a denial is a use and is recorded: {text}");
    let record = &lines[0];
    assert_eq!(record["outcome"], "denied");
    assert!(record["grant"].is_null(), "no grant authorized this run");
    assert_eq!(record["ref"], fixture.reference);
    assert!(record["exit"].is_null());
    assert_eq!(record["prev"], GENESIS_PREV);

    assert!(!text.contains(SECRET));
    assert!(!text.contains(&token_text(&fixture.grant)));
    assert!(!text.contains(&token_text(&forged)));
    assert!(
        !text.contains(fixture.token.to_hex().as_str()),
        "the session token must never be audited"
    );
    assert!(
        !String::from_utf8_lossy(&raw).contains(&token_text(&forged)),
        "the socket reply must not echo the token"
    );

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn consecutive_runs_chain_each_record_to_the_previous_line() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    for _ in 0..2 {
        let request = fixture.run_request("TOKEN", &["/bin/true"]);
        let (frames, _) = read_run(&fixture.socket(), &fixture.token, &request);
        assert_exited(&frames, 0);
    }

    let path = audit_file(&fixture);
    let text = fs::read_to_string(&path).expect("read the audit log");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    let first: Value = serde_json::from_str(lines[0]).expect("first record");
    let second: Value = serde_json::from_str(lines[1]).expect("second record");
    assert_eq!(first["prev"], GENESIS_PREV);
    assert_eq!(
        second["prev"].as_str().expect("prev"),
        audit::chain_hash(lines[0].as_bytes()),
        "each record must commit to the previous line's bytes"
    );

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn a_run_is_refused_when_the_audit_log_cannot_be_written() {
    let fixture = Fixture::new();
    // `state` must be a directory; a file there makes the audit path
    // unusable. The daemon must refuse before spawning anything.
    fs::write(fixture._directory.path().join("state"), b"not a directory")
        .expect("block the state directory");
    let mut daemon = fixture.start();
    let request = fixture.run_request("TOKEN", &["/bin/sh", "-c", "exit 0"]);

    let (frames, _) = read_run(&fixture.socket(), &fixture.token, &request);
    assert_eq!(
        frames,
        vec![RunFrame::Error(ResponseError::Internal)],
        "an unrecordable run must fail closed"
    );

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn a_run_against_a_torn_audit_log_is_refused_before_the_child_starts() {
    // A crash mid-append leaves a last line without its newline. The append
    // after the child would refuse it, so the preflight must refuse it first:
    // otherwise the secret is used and never recorded.
    let fixture = Fixture::new();
    let audit = audit_file(&fixture);
    let state = audit.parent().expect("state directory");
    fs::create_dir_all(state).expect("create the state directory");
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).expect("chmod state");
    fs::write(&audit, br#"{"v":1"#).expect("write a torn log");
    fs::set_permissions(&audit, fs::Permissions::from_mode(0o600)).expect("chmod log");
    let marker = fixture._directory.path().join("child-ran");
    let marker_arg = marker.to_str().expect("UTF-8 marker path");
    let mut daemon = fixture.start();
    let request = fixture.run_request(
        "TOKEN",
        &["/bin/sh", "-c", "touch \"$1\"", "sh", marker_arg],
    );

    let (frames, _) = read_run(&fixture.socket(), &fixture.token, &request);
    assert_eq!(
        frames,
        vec![RunFrame::Error(ResponseError::Internal)],
        "an unrecordable run must fail closed"
    );
    assert!(!marker.exists(), "the child must never have started");

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn a_run_whose_audit_append_fails_is_not_reported_as_success() {
    // The preflight creates and checks the file; the child then makes it
    // unwritable, so the append *after* the child ran is the one that fails
    // (TODO R.68). The daemon must not answer `Exit(0)` for a use it could
    // not record, and the secret-bearing child output must say it ran.
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let audit = audit_file(&fixture);
    let audit_arg = audit.to_str().expect("UTF-8 audit path");
    let request = fixture.run_request(
        "TOKEN",
        &[
            "/bin/sh",
            "-c",
            "printf ran; chmod 400 \"$1\"",
            "sh",
            audit_arg,
        ],
    );

    let (frames, _) = read_run(&fixture.socket(), &fixture.token, &request);
    assert!(
        !frames
            .iter()
            .any(|frame| matches!(frame, RunFrame::Exit(_))),
        "an unrecorded run must not report an exit status: {frames:?}"
    );
    assert_eq!(
        frames.last(),
        Some(&RunFrame::Error(ResponseError::Internal)),
        "an unrecorded run must fail closed: {frames:?}"
    );
    assert!(
        String::from_utf8_lossy(&stdout_bytes(&frames)).contains("ran"),
        "the child must have run before the append failed: {frames:?}"
    );
    let text = fs::read_to_string(&audit).expect("the 0400 log is still readable");
    assert!(text.is_empty(), "nothing was recorded: {text}");

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}

#[test]
fn the_audit_file_is_private_and_its_directory_is_private() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let request = fixture.run_request("TOKEN", &["/bin/true"]);
    let (frames, _) = read_run(&fixture.socket(), &fixture.token, &request);
    assert_exited(&frames, 0);

    let path = audit_file(&fixture);
    let mode = fs::metadata(&path)
        .expect("audit metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the audit file must be 0600");
    let directory_mode = fs::metadata(path.parent().expect("parent"))
        .expect("state metadata")
        .permissions()
        .mode();
    assert_eq!(
        directory_mode & 0o777,
        0o700,
        "the audit directory must be 0700"
    );

    daemon.kill().expect("kill pmd");
    wait_for_exit(&mut daemon, WAIT);
}
