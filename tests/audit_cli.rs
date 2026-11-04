//! End-to-end tests for `pm audit` and `pm audit verify` (TODO 3.9).
//!
//! Each test writes its own audit log under a temporary `XDG_STATE_HOME` with
//! the public `encode_line`/`chain_hash` rules, so no vault, daemon or master
//! password is involved and the timestamps are controllable. The log holds
//! metadata only; a canary stands in for anything that must never be printed.

mod cli_support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cli_support::{assert_success, run_with_env, stderr, stdout};
use passmgr::audit::{Event, GENESIS_PREV, Outcome, Source, Termination, chain_hash, encode_line};
use passmgr::grant::GrantId;
use tempfile::TempDir;

const GRANT_ONE: &str = "00112233445566778899aabbccddeeff";
const GRANT_TWO: &str = "ffeeddccbbaa99887766554433221100";
const REFERENCE: &str = "pm://0123456789abcdef0123456789abcdef";
/// A value that looks like a secret or a grant token. Nothing may print it.
const CANARY: &str = "canary-9f1c2b7e-never-print";

/// A temporary state home with a helper to write a chained audit log into it.
struct State {
    directory: TempDir,
}

impl State {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().expect("state tempdir"),
        }
    }

    fn home(&self) -> &str {
        self.directory
            .path()
            .to_str()
            .expect("UTF-8 temporary path")
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("passmgr").join("audit.jsonl")
    }

    fn env(&self) -> [(&str, &str); 1] {
        [("XDG_STATE_HOME", self.home())]
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        run_with_env(args, "", &self.env())
    }

    /// Write `records` as a correctly chained log, 0600 inside a 0700
    /// directory. Each record carries a fixed reference and one argument.
    fn write(&self, records: &[(u64, Option<&str>, Outcome)]) {
        self.write_lines(&self.encoded(records));
    }

    fn encoded(&self, records: &[(u64, Option<&str>, Outcome)]) -> Vec<String> {
        let mut prev = GENESIS_PREV.to_owned();
        let mut lines = Vec::new();
        for (timestamp, grant, outcome) in records {
            let args = vec![format!("--note={CANARY}")];
            let event = Event {
                source: Source::Daemon,
                outcome: *outcome,
                grant: grant.map(|text| GrantId::from_hex(text).expect("grant id")),
                reference: Some(REFERENCE),
                command: Some("/usr/bin/true"),
                args: &args,
                termination: match outcome {
                    Outcome::Denied | Outcome::NotFound => None,
                    _ => Some(Termination::Code(0)),
                },
            };
            let line = encode_line(&prev, &event, *timestamp);
            prev = chain_hash(line.as_bytes());
            lines.push(line);
        }
        lines
    }

    fn write_lines(&self, lines: &[String]) {
        let state = self.directory.path().join("passmgr");
        fs::create_dir_all(&state).expect("state dir");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let text = if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        };
        fs::write(self.path(), text).expect("write log");
        fs::set_permissions(self.path(), fs::Permissions::from_mode(0o600)).expect("chmod file");
    }

    fn lines(&self) -> Vec<String> {
        read_lines(&self.path())
    }

    fn rewrite(&self, lines: &[String]) {
        self.write_lines(lines);
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read log")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn json_records(output: &std::process::Output) -> Vec<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(&stdout(output)).expect("audit --json must be JSON");
    value["records"]
        .as_array()
        .expect("records must be an array")
        .clone()
}

#[test]
fn audit_lists_records_as_metadata_including_arguments() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, None, Outcome::Denied),
    ]);

    let output = state.run(&["audit"]);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("Audit records (showing 2 of 2):"), "{text}");
    assert!(
        text.contains("2025-01-01T00:00:00Z  allowed  daemon"),
        "{text}"
    );
    assert!(text.contains(&format!("grant={GRANT_ONE}")), "{text}");
    assert!(text.contains(&format!("ref={REFERENCE}")), "{text}");
    assert!(text.contains("command=/usr/bin/true"), "{text}");
    assert!(text.contains(&format!("args=[--note={CANARY}]")), "{text}");
    assert!(text.contains("exit=0"), "{text}");
    assert!(
        text.contains("2025-01-01T00:00:01Z  denied  daemon"),
        "{text}"
    );
    assert!(!text.contains("prev="), "the listing is not a dump: {text}");
    assert_eq!(stderr(&output), "", "a listing needs no prompt or warning");
}

#[test]
fn audit_json_is_parseable_and_carries_only_record_fields() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, None, Outcome::Denied),
    ]);

    let output = state.run(&["audit", "--json"]);
    assert_success(&output);
    let records = json_records(&output);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["v"], 1);
    assert_eq!(records[0]["ts"], "2025-01-01T00:00:00Z");
    assert_eq!(records[0]["source"], "daemon");
    assert_eq!(records[0]["event"], "run");
    assert_eq!(records[0]["outcome"], "allowed");
    assert_eq!(records[0]["grant"], GRANT_ONE);
    assert_eq!(records[0]["ref"], REFERENCE);
    assert_eq!(records[0]["command"], "/usr/bin/true");
    assert_eq!(records[0]["exit"], 0);
    assert!(records[1]["grant"].is_null());
    assert!(records[1]["exit"].is_null());

    // A record is metadata; the only strings are the ones the writer stores.
    let text = stdout(&output);
    assert!(!text.contains("token"), "no token field: {text}");
    assert!(!text.contains("password"), "no password field: {text}");
}

#[test]
fn audit_filters_by_grant_and_time_and_limits_the_tail() {
    let state = State::new();
    let now = now();
    state.write(&[
        (now - 7_300, Some(GRANT_ONE), Outcome::Allowed),
        (now - 3_500, Some(GRANT_TWO), Outcome::Allowed),
        (now - 90, Some(GRANT_ONE), Outcome::Allowed),
        (now, None, Outcome::Denied),
    ]);

    let output = state.run(&["audit", "--grant", GRANT_ONE]);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("showing 2 of 2"), "{text}");
    assert_eq!(
        text.matches(&format!("grant={GRANT_ONE}")).count(),
        2,
        "{text}"
    );

    let output = state.run(&["audit", "--since", "1h"]);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("showing 3 of 3"), "{text}");

    let output = state.run(&["audit", "--limit", "1"]);
    assert_success(&output);
    let text = stdout(&output);
    assert!(text.contains("showing 1 of 4"), "{text}");
    assert_eq!(
        text.matches("denied").count(),
        1,
        "the newest record: {text}"
    );

    let output = state.run(&["audit", "--grant", GRANT_TWO, "--json"]);
    assert_success(&output);
    let records = json_records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["grant"], GRANT_TWO);

    // A filter that matches nothing says so instead of dumping everything.
    let output = state.run(&["audit", "--grant", GRANT_TWO, "--since", "1s"]);
    assert_success(&output);
    assert!(stdout(&output).contains("No audit records match the filter."));
}

#[test]
fn audit_verify_accepts_a_valid_chain() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, None, Outcome::Denied),
    ]);
    let output = state.run(&["audit", "verify"]);
    assert_success(&output);
    assert_eq!(stdout(&output), "Audit log verified: 2 records.\n");
}

#[test]
fn audit_verify_reports_an_edited_record_with_exit_6() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, Some(GRANT_ONE), Outcome::Denied),
        (1_735_689_602, Some(GRANT_TWO), Outcome::Allowed),
    ]);
    let mut lines = state.lines();
    // Same byte length: only the chain can notice the edit.
    lines[1] = lines[1].replace("\"denied\"", "\"allowed\"");
    state.rewrite(&lines);

    let output = state.run(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let error = stderr(&output);
    assert!(error.contains("audit log verification failed"), "{error}");
    assert!(
        error.contains("line 3"),
        "names the first impossible link: {error}"
    );
    assert!(error.contains("line 2"), "{error}");
    assert!(
        !error.contains(&lines[1]),
        "the record itself is not echoed"
    );
}

#[test]
fn audit_verify_reports_a_deleted_record_with_exit_6() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_602, Some(GRANT_ONE), Outcome::Allowed),
    ]);
    let lines = state.lines();
    state.rewrite(&[lines[0].clone(), lines[2].clone()]);

    let output = state.run(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(stderr(&output).contains("line 2"), "{output:?}");
}

#[test]
fn audit_verify_reports_reordered_records_with_exit_6() {
    let state = State::new();
    state.write(&[
        (1_735_689_600, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_601, Some(GRANT_ONE), Outcome::Allowed),
        (1_735_689_602, Some(GRANT_ONE), Outcome::Allowed),
    ]);
    let lines = state.lines();
    state.rewrite(&[lines[1].clone(), lines[0].clone(), lines[2].clone()]);

    let output = state.run(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(stderr(&output).contains("line 1"), "{output:?}");
}

#[test]
fn audit_verify_reports_a_torn_final_record_with_exit_6() {
    let state = State::new();
    state.write(&[(1_735_689_600, Some(GRANT_ONE), Outcome::Allowed)]);
    let mut text = fs::read_to_string(state.path()).expect("read log");
    text.pop();
    fs::write(state.path(), text).expect("write torn log");

    let output = state.run(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(
        stderr(&output).contains("not newline-terminated"),
        "{output:?}"
    );
}

#[test]
fn audit_without_a_log_is_empty_and_still_succeeds() {
    let state = State::new();
    let output = state.run(&["audit"]);
    assert_success(&output);
    assert_eq!(stdout(&output), "No audit records.\n");

    let output = state.run(&["audit", "verify"]);
    assert_success(&output);
    assert_eq!(stdout(&output), "Audit log verified: 0 records.\n");

    let output = state.run(&["audit", "--json"]);
    assert_success(&output);
    assert_eq!(json_records(&output).len(), 0);
}

#[test]
fn audit_refuses_a_loose_log_instead_of_reading_it() {
    let state = State::new();
    state.write(&[(1_735_689_600, Some(GRANT_ONE), Outcome::Allowed)]);
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o644)).expect("chmod file");

    let output = state.run(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error = stderr(&output);
    assert!(error.contains("refusing the audit path"), "{error}");
    assert!(error.contains("0644"), "{error}");
}

/// The listing path must never open the vault: it is metadata-only and works
/// with no stdin at all. `run_with_env` gives every command an empty stdin and
/// no TTY, so a password prompt would fail rather than hang.
#[test]
fn audit_never_prompts_for_the_master_password() {
    let state = State::new();
    state.write(&[(1_735_689_600, Some(GRANT_ONE), Outcome::Allowed)]);
    for args in [
        vec!["audit"],
        vec!["audit", "verify"],
        vec!["audit", "--json"],
    ] {
        let output = state.run(&args);
        assert_success(&output);
        assert_eq!(stderr(&output), "", "{args:?} must not prompt");
    }
}

/// `pm audit` must resolve the same path the writer used, including the
/// `$HOME/.local/state` fallback when `XDG_STATE_HOME` is absent.
#[test]
fn audit_reads_the_home_fallback_when_xdg_state_home_is_unset() {
    let state = State::new();
    state.write(&[(1_735_689_600, Some(GRANT_ONE), Outcome::Allowed)]);
    let home = state.directory.path().join("home");
    let fallback = home.join(".local").join("state").join("passmgr");
    fs::create_dir_all(&fallback).expect("fallback dir");
    fs::set_permissions(&fallback, fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let path = fallback.join("audit.jsonl");
    fs::copy(state.path(), &path).expect("copy log");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod file");

    let home_text = home.to_str().expect("UTF-8 home");
    let output = run_with_env(
        &["audit"],
        "",
        &[("HOME", home_text), ("XDG_STATE_HOME", "")],
    );
    assert_success(&output);
    assert!(
        stdout(&output).contains("showing 1 of 1"),
        "{}",
        stdout(&output)
    );
}
