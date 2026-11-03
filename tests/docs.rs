//! Documentation contracts.
//!
//! `SECURITY.md` is the canonical list of accepted limits. These tests keep
//! the load-bearing statements from silently disappearing; behavior itself is
//! tested in the other integration suites.

const SECURITY: &str = include_str!("../SECURITY.md");
const README: &str = include_str!("../README.md");

/// Collapse Markdown emphasis and line wrapping so a sentence can be matched
/// regardless of how it is formatted in the source.
fn plain(markdown: &str) -> String {
    markdown
        .replace("**", "")
        .replace('`', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `--help` as an agent would read it (stdout of the real binary).
fn help_text() -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_passmgr"))
        .arg("--help")
        .output()
        .expect("run passmgr --help");
    assert!(output.status.success(), "--help must exit 0");
    String::from_utf8(output.stdout).expect("--help must be UTF-8")
}

/// The `/proc/<pid>/environ` limit is not optional: every injection path that
/// puts a value in a child's environment must disclose it.
#[test]
fn security_documents_the_proc_environ_limit() {
    assert!(
        SECURITY.contains("/proc/<pid>/environ"),
        "SECURITY.md must name /proc/<pid>/environ"
    );
    assert!(
        SECURITY.contains("same user"),
        "SECURITY.md must say that any same-user process can read it"
    );
}

/// An allowlisted interpreter turns a grant into full access to the value.
#[test]
fn security_documents_interpreter_exfiltration() {
    assert!(
        SECURITY.contains("--allow-interpreter"),
        "SECURITY.md must document the interpreter allowlist rule"
    );
    assert!(
        SECURITY.contains("equivalent to handing the agent the secret"),
        "SECURITY.md must state the consequence of an interpreter grant"
    );
}

/// Redaction is output-only; claiming more would be a security lie.
#[test]
fn security_documents_that_redaction_is_not_a_sandbox() {
    assert!(
        plain(SECURITY).contains("It is not a sandbox."),
        "SECURITY.md must state that redaction is not a sandbox"
    );
}

/// Until TODO 3.6 lands, the session token is not an agent boundary. The
/// disclosure must stay until grants replace it; updating this test is part of
/// that change, not a way to silence it.
#[test]
fn security_discloses_the_transitional_session_token_gap() {
    assert!(
        plain(SECURITY).contains("is not an agent/human boundary"),
        "SECURITY.md must disclose the transitional session-token gap"
    );
    assert!(
        SECURITY.contains("TODO 3.6"),
        "SECURITY.md must name the TODO that closes the gap"
    );
}

/// The README's security section must point at the detailed limits.
#[test]
fn readme_points_at_security_md() {
    assert!(
        README.contains("SECURITY.md"),
        "README.md must link to SECURITY.md"
    );
}

/// `run` injects from the daemon's vault and refuses an explicit `--db` or
/// `PASSMGR_DB` before connecting (TODO R.4). An agent that believes the flag
/// selected a vault would be wrong, so both documents must say so.
#[test]
fn docs_say_run_refuses_an_explicit_vault() {
    let documents = [
        ("README.md", plain(README)),
        ("--help", plain(&help_text())),
    ];
    for (name, text) in documents {
        assert!(
            text.contains("refuses --db and PASSMGR_DB"),
            "{name} must say that run refuses --db and PASSMGR_DB"
        );
        assert!(
            text.contains("the vault the running daemon was unlocked with")
                || text.contains("the one the running daemon was unlocked with"),
            "{name} must say which vault run uses"
        );
    }
}

/// Redaction replaces only an exact, contiguous occurrence of the value; it
/// does not follow encodings (TODO 4.6). README and `--help` once promised
/// "common encodings" and thereby overstated the guarantee, so this contract
/// pins all three documents to the same limit. When 4.6 lands, update the
/// documents and this test together, and keep
/// `redaction_replaces_only_the_exact_secret_not_its_encodings` in
/// `tests/run.rs` honest.
#[test]
fn docs_agree_that_redaction_does_not_follow_encodings() {
    assert!(
        plain(SECURITY).contains("follow encodings or transformations"),
        "SECURITY.md limit 3 must keep the encoding/transformation limit"
    );

    let documents = [
        ("README.md", plain(README)),
        ("--help", plain(&help_text())),
    ];
    for (name, text) in documents {
        let text = text.to_lowercase();
        assert!(
            text.contains("exact, contiguous occurrence of the secret"),
            "{name} must say that only an exact occurrence is redacted"
        );
        assert!(
            text.contains("encoded or transformed copies"),
            "{name} must state that encoded copies are not redacted"
        );
        assert!(
            !text.contains("common encodings"),
            "{name} must not claim that common encodings are redacted"
        );
    }
}
