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
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
