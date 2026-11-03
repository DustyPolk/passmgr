//! Documentation contracts.
//!
//! `SECURITY.md` is the canonical list of accepted limits. These tests keep
//! the load-bearing statements from silently disappearing; behavior itself is
//! tested in the other integration suites.

const SECURITY: &str = include_str!("../SECURITY.md");
const README: &str = include_str!("../README.md");
const MCP: &str = include_str!("../MCP.md");
const FORMAT: &str = include_str!("../FORMAT.md");
const DECISIONS: &str = include_str!("../DECISIONS.md");

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

/// Body of one numbered `### N.` subsection, normalized with [`plain`].
///
/// A global `contains` check can be satisfied by an unrelated sentence
/// elsewhere in the document (the failure recorded as TODO R.5), so limit
/// contracts must be scoped to the limit that carries them. Returns `None`
/// when the subsection does not exist.
fn markdown_limit(markdown: &str, number: u8) -> Option<String> {
    let marker = format!("### {number}.");
    let mut collecting = false;
    let mut body = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(marker.as_str())
            && trimmed.as_bytes().get(marker.len()) == Some(&b' ')
        {
            collecting = true;
            body.push(trimmed);
            continue;
        }
        if collecting && (trimmed.starts_with("## ") || trimmed.starts_with("### ")) {
            break;
        }
        if collecting {
            body.push(trimmed);
        }
    }
    if body.is_empty() {
        return None;
    }
    Some(plain(&body.join("\n")))
}

/// `markdown_limit` for `SECURITY.md`; missing section is a hard failure so
/// deleting a limit cannot turn its contract into a vacuous pass.
fn security_limit(number: u8) -> String {
    markdown_limit(SECURITY, number).unwrap_or_else(|| panic!("SECURITY.md has no limit {number}"))
}

/// The `/proc/<pid>/environ` limit is not optional: every injection path that
/// puts a value in a child's environment must disclose it, in limit 1 itself.
/// The old test accepted `same user` from `SECURITY.md:16` (the session-file
/// sentence), so rewording the accepted limit stayed green (TODO R.5).
#[test]
fn security_documents_the_proc_environ_limit() {
    let limit = security_limit(1);
    assert!(
        limit.contains("any process running as the same user can read /proc/<pid>/environ"),
        "SECURITY.md limit 1 must say that any same-user process can read it"
    );
    assert!(
        limit.contains("it does not apply to the child, which is a separate process"),
        "SECURITY.md limit 1 must say that pmd hardening does not cover the child"
    );
    assert!(
        limit.contains("does not defend against malware already running as you"),
        "SECURITY.md limit 1 must keep the consequence for a hostile same-user process"
    );
}

/// Regression for TODO R.5: the disclosure phrase is only accepted from
/// limit 1, never from another section of the same document.
#[test]
fn limit_contracts_reject_the_phrase_from_another_section() {
    let doc = "Intro. Any process running as the same user can read \
               /proc/<pid>/environ.\n\n\
               ### 1. A same-user process can read an injected value from \
               /proc\n\nThe child receives the value in its environment.\n\n\
               ### 2. Next\n\nUnrelated.\n";
    let limit = markdown_limit(doc, 1).expect("synthetic limit 1");
    assert!(!limit.contains("any process running as the same user can read /proc/<pid>/environ"));
    assert!(limit.contains("The child receives the value in its environment."));
    assert!(
        markdown_limit(doc, 2)
            .expect("synthetic limit 2")
            .contains("Unrelated.")
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
        security_limit(3).contains("It is not a sandbox."),
        "SECURITY.md limit 3 must state that redaction is not a sandbox"
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

/// TODO R.18: `FORMAT.md` and `DECISIONS.md` described fewer character
/// classes than `is_hidden_or_reordering` rejects, and the error message
/// named fewer still. The rejection error now names
/// `LABEL_FORBIDDEN_CLASSES`, so pinning both documents to the same constant
/// keeps the class list from drifting in either direction. Behavior (which
/// code points are refused) is tested in `tests/grant.rs`.
#[test]
fn docs_name_every_forbidden_label_character_class() {
    let classes = passmgr::grant::LABEL_FORBIDDEN_CLASSES;
    for (name, markdown) in [("FORMAT.md", FORMAT), ("DECISIONS.md", DECISIONS)] {
        assert!(
            plain(markdown).contains(classes),
            "{name} must list the forbidden label classes as \"{classes}\""
        );
    }
    assert!(
        plain(DECISIONS).contains("VS15/VS16"),
        "DECISIONS.md must record that the emoji-presentation selectors are refused"
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
        security_limit(3).contains("follow encodings or transformations"),
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

/// `MCP.md` promised encoded-secret redaction that the daemon does not do
/// (TODO R.10). It must state the exact-bytes limit that ships today and defer
/// encodings to TODO 4.6, or the MCP contract lies about a security property.
#[test]
fn mcp_documents_the_exact_bytes_redaction_limit() {
    let text = plain(MCP).to_lowercase();
    assert!(
        text.contains("exact, contiguous byte sequence"),
        "MCP.md must say redaction covers only exact contiguous secret bytes"
    );
    assert!(
        text.contains("not redacted yet") && text.contains("todo 4.6"),
        "MCP.md must defer encoded-copy redaction to TODO 4.6"
    );
    assert!(
        !text.contains("best-effort encodings"),
        "MCP.md must not promise encoded redaction before TODO 4.6"
    );
}

/// The allowlist check must happen in `pmd`, because the MCP server is
/// untrusted plumbing. `MCP.md` once said the rules were "enforced by the
/// daemon" and then left `command[0]` resolution to the MCP server (TODO R.10).
#[test]
fn mcp_says_the_daemon_checks_the_canonical_command_path() {
    let text = plain(MCP);
    assert!(
        text.contains("the daemon canonicalizes it itself"),
        "MCP.md must say the daemon canonicalizes command[0] itself"
    );
    assert!(
        text.contains("checks that canonical path against the allowlist"),
        "MCP.md must say the daemon checks the canonical path against the allowlist"
    );
    assert!(
        !text.contains("the MCP server does the resolving"),
        "MCP.md must not leave command[0] resolution to the untrusted MCP server"
    );
}
