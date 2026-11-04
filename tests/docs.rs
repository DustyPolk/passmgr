//! Documentation contracts.
//!
//! `SECURITY.md` is the canonical list of accepted limits. These tests keep
//! the load-bearing statements from silently disappearing; behavior itself is
//! tested in the other integration suites.

use std::path::Path;

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

/// Body of a `## ` section, normalized with [`plain`]. `None` when the
/// heading is missing, so a renamed section fails its contract instead of
/// turning it vacuous.
fn markdown_section(markdown: &str, heading: &str) -> Option<String> {
    let mut collecting = false;
    let mut body = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("## ") {
            if collecting {
                break;
            }
            if trimmed == heading {
                collecting = true;
                continue;
            }
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

/// TODO R.55: the terminal-safety bullet is the claim a reviewer trusts before
/// pasting a `pm://` reference out of a `list` line. R.48 landed (new names are
/// refused, stored ones escaped), so the universal form is allowed again -- but
/// only if the bullet keeps both halves and the backstop, and only inside the
/// section that makes the promise, so an unrelated sentence elsewhere cannot
/// satisfy it (the failure recorded as TODO R.5). The per-site behavior is
/// proven by `tests/cli_args_escape.rs`; this pins the claim itself.
#[test]
fn security_documents_terminal_safety_for_its_own_output() {
    let protections = markdown_section(SECURITY, "## What passmgr protects")
        .expect("SECURITY.md must keep a What passmgr protects section");
    for phrase in [
        "written as visible \\u{..} escapes",
        "every error line and every argv value the CLI echoes",
        "stored names printed by list, get, show and the grant approval summary",
        "refused at validation",
        "a vault written by an earlier build may hold one",
        "escapes every error line again as a backstop",
        "cannot emit an OSC 52 clipboard write or erase the line it is printed on",
        "--json is a data channel, not a terminal",
    ] {
        assert!(
            protections.contains(phrase),
            "SECURITY.md What passmgr protects must keep the terminal-safety claim: {phrase}"
        );
    }
}

/// TODO R.38: the run's process group is killed when the run ends, but a
/// descendant that starts a new session escapes that cleanup. Both the
/// mitigation and the accepted gap belong in limit 1, next to the
/// `/proc/<pid>/environ` exposure they are about.
#[test]
fn security_documents_post_run_survivors_and_the_setsid_escape() {
    let limit = security_limit(1);
    assert!(
        limit.contains("whole process group is killed when the run ends"),
        "SECURITY.md limit 1 must say the run's group is killed when the run ends"
    );
    assert!(
        limit.contains("does not keep the value after the run, after lock or after pmd exits"),
        "SECURITY.md limit 1 must say a background process does not keep the value"
    );
    assert!(
        limit.contains("setsid") && limit.contains("escapes that cleanup"),
        "SECURITY.md limit 1 must document that a new session escapes the group kill"
    );
    assert!(
        limit.contains("Start long-lived services outside a passmgr run"),
        "SECURITY.md limit 1 must give the reader a way to avoid the gap"
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

/// An allowlisted program that can run another turns a grant into full access
/// to the value, and the name list cannot be complete (TODO R.25). The limit
/// must name the class, keep the `-allow-interpreter` escape hatch, and admit
/// what the list can and cannot do.
#[test]
fn security_documents_program_runner_exfiltration() {
    let limit = security_limit(2);
    assert!(
        limit.contains("argv[0]"),
        "SECURITY.md limit 2 must explain that only argv[0] is checked"
    );
    for name in [
        "gh",
        "git",
        "find -exec",
        "tar --to-command",
        "ssh",
        "docker",
    ] {
        assert!(
            limit.contains(name),
            "SECURITY.md limit 2 must name {name} as a runner"
        );
    }
    assert!(
        limit.contains("--allow-interpreter"),
        "SECURITY.md limit 2 must document the human override"
    );
    assert!(
        limit.contains("equivalent to handing the agent the secret"),
        "SECURITY.md limit 2 must state the consequence of allowing a runner"
    );
    assert!(
        limit.contains("best-effort, not a boundary"),
        "SECURITY.md limit 2 must say the name table is not a boundary"
    );
    assert!(
        limit.contains("allowlisting a program is trusting it with the value"),
        "SECURITY.md limit 2 must state the residual trust decision"
    );
}

/// `gh` is a program runner too (`gh alias set --shell`), so the grant example
/// in the README may not allow it without the flag, and `--help` must describe
/// the flag as covering more than shells and interpreters (TODO R.25).
#[test]
fn documented_grant_example_flags_a_program_runner() {
    let example = fenced_block_after(README, "### Create a grant")
        .expect("README.md must keep a grant create example");
    assert!(
        example.contains("--command /usr/bin/gh"),
        "the README example is expected to allow gh: {example}"
    );
    assert!(
        example.contains("--allow-interpreter"),
        "a grant example that allows a runner must pass --allow-interpreter: {example}"
    );

    let help = plain(&help_text());
    assert!(
        help.contains("or program runner in the") && help.contains("'grant create' refuses one"),
        "--help must say that the flag covers program runners"
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

/// TODO R.44: a same-user process can put an older `vault.dat` back, and that
/// copy opens with the daemon's key. The limit must name the in-memory mark,
/// its lifetime, and the restart residual, so a later edit cannot quietly
/// turn "revocation always holds" back into a promise the file cannot keep.
#[test]
fn security_documents_the_vault_rollback_limit() {
    let limit = security_limit(7);
    assert!(
        limit.contains("older copy"),
        "SECURITY.md limit 7 must say an older vault copy can be put back"
    );
    assert!(
        limit.contains("in memory") && limit.contains("for its own lifetime"),
        "SECURITY.md limit 7 must say the mark is in memory and lasts one daemon"
    );
    assert!(
        limit.contains("with denied"),
        "SECURITY.md limit 7 must say a regressed run is denied"
    );
    assert!(
        limit.contains("not") && limit.contains("persisted"),
        "SECURITY.md limit 7 must say the mark is deliberately not persisted"
    );
    assert!(
        limit.contains("restart") && limit.contains("empty mark"),
        "SECURITY.md limit 7 must give the restart residual"
    );
    assert!(
        limit.contains("kill switch keeps working"),
        "SECURITY.md limit 7 must say revocation still works after a rollback"
    );
}

/// TODO R.32: the "Current status" section described the pre-3.6 state, so a
/// reviewer could treat `run` as session-token gated (the hole 3.6 closed)
/// and expect an audit log that does not exist yet. Pin the implemented flow
/// to the section that makes the claim, not to the whole document.
#[test]
fn security_current_status_matches_the_implemented_grant_flow() {
    let status = markdown_section(SECURITY, "## Current status")
        .expect("SECURITY.md must keep a Current status section");
    assert!(
        !status.contains("not implemented yet"),
        "SECURITY.md Current status must not say grant authorization is unimplemented"
    );
    assert!(
        !status.contains("authorized by the session token"),
        "SECURITY.md Current status must not say run is authorized by the session token"
    );
    for request in passmgr::protocol::REQUEST_WIRE_NAMES {
        if *request == "run" {
            // `run` is listed separately: it needs a grant token, not just
            // the session token.
            continue;
        }
        assert!(
            status.contains(request),
            "SECURITY.md Current status must list {request} as authorized by the session token"
        );
    }
    assert!(
        status.contains("requires a human-created grant token"),
        "SECURITY.md Current status must say run needs a grant token"
    );
    assert!(
        status.contains("audit log") && status.contains("TODO 3.8"),
        "SECURITY.md Current status must say run is audited (TODO 3.8)"
    );
    assert!(
        !status.contains("no audit record is written today"),
        "SECURITY.md Current status must not say no audit record is written"
    );
    assert!(
        status.contains("TODO 3.9") && status.contains("pm audit verify"),
        "SECURITY.md Current status must say pm audit verify is still TODO 3.9"
    );
}

/// Body of a `## ` section, line for line rather than flattened by [`plain`],
/// for contracts that need Markdown structure such as a table.
fn markdown_section_lines<'a>(markdown: &'a str, heading: &str) -> Option<Vec<&'a str>> {
    let mut collecting = false;
    let mut body = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("## ") {
            if collecting {
                break;
            }
            if trimmed == heading {
                collecting = true;
                continue;
            }
        }
        if collecting && !trimmed.is_empty() {
            body.push(trimmed);
        }
    }
    if body.is_empty() { None } else { Some(body) }
}

/// TODO R.51: the README exit-code table is the contract scripts and agents
/// read. Every code the library can return must be documented (plus 0 and
/// 141, which `main` produces without an `Error`), and the two rows the R.51
/// review found incomplete must name the conditions that actually cause them.
/// Deriving the table instead of matching prose keeps a new code or a changed
/// mapping from silently drifting out of the docs.
#[test]
fn readme_exit_code_table_covers_every_error_code() {
    let mut codes = std::collections::BTreeMap::new();
    for line in
        markdown_section_lines(README, "## Exit codes").expect("README must keep Exit codes")
    {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() != 2 {
            continue;
        }
        if let Ok(code) = cells[0].parse::<u16>() {
            codes.insert(code, plain(cells[1]));
        }
    }
    assert_eq!(
        codes.keys().copied().collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5, 6, 141],
        "the README table must document exactly the stable codes"
    );

    use passmgr::error::Error;
    let grant_id = passmgr::grant::GrantId::from_hex("00112233445566778899aabbccddeeff")
        .expect("fixed grant id");
    let errors = [
        Error::Io(std::io::Error::other("x")),
        Error::VaultNotFound(std::path::PathBuf::from("v.dat")),
        Error::NotAVault,
        Error::LegacyVault,
        Error::UnsupportedVersion(9),
        Error::UnsupportedFormat("x".into()),
        Error::MalformedVault("x".into()),
        Error::Crypto("x".into()),
        Error::AuthenticationFailed,
        Error::Refused("no".into()),
        Error::DuplicateService("svc".into()),
        Error::ServiceNotFound("svc".into()),
        Error::EntryNotFound("pm://00".into()),
        Error::GrantNotFound(grant_id),
        Error::ReadOnlyVault(std::path::PathBuf::from("v.dat")),
        Error::VaultBusy(std::path::PathBuf::from("v.dat")),
        Error::VaultChanged(std::path::PathBuf::from("v.dat")),
        Error::Daemon("x".into()),
        Error::InvalidInput("x".into()),
    ];
    for error in &errors {
        let code = u16::from(error.exit_code());
        assert!(
            codes.contains_key(&code),
            "README must document exit code {code} ({error:?})"
        );
    }

    let not_found = &codes[&3];
    assert!(
        not_found.contains("reference") && not_found.contains("grant id"),
        "README exit code 3 must name an unknown reference and an unknown grant id"
    );
    let refused = &codes[&5];
    for condition in [
        "run without a usable grant",
        "grant file",
        "environment variable",
        "creating a grant in agent mode",
    ] {
        assert!(
            refused.contains(condition),
            "README exit code 5 must mention {condition}"
        );
    }
}

/// TODO R.51: the protocol module doc is what a client author reads first.
/// Derive the request types from [`passmgr::protocol::REQUEST_WIRE_NAMES`] so a
/// new `Request` variant cannot be implemented without a line here.
#[test]
fn protocol_module_doc_lists_every_request_type() {
    let doc: String = include_str!("../src/protocol/mod.rs")
        .lines()
        .take_while(|line| line.starts_with("//!") || line.is_empty())
        .map(|line| line.trim_start_matches("//!"))
        .collect::<Vec<_>>()
        .join(" ");
    let doc = plain(&doc);
    for name in passmgr::protocol::REQUEST_WIRE_NAMES {
        assert!(
            doc.contains(name),
            "src/protocol/mod.rs module doc must name the {name} request"
        );
    }
}

/// TODO R.32: `DECISIONS.md` said the CLI could not create a grant after
/// TODO 3.4d landed, which invites reimplementing the write path (or trusting
/// the daemon with it). The decision must name the CLI as the writer.
#[test]
fn decisions_says_the_cli_creates_grants_and_the_daemon_does_not() {
    let text = plain(DECISIONS);
    assert!(
        text.contains("pm grant create (TODO 3.4d) creates grants in the human's CLI"),
        "DECISIONS.md must say the CLI creates grants"
    );
    assert!(
        !text.contains("The CLI still cannot create a grant"),
        "DECISIONS.md must not say the CLI cannot create a grant"
    );
}

/// TODO R.32: `MCP.md` described a claim exchange in which the daemon hands
/// the grant token over. It never has the token: the approving CLI stores
/// only its SHA-256. An MCP implementation that follows the old sentence
/// would call a request that cannot exist, so pin token ownership.
#[test]
fn mcp_says_the_daemon_never_holds_a_grant_token() {
    let text = plain(MCP);
    assert!(
        text.contains("the daemon never holds a grant token"),
        "MCP.md must say the daemon never holds a grant token"
    );
    assert!(
        text.contains("sent to the daemon only as its SHA-256"),
        "MCP.md must say only the token hash reaches the daemon"
    );
    assert!(
        text.contains("request_claim never returns a token"),
        "MCP.md must say request_claim cannot hand a token back"
    );
    assert!(
        !text.contains("daemon hands the grant token over"),
        "MCP.md must not say the daemon hands a grant token over"
    );
}

/// TODO R.32: the grant token reader accepts 0400 as well as 0600 (and any
/// mode without group/world bits), but the README and `MCP.md` promised a
/// 0600 file, so an operator could think a stricter file is refused.
#[test]
fn docs_agree_on_the_accepted_grant_token_file_modes() {
    for (name, text) in [("README.md", plain(README)), ("MCP.md", plain(MCP))] {
        assert!(
            text.contains("0600 or 0400"),
            "{name} must say a grant token file may be 0600 or 0400"
        );
        assert!(
            !text.contains("must be in a 0600 file"),
            "{name} must not claim only a 0600 token file is accepted"
        );
    }
}

/// The session token is not an agent boundary: `run` needs a grant token too.
/// Keep the disclosure pinned so a future change cannot quietly drop it.
#[test]
fn security_keeps_the_session_token_and_grant_separation() {
    let text = plain(SECURITY);
    assert!(
        text.contains("requires a human-created grant token"),
        "SECURITY.md must disclose that run needs a grant token"
    );
    assert!(
        text.contains("can never inject a secret by itself"),
        "SECURITY.md must state that the session token alone cannot use a secret"
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

/// The pre-spend check can only apply the expiry rules, because the daemon
/// never opens the vault for `grant_create`. It once claimed an approval was
/// "never spent on a request no write could accept", which a full vault
/// falsified (TODO R.22). The documents must name the owner of the vault-level
/// check and when it runs, and the code comments must not promise more.
#[test]
fn docs_say_who_checks_vault_limits_before_the_proof() {
    let mcp = plain(MCP).to_lowercase();
    assert!(
        mcp.contains("the daemon cannot see the vault's limits, because it never opens the vault for this request"),
        "MCP.md must say why the daemon cannot check vault-level limits"
    );
    assert!(
        mcp.contains("before it asks for a proof, so a full vault cannot consume an approval"),
        "MCP.md must say the CLI checks a full vault before the proof"
    );

    let decisions = plain(DECISIONS);
    assert!(
        decisions.contains("Vault::check_grant_writable"),
        "DECISIONS.md must name the pre-check the CLI runs"
    );

    // The code comments describe the same rule, not an absolute guarantee.
    const REQUEST_SRC: &str = include_str!("../src/grant/request.rs");
    const DAEMON_SRC: &str = include_str!("../src/daemon.rs");
    for (name, source) in [
        ("src/grant/request.rs", REQUEST_SRC),
        ("src/daemon.rs", DAEMON_SRC),
    ] {
        assert!(
            !source.to_lowercase().contains("no write could accept"),
            "{name} must not claim the pre-spend check covers vault-level limits"
        );
    }
    assert!(
        REQUEST_SRC.contains("check_grant_writable") && REQUEST_SRC.contains("expiry rule alone"),
        "check_approvable's doc must say it covers the expiry rule only"
    );
}

/// Every fenced block in a Markdown document, with the fence lines stripped.
/// Blocks are returned separately so a check cannot borrow a `--command` from
/// one example to satisfy another.
fn fenced_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            match current.take() {
                Some(block) => blocks.push(block.join("\n")),
                None => current = Some(Vec::new()),
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push(line);
        }
    }
    blocks
}

/// Join shell continuation lines (`\` at end of line) so a multi-line
/// `grant create` is one logical command.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let continued = trimmed.ends_with('\\');
        let part = trimmed.strip_suffix('\\').unwrap_or(trimmed).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(part);
        if !continued && !current.trim().is_empty() {
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        lines.push(current);
    }
    lines
}

/// The text between `start` and the next `end`, used to isolate `--help`'s
/// examples from its notes.
fn section_between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let after = &text[text.find(start)? + start.len()..];
    Some(&after[..after.find(end)?])
}

/// Check every `grant create` line in `text` and return how many grant lines
/// were seen. A `--command` that names a program runner must be accompanied by
/// `--allow-interpreter`, because `grant create` refuses it otherwise.
fn check_grant_examples(name: &str, text: &str) -> usize {
    let mut grant_lines = 0;
    for line in logical_lines(text) {
        if !line.contains("grant create") {
            continue;
        }
        grant_lines += 1;
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut index = 0;
        while index < tokens.len() {
            let path = if tokens[index] == "--command" {
                index += 1;
                tokens.get(index).copied()
            } else {
                tokens[index].strip_prefix("--command=")
            };
            if let Some(path) = path {
                if passmgr::grant::is_program_runner(Path::new(path)) {
                    assert!(
                        line.contains("--allow-interpreter"),
                        "{name}: a grant example allows the program runner {path} \
                         without --allow-interpreter: {line}"
                    );
                }
            }
            index += 1;
        }
    }
    grant_lines
}

/// TODO R.43: the README's quickstart allowed `/usr/bin/gh` without
/// `--allow-interpreter`, so the first command a reader copied exited 5. Every
/// `grant create` example in the README and in `--help` must flag a program
/// runner, not just the one under "### Create a grant" (which R.25 fixed).
#[test]
fn every_documented_grant_example_flags_a_program_runner() {
    let mut readme_grants = 0;
    for block in fenced_blocks(README) {
        readme_grants += check_grant_examples("README.md", &block);
    }
    assert!(
        readme_grants >= 2,
        "README.md must keep both its grant create examples, found {readme_grants}"
    );

    let help = help_text();
    let examples = section_between(&help, "Examples:", "Notes:")
        .expect("--help must keep an Examples section");
    assert!(
        check_grant_examples("--help", examples) >= 1,
        "--help must keep its grant create example"
    );
}

/// First fenced block of any language after the line containing `marker`, with
/// the fence lines stripped. `None` when either is missing, so deleting the
/// example fails its contract instead of turning the contract vacuous.
fn fenced_block_after(markdown: &str, marker: &str) -> Option<String> {
    let mut lines = markdown.lines().skip_while(|line| !line.contains(marker));
    lines
        .by_ref()
        .find(|line| line.trim_start().starts_with("```"))?;
    let mut block = Vec::new();
    for line in lines {
        if line.trim_start().starts_with("```") {
            return Some(block.join("\n"));
        }
        block.push(line.trim_end().to_owned());
    }
    None
}

/// First fenced ```json block after the line containing `marker`, with the
/// fence lines stripped. `None` when either is missing, so deleting the
/// example fails its contract instead of turning the contract vacuous.
fn fenced_json_after(markdown: &str, marker: &str) -> Option<String> {
    let mut lines = markdown.lines().skip_while(|line| !line.contains(marker));
    lines
        .by_ref()
        .find(|line| line.trim_start().starts_with("```json"))?;
    let mut block = Vec::new();
    for line in lines {
        if line.trim_start().starts_with("```") {
            return Some(block.join("\n"));
        }
        block.push(line.trim().to_owned());
    }
    None
}

fn object_keys(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("expected a JSON object, got {value}"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// TODO R.24: `grant_create` has a flat wire shape, but TODO.md's spec line
/// nested its fields under a `request` key, the implementation and its Done
/// note were flat, and MCP.md described the fields in prose without naming a
/// single key. MCP.md now carries the one concrete body, so its keys must be
/// the encoder's keys. A nested `request` shape, an added key or a new value
/// fails here before a client is written from it.
#[test]
fn mcp_grant_create_example_has_the_encoder_keys() {
    let example = fenced_json_after(MCP, "The daemon never writes a grant")
        .expect("MCP.md must carry the grant_create frame example");
    let example: serde_json::Value =
        serde_json::from_str(&example).expect("the MCP.md example must be JSON");

    let token = passmgr::token::SessionToken::from_hex(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .expect("example session token");
    let scope = passmgr::grant::Scope::new(
        Vec::new(),
        vec!["prod".to_owned()],
        Some(vec!["password".to_owned()]),
    )
    .expect("scope");
    let request = passmgr::grant::GrantRequest::new(
        passmgr::grant::GrantSpec {
            label: "deploy prod".to_owned(),
            scope,
            commands: vec!["/usr/bin/gh".into()],
            capabilities: passmgr::grant::Capabilities::RUN,
            expires_at: 1_700_003_600,
            max_uses: Some(2),
        },
        passmgr::grant::TokenHash::of(b"grant-token"),
    )
    .expect("grant request");
    let frame = passmgr::protocol::encode(
        &token,
        &passmgr::protocol::Request::GrantCreate(
            passmgr::protocol::GrantCreateRequest::from_grant_request(&request),
        ),
    )
    .expect("encode");
    let encoded: serde_json::Value =
        serde_json::from_slice(&frame[4..]).expect("encoded body is JSON");

    assert_eq!(
        object_keys(&example),
        object_keys(&encoded),
        "MCP.md's example envelope must have the encoder's keys"
    );
    assert_eq!(
        object_keys(&example["request"]),
        object_keys(&encoded["request"]),
        "MCP.md's example request must have the encoder's keys (flat, not nested)"
    );
    assert_eq!(
        example, encoded,
        "MCP.md's example must be the encoder's body; fix the example, not the decoder"
    );
}
