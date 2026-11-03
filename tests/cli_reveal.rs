//! End-to-end tests of the TTY-only reveal path and agent-mode refusals.
//!
//! These are separate from `tests/cli.rs` only because that file grew past the
//! ~1,000-line rule; they share every helper through `tests/cli_support`.

mod cli_support;

use tempfile::TempDir;

use cli_support::*;

/// A reveal must be refused when stdin is a pipe, even with a working vault and
/// the correct master password on that pipe.
#[test]
fn reveal_is_refused_when_stdin_is_piped() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &["--db", &vault, "get", "--reveal", "example.com"],
        "master\n",
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(stdout(&output), "", "refusal must not write to stdout");
    assert!(
        stderr(&output).contains("stdin is not a terminal"),
        "stderr was: {}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));
}

/// Every agent marker refuses a reveal, and the refusal names the marker.
#[test]
fn reveal_is_refused_in_an_agent_context() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    for marker in passmgr::agent::AGENT_MARKERS {
        let output = run_with_env(
            &["--db", &vault, "get", "--reveal", "example.com"],
            "",
            &[(marker, "1")],
        );
        assert_eq!(
            output.status.code(),
            Some(5),
            "marker {marker} must refuse the reveal"
        );
        assert_eq!(stdout(&output), "");
        assert!(
            stderr(&output).contains(marker),
            "stderr for {marker} was: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains(EXAMPLE_SECRET));
    }
}

/// With a terminal on stdin but a pipe on stdout, the reveal is refused: the
/// value would be captured by the pipe.
#[cfg(target_os = "linux")]
#[test]
fn reveal_is_refused_when_stdout_is_piped() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run_on_pty(
        &["--db", &vault, "get", "--reveal", "example.com"],
        "master\n",
        true,
        false,
        &[],
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(output.stdout, "");
    assert!(
        output.stderr.contains("stdout is not a terminal"),
        "stderr was: {}",
        output.stderr
    );
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

/// A human at a terminal can still reveal; the gate is not a blanket refusal.
#[cfg(target_os = "linux")]
#[test]
fn reveal_succeeds_on_a_terminal() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run_on_pty(
        &["--db", &vault, "get", "--reveal", "example.com"],
        "master\n",
        true,
        true,
        &[],
    );
    assert!(
        output.status.success(),
        "reveal on a terminal failed: {}",
        output.stderr
    );
    assert!(
        output
            .stdout
            .contains(&format!("Password: {EXAMPLE_SECRET}")),
        "stdout was: {}",
        output.stdout
    );
}

/// A terminal alone is not enough: an inherited agent marker still refuses.
#[cfg(target_os = "linux")]
#[test]
fn agent_marker_blocks_reveal_even_on_a_terminal() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run_on_pty(
        &["--db", &vault, "get", "--reveal", "example.com"],
        "",
        true,
        true,
        &[("PASSMGR_AGENT", "1")],
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stderr.contains("PASSMGR_AGENT"));
    assert!(!output.stdout.contains(EXAMPLE_SECRET));
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

/// The global `--agent` flag refuses a reveal even when both streams are
/// terminals and the environment is clean: the flag only ever adds refusal.
#[cfg(target_os = "linux")]
#[test]
fn agent_flag_blocks_reveal_even_on_a_terminal() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run_on_pty(
        &["--agent", "--db", &vault, "get", "--reveal", "example.com"],
        "",
        true,
        true,
        &[],
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(
        output.stderr.contains("--agent"),
        "stderr was: {}",
        output.stderr
    );
    assert!(!output.stdout.contains(EXAMPLE_SECRET));
    assert!(!output.stderr.contains(EXAMPLE_SECRET));
}

/// `--agent` also wins over a terminal on stdin with a pipe on stdout, and the
/// refusal is reported before the vault is opened (no prompt is consumed).
#[test]
fn agent_flag_blocks_reveal_over_pipes() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &["--agent", "--db", &vault, "get", "--reveal", "example.com"],
        "master\n",
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("--agent"),
        "stderr was: {}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));
}

/// Agent mode is not a blanket refusal: metadata commands still work.
#[test]
fn agent_flag_still_allows_metadata_commands() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &["--agent", "--db", &vault, "get", "example.com"],
        "master\n",
    );
    assert_success(&output);
    let reference = get_reference(&output);
    assert_canonical_reference(&reference);
    assert_eq!(
        stdout(&output),
        format!("Ref: {reference}\nService: example.com\nUsername: alice\nPassword: <redacted>\n")
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--agent", "--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        format!("Stored Services:\n- example.com (alice) [{reference}]\n")
    );
}

/// `--agent` is a global option: it is documented and rejected after the
/// command rather than silently ignored.
#[test]
fn agent_flag_is_global_and_documented() {
    let _guard = serial();

    let output = run(&["get", "--agent", "example.com"], "");
    assert_eq!(output.status.code(), Some(2), "usage error");
    assert!(stderr(&output).contains("--agent"));

    let output = run(&["--help"], "");
    assert_success(&output);
    assert!(stdout(&output).contains("--agent"));
    assert!(stdout(&output).contains("must come before the command"));
}
