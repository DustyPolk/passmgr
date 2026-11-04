//! Every error message that echoes a value typed on the command line must
//! name its control characters instead of writing them to the terminal.
//!
//! The values below are the argument slots a person or an agent fills in:
//! an `--env` name, a `--ref`, an `--expires` duration, a
//! `--length`, an unknown flag and the `--db` path. An OSC 52 sequence in any
//! of them must reach stderr as `\u{1b}` / `\u{7}`, never as raw bytes that a
//! terminal would execute.
//!
//! The last tests cover a stored service name or username: new ones must not
//! carry a hidden or reordering character (TODO R.48), and a value an earlier
//! build already stored is escaped wherever it is printed.

#![cfg(unix)]

mod cli_support;

use std::path::Path;
use std::process::Output;

use cli_support::{run, stderr, stdout};
use passmgr::crypto::{self, KdfParams};
use tempfile::TempDir;

const ESC: char = '\u{1b}';
const BEL: char = '\u{7}';

/// An OSC 52 clipboard-write sequence, the classic terminal-injection payload.
fn attack() -> String {
    format!("{ESC}]52;c;ZXZpbA=={BEL}")
}

/// A well-formed reference, so the failure under test is the control
/// character and not some earlier complaint about the reference.
const REFERENCE: &str = "pm://00112233445566778899aabbccddeeff";

/// No raw control character survived to either stream, and the escaped form
/// is present — the value was named, not silently dropped.
#[track_caller]
fn assert_escaped(label: &str, output: &Output) {
    let stdout = stdout(output);
    let stderr = stderr(output);
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.contains(ESC),
            "{label}: raw ESC on {stream}: {text:?}"
        );
        assert!(
            !text.contains(BEL),
            "{label}: raw BEL on {stream}: {text:?}"
        );
    }
    assert!(
        stderr.contains(r"\u{1b}") && stderr.contains(r"\u{7}"),
        "{label}: stderr must name both control characters: {stderr:?}"
    );
}

#[test]
fn argument_errors_never_write_control_characters_to_the_terminal() {
    let _guard = cli_support::serial();
    let attack = attack();

    // No '=' in this one: `--env` splits the spec at the first '=', so an
    // `=` inside the name would move the tail into the reference.
    let env_name = format!("API{ESC}[2K{BEL}");
    let bad_flag = format!("--{attack}");
    let bad_expires = format!("10{attack}");
    let bad_length = format!("x{attack}");
    let bad_db = format!("/nonexistent{attack}/vault.dat");

    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        (
            "--env name",
            vec![
                "run".into(),
                "--env".into(),
                format!("{env_name}={REFERENCE}"),
                "--".into(),
                "/bin/true".into(),
            ],
            "",
        ),
        ("unknown flag", vec!["list".into(), bad_flag], ""),
        (
            "--expires",
            vec![
                "grant".into(),
                "create".into(),
                "--expires".into(),
                bad_expires,
            ],
            "",
        ),
        (
            "--length",
            vec!["generate".into(), "--length".into(), bad_length],
            "",
        ),
        (
            "--db",
            vec!["--db".into(), bad_db, "list".into()],
            "master\n",
        ),
    ];

    for (label, args, input) in cases {
        let arguments: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = run(&arguments, input);
        assert!(!output.status.success(), "{label}: expected a failure");
        assert_escaped(label, &output);
    }
}

/// A mistaken `--env` value may be the secret itself (`GH_TOKEN=ghp_...`), so
/// the refusal names the flag and never repeats the value, escaped or not.
#[test]
fn a_literal_env_value_is_never_echoed() {
    let _guard = cli_support::serial();
    let canary = "ghp_canaryEnvLiteral7d41";
    for value in [canary.to_owned(), format!("pm://{}", attack())] {
        let spec = format!("GH_TOKEN={value}");
        let output = run(&["run", "--env", &spec, "--", "/bin/true"], "");
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let (stdout, stderr) = (stdout(&output), stderr(&output));
        assert!(stderr.contains("is not a pm:// reference"), "{stderr:?}");
        for text in [&stdout, &stderr] {
            assert!(!text.contains(canary), "the value was echoed: {text:?}");
            assert!(!text.contains(ESC) && !text.contains(r"\u{1b}"), "{text:?}");
        }
    }
}

/// The `--ref` value is rejected by the reference parser, whose message must
/// escape it at the source as well.
#[test]
fn invalid_reference_escapes_the_value_it_echoes() {
    let _guard = cli_support::serial();
    let reference = format!("{REFERENCE}{}", attack());
    let output = run(&["grant", "create", "--ref", &reference], "");
    assert!(!output.status.success());
    assert_escaped("--ref", &output);
}

/// A path in `--db` is also echoed by the permissions warning, which prints it
/// before any vault is opened.
#[test]
fn insecure_permissions_warning_escapes_the_vault_path() {
    let _guard = cli_support::serial();
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join(format!("vault{}.dat", attack()));
    std::fs::write(&path, b"not a vault").expect("write file");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
        .expect("widen permissions");
    let path = path.to_str().expect("temporary path is UTF-8");

    // `list` warns about the mode, then fails to open the file; both messages
    // must escape the path, whether it reaches the terminal as a warning or
    // inside an error.
    let output = run(&["--db", path, "list"], "master\n");
    assert!(!output.status.success());
    assert_escaped("--db warning", &output);
}

/// A master password long enough for the CLI's own validation. The legacy
/// vault below is written directly, so only the open path sees it.
const LEGACY_MASTER: &str = "legacy-display-test-master";

/// Write a vault the way the release before TODO R.48 could have: store
/// version 4 (no grant list), one entry whose service name and username hold
/// a bidi override and a zero-width space, encrypted with cheap KDF
/// parameters so the test stays fast.
fn write_legacy_vault(path: &Path, service: &str, username: &str) {
    let mut payload = vec![4u8];
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0x22; 16]);
    payload.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    payload.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    for field in [service, username, "not-the-secret"] {
        payload.extend_from_slice(&(field.len() as u32).to_le_bytes());
        payload.extend_from_slice(field.as_bytes());
    }
    payload.extend_from_slice(&0u32.to_le_bytes());

    let container = crypto::encrypt(&payload, LEGACY_MASTER, KdfParams::new(8 * 1024, 1, 1))
        .expect("encrypt legacy vault");
    std::fs::write(path, container).expect("write vault");
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("chmod vault");
}

#[track_caller]
fn assert_success(label: &str, output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{label}: {}", stderr(output));
}

#[track_caller]
fn assert_no_raw_hidden(label: &str, output: &Output) {
    let stdout = stdout(output);
    let stderr = stderr(output);
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        for character in ['\u{202e}', '\u{200b}', '\u{fe0f}'] {
            assert!(
                !text.contains(character),
                "{label}: raw {character:?} on {stream}: {text:?}"
            );
        }
    }
}

/// A name a human will read must not carry a bidi override or a zero-width
/// character, and the refusal happens before any password prompt or vault
/// access (TODO R.48).
#[test]
fn a_hidden_character_in_a_new_name_is_refused_before_any_prompt() {
    let _guard = cli_support::serial();
    let directory = TempDir::new().expect("temp dir");
    let vault_path = directory.path().join("vault.dat");
    let vault = vault_path.to_str().expect("temporary path is UTF-8");

    for name in ["git\u{202e}moc.buh", "ali\u{200b}ce", "heart\u{fe0f}"] {
        for args in [
            vec!["--db", vault, "add", name, "alice"],
            vec!["--db", vault, "add", "example.com", name],
        ] {
            let output = run(&args, "");
            assert_eq!(
                output.status.code(),
                Some(2),
                "{name:?}: {}",
                stderr(&output)
            );
            assert_eq!(stdout(&output), "", "{name:?}");
            let error = stderr(&output);
            assert!(
                !error.to_ascii_lowercase().contains("master password"),
                "{name:?}: refused before any prompt: {error:?}"
            );
            assert_no_raw_hidden("add", &output);
            assert!(!vault_path.exists(), "{name:?}: no vault was created");
        }
    }
}

/// A vault written by an earlier build may already hold a hidden character in
/// a stored name. It must still open, and every human-facing line escapes the
/// value so a bidi override cannot reorder the rest of the terminal line --
/// including the `pm://` reference a human is about to copy into a grant.
#[test]
fn a_legacy_hidden_name_is_escaped_wherever_it_is_printed() {
    let _guard = cli_support::serial();
    let directory = TempDir::new().expect("temp dir");
    let vault_path = directory.path().join("vault.dat");
    let service = "git\u{202e}moc.buh";
    let username = "ali\u{200b}ce";
    write_legacy_vault(&vault_path, service, username);
    let vault = vault_path.to_str().expect("temporary path is UTF-8");
    let input = format!("{LEGACY_MASTER}\n");

    let listed = run(&["--db", vault, "list"], &input);
    assert_success("list", &listed);
    let text = stdout(&listed);
    assert!(text.contains(r"git\u{202e}moc.buh"), "{text:?}");
    assert!(text.contains(r"ali\u{200b}ce"), "{text:?}");
    assert_no_raw_hidden("list", &listed);

    // `get` prints the entry the human typed and its stored metadata.
    let got = run(&["--db", vault, "get", service], &input);
    assert_success("get", &got);
    let text = stdout(&got);
    assert!(text.contains(r"Service: git\u{202e}moc.buh"), "{text:?}");
    assert!(text.contains(r"Username: ali\u{200b}ce"), "{text:?}");
    assert_no_raw_hidden("get", &got);

    // `show` by reference renders the same metadata.
    let reference = format!("pm://{}", "22".repeat(16));
    let shown = run(&["--db", vault, "show", &reference], &input);
    assert_success("show", &shown);
    let text = stdout(&shown);
    assert!(text.contains(r"Service: git\u{202e}moc.buh"), "{text:?}");
    assert!(text.contains(r"Username: ali\u{200b}ce"), "{text:?}");
    assert_no_raw_hidden("show", &shown);
}
