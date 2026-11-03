//! Every error message that echoes a value typed on the command line must
//! name its control characters instead of writing them to the terminal.
//!
//! The values below are the argument slots a person or an agent fills in:
//! an `--env` name and reference, a `--ref`, an `--expires` duration, a
//! `--length`, an unknown flag and the `--db` path. An OSC 52 sequence in any
//! of them must reach stderr as `\u{1b}` / `\u{7}`, never as raw bytes that a
//! terminal would execute.

#![cfg(unix)]

mod cli_support;

use std::process::Output;

use cli_support::{run, stderr, stdout};
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
    let env_reference = format!("API=pm://{attack}");
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
        (
            "--env reference",
            vec![
                "run".into(),
                "--env".into(),
                env_reference,
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
