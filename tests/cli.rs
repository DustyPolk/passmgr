//! End-to-end tests of the command-line interface.

use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

use tempfile::TempDir;

/// Argon2 uses 64 MiB per unlock; run CLI tests one at a time to keep memory
/// use predictable.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_passmgr"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start passmgr");
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write stdin");
    }
    child
        .wait_with_output()
        .expect("failed to wait for passmgr")
}

fn vault_path(directory: &TempDir) -> String {
    directory
        .path()
        .join("vault.dat")
        .to_str()
        .expect("temporary path is valid UTF-8")
        .to_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn add_example(vault: &str) {
    let output = run(
        &["--db", vault, "add", "example.com", "alice"],
        "master\nmaster\nsecret\nsecret\n",
    );
    assert_success(&output);
    assert!(stderr(&output).contains("Credential added successfully."));
}

#[test]
fn add_get_list_and_delete() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);

    add_example(&vault);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault must be created owner-only");
    }

    let output = run(&["--db", &vault, "get", "example.com"], "master\n");
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        "Service: example.com\nUsername: alice\nPassword: secret\n"
    );

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "Stored Services:\n- example.com (alice)\n");

    let output = run(&["--db", &vault, "delete", "example.com"], "master\n");
    assert_success(&output);
    assert!(stderr(&output).contains("Credential deleted successfully."));

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("No credentials stored."));
}

#[test]
fn generated_add_then_get_returns_same_password() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);

    let output = run(
        &[
            "--db",
            &vault,
            "add",
            "--generate",
            "--simple",
            "--length",
            "12",
            "svc",
            "user",
        ],
        "master\nmaster\n",
    );
    assert_success(&output);
    let generated = stdout(&output)
        .strip_prefix("Generated password: ")
        .expect("generated password line")
        .trim()
        .to_owned();
    assert_eq!(generated.len(), 12);
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));

    let output = run(&["--db", &vault, "get", "svc"], "master\n");
    assert_success(&output);
    assert!(stdout(&output).contains(&format!("Password: {generated}\n")));
}

#[test]
fn wrong_master_password_fails() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "get", "example.com"], "wrong\n");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("wrong master password or corrupted vault"));
}

#[test]
fn duplicate_service_is_rejected() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &["--db", &vault, "add", "example.com", "someone-else"],
        "master\n",
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("already exists"));
}

#[test]
fn missing_vault_is_reported() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no vault found"));
}

#[test]
fn legacy_c_vault_is_rejected() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    let mut legacy = Vec::from(*b"PMGR");
    legacy.push(1);
    legacy.extend_from_slice(&[0u8; 60]);
    fs::write(&vault, legacy).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("legacy C format"));
}

#[cfg(unix)]
#[test]
fn insecure_permissions_are_warned_about() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert!(stderr(&output).contains("permissions 0644"));
    assert!(stderr(&output).contains("chmod 600"));
}
