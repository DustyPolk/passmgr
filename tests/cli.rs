//! End-to-end tests of the command-line interface.

mod cli_support;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;

use cli_support::*;

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
    let reference = get_reference(&output);
    assert_canonical_reference(&reference);
    assert_eq!(
        stdout(&output),
        format!("Ref: {reference}\nService: example.com\nUsername: alice\nPassword: <redacted>\n")
    );
    assert!(
        !stdout(&output).contains(EXAMPLE_SECRET) && !stderr(&output).contains(EXAMPLE_SECRET),
        "plain get must never print the stored password"
    );

    let output = run(
        &["--db", &vault, "get", "--reveal", "example.com"],
        "master\n",
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "reveal over a pipe is refused"
    );
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("refusing"));
    assert!(
        !stdout(&output).contains(EXAMPLE_SECRET) && !stderr(&output).contains(EXAMPLE_SECRET),
        "a refused reveal must never print the stored password"
    );
    assert_eq!(
        vault_password(&vault, "example.com", "master"),
        EXAMPLE_SECRET,
        "the credential itself is stored intact"
    );

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        format!("Stored Services:\n- example.com (alice) [{reference}]\n")
    );

    let output = run(&["--db", &vault, "delete", "example.com"], "master\n");
    assert_success(&output);
    assert!(stderr(&output).contains("Credential deleted successfully."));

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("No credentials stored."));
}

/// Tags are metadata: they can be attached, listed, filtered on, and
/// replaced without rotating the password, and they never expose a secret.
#[test]
fn tags_are_stored_filtered_and_metadata_only() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);

    const OTHER_SECRET: &str = "other-s3cret-value-should-never-leak";
    let output = run(
        &[
            "--db",
            &vault,
            "add",
            "--tag",
            "work",
            "--tag=prod",
            "work.example",
            "alice",
        ],
        &format!("master\nmaster\n{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n"),
    );
    assert_success(&output);
    let output = run(
        &[
            "--db",
            &vault,
            "add",
            "--tag",
            "home",
            "home.example",
            "bob",
        ],
        &format!("master\n{OTHER_SECRET}\n{OTHER_SECRET}\n"),
    );
    assert_success(&output);

    let output = run(&["--db", &vault, "list", "--json"], "master\n");
    assert_success(&output);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let entry_for = |service: &str| {
        entries
            .iter()
            .find(|entry| entry["service"] == serde_json::json!(service))
            .expect("entry present")
    };
    assert_eq!(
        entry_for("work.example")["tags"],
        serde_json::json!(["prod", "work"]),
        "tags are sorted metadata"
    );
    assert_eq!(
        entry_for("home.example")["tags"],
        serde_json::json!(["home"])
    );
    for entry in entries {
        assert!(entry.get("password").is_none());
        assert!(entry["created"].as_str().is_some());
        assert!(entry["last_rotated"].as_str().is_some());
    }
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stdout(&output).contains(OTHER_SECRET));

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    let work_ref = get_reference(&run(&["--db", &vault, "get", "work.example"], "master\n"));
    let home_ref = get_reference(&run(&["--db", &vault, "get", "home.example"], "master\n"));
    let listing = stdout(&output);
    assert!(listing.contains(&format!(
        "- work.example (alice) [{work_ref}]\n  tags: prod, work\n"
    )));
    assert!(listing.contains(&format!(
        "- home.example (bob) [{home_ref}]\n  tags: home\n"
    )));
    assert!(!listing.contains(EXAMPLE_SECRET) && !listing.contains(OTHER_SECRET));

    let output = run(&["--db", &vault, "list", "--tag", "prod"], "master\n");
    assert_success(&output);
    assert!(stdout(&output).contains("work.example"));
    assert!(!stdout(&output).contains("home.example"));

    let output = run(
        &["--db", &vault, "list", "--tag", "prod", "--tag", "home"],
        "master\n",
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("No credentials match tags: home, prod."));

    // A metadata-only tag edit does not ask for a new password.
    let output = run(
        &["--db", &vault, "edit", "--tag", "prod", "work.example"],
        "master\n",
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert_eq!(
        vault_password(&vault, "work.example", "master"),
        EXAMPLE_SECRET
    );
    let output = run(&["--db", &vault, "list", "--tag", "prod"], "master\n");
    assert_success(&output);
    let listing = stdout(&output);
    assert!(
        listing.contains("  tags: prod\n"),
        "tags were replaced: {listing}"
    );
    assert!(!listing.contains("prod, work"));

    let output = run(
        &["--db", &vault, "edit", "--clear-tags", "home.example"],
        "master\n",
    );
    assert_success(&output);
    let output = run(&["--db", &vault, "get", "home.example"], "master\n");
    assert_success(&output);
    assert!(!stdout(&output).contains("Tags:"));

    let output = run(&["--db", &vault, "get", "work.example"], "master\n");
    assert_success(&output);
    assert!(stdout(&output).contains("Tags: prod\n"));

    let output = run(
        &["--db", &vault, "add", "--tag", "Prod", "bad.example", "eve"],
        "master\n",
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid tags fail at parse time"
    );
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("invalid tag"));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));
}

/// Entry references are stable across processes and metadata edits, and
/// printing them never exposes the stored password.
#[test]
fn entry_references_are_stable_and_leak_no_secrets() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "get", "example.com"], "master\n");
    assert_success(&output);
    let first = get_reference(&output);
    assert_canonical_reference(&first);

    // A separate process must report the same reference.
    let output = run(&["--db", &vault, "get", "example.com"], "master\n");
    assert_success(&output);
    assert_eq!(get_reference(&output), first);

    // Renaming and changing the username must not change the id.
    let output = run(
        &[
            "--db",
            &vault,
            "edit",
            "example.com",
            "--rename",
            "renamed.example",
            "--username",
            "bob",
        ],
        "master\n",
    );
    assert_success(&output);
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--db", &vault, "get", "renamed.example"], "master\n");
    assert_success(&output);
    assert_eq!(get_reference(&output), first);

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        format!("Stored Services:\n- renamed.example (bob) [{first}]\n")
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));
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

    // Read the stored value in-process: the CLI must never print it.
    let generated = vault_password(&vault, "svc", "master");
    assert_eq!(generated.len(), 12);
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));

    assert_eq!(
        stdout(&output),
        "",
        "add --generate must not print the generated password to stdout"
    );
    assert!(
        !stdout(&output).contains(&generated) && !stderr(&output).contains(&generated),
        "the generated password must never appear on stdout or stderr"
    );
    assert!(
        stderr(&output).contains("svc"),
        "the confirmation names the entry"
    );

    let output = run(&["--db", &vault, "get", "svc"], "master\n");
    assert_success(&output);
    assert!(
        !stdout(&output).contains(&generated) && !stderr(&output).contains(&generated),
        "plain get must not print a generated password"
    );

    assert_eq!(
        vault_password(&vault, "svc", "master"),
        generated,
        "the generated password is stored unchanged"
    );
}

#[test]
fn wrong_master_password_fails() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "get", "example.com"], "wrong\n");
    assert_eq!(
        output.status.code(),
        Some(4),
        "wrong password is an auth error"
    );
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

/// `add` must collect the master password and the credential secret before it
/// takes the write lock, so a human sitting at a prompt cannot block a scripted
/// writer (TODO R.9). The sidecar lock file must not even exist yet.
#[test]
fn add_prompts_for_the_secret_before_creating_the_write_lock() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    let stderr_path = directory.path().join("add-stderr.txt");
    let stderr_file = fs::File::create(&stderr_path).unwrap();

    let mut child = base_command(&["--db", &vault, "add", "example.com", "alice"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("failed to start passmgr add");
    let mut stdin = child.stdin.take().expect("stdin was piped");
    // Master password and its confirmation for a new vault.
    stdin.write_all(b"master\nmaster\n").unwrap();

    let lock_path = passmgr::vault::lock_path(Path::new(&vault));
    wait_for_prompt(
        &mut child,
        &stderr_path,
        "Enter password for example.com:",
        Duration::from_secs(10),
    );
    assert!(
        !lock_path.exists(),
        "the write lock file must not exist while the credential is prompted"
    );
    assert!(
        !Path::new(&vault).exists(),
        "nothing may be written before the secret is collected"
    );

    stdin
        .write_all(format!("{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n").as_bytes())
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().expect("failed to wait for add");
    assert_success(&output);
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert_eq!(
        vault_password(&vault, "example.com", "master"),
        EXAMPLE_SECRET
    );
    assert!(
        lock_path.exists(),
        "the lock file is created when the lock is finally taken"
    );
}

/// `edit` must prompt for the replacement secret before it waits for the write
/// lock. Here the lock is held by the test: at the unfixed HEAD the command
/// blocks for the whole 30 s lock timeout without ever prompting (TODO R.9).
#[test]
fn edit_prompts_for_the_secret_before_waiting_for_the_write_lock() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let lock_path = passmgr::vault::lock_path(Path::new(&vault));
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .expect("the lock file exists after add");
    // SAFETY: `lock_file` owns a valid descriptor for the whole call.
    assert_eq!(
        unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) },
        0,
        "failed to hold the vault write lock"
    );

    let stderr_path = directory.path().join("edit-stderr.txt");
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let mut child = base_command(&["--db", &vault, "edit", "example.com"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("failed to start passmgr edit");
    let mut stdin = child.stdin.take().expect("stdin was piped");
    stdin.write_all(b"master\n").unwrap();

    wait_for_prompt(
        &mut child,
        &stderr_path,
        "Enter password for example.com:",
        Duration::from_secs(10),
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "edit must wait at the prompt, not exit with a lock error"
    );

    // Release the lock only now: the secret was collected without holding it.
    drop(lock_file);

    const NEW_SECRET: &str = "rotated-before-the-lock-was-taken";
    stdin
        .write_all(format!("{NEW_SECRET}\n{NEW_SECRET}\n").as_bytes())
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().expect("failed to wait for edit");
    assert_success(&output);
    assert!(
        !stdout(&output).contains(NEW_SECRET) && !stderr(&output).contains(NEW_SECRET),
        "the replacement secret must never be printed"
    );
    assert_eq!(vault_password(&vault, "example.com", "master"), NEW_SECRET);
}

#[test]
fn missing_vault_is_reported() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_eq!(output.status.code(), Some(3), "missing vault is not found");
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
    assert_eq!(
        output.status.code(),
        Some(6),
        "a legacy vault is an unreadable format"
    );
    assert!(stderr(&output).contains("legacy C format"));
}

/// Exit codes are part of the CLI contract: 0 success, 2 usage/invalid input,
/// 3 not found, 4 auth failed, 5 refused, 6 malformed vault. Agents and
/// scripts rely on these, so every class is exercised here.
#[test]
fn exit_codes_are_stable() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    // 3: the vault exists but the credential does not.
    let output = run(&["--db", &vault, "get", "missing.example"], "master\n");
    assert_eq!(output.status.code(), Some(3), "unknown service");
    assert!(stderr(&output).contains("no credential found"));

    // 4: wrong master password.
    let output = run(&["--db", &vault, "list"], "wrong\n");
    assert_eq!(output.status.code(), Some(4), "wrong master password");

    // 6: a truncated vault file must be reported as malformed, not as a
    // crash and not as a generic failure.
    let bytes = fs::read(&vault).unwrap();
    let truncated = directory.path().join("truncated.dat");
    fs::write(&truncated, &bytes[..bytes.len() - 1]).unwrap();
    let output = run(&["--db", truncated.to_str().unwrap(), "list"], "master\n");
    assert_eq!(output.status.code(), Some(6), "truncated vault");
    assert!(stderr(&output).contains("malformed vault"));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    // 6: a file that is not a vault at all.
    let garbage = directory.path().join("garbage.dat");
    fs::write(&garbage, b"this is not a vault").unwrap();
    let output = run(&["--db", garbage.to_str().unwrap(), "list"], "master\n");
    assert_eq!(output.status.code(), Some(6), "not a vault");
    assert!(stderr(&output).contains("not a passmgr vault"));

    // 2: an empty master password is invalid input, not an auth failure.
    let output = run(&["--db", &vault, "list"], "\n");
    assert_eq!(output.status.code(), Some(2), "empty master password");
    assert!(stderr(&output).contains("master password cannot be empty"));

    // 2: a usage error.
    let output = run(&["--bogus"], "");
    assert_eq!(output.status.code(), Some(2), "unknown global option");

    // 0: success, and the help text documents the contract.
    let output = run(&["--help"], "");
    assert_success(&output);
    let help = stdout(&output);
    for code in [
        "0 success",
        "2 usage",
        "3 not found",
        "4 wrong master password",
        "5 refused",
        "6 malformed",
    ] {
        assert!(
            help.contains(code),
            "--help must document exit codes; missing {code:?}"
        );
    }
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

/// `--help` is a stable contract that docs and agents quote. The golden file
/// was captured from the binary before the `src/cli/` split (TODO H.2), so
/// this test proves the refactor did not change a single byte of output.
#[test]
fn help_output_matches_the_golden_file() {
    let output = run(&["--help"], "");
    assert_success(&output);
    assert_eq!(stdout(&output), include_str!("fixtures/help.txt"));
}

/// Editing without metadata flags rotates the password. The new value is
/// prompted twice, stored, and never written to stdout or stderr.
#[test]
fn edit_rotates_the_password_without_printing_it() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let (created_before, rotated_before) = {
        let opened = passmgr::Vault::open(&vault, "master").expect("vault opens");
        let credential = opened.get("example.com").expect("credential exists");
        (credential.created_unix(), credential.last_rotated_unix())
    };
    assert!(
        created_before > 0,
        "a new credential records a creation time"
    );

    const NEW_SECRET: &str = "rotated-s3cret-should-never-leak";
    let output = run(
        &["--db", &vault, "edit", "example.com"],
        &format!("master\n{NEW_SECRET}\n{NEW_SECRET}\n"),
    );
    assert_success(&output);

    assert_eq!(
        stdout(&output),
        "",
        "edit must not write command data to stdout"
    );
    assert!(
        !stdout(&output).contains(NEW_SECRET) && !stderr(&output).contains(NEW_SECRET),
        "the new password must never appear on stdout or stderr"
    );
    assert!(
        !stdout(&output).contains(EXAMPLE_SECRET) && !stderr(&output).contains(EXAMPLE_SECRET),
        "the old password must never appear on stdout or stderr"
    );
    assert!(stderr(&output).contains("example.com"));

    assert_eq!(vault_password(&vault, "example.com", "master"), NEW_SECRET);

    let vault = passmgr::Vault::open(&vault, "master").expect("vault opens");
    let credential = vault.get("example.com").expect("credential exists");
    assert_eq!(credential.username(), "alice", "username is unchanged");
    assert_eq!(
        credential.created_unix(),
        created_before,
        "rotation must preserve the creation time"
    );
    assert!(
        credential.last_rotated_unix() >= rotated_before,
        "rotation must record a rotation time"
    );
}

/// `edit --rename --username` is a metadata-only change: it must not prompt
/// for a credential password, and no secret may be printed.
#[test]
fn edit_renames_and_updates_the_username() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &[
            "--db",
            &vault,
            "edit",
            "example.com",
            "--rename",
            "new.example",
            "--username",
            "bob",
        ],
        "master\n",
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    let reference = {
        let opened = passmgr::Vault::open(&vault, "master").expect("vault opens");
        opened
            .get("new.example")
            .expect("renamed credential")
            .reference()
    };
    assert_canonical_reference(&reference);
    assert_eq!(
        stdout(&output),
        format!("Stored Services:\n- new.example (bob) [{reference}]\n")
    );

    let output = run(&["--db", &vault, "get", "example.com"], "master\n");
    assert_eq!(output.status.code(), Some(3), "the old name is gone");

    let opened = passmgr::Vault::open(&vault, "master").expect("vault opens");
    let credential = opened.get("new.example").expect("renamed credential");
    assert_eq!(credential.username(), "bob");
    assert_eq!(credential.password(), EXAMPLE_SECRET);
}

/// `edit --generate` stores a fresh password and only confirms by entry name.
#[test]
fn edit_generates_a_password_without_printing_it() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(
        &[
            "--db",
            &vault,
            "edit",
            "example.com",
            "--generate",
            "--pin",
            "--length",
            "8",
        ],
        "master\n",
    );
    assert_success(&output);

    let generated = vault_password(&vault, "example.com", "master");
    assert_eq!(generated.len(), 8);
    assert!(generated.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(generated, EXAMPLE_SECRET);
    assert_eq!(stdout(&output), "");
    assert!(
        !stdout(&output).contains(&generated) && !stderr(&output).contains(&generated),
        "a generated replacement must never be printed"
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET) && !stderr(&output).contains(EXAMPLE_SECRET));
    assert!(stderr(&output).contains("generated password"));
}

/// An unknown service is a not-found error and must be detected before the
/// replacement password is prompted for.
#[test]
fn edit_unknown_service_is_not_found() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "edit", "missing.example"], "master\n");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("no credential found"));
    assert!(
        !stderr(&output).contains("Enter password for"),
        "the new password must not be prompted before the entry is found"
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    // The existing credential is untouched.
    assert_eq!(
        vault_password(&vault, "example.com", "master"),
        EXAMPLE_SECRET
    );
}

/// `rm` is a pure alias: same behavior, same messages, same exit codes.
#[test]
fn rm_is_an_alias_for_delete() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "rm", "example.com"], "master\n");
    assert_success(&output);
    assert!(stderr(&output).contains("Credential deleted successfully."));

    let output = run(&["--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("No credentials stored."));

    let output = run(&["--db", &vault, "rm", "missing.example"], "master\n");
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("no credential found"));
}

/// `show` resolves a `pm://` reference and `list --json`/`show --json` emit
/// references and metadata only. No output may contain the stored password.
#[test]
fn show_and_list_json_expose_metadata_only() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    let output = run(&["--db", &vault, "get", "example.com"], "master\n");
    assert_success(&output);
    let reference = get_reference(&output);
    assert_canonical_reference(&reference);

    // Text mode shows the same metadata as `get`, but never a password field.
    let output = run(&["--db", &vault, "show", &reference], "master\n");
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        format!("Ref: {reference}\nService: example.com\nUsername: alice\n")
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    // The reference lookup survives a rename; tags are metadata-only here, so
    // the timestamps below stay as `add` wrote them.
    let output = run(
        &[
            "--db",
            &vault,
            "edit",
            "example.com",
            "--rename",
            "renamed.example",
            "--tag",
            "prod",
            "--tag",
            "work",
        ],
        "master\n",
    );
    assert_success(&output);
    let output = run(&["--db", &vault, "show", &reference], "master\n");
    assert_success(&output);
    assert!(stdout(&output).contains("Service: renamed.example"));

    // JSON mode: the flag may appear before or after the reference.
    let output = run(&["--db", &vault, "show", "--json", &reference], "master\n");
    assert_success(&output);
    let shown: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(shown["ref"], serde_json::json!(reference));
    assert_eq!(shown["service"], serde_json::json!("renamed.example"));
    assert_eq!(shown["username"], serde_json::json!("alice"));
    assert_eq!(shown["tags"], serde_json::json!(["prod", "work"]));
    assert!(shown.get("password").is_none());

    // Timestamps are RFC 3339 UTC strings. `add` sets both, and the rename/tag
    // edit above must not rotate the password.
    let created = shown["created"].as_str().expect("created is a string");
    let last_rotated = shown["last_rotated"]
        .as_str()
        .expect("last_rotated is a string");
    assert_eq!(created.len(), 20, "unexpected timestamp shape: {created}");
    assert!(created.ends_with('Z'), "timestamps are UTC: {created}");
    assert_eq!(created, last_rotated, "metadata edits must not rotate");
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--db", &vault, "show", &reference, "--json"], "master\n");
    assert_success(&output);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stdout(&output)).unwrap(),
        shown
    );

    let output = run(&["--db", &vault, "list", "--json"], "master\n");
    assert_success(&output);
    assert!(!stderr(&output).contains("No credentials stored"));
    let listed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(listed["entries"], serde_json::json!([shown]));
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--help"], "");
    assert_success(&output);
    assert!(stdout(&output).contains("list [--json]"));
    assert!(stdout(&output).contains("show [--json] <ref>"));
}

/// Metadata that needs JSON escaping round-trips exactly; the encoder must not
/// be able to produce a document that hides a field or leaks a value.
#[test]
fn json_output_escapes_metadata() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    // The vault already exists, so only the master password, then the new
    // credential password and its confirmation are prompted for.
    let service = "quote\"back\\slash\u{00e9}";
    let input = format!("master\n{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n");
    let output = run(&["--db", &vault, "add", service, "bob"], &input);
    assert_success(&output);

    let output = run(&["--db", &vault, "list", "--json"], "master\n");
    assert_success(&output);
    let listed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let entries = listed["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| entry["service"] == serde_json::json!(service))
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));
}

/// Bad and unknown references are rejected without unlocking or printing data.
#[test]
fn show_rejects_bad_and_unknown_references() {
    let _guard = serial();
    let directory = TempDir::new().unwrap();
    let vault = vault_path(&directory);
    add_example(&vault);

    // Malformed reference: usage error, and no master-password prompt.
    for bad in [
        "pm://abc",
        "pm://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "example.com",
    ] {
        let output = run(&["--db", &vault, "show", bad], "");
        assert_eq!(
            output.status.code(),
            Some(2),
            "'{bad}' must be a usage error"
        );
        assert_eq!(stdout(&output), "");
        assert!(!stderr(&output).contains("Enter Master Password"));
        assert!(!stdout(&output).contains(EXAMPLE_SECRET));
        assert!(!stderr(&output).contains(EXAMPLE_SECRET));
    }

    // A well-formed reference that matches nothing: not found.
    let missing = "pm://ffffffffffffffffffffffffffffffff";
    let output = run(&["--db", &vault, "show", missing], "master\n");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("no credential found for reference"));
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--db", &vault, "show", "--json", missing], "master\n");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stdout(&output), "");

    // An empty vault still produces a valid, empty JSON document.
    let empty = TempDir::new().unwrap();
    let empty_vault = vault_path(&empty);
    let output = run(
        &["--db", &empty_vault, "add", "example.com", "alice"],
        &format!("master\nmaster\n{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n"),
    );
    assert_success(&output);
    let output = run(&["--db", &empty_vault, "delete", "example.com"], "master\n");
    assert_success(&output);
    let output = run(&["--db", &empty_vault, "list", "--json"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "{\"entries\":[]}\n");
    assert!(
        !stderr(&output).contains("No credentials stored"),
        "JSON mode must not mix prose into the document"
    );
}
