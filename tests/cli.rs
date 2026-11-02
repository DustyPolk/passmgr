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
    run_with_env(args, input, &[])
}

/// Build a command with every agent marker removed, so the environment of the
/// test harness itself cannot change the outcome.
fn base_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_passmgr"));
    command.args(args);
    for marker in passmgr::agent::AGENT_MARKERS {
        command.env_remove(marker);
    }
    command
}

fn run_with_env(args: &[&str], input: &str, envs: &[(&str, &str)]) -> Output {
    let mut command = base_command(args);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("failed to start passmgr");
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

/// Read a stored password straight from the vault, bypassing the CLI. Used to
/// check what was stored without going through the TTY-gated reveal path.
fn vault_password(vault: &str, service: &str, master: &str) -> String {
    let vault = passmgr::Vault::open(vault, master).expect("vault opens");
    vault
        .get(service)
        .expect("credential exists")
        .password()
        .to_owned()
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

const EXAMPLE_SECRET: &str = "s3cret-value-should-never-leak";

fn add_example(vault: &str) {
    let input = format!("master\nmaster\n{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n");
    let output = run(&["--db", vault, "add", "example.com", "alice"], &input);
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
        "Service: example.com\nUsername: alice\nPassword: <redacted>\n"
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

/// Run the CLI with a pseudo-terminal on the requested standard streams.
///
/// The pty is created with `posix_openpt`, so no external helper binary is
/// needed. `stdin_is_tty` and `stdout_is_tty` select which streams get the pty
/// slave; the others stay pipes so we can read them directly. This is how the
/// TTY gate is tested without an interactive terminal.
#[cfg(target_os = "linux")]
struct PtyOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

#[cfg(target_os = "linux")]
fn run_on_pty(
    args: &[&str],
    input: &str,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    envs: &[(&str, &str)],
) -> PtyOutput {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    // SAFETY: the returned descriptors are valid and each is owned by exactly
    // one `File` afterwards.
    let (mut master, slave) = unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(
            master >= 0,
            "posix_openpt failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname failed");
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
        assert!(
            slave >= 0,
            "opening the pty slave failed: {}",
            std::io::Error::last_os_error()
        );
        (File::from_raw_fd(master), File::from_raw_fd(slave))
    };

    let mut command = base_command(args);
    for (name, value) in envs {
        command.env(name, value);
    }
    if stdin_is_tty {
        command.stdin(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    } else {
        command.stdin(Stdio::piped());
    }
    if stdout_is_tty {
        command.stdout(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    } else {
        command.stdout(Stdio::piped());
    }
    command.stderr(Stdio::piped());

    let mut child = command.spawn().expect("failed to start passmgr");
    // The child holds the only remaining slave reference; close ours so reads
    // on the master see end-of-file once the child exits.
    drop(slave);

    if stdin_is_tty {
        master
            .write_all(input.as_bytes())
            .expect("failed to write to the pty");
    } else {
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(input.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for passmgr");
    let stdout_text = if stdout_is_tty {
        read_pty(&mut master)
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    PtyOutput {
        status: output.status,
        stdout: stdout_text,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Drain a pty master after the child exited. Linux reports EIO once the last
/// slave is closed; macOS reports EOF.
#[cfg(target_os = "linux")]
fn read_pty(master: &mut std::fs::File) -> String {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    // SAFETY: `master` is an open file descriptor owned by this function.
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0, "fcntl F_GETFL failed");
        assert!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0,
            "fcntl F_SETFL failed"
        );
    }

    let mut collected = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => collected.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => panic!("reading the pty failed: {error}"),
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
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
    assert_eq!(
        stdout(&output),
        "Service: example.com\nUsername: alice\nPassword: <redacted>\n"
    );
    assert!(!stdout(&output).contains(EXAMPLE_SECRET));
    assert!(!stderr(&output).contains(EXAMPLE_SECRET));

    let output = run(&["--agent", "--db", &vault, "list"], "master\n");
    assert_success(&output);
    assert_eq!(stdout(&output), "Stored Services:\n- example.com (alice)\n");
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
