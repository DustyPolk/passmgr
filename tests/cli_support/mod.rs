//! Shared helpers for the CLI end-to-end tests.
//!
//! Both `tests/cli.rs` and `tests/cli_reveal.rs` include this module, so each
//! binary uses a different subset of it. The PTY helper is Linux-only because
//! it uses `posix_openpt` directly instead of an external helper binary.

#![allow(dead_code)] // each integration-test binary uses a different subset

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Argon2 uses 64 MiB per unlock; run CLI tests one at a time to keep memory
/// use predictable.
static SERIAL: Mutex<()> = Mutex::new(());

pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn run(args: &[&str], input: &str) -> Output {
    run_with_env(args, input, &[])
}

/// Build a command with every agent marker removed, so the environment of the
/// test harness itself cannot change the outcome.
pub fn base_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_passmgr"));
    command.args(args);
    for marker in passmgr::agent::AGENT_MARKERS {
        command.env_remove(marker);
    }
    command
}

pub fn run_with_env(args: &[&str], input: &str, envs: &[(&str, &str)]) -> Output {
    let mut command = base_command(args);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("failed to start passmgr");
    script_stdin(&mut child, input);
    child
        .wait_with_output()
        .expect("failed to wait for passmgr")
}

/// Write the scripted input to a piped child and close it.
///
/// A child may legitimately exit before reading any input: several tests drive
/// a refusal that happens before the first prompt (`--agent`, a non-TTY
/// reveal, an agent-context `grant create`). The kernel then answers `EPIPE` on
/// our write. That is a property of the test's setup, not a failure — the
/// outcome is asserted from the child's output — and panicking made the test
/// depend on whether the write or the exit won the race. Any other write error
/// is still a harness bug.
fn script_stdin(child: &mut Child, input: &str) {
    let mut stdin = child.stdin.take().expect("stdin was piped");
    if let Err(error) = stdin.write_all(input.as_bytes()) {
        assert_eq!(
            error.kind(),
            io::ErrorKind::BrokenPipe,
            "failed to write stdin: {error}"
        );
    }
}

/// Read a stored password straight from the vault, bypassing the CLI. Used to
/// check what was stored without going through the TTY-gated reveal path.
pub fn vault_password(vault: &str, service: &str, master: &str) -> String {
    let vault = passmgr::Vault::open(vault, master).expect("vault opens");
    vault
        .get(service)
        .expect("credential exists")
        .password()
        .to_owned()
}

pub fn vault_path(directory: &TempDir) -> String {
    directory
        .path()
        .join("vault.dat")
        .to_str()
        .expect("temporary path is valid UTF-8")
        .to_owned()
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Extract the `pm://...` reference from `passmgr get` output.
pub fn get_reference(output: &Output) -> String {
    stdout(output)
        .lines()
        .find_map(|line| line.strip_prefix("Ref: "))
        .expect("get output must contain a Ref line")
        .to_owned()
}

/// References are `pm://` followed by 32 lowercase hex characters (16 bytes).
pub fn assert_canonical_reference(reference: &str) {
    let hex = reference
        .strip_prefix("pm://")
        .unwrap_or_else(|| panic!("reference '{reference}' must start with pm://"));
    assert_eq!(hex.len(), 32, "reference '{reference}' must carry 16 bytes");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "reference '{reference}' must use lowercase hex"
    );
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

pub const EXAMPLE_SECRET: &str = "s3cret-value-should-never-leak";

pub fn add_example(vault: &str) {
    let input = format!("master\nmaster\n{EXAMPLE_SECRET}\n{EXAMPLE_SECRET}\n");
    let output = run(&["--db", vault, "add", "example.com", "alice"], &input);
    assert_success(&output);
    assert!(stderr(&output).contains("Credential added successfully."));
}

/// Wait until the child's stderr (redirected to `stderr_path`) contains
/// `needle`, polling with a deadline so a regression fails instead of hanging.
/// Kills the child on timeout so a failing test leaves no process behind.
pub fn wait_for_prompt(
    child: &mut Child,
    stderr_path: &Path,
    needle: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let text = fs::read_to_string(stderr_path).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out after {timeout:?} waiting for {needle:?}; stderr so far:\n{text}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Run the CLI with a pseudo-terminal on the requested standard streams.
///
/// The pty is created with `posix_openpt`, so no external helper binary is
/// needed. `stdin_is_tty` and `stdout_is_tty` select which streams get the pty
/// slave; the others stay pipes so we can read them directly. This is how the
/// TTY gate is tested without an interactive terminal.
#[cfg(target_os = "linux")]
pub struct PtyOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(target_os = "linux")]
pub fn run_on_pty(
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
        script_stdin(&mut child, input);
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
pub fn read_pty(master: &mut std::fs::File) -> String {
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
