//! `run`: use a credential through the unlock daemon.
//!
//! This is the agent-facing way to *use* a secret. The CLI sends a reference
//! and an argv to `pmd`; the daemon decrypts, injects and redacts. No secret
//! value is read, printed or stored by this process, and the isolated output
//! that is relayed has already been redacted on the daemon side.

use passmgr::Error;

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::ExitCode;

#[cfg(unix)]
use passmgr::client::{self, RunOutcome};
#[cfg(unix)]
use passmgr::protocol::{ResponseError, RunExit, RunFrame, RunRequest};
#[cfg(unix)]
use passmgr::runner;
#[cfg(unix)]
use passmgr::socket::SocketError;

#[cfg(not(unix))]
pub(crate) const DAEMON_UNSUPPORTED: &str = "the unlock daemon is supported on Unix systems only";

/// `passmgr run --env NAME=<ref> -- <command>`.
///
/// Returns the child's status as this process's exit code. Every refusal is a
/// stable-code [`Error`]; the parsing path already rejected malformed specs
/// with a usage error (exit 2) before this function was reached.
#[cfg(unix)]
pub(crate) fn command_run(options: super::RunOptions) -> Result<ExitCode, Error> {
    // The daemon checks this too (it must not trust a client), but refusing
    // here avoids a connection and gives the better message. Exit 5 is the
    // documented "refused for safety" code, like `get --reveal` without a TTY.
    if runner::denied_env_name(&options.env) {
        return Err(Error::Refused(format!(
            "refusing to inject into '{}': that variable could change how the child runs",
            options.env
        )));
    }

    // Resolve the program and the working directory here, not in the daemon.
    // The daemon's cwd and PATH belong to the shell that ran `unlock`; using
    // them would silently run a different file than the caller named.
    let cwd = std::env::current_dir().map_err(Error::Io)?;
    let cwd_text = cwd
        .to_str()
        .ok_or_else(|| Error::InvalidInput("the current directory is not valid UTF-8".into()))?
        .to_owned();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let program = resolve_program(&options.command[0], &cwd, &path_var)?;
    let program_text = program
        .to_str()
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "the resolved command path is not valid UTF-8: {}",
                program.display()
            ))
        })?
        .to_owned();
    let mut command = options.command;
    command[0] = program_text;

    let paths = passmgr::socket::RuntimePaths::resolve();
    let token = match passmgr::session::load(&paths) {
        Ok(token) => token,
        Err(error) => {
            // Distinguish "nothing is running" from "a daemon is running but
            // this client cannot authenticate" (a stale or unreadable token).
            return match passmgr::socket::connect_at(&paths) {
                Ok(_) => Err(Error::Daemon(format!(
                    "cannot authenticate to the unlock daemon: {error}; \
                     run 'passmgr lock' and 'passmgr unlock' again"
                ))),
                Err(SocketError::NotRunning) => Err(no_daemon()),
                Err(error) => Err(Error::Daemon(error.to_string())),
            };
        }
    };

    let request = RunRequest {
        env: options.env,
        reference: options.reference.clone(),
        command,
        cwd: cwd_text,
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let outcome = client::run(&paths, &token, &request, |frame| match frame {
        RunFrame::Stdout(bytes) => {
            out.write_all(bytes)?;
            out.flush()?;
            Ok(())
        }
        RunFrame::Stderr(bytes) => {
            err.write_all(bytes)?;
            err.flush()?;
            Ok(())
        }
        // `client::run` returns terminal frames instead of relaying them.
        other => Err(Error::Daemon(format!(
            "unexpected frame in a run stream: {other:?}"
        ))),
    })?;
    // Release the locks before returning to the dispatch loop.
    drop(out);
    drop(err);

    match outcome {
        RunOutcome::Exited(exit) => Ok(ExitCode::from(status_code(exit))),
        RunOutcome::Refused(error) => Err(refusal(error, &options.reference)),
    }
}

#[cfg(not(unix))]
pub(crate) fn command_run(options: super::RunOptions) -> Result<std::process::ExitCode, Error> {
    let _ = options;
    Err(Error::Daemon(DAEMON_UNSUPPORTED))
}

#[cfg(unix)]
fn no_daemon() -> Error {
    Error::Daemon("no passmgr daemon is running; start one with 'passmgr unlock'".into())
}

/// Resolve `program` to an absolute path using `cwd` and `path_var`.
///
/// * An absolute path is used as given (a missing file is reported by the
///   daemon as a spawn failure, which is the honest error).
/// * A path with a separator is relative to `cwd`.
/// * A bare name is searched in `path_var`, in order, skipping empty entries
///   (POSIX says an empty entry means the current directory; searching there
///   would make the result depend on the caller's cwd in a surprising way).
///
/// Only a regular file with at least one execute bit counts, so a directory or
/// a non-executable file earlier on `PATH` does not shadow the real program.
#[cfg(unix)]
fn resolve_program(program: &str, cwd: &Path, path_var: &OsStr) -> Result<PathBuf, Error> {
    let candidate = Path::new(program);
    if candidate.is_absolute() {
        return Ok(candidate.to_path_buf());
    }
    if program.contains('/') {
        let joined = cwd.join(candidate);
        if is_executable_file(&joined) {
            return Ok(absolute(&joined));
        }
        return Err(program_not_found(program));
    }
    for directory in std::env::split_paths(path_var) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let joined = directory.join(candidate);
        if is_executable_file(&joined) {
            return Ok(absolute(&joined));
        }
    }
    Err(program_not_found(program))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Lexically make `path` absolute without resolving symlinks, so the program
/// the daemon spawns is the one this process found and `argv[0]` keeps the
/// name the caller used.
#[cfg(unix)]
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(unix)]
fn program_not_found(program: &str) -> Error {
    Error::InvalidInput(format!(
        "cannot find the command '{program}': use an absolute path or put it on PATH"
    ))
}

/// The shell-visible status for a finished child.
///
/// A normal exit passes through unchanged. A child killed by signal `N`
/// becomes `128 + N`, the usual shell convention; the daemon keeps the two
/// cases distinct on the wire, and this is the only place they are flattened.
#[cfg(unix)]
fn status_code(exit: RunExit) -> u8 {
    match exit {
        RunExit::Code(code) => code,
        RunExit::Signal(signal) => 128u8.saturating_add(signal),
    }
}

/// Map a terminal daemon error to a stable error and exit code.
#[cfg(unix)]
fn refusal(error: ResponseError, reference: &str) -> Error {
    match error {
        // The reference is metadata, never a secret.
        ResponseError::NotFound => Error::EntryNotFound(reference.to_owned()),
        ResponseError::SpawnFailed => {
            Error::Daemon("the unlock daemon could not start the command".into())
        }
        ResponseError::BadRequest => {
            Error::Daemon("the unlock daemon rejected the run request (bad_request)".into())
        }
        ResponseError::Unsupported => Error::Daemon(
            "the unlock daemon does not support run requests; \
             run 'passmgr lock' and 'passmgr unlock' again"
                .into(),
        ),
        ResponseError::Unauthorized => Error::Daemon(
            "the unlock daemon rejected the session token; \
             run 'passmgr lock' and 'passmgr unlock' again"
                .into(),
        ),
        ResponseError::Internal => {
            Error::Daemon("the unlock daemon could not read its vault (internal)".into())
        }
        ResponseError::Busy => Error::Daemon(
            "the unlock daemon is already running the maximum number of commands; \
             wait for one to finish and try again (busy)"
                .into(),
        ),
        // `denied` can only be the answer to a `prove` request; a run is
        // never refused that way. Keep the message truthful anyway.
        ResponseError::Denied => {
            Error::Refused("the unlock daemon refused the request (denied)".into())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn make_exe(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write fake program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("set mode");
        path
    }

    #[test]
    fn a_bare_name_is_resolved_through_the_callers_path_in_order() {
        let first = tempfile::tempdir().expect("tempdir");
        let second = tempfile::tempdir().expect("tempdir");
        let expected = make_exe(first.path(), "passmgr-fake-tool", 0o755);
        let shadowed = make_exe(second.path(), "passmgr-fake-tool", 0o755);
        let path_var = std::env::join_paths([first.path(), second.path()]).expect("join PATH");

        let resolved =
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve");
        assert_eq!(resolved, absolute(&expected));
        assert_ne!(resolved, absolute(&shadowed));
    }

    #[test]
    fn a_non_executable_or_directory_entry_does_not_shadow_the_program() {
        let broken = tempfile::tempdir().expect("tempdir");
        let working = tempfile::tempdir().expect("tempdir");
        let not_executable = make_exe(broken.path(), "passmgr-fake-tool", 0o644);
        std::fs::create_dir(broken.path().join("passmgr-fake-dir")).expect("mkdir");
        let expected = make_exe(working.path(), "passmgr-fake-tool", 0o755);
        let path_var = std::env::join_paths([broken.path(), working.path()]).expect("join PATH");

        assert!(resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).is_ok());
        assert_ne!(
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve"),
            absolute(&not_executable)
        );
        assert_eq!(
            resolve_program("passmgr-fake-tool", Path::new("/"), &path_var).expect("resolve"),
            absolute(&expected)
        );
        // A directory named like the program is not a program either.
        assert!(resolve_program("passmgr-fake-dir", Path::new("/"), &path_var).is_err());
    }

    #[test]
    fn a_path_with_a_separator_is_relative_to_the_callers_cwd() {
        let cwd = tempfile::tempdir().expect("tempdir");
        let expected = make_exe(cwd.path(), "rel-tool", 0o755);

        assert_eq!(
            resolve_program("./rel-tool", cwd.path(), OsStr::new("")).expect("resolve"),
            absolute(&expected)
        );
        assert!(resolve_program("./missing-tool", cwd.path(), OsStr::new("")).is_err());
    }

    #[test]
    fn an_empty_path_entry_is_not_the_current_directory() {
        // POSIX reads an empty PATH entry as the current directory. Searching
        // there would make `run` pick up whatever file happens to sit in the
        // caller's cwd, so it is skipped.
        let cwd = tempfile::tempdir().expect("tempdir");
        make_exe(cwd.path(), "passmgr-local-tool", 0o755);
        let error = resolve_program("passmgr-local-tool", cwd.path(), OsStr::new(""))
            .expect_err("must not search the cwd");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn an_absolute_path_is_passed_through_unchanged() {
        // Existing or not: the daemon's spawn failure is the accurate report,
        // and rewriting the path would change what the caller asked for.
        assert_eq!(
            resolve_program("/nonexistent/passmgr-tool", Path::new("/"), OsStr::new(""))
                .expect("absolute"),
            Path::new("/nonexistent/passmgr-tool")
        );
        assert_eq!(
            resolve_program("/bin/true", Path::new("/"), OsStr::new("")).expect("absolute"),
            Path::new("/bin/true")
        );
    }

    #[test]
    fn a_missing_bare_name_is_a_usage_error() {
        let error = resolve_program(
            "passmgr-no-such-program",
            Path::new("/"),
            OsStr::new("/bin"),
        )
        .expect_err("missing program");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error.to_string().contains("passmgr-no-such-program"),
            "the caller must learn which program was missing: {error}"
        );
    }

    #[test]
    fn status_codes_match_the_shell_convention() {
        assert_eq!(status_code(RunExit::Code(0)), 0);
        assert_eq!(status_code(RunExit::Code(7)), 7);
        assert_eq!(status_code(RunExit::Code(255)), 255);
        assert_eq!(status_code(RunExit::Signal(1)), 129);
        assert_eq!(status_code(RunExit::Signal(9)), 137);
        assert_eq!(status_code(RunExit::Signal(15)), 143);
        assert_eq!(status_code(RunExit::Signal(127)), 255);
    }

    #[test]
    fn terminal_errors_have_stable_exit_codes() {
        assert_eq!(refusal(ResponseError::NotFound, "pm://x").exit_code(), 3);
        for error in [
            ResponseError::BadRequest,
            ResponseError::SpawnFailed,
            ResponseError::Internal,
            ResponseError::Unauthorized,
            ResponseError::Unsupported,
            ResponseError::Busy,
        ] {
            assert_eq!(refusal(error, "pm://x").exit_code(), 1, "{error:?}");
        }
        assert!(
            refusal(ResponseError::NotFound, "pm://x")
                .to_string()
                .contains("pm://x"),
            "the caller must learn which reference was missing"
        );
    }
}
