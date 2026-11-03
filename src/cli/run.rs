//! `run`: use a credential through the unlock daemon.
//!
//! This is the agent-facing way to *use* a secret. The CLI sends a reference
//! and an argv to `pmd`; the daemon decrypts, injects and redacts. No secret
//! value is read, printed or stored by this process, and the isolated output
//! that is relayed has already been redacted on the daemon side.

use passmgr::Error;

#[cfg(unix)]
use std::io::Write;
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
        command: options.command,
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
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

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
