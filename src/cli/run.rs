//! `run`: use a credential with the secret injected into a child.
//!
//! With a grant token (`--grant-file` or `PASSMGR_GRANT_FILE`) this is the
//! agent-facing way to *use* a secret: the CLI sends a reference and an argv
//! to `pmd`, the daemon decrypts, injects and redacts. No secret value is read,
//! printed or stored by this process.
//!
//! Without a grant token, a human at a terminal may run against a local vault
//! (TODO 3.7). This process prompts for the master password, decrypts the one
//! credential and calls the same [`runner::execute`] the daemon uses, so the
//! child gets the same fixed environment and the same streaming redaction.
//! The local path is human-only under [`agent::check_human`]: no agent marker,
//! no `--agent`, and both standard streams are terminals. An agent uses a
//! grant instead.

use passmgr::Error;

#[cfg(unix)]
use std::cell::Cell;
#[cfg(unix)]
use std::io::{self, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use zeroize::Zeroizing;

#[cfg(unix)]
use passmgr::agent;
#[cfg(unix)]
use passmgr::audit;
#[cfg(unix)]
use passmgr::client::{self, RunOutcome};
#[cfg(unix)]
use passmgr::error::EXIT_OUTPUT_CLOSED;
#[cfg(unix)]
use passmgr::protocol::{EnvBinding, ResponseError, RunExit, RunFrame, RunLimits, RunRequest};
#[cfg(unix)]
use passmgr::runner;
#[cfg(unix)]
use passmgr::socket::SocketError;
#[cfg(unix)]
use passmgr::store;

#[cfg(not(unix))]
pub(crate) const DAEMON_UNSUPPORTED: &str = "the unlock daemon is supported on Unix systems only";

/// `passmgr run --env NAME=<ref> -- <command>`.
///
/// Returns the child's status as this process's exit code. Every refusal is a
/// stable-code [`Error`]; the parsing path already rejected malformed specs
/// with a usage error (exit 2) before this function was reached.
#[cfg(unix)]
pub(crate) fn command_run(
    options: super::RunOptions,
    agent_mode: bool,
    db_path: &Path,
) -> Result<ExitCode, Error> {
    // The daemon checks this too (it must not trust a client), but refusing
    // here avoids a connection and gives the better message. Exit 5 is the
    // documented "refused for safety" code, like `get --reveal` without a TTY.
    if runner::denied_env_name(&options.env) {
        return Err(Error::Refused(format!(
            "refusing to inject into '{}': that variable could change how the child runs",
            options.env
        )));
    }

    let grant_file = options
        .grant_file
        .clone()
        .or_else(|| std::env::var_os("PASSMGR_GRANT_FILE").map(PathBuf::from));

    // No grant token means the local, human-only fallback. Check the human
    // gate before resolving the program or prompting for the master password,
    // so an agent context or a pipe is always the stable exit 5 the docs
    // promise. This is the same gate as `unlock`: both standard streams must
    // be terminals, because the human is about to hand a secret to an
    // arbitrary command (the relayed output is redacted, but the command is
    // still chosen at this terminal).
    if grant_file.is_none() {
        agent::check_human(agent_mode).map_err(|refusal| {
            Error::Refused(refusal.message_for("run a command with a local vault"))
        })?;
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

    match grant_file {
        Some(grant_file) => run_via_daemon(
            options.env,
            options.reference,
            command,
            cwd_text,
            grant_file,
        ),
        None => run_locally(
            options.env,
            options.reference,
            command,
            &cwd,
            &program,
            db_path,
        ),
    }
}

/// Send the request to `pmd`, the only path that mints a secret from a grant.
#[cfg(unix)]
fn run_via_daemon(
    env: String,
    reference: String,
    command: Vec<String>,
    cwd_text: String,
    grant_file: PathBuf,
) -> Result<ExitCode, Error> {
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

    let grant = passmgr::grant::read_grant_token(&grant_file).map_err(|error| {
        Error::Refused(format!(
            "{error}; ask the human who approved the grant for its token file"
        ))
    })?;

    let request = RunRequest {
        env: vec![EnvBinding {
            name: env,
            reference: reference.clone(),
        }],
        limits: RunLimits::default(),
        plain_env: Vec::new(),
        command,
        cwd: cwd_text,
        grant,
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let output_closed = Cell::new(false);
    let outcome = match client::run(&paths, &token, &request, |frame| match frame {
        RunFrame::Stdout(bytes) => relay(&mut out, bytes, &output_closed).map_err(Error::Io),
        RunFrame::Stderr(bytes) => relay(&mut err, bytes, &output_closed).map_err(Error::Io),
        // `client::run` returns terminal frames instead of relaying them.
        other => Err(Error::Daemon(format!(
            "unexpected frame in a run stream: {other:?}"
        ))),
    }) {
        Ok(outcome) => outcome,
        // The caller stopped reading (a closed pipe, `head -1`, an agent host
        // that dropped its reader). Nothing relaying the child's output is
        // left, so even a successful status could not be trusted to describe
        // what the caller saw: cancel the run (dropping the connection makes
        // the daemon kill the child) and exit 141 instead of letting the
        // generic BrokenPipe mapping report success (TODO R.47).
        Err(_) if output_closed.get() => {
            // Best effort: the caller may have closed stderr too.
            let _ = writeln!(
                err,
                "passmgr: output pipe closed; cancelled the run (exit {EXIT_OUTPUT_CLOSED})"
            );
            return Ok(ExitCode::from(EXIT_OUTPUT_CLOSED));
        }
        Err(error) => return Err(error),
    };

    match outcome {
        RunOutcome::Exited(finished) => {
            // Without these the caller cannot tell cut-short output from the
            // child's own. The exit code stays the child's.
            let RunLimits {
                timeout_secs,
                max_output_bytes: cap,
            } = request.limits;
            let notices = [
                (
                    finished.timed_out,
                    format!("the command hit the {timeout_secs} s time limit and was killed"),
                ),
                (
                    finished.stdout_truncated,
                    format!("standard output hit the {cap}-byte cap and was truncated"),
                ),
                (
                    finished.stderr_truncated,
                    format!("standard error hit the {cap}-byte cap and was truncated"),
                ),
            ];
            for (_, notice) in notices.iter().filter(|(set, _)| *set) {
                // Best effort: the caller may have closed stderr.
                let _ = writeln!(err, "passmgr: {notice}");
            }
            Ok(ExitCode::from(status_code(finished.exit)))
        }
        RunOutcome::Refused(error) => Err(refusal(error, &reference)),
    }
}

/// Run against a vault this process opened itself (no daemon, no grant).
///
/// The human gate already ran in [`command_run`]. The credential is copied
/// into a [`Zeroizing`] buffer and the decrypted vault is dropped before the
/// child starts, so the only plaintext this process keeps is the one value the
/// child needs; [`runner::execute`] redacts both output streams exactly as the
/// daemon does.
#[cfg(unix)]
fn run_locally(
    env: String,
    reference: String,
    command: Vec<String>,
    cwd: &Path,
    program: &Path,
    db_path: &Path,
) -> Result<ExitCode, Error> {
    // Parse before unlocking: a malformed reference is a usage error and must
    // not cost the human a master-password prompt.
    let id = store::EntryId::parse_ref(&reference)?;
    // A human run is still a credential use, so it is audited like a daemon
    // run (TODO 3.8). Refuse before decrypting when the record could not be
    // written: an unrecorded use is worse than a refused one.
    let audit_path = audit::default_path().map_err(|error| {
        Error::Refused(format!("refusing to run without an audit log: {error}"))
    })?;
    audit::check_writable(&audit_path).map_err(|error| {
        Error::Refused(format!("refusing to run without an audit log: {error}"))
    })?;
    let program_text = program.to_string_lossy();
    // The result is returned so a run that reports success cannot hide a
    // missing record (TODO R.68).
    let record = |outcome: audit::Outcome,
                  termination: Option<audit::Termination>|
     -> Result<(), audit::AuditError> {
        let event = audit::Event {
            source: audit::Source::Local,
            outcome,
            grant: None,
            reference: Some(reference.as_str()),
            command: Some(program_text.as_ref()),
            args: command.get(1..).unwrap_or(&[]),
            termination,
        };
        audit::append(&audit_path, &event)
    };
    let warn = |result: Result<(), audit::AuditError>| {
        if let Err(error) = result {
            eprintln!("passmgr: could not append the audit record: {error}");
        }
    };
    let secret_env = {
        let (vault, _master) = super::unlock(db_path)?;
        let Some(credential) = vault.get_by_ref(id) else {
            warn(record(audit::Outcome::NotFound, None));
            return Err(Error::EntryNotFound(reference.clone()));
        };
        vec![(env, Zeroizing::new(credential.password().to_owned()))]
    };

    let inherited = runner::inherited_env(std::env::vars_os());
    let cancel = AtomicBool::new(false);
    let stop = runner::Stop::on_cancel(&cancel);
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let output_closed = Cell::new(false);
    let result = runner::execute(
        program,
        &command[1..],
        &secret_env,
        &[],
        cwd,
        &inherited,
        runner::Limits::NONE,
        &stop,
        |frame| match frame {
            RunFrame::Stdout(bytes) => relay(&mut out, &bytes, &output_closed),
            RunFrame::Stderr(bytes) => relay(&mut err, &bytes, &output_closed),
            // `runner::execute` only emits the two output variants; anything
            // else is a bug, and its Debug never renders child bytes.
            other => Err(io::Error::other(format!(
                "unexpected frame from the local runner: {other:?}"
            ))),
        },
    );

    match result {
        Ok(finished) => {
            let exit = finished.exit;
            let termination = match exit {
                RunExit::Code(code) => audit::Termination::Code(code),
                RunExit::Signal(signal) => audit::Termination::Signal(signal),
            };
            // The child ran, but the human must not see the child's success
            // status when the use is missing from the audit trail (TODO
            // R.68). Exit 5, like the pre-spawn refusal, and name the log.
            if let Err(error) = record(audit::Outcome::Allowed, Some(termination)) {
                return Err(Error::Refused(format!(
                    "the run finished but its audit record could not be written: {error}"
                )));
            }
            Ok(ExitCode::from(status_code(exit)))
        }
        Err(runner::RunError::Output(_)) if output_closed.get() => {
            warn(record(audit::Outcome::OutputError, None));
            let _ = writeln!(
                err,
                "passmgr: output pipe closed; cancelled the run (exit {EXIT_OUTPUT_CLOSED})"
            );
            Ok(ExitCode::from(EXIT_OUTPUT_CLOSED))
        }
        Err(runner::RunError::Spawn(error)) => {
            warn(record(audit::Outcome::SpawnFailed, None));
            Err(Error::Daemon(format!(
                "could not start the command: {error}"
            )))
        }
        Err(runner::RunError::Output(error)) => {
            warn(record(audit::Outcome::OutputError, None));
            Err(Error::Io(error))
        }
        Err(runner::RunError::Cancelled) => {
            warn(record(audit::Outcome::Cancelled, None));
            Err(Error::Daemon("the run was cancelled".into()))
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn command_run(
    options: super::RunOptions,
    agent_mode: bool,
    db_path: &std::path::Path,
) -> Result<std::process::ExitCode, Error> {
    let _ = (options, agent_mode, db_path);
    Err(Error::Daemon(DAEMON_UNSUPPORTED))
}

#[cfg(unix)]
fn no_daemon() -> Error {
    Error::Daemon("no passmgr daemon is running; start one with 'passmgr unlock'".into())
}

/// Resolve a caller-supplied program name to an absolute path.
///
/// The rule is shared with the MCP server's `run_with_credentials` (TODO
/// 4.5d) and lives in [`passmgr::program`] so both sides resolve the same way;
/// the daemon still canonicalizes and allowlist-checks whatever path it is
/// sent.
#[cfg(unix)]
pub(crate) use passmgr::program::resolve_program;

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

/// Relay one output frame and flush it.
///
/// A closed pipe is only remembered in `closed`: it is the caller's own output
/// stream going away, not a daemon failure. Only the relayed-output path may
/// turn it into exit 141; every socket write failure is `Error::Daemon` from
/// `client` and never reaches this function (TODO R.47, R.60).
fn relay(sink: &mut impl Write, bytes: &[u8], closed: &Cell<bool>) -> io::Result<()> {
    if let Err(error) = sink.write_all(bytes).and_then(|()| sink.flush()) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            closed.set(true);
        }
        return Err(error);
    }
    Ok(())
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
        // The daemon returns one generic `denied` for an unknown, expired,
        // revoked, used-up or out-of-scope grant, so the message must cover
        // all of them without becoming an oracle.
        ResponseError::Denied => Error::Refused(
            "the unlock daemon refused the run: the grant is missing, expired, revoked, \
             used up, or does not cover this credential and command"
                .into(),
        ),
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
