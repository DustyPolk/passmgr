//! Client side of the unlock daemon: requests, and starting `pmd`.
//!
//! `passmgr unlock` derives the vault key once, hands exactly those
//! bytes to a freshly spawned `pmd` over an inherited pipe, and waits until the
//! daemon answers a `ping`. `passmgr lock` sends one `lock` request. The master
//! password and the key never appear in argv, the environment, or any output.
//!
//! # Why the key goes over a pipe
//!
//! The daemon accepts exactly [`crate::crypto::KEY_LEN`] bytes on stdin and
//! then requires EOF. A pipe is not observable through `ps` or `/proc/<pid>/
//! cmdline` the way an argument or an environment variable is, and the write
//! end is closed before the daemon is ready. The key itself is derived in this
//! process and zeroized when the caller's [`zeroize::Zeroizing`] buffer drops.
//!
//! # Startup diagnostics
//!
//! `pmd`'s stdout is discarded and its stderr goes to an anonymous temporary
//! file (created 0600 by `tempfile`, immediately unlinked). That keeps a
//! failing daemon from contaminating the human's terminal and, just as
//! important, keeps a *successful* daemon's stderr away from the caller's pipe:
//! the parent exits while the daemon lives, so sharing the pipe would break
//! `Command::output()`-style capture and later writes. The contents are only
//! read (bounded) to explain a startup failure; `pmd` messages never contain
//! key material.
//!
//! # Authorization
//!
//! Every request carries the session token from the 0600 session file, and the
//! daemon rejects a mismatch with `unauthorized`. The token proves the client
//! can read the owner's runtime directory, which every same-user process can;
//! it is not a boundary between an agent and its owner, and it is never enough
//! to use a secret: `run` also needs a grant token whose grant covers the
//! credential and command (TODO 3.6). There is still no request that returns
//! plaintext, so a process holding only the session token cannot read or
//! inject anything; the worst it can do is make the human unlock again or
//! revoke grants.

use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::presence::ChallengeNonce;
use crate::protocol::{self, Request, Response, ResponseError, RunFinished, RunFrame, RunStream};
use crate::session;
use crate::socket::{self, RuntimePaths, SocketError};
use crate::token::SessionToken;

/// How long the client waits for a daemon response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `unlock` waits for a spawned `pmd` to answer a ping.
pub const START_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for daemon readiness.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// How much of the daemon's startup stderr is reported on failure.
const LOG_LIMIT: u64 = 8 * 1024;

/// One framed request, one framed response.
///
/// Fails with [`Error::Daemon`] when the daemon is not running, does not answer
/// within [`REQUEST_TIMEOUT`], or sends bytes that are not a valid response.
pub fn request(paths: &RuntimePaths, token: &SessionToken, request: &Request) -> Result<Response> {
    let mut stream = socket::connect_at(paths).map_err(socket_error)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    send_request(&mut stream, token, request)?;
    let bytes = read_response(&mut stream)?;
    protocol::decode_response(&bytes).map_err(protocol_error)
}

/// Read the daemon's whole answer, bounded by one maximum-size frame.
///
/// A peer that never stops sending must not grow this buffer, and a timeout is
/// reported as a timeout rather than as a `WouldBlock` I/O error. An empty
/// answer and every other read failure are transport failures on the *socket*
/// and become [`Error::Daemon`]: after a successful connect, losing the daemon
/// is a daemon problem, never this process's own output pipe closing (see
/// [`socket_failure`]).
fn read_response(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let limit = (protocol::MAX_MESSAGE_BYTES + protocol::LENGTH_PREFIX_BYTES + 1) as u64;
    let mut bytes = Vec::new();
    let mut limited = Read::by_ref(stream).take(limit);
    match limited.read_to_end(&mut bytes) {
        Ok(0) => Err(Error::Daemon(
            "the unlock daemon closed the connection without answering".into(),
        )),
        Ok(_) => Ok(bytes),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(Error::Daemon(format!(
                "timed out after {} seconds waiting for the unlock daemon",
                REQUEST_TIMEOUT.as_secs()
            )))
        }
        Err(err) => Err(socket_failure("while answering the request", err)),
    }
}

/// Turn a transport failure on a request's socket into a daemon error.
///
/// The CLI's `main` maps a bare [`Error::Io`] of kind `BrokenPipe` to exit 0,
/// because a pipe to the caller's own terminal going away (for example
/// `passmgr list | head -1`) is not a failure. A *socket* write fails the same
/// way when `pmd` exits after accepting the connection — `pm lock`, the idle
/// timeout, a crash — and letting that reach the same mapping would tell an
/// agent "done" for a request the daemon never received. A reset or another
/// I/O error while reading the answer is the same story from the other
/// direction: the daemon went away, so the request's fate is unknown. Keeping
/// both mappings here is what makes that impossible: every remaining
/// `BrokenPipe` `main` can see is one of this process's own writes, and every
/// connected-but-lost request names the daemon and exits nonzero (TODO R.60).
fn socket_failure(when: &str, error: io::Error) -> Error {
    Error::Daemon(format!("the unlock daemon went away {when}: {error}"))
}

/// Encode and write one request frame over the connected socket.
fn send_request(stream: &mut UnixStream, token: &SessionToken, request: &Request) -> Result<()> {
    let frame = protocol::encode(token, request).map_err(protocol_error)?;
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|error| socket_failure("before it received the request", error))
}

/// Terminal outcome of a `run` request.
///
/// The daemon either finishes the child (with a status this process must
/// reproduce) or refuses before/while starting it. Both are protocol-level
/// outcomes, not transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// The child finished; the caller renders this as its own exit status.
    Exited(RunFinished),
    /// The daemon refused the request. No child output was produced.
    Refused(ResponseError),
}

/// Send one `run` request and relay every frame to `on_frame` as it arrives.
///
/// This is the client half of the streaming protocol: stdout/stderr frames are
/// handed to the caller in order (the daemon has already redacted them), and
/// the loop stops at the terminal frame, which is returned rather than passed
/// to `on_frame`. The secret never crosses this function: it only carries
/// references and the child's (redacted) output.
///
/// There is deliberately no read timeout: a command may legitimately stay
/// silent for a long time (`sleep 60`), and the daemon closes the connection
/// when it exits. Connecting still fails fast when no daemon is running.
///
/// # Errors
///
/// [`Error::Daemon`] when the daemon is not running, cannot be reached, speaks
/// the protocol incorrectly, or closes the stream before a terminal frame.
/// Errors returned by `on_frame` (for example a broken stdout pipe) abort the
/// stream and are returned unchanged.
pub fn run<F>(
    paths: &RuntimePaths,
    token: &SessionToken,
    run: &protocol::RunRequest,
    mut on_frame: F,
) -> Result<RunOutcome>
where
    F: FnMut(&RunFrame) -> Result<()>,
{
    let mut stream = socket::connect_at(paths).map_err(socket_error)?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    send_request(&mut stream, token, &Request::Run(run.clone()))?;

    let mut frames = RunStream::new();
    let mut decoder = protocol::FrameDecoder::new();
    let mut buffer = [0u8; protocol::MAX_CHUNK_BYTES];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(socket_failure("while running the command", err)),
        };
        decoder.push(&buffer[..read]).map_err(protocol_error)?;
        while let Some(body) = decoder.next_frame().map_err(protocol_error)? {
            let frame = decode_frame_body(&body)?;
            // Rejects a second terminal frame or any frame after one, before
            // the caller ever sees it.
            frames.accept(&frame).map_err(protocol_error)?;
            match frame {
                RunFrame::Exit(exit) => return Ok(RunOutcome::Exited(exit)),
                RunFrame::Error(error) => return Ok(RunOutcome::Refused(error)),
                stdout_or_stderr => on_frame(&stdout_or_stderr)?,
            }
        }
    }
    Err(Error::Daemon(
        "the unlock daemon closed the connection before the command finished".into(),
    ))
}

/// Decode one frame body returned by [`protocol::FrameDecoder`].
///
/// The decoder strips the 4-byte prefix; [`protocol::decode_run_frame`] takes a
/// complete frame, so put the prefix back. The body is already bounded by the
/// decoder, so this allocation is small.
fn decode_frame_body(body: &[u8]) -> Result<RunFrame> {
    let length = u32::try_from(body.len())
        .map_err(|_| Error::Daemon("invalid daemon response: frame is too large".into()))?;
    let mut frame = Vec::with_capacity(protocol::LENGTH_PREFIX_BYTES + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    protocol::decode_run_frame(&frame).map_err(protocol_error)
}

/// Ask the daemon for a fresh, single-use presence challenge nonce.
///
/// Any same-user process can ask for one; the nonce is public and worthless
/// without the vault key. It only guards against replaying a recorded proof.
pub fn challenge(paths: &RuntimePaths, token: &SessionToken) -> Result<ChallengeNonce> {
    match request(paths, token, &Request::Challenge)? {
        Response::Challenge(nonce) => Ok(nonce),
        Response::Error(error) => Err(Error::Daemon(format!(
            "the unlock daemon refused a presence challenge ({})",
            error.code()
        ))),
        other => Err(unexpected_response("a challenge", &other)),
    }
}

/// Present a presence proof and require the daemon to accept it.
///
/// The daemon spends the nonce on every attempt, so a refused proof (wrong
/// key, altered digest, stale nonce) is final for that challenge: ask for a
/// new one rather than retrying. On success the daemon records the digest as
/// a one-shot approval; this call does not authorize anything, and the write
/// for exactly that digest must spend the approval within 60 seconds. The
/// detail never includes the proof.
pub fn prove(
    paths: &RuntimePaths,
    token: &SessionToken,
    prove: &protocol::ProveRequest,
) -> Result<()> {
    match request(paths, token, &Request::Prove(prove.clone()))? {
        Response::Proven => Ok(()),
        Response::Error(error) => Err(Error::Daemon(format!(
            "the unlock daemon refused the approval proof ({})",
            error.code()
        ))),
        other => Err(unexpected_response("a proof", &other)),
    }
}

fn unexpected_response(what: &str, response: &Response) -> Error {
    Error::Daemon(format!(
        "the unlock daemon answered {what} with an unexpected response ({}).",
        response_kind(response)
    ))
}

/// A non-secret label for a response, for diagnostics.
fn response_kind(response: &Response) -> &'static str {
    match response {
        Response::Pong => "pong",
        Response::Locked => "locked",
        Response::Challenge(_) => "challenge",
        Response::Proven => "proven",
        Response::GrantApproved => "grant_approved",
        Response::GrantRevoked { .. } => "grant_revoked",
        Response::Entries { .. } => "entries",
        Response::Entry(_) => "entry",
        Response::Error(error) => error.code(),
    }
}

/// Ask whether a daemon is alive (and holds a key) at `paths`.
pub fn ping(paths: &RuntimePaths, token: &SessionToken) -> Result<()> {
    match request(paths, token, &Request::Ping)? {
        Response::Pong => Ok(()),
        Response::Error(error) => Err(Error::Daemon(format!(
            "the unlock daemon rejected a ping ({})",
            error.code()
        ))),
        other => Err(unexpected_response("a ping", &other)),
    }
}

/// Ask the daemon to wipe its key and stop.
///
/// The token comes from the session file. When that file is gone, the socket is
/// probed first so the caller still gets the precise "no daemon is running"
/// error instead of a confusing token error; a reachable daemon with no
/// readable token is a real error, not a success.
pub fn lock(paths: &RuntimePaths) -> Result<()> {
    let token = match session::load(paths) {
        Ok(token) => token,
        Err(err) => {
            // Distinguish "nothing is running" from "a daemon is running but
            // this client cannot authenticate to it".
            socket::connect_at(paths).map_err(socket_error)?;
            return Err(Error::Daemon(format!(
                "cannot authenticate to the unlock daemon: {err}"
            )));
        }
    };
    lock_with(paths, &token)
}

/// [`lock`] with a token the caller already holds.
pub fn lock_with(paths: &RuntimePaths, token: &SessionToken) -> Result<()> {
    match request(paths, token, &Request::Lock)? {
        Response::Locked => {
            // The daemon removes the file too, but only if it still matches;
            // this makes `lock` leave no stale token even if the daemon died
            // between answering and cleaning up, and never removes a newer
            // session's file.
            session::remove_if_matches(paths, token);
            Ok(())
        }
        Response::Error(error) => Err(Error::Daemon(format!(
            "the unlock daemon rejected the lock request ({})",
            error.code()
        ))),
        other => Err(unexpected_response("a lock request", &other)),
    }
}

/// Spawn `pmd` for `vault`, hand it `key` over stdin, and wait until it is
/// ready. Returns the daemon's pid.
///
/// A daemon that is already running is not reused: the caller checks for that
/// first, and a child that loses the instance lock exits, which is reported
/// here as a failure. `pmd` itself calls `setsid`, so it survives the caller
/// exiting. `idle_timeout` is passed through as `--idle-timeout`; it is a
/// duration, never a secret.
pub fn spawn_daemon(
    vault: &Path,
    paths: &RuntimePaths,
    key: &[u8],
    token: &SessionToken,
    idle_timeout: Duration,
) -> Result<u32> {
    if key.len() != KEY_LEN {
        return Err(Error::Daemon(format!(
            "internal error: the vault key must be {KEY_LEN} bytes"
        )));
    }

    let program = daemon_binary()?;
    let mut log = tempfile::tempfile()
        .map_err(|err| Error::Daemon(format!("could not create the pmd startup log: {err}")))?;
    let child_log = log
        .try_clone()
        .map_err(|err| Error::Daemon(format!("could not duplicate the pmd startup log: {err}")))?;

    let mut child = Command::new(&program)
        .arg("--vault")
        .arg(vault)
        .arg("--runtime-dir")
        .arg(paths.dir())
        .arg("--idle-timeout")
        .arg(idle_timeout.as_secs().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(child_log))
        .spawn()
        .map_err(|err| Error::Daemon(format!("could not start '{}': {err}", program.display())))?;
    let pid = child.id();

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Daemon("internal error: pmd stdin was not piped".into()))?;
    // Exactly the key then the token, then close: pmd requires EOF after those
    // bytes. Neither is ever in argv, the environment or a log.
    let handover = stdin
        .write_all(key)
        .and_then(|()| stdin.write_all(token.as_bytes()))
        .and_then(|()| stdin.flush());
    drop(stdin);
    if let Err(err) = handover {
        return Err(startup_failure(
            &mut child,
            &mut log,
            format!("could not be handed the vault key and session token: {err}"),
        ));
    }

    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(startup_failure(
                    &mut child,
                    &mut log,
                    format!("exited during startup ({status})"),
                ));
            }
            Ok(None) => {}
            Err(err) => {
                return Err(Error::Daemon(format!("could not check on pmd: {err}")));
            }
        }

        if ping(paths, token).is_ok() {
            // A daemon started earlier could answer before our child discovers
            // it cannot take the instance lock. Let pmd reach that decision,
            // then require that our own child is still alive.
            std::thread::sleep(POLL_INTERVAL);
            match child.try_wait() {
                Ok(None) => return Ok(pid),
                Ok(Some(status)) => {
                    return Err(startup_failure(
                        &mut child,
                        &mut log,
                        format!("exited during startup ({status})"),
                    ));
                }
                Err(err) => {
                    return Err(Error::Daemon(format!("could not check on pmd: {err}")));
                }
            }
        }

        if Instant::now() >= deadline {
            return Err(startup_failure(
                &mut child,
                &mut log,
                format!(
                    "did not become ready within {} seconds",
                    START_TIMEOUT.as_secs()
                ),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Path to the `pmd` binary that belongs with this executable.
fn daemon_binary() -> Result<PathBuf> {
    let exe = env::current_exe()
        .map_err(|err| Error::Daemon(format!("could not locate this executable: {err}")))?;
    let directory = exe.parent().ok_or_else(|| {
        Error::Daemon(format!(
            "could not locate the directory of '{}'",
            exe.display()
        ))
    })?;
    let candidate = directory.join("pmd");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(Error::Daemon(format!(
            "the 'pmd' binary was not found next to '{}'; install both binaries together",
            exe.display()
        )))
    }
}

/// Reap or kill a failed child and turn its status and startup stderr into an
/// error message. Never includes key material: only the fixed `reason`, the
/// exit status and whatever `pmd` wrote (paths and fixed reasons).
fn startup_failure(child: &mut Child, log: &mut File, reason: String) -> Error {
    let status = match child.try_wait() {
        Ok(Some(status)) => Some(status),
        _ => {
            let _ = child.kill();
            child.wait().ok()
        }
    };
    let message = match status {
        // `reason` normally names the status already; only a child killed here
        // needs it appended.
        Some(status) if !reason.contains(&status.to_string()) => {
            format!("pmd {reason}: {status}")
        }
        _ => format!("pmd {reason}"),
    };
    let log = read_log(log);
    if log.is_empty() {
        Error::Daemon(message)
    } else {
        Error::Daemon(format!("{message}: {log}"))
    }
}

/// Read the bounded startup log from an anonymous temporary file.
fn read_log(log: &mut File) -> String {
    if log.seek(SeekFrom::Start(0)).is_err() {
        return String::new();
    }
    let mut text = String::new();
    if log.take(LOG_LIMIT).read_to_string(&mut text).is_err() {
        return String::new();
    }
    text.trim().to_owned()
}

/// Daemon connection failures are user-facing runtime errors (exit code 1).
fn socket_error(error: SocketError) -> Error {
    Error::Daemon(error.to_string())
}

/// Protocol failures carry structure only; surface them as runtime errors.
fn protocol_error(error: protocol::ProtocolError) -> Error {
    Error::Daemon(format!("invalid daemon response: {error}"))
}

#[cfg(test)]
mod tests;
