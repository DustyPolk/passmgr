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
        other => Err(Error::Daemon(format!(
            "unexpected reply to a ping: {other:?}"
        ))),
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
    match request(paths, &token, &Request::Lock)? {
        Response::Locked => {
            // The daemon removes the file too, but only if it still matches;
            // this makes `lock` leave no stale token even if the daemon died
            // between answering and cleaning up.
            let _ = session::remove(paths);
            Ok(())
        }
        Response::Error(error) => Err(Error::Daemon(format!(
            "the unlock daemon rejected the lock request ({})",
            error.code()
        ))),
        other => Err(Error::Daemon(format!(
            "unexpected reply to a lock request: {other:?}"
        ))),
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
mod tests {
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;

    use super::*;
    use crate::presence::{Proof, RequestDigest};
    use crate::protocol::{AuthenticatedRequest, FrameDecoder, RunExit};
    use crate::socket::DaemonSocket;
    use tempfile::TempDir;

    fn test_token() -> SessionToken {
        SessionToken::from_bytes(&[0x5Au8; crate::token::TOKEN_BYTES]).expect("token")
    }

    /// Bind a socket in `paths` and answer one request with `response` on a
    /// background thread. The socket (and its instance lock) lives until the
    /// thread finishes.
    fn serve_once(
        paths: RuntimePaths,
        response: Response,
    ) -> std::thread::JoinHandle<AuthenticatedRequest> {
        let socket = DaemonSocket::bind_at(paths.clone())
            .unwrap_or_else(|error| panic!("bind test socket at {paths:?}: {error:?}"));
        std::thread::spawn(move || {
            let (mut stream, _peer) = socket.accept_peer().expect("accept client");
            let mut decoder = FrameDecoder::new();
            let mut buffer = [0u8; 4096];
            let request = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => panic!("client closed before sending a request"),
                    Ok(read) => decoder.push(&buffer[..read]).expect("frame"),
                    Err(err) => panic!("read failed: {err}"),
                }
                if let Some(request) = decoder.next_request().expect("decode request") {
                    break request;
                }
            };
            let frame = protocol::encode_response(&response).expect("encode response");
            stream.write_all(&frame).expect("write response");
            request
        })
    }

    /// A 0700 runtime directory inside a temporary directory.
    fn runtime_paths() -> (TempDir, RuntimePaths) {
        let directory = TempDir::new().expect("tempdir");
        let runtime = directory.path().join("runtime");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .expect("create runtime dir");
        let paths = RuntimePaths::at(&runtime);
        (directory, paths)
    }

    /// A daemon that goes away between the connect and the request must not
    /// look like the CLI's own output pipe closing (TODO R.60). A dropped peer
    /// makes the write fail with `EPIPE` deterministically, so this pins the
    /// variant `main` sees rather than only the end-to-end exit code: a bare
    /// `Error::Io(BrokenPipe)` would be mapped to exit 0 by `main`.
    #[test]
    fn a_failed_request_write_is_a_daemon_error_not_a_broken_pipe() {
        let (mut stream, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);

        let error = send_request(&mut stream, &test_token(), &Request::Ping)
            .expect_err("a write with no reader must fail");
        assert!(
            matches!(error, Error::Daemon(_)),
            "a socket write failure must not be a bare I/O error: {error:?}"
        );
        assert_ne!(
            error.exit_code(),
            0,
            "a lost request must never report success"
        );
    }

    /// A daemon that dies after accepting the connection can also fail the
    /// *read* (an end-of-file, or a reset, depending on which side wins the
    /// race). That must name the daemon too, not surface as a bare
    /// `Error::Io`: `main` maps a `BrokenPipe` I/O error to exit 0 for this
    /// process's own output, and a lost request must never look like success
    /// (TODO R.60).
    #[test]
    fn a_closed_connection_without_an_answer_is_a_daemon_error() {
        let (mut stream, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);

        let error = read_response(&mut stream).expect_err("a read with no writer must fail");
        assert!(
            matches!(error, Error::Daemon(_)),
            "a socket read failure must not be a bare I/O error: {error:?}"
        );
        assert_ne!(
            error.exit_code(),
            0,
            "a lost answer must never look like success"
        );
        assert!(
            format!("{error}").contains("unlock daemon"),
            "the failure must name the daemon: {error}"
        );
    }

    #[test]
    fn ping_and_lock_round_trip() {
        let (_directory, paths) = runtime_paths();
        let token = test_token();

        let server = serve_once(paths.clone(), Response::Pong);
        ping(&paths, &token).expect("ping");
        let seen = server.join().expect("server thread");
        assert!(
            seen.token().matches(&token),
            "the ping must carry the token"
        );
        assert_eq!(seen.into_request(), Request::Ping);

        session::store(&paths, &token).expect("store token");
        let server = serve_once(paths.clone(), Response::Locked);
        lock(&paths).expect("lock");
        let seen = server.join().expect("server thread");
        assert!(seen.token().matches(&token), "lock must carry the token");
        assert_eq!(seen.into_request(), Request::Lock);
        assert!(
            !paths.session().exists(),
            "lock must not leave a stale session token behind"
        );
    }

    #[test]
    fn challenge_and_prove_round_trip_and_denial_is_reported() {
        let (_directory, paths) = runtime_paths();
        let token = test_token();

        let nonce = ChallengeNonce::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("nonce");
        let server = serve_once(paths.clone(), Response::Challenge(nonce));
        let received = challenge(&paths, &token).expect("challenge");
        assert!(received.matches(&nonce));
        assert_eq!(
            server.join().expect("server thread").into_request(),
            Request::Challenge
        );

        let digest = RequestDigest::new([0x24; 32]);
        let proof = Proof::compute(&[0x0bu8; 32], &nonce, &digest).expect("proof");
        let request_proof = protocol::ProveRequest {
            nonce,
            digest,
            proof,
        };
        let server = serve_once(paths.clone(), Response::Proven);
        prove(&paths, &token, &request_proof).expect("proven");
        assert_eq!(
            server.join().expect("server thread").into_request(),
            Request::Prove(request_proof.clone())
        );

        // A refusal names the code and never the proof.
        let server = serve_once(paths.clone(), Response::Error(ResponseError::Denied));
        let error = prove(&paths, &token, &request_proof).expect_err("denied");
        let message = error.to_string();
        assert!(message.contains("denied"), "{message}");
        assert!(
            !message.contains(request_proof.proof.to_hex().as_str()),
            "{message}"
        );
        server.join().expect("server thread");

        // A daemon that answers a proof with the wrong shape is a protocol
        // error, not a silently accepted approval.
        let server = serve_once(paths.clone(), Response::Pong);
        assert!(prove(&paths, &token, &request_proof).is_err());
        server.join().expect("server thread");
    }

    #[test]
    fn lock_without_a_session_file_reports_the_real_problem() {
        let (_directory, paths) = runtime_paths();
        // No daemon and no token: the caller hears about the missing daemon.
        let error = lock(&paths).expect_err("no daemon");
        assert!(
            error.to_string().contains("no passmgr daemon is running"),
            "{error}"
        );

        // A daemon is reachable but the token is gone: that is not success,
        // and nothing is sent (the client cannot authenticate).
        let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _peer) = socket.accept_peer().expect("accept");
            let mut buffer = [0u8; 1];
            assert_eq!(stream.read(&mut buffer).expect("read"), 0);
        });
        let error = lock(&paths).expect_err("no token file");
        assert!(error.to_string().contains("authenticate"), "{error}");
        server.join().expect("server thread");
    }

    #[test]
    fn an_error_response_is_returned_to_the_caller() {
        let (_directory, paths) = runtime_paths();
        let token = test_token();
        let server = serve_once(
            paths.clone(),
            Response::Error(protocol::ResponseError::Unsupported),
        );
        let response = request(&paths, &token, &Request::Ping).expect("request");
        assert_eq!(
            response,
            Response::Error(protocol::ResponseError::Unsupported)
        );
        server.join().expect("server thread");
    }

    #[test]
    fn a_missing_daemon_is_a_clear_error() {
        let directory = TempDir::new().expect("tempdir");
        let paths = RuntimePaths::at(directory.path().join("no-daemon-here"));
        let error = ping(&paths, &test_token()).expect_err("no daemon");
        let message = error.to_string();
        assert!(
            message.contains("no passmgr daemon is running"),
            "{message}"
        );
        assert!(message.contains("passmgr unlock"), "{message}");
    }

    #[test]
    fn garbage_and_empty_responses_are_rejected_without_a_panic() {
        for body in [
            &b"not a frame"[..],
            &b""[..],
            &[0xff, 0xff, 0xff, 0xff, b'{', b'}'][..],
        ] {
            let (_directory, paths) = runtime_paths();
            let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
            let body = body.to_vec();
            let server = std::thread::spawn(move || {
                let (mut stream, _peer) = socket.accept_peer().expect("accept");
                let mut buffer = [0u8; 4096];
                // Consume the client's request first so it is not racing us.
                let _ = stream.read(&mut buffer);
                stream.write_all(&body).expect("write garbage");
            });
            let error =
                request(&paths, &test_token(), &Request::Ping).expect_err("garbage response");
            assert!(matches!(error, Error::Daemon(_)), "{error:?}");
            assert!(!error.to_string().contains("not a frame"));
            server.join().expect("server thread");
        }
    }

    #[test]
    fn spawn_refuses_a_key_of_the_wrong_length_before_spawning() {
        let (_directory, paths) = runtime_paths();
        let error = spawn_daemon(
            Path::new("/nonexistent/vault.dat"),
            &paths,
            &[0u8; 4],
            &test_token(),
            crate::daemon::DEFAULT_IDLE_TIMEOUT,
        )
        .expect_err("short key");
        assert!(matches!(error, Error::Daemon(_)));
        assert!(error.to_string().contains("32 bytes"), "{error}");
    }

    #[test]
    fn startup_failure_reports_the_exit_status_and_log() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("echo 'boom: startup failed' >&2; exit 7")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn helper");

        // Route the helper's stderr through the same anonymous-file path used
        // for pmd, then wait so `try_wait` sees the exit.
        let mut log = tempfile::tempfile().expect("tempfile");
        let mut stderr = child.stderr.take().expect("piped stderr");
        io::copy(&mut stderr, &mut log).expect("copy stderr");
        child.wait().expect("reap helper");

        let error = startup_failure(
            &mut child,
            &mut log,
            "exited during startup (exit 7)".into(),
        );
        let message = error.to_string();
        assert!(message.contains("pmd exited during startup"), "{message}");
        assert!(message.contains("boom: startup failed"), "{message}");
    }
    /// Bind a socket in `paths` and answer one `run` request with `frames`.
    fn serve_frames(
        paths: RuntimePaths,
        frames: Vec<RunFrame>,
    ) -> std::thread::JoinHandle<AuthenticatedRequest> {
        let socket = DaemonSocket::bind_at(paths.clone())
            .unwrap_or_else(|error| panic!("bind test socket at {paths:?}: {error:?}"));
        std::thread::spawn(move || {
            let (mut stream, _peer) = socket.accept_peer().expect("accept client");
            let mut decoder = FrameDecoder::new();
            let mut buffer = [0u8; 4096];
            let request = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => panic!("client closed before sending a request"),
                    Ok(read) => decoder.push(&buffer[..read]).expect("frame"),
                    Err(err) => panic!("read failed: {err}"),
                }
                if let Some(request) = decoder.next_request().expect("decode request") {
                    break request;
                }
            };
            for frame in frames {
                let encoded = protocol::encode_run_frame(&frame).expect("encode frame");
                // A client that stops at a terminal frame closes the stream;
                // that is what some of these tests prove, so a failed write
                // just ends the exchange instead of panicking here.
                if stream.write_all(&encoded).is_err() {
                    break;
                }
            }
            request
        })
    }

    fn run_request() -> protocol::RunRequest {
        protocol::RunRequest {
            limits: Default::default(),
            env: vec![protocol::EnvBinding {
                name: "API_KEY".into(),
                reference: "pm://00112233445566778899aabbccddeeff".into(),
            }],
            plain_env: Vec::new(),
            command: vec!["/bin/true".into()],
            cwd: "/tmp".into(),
            grant: crate::grant::GrantToken::from_hex(&"11".repeat(32)).expect("token"),
        }
    }

    #[test]
    fn run_relays_frames_in_order_and_returns_the_status() {
        let (_directory, paths) = runtime_paths();
        let token = test_token();
        let server = serve_frames(
            paths.clone(),
            vec![
                RunFrame::Stdout(b"one".to_vec()),
                RunFrame::Stderr(b"two".to_vec()),
                RunFrame::Stdout(b"three".to_vec()),
                RunFrame::Exit(RunFinished::exited(RunExit::Code(7))),
            ],
        );

        let mut relayed = Vec::new();
        let outcome = run(&paths, &token, &run_request(), |frame| {
            match frame {
                RunFrame::Stdout(bytes) => relayed.push(("out", bytes.clone())),
                RunFrame::Stderr(bytes) => relayed.push(("err", bytes.clone())),
                other => panic!("terminal frame reached the callback: {other:?}"),
            }
            Ok(())
        })
        .expect("run");

        assert_eq!(
            outcome,
            RunOutcome::Exited(RunFinished::exited(RunExit::Code(7)))
        );
        assert_eq!(
            relayed,
            [
                ("out", b"one".to_vec()),
                ("err", b"two".to_vec()),
                ("out", b"three".to_vec()),
            ]
        );
        let seen = server.join().expect("server thread");
        assert!(seen.token().matches(&token));
        assert_eq!(seen.into_request(), Request::Run(run_request()));
    }

    #[test]
    fn run_returns_a_terminal_error_as_a_refusal() {
        let (_directory, paths) = runtime_paths();
        let server = serve_frames(
            paths.clone(),
            vec![
                RunFrame::Stderr(b"partial".to_vec()),
                RunFrame::Error(protocol::ResponseError::NotFound),
            ],
        );
        let mut relayed = 0;
        let outcome = run(&paths, &test_token(), &run_request(), |_frame| {
            relayed += 1;
            Ok(())
        })
        .expect("run");
        assert_eq!(
            outcome,
            RunOutcome::Refused(protocol::ResponseError::NotFound)
        );
        assert_eq!(relayed, 1, "only the non-terminal frame is relayed");
        server.join().expect("server thread");
    }

    #[test]
    fn run_rejects_a_stream_without_a_terminal_frame() {
        let (_directory, paths) = runtime_paths();
        let server = serve_frames(paths.clone(), vec![RunFrame::Stdout(b"truncated".to_vec())]);
        let error = run(&paths, &test_token(), &run_request(), |_frame| Ok(()))
            .expect_err("no terminal frame");
        assert!(
            error
                .to_string()
                .contains("closed the connection before the command finished"),
            "{error}"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn run_stops_at_the_first_terminal_frame() {
        // A stream must end at its terminal frame; a client that has the
        // status must not wait for (or trust) whatever follows it.
        let (_directory, paths) = runtime_paths();
        let server = serve_frames(
            paths.clone(),
            vec![
                RunFrame::Exit(RunFinished::exited(RunExit::Signal(9))),
                RunFrame::Stdout(b"late".to_vec()),
            ],
        );
        let outcome = run(&paths, &test_token(), &run_request(), |_frame| Ok(()))
            .expect("first terminal frame wins");
        assert_eq!(
            outcome,
            RunOutcome::Exited(RunFinished::exited(RunExit::Signal(9)))
        );
        server.join().expect("server thread");
    }

    #[test]
    fn run_rejects_a_malformed_frame() {
        let directory = TempDir::new().expect("tempdir");
        let paths = RuntimePaths::at(directory.path().join("malformed"));
        let socket = DaemonSocket::bind_at(paths.clone()).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _peer) = socket.accept_peer().expect("accept");
            let mut decoder = FrameDecoder::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read");
                if read == 0 {
                    break;
                }
                decoder.push(&buffer[..read]).expect("push");
                if decoder.next_request().expect("request").is_some() {
                    break;
                }
            }
            // A well-formed frame whose body is not a run frame.
            let body = br#"{"type":"pong"}"#;
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            stream.write_all(&frame).expect("write");
        });

        let error = run(&paths, &test_token(), &run_request(), |_frame| Ok(()))
            .expect_err("not a run frame");
        assert!(
            error.to_string().contains("invalid daemon response"),
            "{error}"
        );
        server.join().expect("server thread");
    }
}
