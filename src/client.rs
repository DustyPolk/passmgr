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
//! # What this module does not do
//!
//! There is no request that returns plaintext, and no authorization beyond the
//! socket's peer-uid check yet (the session token is TODO 2.5, grants are 3.1).
//! `lock` is therefore available to any process running as the owner; the
//! worst it can do is make the human unlock again.

use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::protocol::{self, Request, Response};
use crate::socket::{self, RuntimePaths, SocketError};

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
pub fn request(paths: &RuntimePaths, request: &Request) -> Result<Response> {
    let mut stream = socket::connect_at(paths).map_err(socket_error)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    let frame = protocol::encode(request).map_err(protocol_error)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    // The daemon answers with exactly one frame and then closes. Bound the
    // read: a peer that never stops sending must not grow this buffer.
    let limit = (protocol::MAX_MESSAGE_BYTES + protocol::LENGTH_PREFIX_BYTES + 1) as u64;
    let mut bytes = Vec::new();
    let mut limited = Read::by_ref(&mut stream).take(limit);
    match limited.read_to_end(&mut bytes) {
        Ok(_) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(Error::Daemon(format!(
                "timed out after {} seconds waiting for the unlock daemon",
                REQUEST_TIMEOUT.as_secs()
            )));
        }
        Err(err) => return Err(err.into()),
    }

    if bytes.is_empty() {
        return Err(Error::Daemon(
            "the unlock daemon closed the connection without answering".into(),
        ));
    }
    protocol::decode_response(&bytes).map_err(protocol_error)
}

/// Ask whether a daemon is alive (and holds a key) at `paths`.
pub fn ping(paths: &RuntimePaths) -> Result<()> {
    match request(paths, &Request::Ping)? {
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
pub fn lock(paths: &RuntimePaths) -> Result<()> {
    match request(paths, &Request::Lock)? {
        Response::Locked => Ok(()),
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
    // Exactly the key, then close: pmd requires EOF after KEY_LEN bytes.
    let handover = stdin.write_all(key).and_then(|()| stdin.flush());
    drop(stdin);
    if let Err(err) = handover {
        return Err(startup_failure(
            &mut child,
            &mut log,
            format!("could not be handed the vault key: {err}"),
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

        if ping(paths).is_ok() {
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
    use crate::protocol::FrameDecoder;
    use crate::socket::DaemonSocket;
    use tempfile::TempDir;

    /// Bind a socket in `paths` and answer one request with `response` on a
    /// background thread. The socket (and its instance lock) lives until the
    /// thread finishes.
    fn serve_once(paths: RuntimePaths, response: Response) -> std::thread::JoinHandle<Request> {
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

    #[test]
    fn ping_and_lock_round_trip() {
        let (_directory, paths) = runtime_paths();
        let server = serve_once(paths.clone(), Response::Pong);
        ping(&paths).expect("ping");
        assert_eq!(server.join().expect("server thread"), Request::Ping);

        let server = serve_once(paths.clone(), Response::Locked);
        lock(&paths).expect("lock");
        assert_eq!(server.join().expect("server thread"), Request::Lock);
    }

    #[test]
    fn an_error_response_is_returned_to_the_caller() {
        let (_directory, paths) = runtime_paths();
        let server = serve_once(
            paths.clone(),
            Response::Error(protocol::ResponseError::Unsupported),
        );
        let response = request(&paths, &Request::Ping).expect("request");
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
        let error = ping(&paths).expect_err("no daemon");
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
            let error = request(&paths, &Request::Ping).expect_err("garbage response");
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
}
