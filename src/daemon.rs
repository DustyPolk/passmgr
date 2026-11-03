//! The unlock daemon (`pmd`): holds the derived vault key, not the vault.
//!
//! The human runs `passmgr unlock` (TODO 2.4b) at a TTY. That process derives
//! the 32-byte vault key once and hands exactly those bytes to `pmd` over an
//! inherited pipe; the master password never leaves the human's process and
//! the key never appears in argv, the environment or a log.
//!
//! # Why only the key
//!
//! Holding the key instead of the decrypted vault keeps plaintext on disk out
//! of a long-lived process. A `run` request decrypts the vault, copies one
//! value, drops (and zeroizes) the rest, then spawns the child. The key is
//! locked in memory where the platform allows it and is zeroized on drop.
//!
//! # No plaintext responses
//!
//! Every request is untrusted and any same-user process can connect. The
//! daemon therefore has no request type that returns a secret; see
//! [`crate::protocol`]. It answers `ping` and `lock`, and `run` streams the
//! child's already-redacted output plus an exit status (TODO 2.6c). There is
//! no request that returns a value.
//!
//! # Lifetime
//!
//! `SIGTERM`/`SIGINT`, a successful `lock`, or
//! [`DEFAULT_IDLE_TIMEOUT`] (configurable) without a successfully handled
//! request wipe the key, remove the socket and the session file, and exit.
//! The idle deadline is suspended while a run is in flight, so a long command
//! is never killed mid-work; accepting a run refreshes the timer, which starts
//! again when the last run finishes.
//! Each `run` is served on its own worker thread so the accept loop stays
//! responsive: `lock`, `ping` and a signal are observed even while a child is
//! still running. At most [`MAX_CONCURRENT_RUNS`] workers exist at once; a
//! further request is answered `busy` before anything is decrypted or spawned,
//! so a client cannot multiply workers, threads and injected environments
//! without bound. Every in-flight child is killed and reaped -- together with
//! its process group, so pipe-holding grandchildren die too -- before the
//! daemon returns, so no copy of the injected secret outlives the key. A
//! `lock` is only acknowledged after that join, the socket unlink, the
//! session removal and the key wipe: the message `passmgr lock` prints is
//! true by the time the client sees it.
//!
//! # Authorization
//!
//! Besides the peer-uid check on the socket, every request must carry the
//! session token that `unlock` handed over with the key. A request with a
//! missing or wrong token is answered `unauthorized` and, importantly, does
//! **not** refresh the idle timer: an unauthenticated peer must not be able to
//! keep the key in memory.
//!
//! The token is not an agent/human boundary (any same-user process can read a
//! 0600 file). Grants in TODO 3.1 are. The idle timeout still guarantees that
//! a session left alone does not keep the key in memory indefinitely.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::protocol::{
    self, FrameDecoder, ProtocolError, Request, Response, ResponseError, RunFrame,
};
use crate::runner;
use crate::session;
use crate::socket::{DaemonSocket, RuntimePaths, SocketError};
use crate::store::EntryId;
use crate::token::{SessionToken, TOKEN_BYTES};
use crate::vault::Vault;

/// How long the accept loop sleeps between non-blocking accepts.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The default idle timeout: how long the daemon keeps the key without a
/// successfully handled request.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Most `run` requests served at once.
///
/// Each worker owns a child, a process group and two pipe-reader threads, and
/// the child's environment holds the injected value where `/proc` can expose
/// it. The cap bounds all of that, so one client opening many connections
/// cannot exhaust pids or memory or widen the exposure window arbitrarily.
/// It is generous for real parallel work (a build plus a test run plus a few
/// tools). A request over the cap is answered `busy` before the vault is
/// opened: nothing is decrypted and no child starts.
pub const MAX_CONCURRENT_RUNS: usize = 16;

/// How long a single client gets to send a complete request.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Read buffer for one connection. A request is bounded by
/// [`protocol::MAX_MESSAGE_BYTES`].
const READ_CHUNK: usize = 4096;

/// Set from the `SIGTERM`/`SIGINT` handler, which may only touch atomics.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Parse an idle timeout in whole seconds.
///
/// Zero is refused: such a daemon would exit before serving anything, which
/// is a configuration mistake rather than a useful "never keep the key"
/// setting. There is no upper bound; a very large value is the caller's
/// explicit choice.
pub fn parse_idle_timeout(text: &str) -> Result<Duration, String> {
    let seconds: u64 = text
        .parse()
        .map_err(|_| format!("idle timeout must be a whole number of seconds, got '{text}'"))?;
    if seconds == 0 {
        return Err("idle timeout must be at least 1 second".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

/// Why the daemon could not start, or had to stop.
///
/// Messages name paths and fixed reasons only. No variant carries key bytes,
/// vault plaintext or a request body.
#[derive(Debug)]
pub enum DaemonError {
    /// Socket setup, peer check or instance-lock failure.
    Socket(SocketError),
    /// Key handover over stdin was wrong (short, long, or unreadable).
    KeyHandover(String),
    /// The daemon was started with bad arguments.
    Usage(String),
    /// The key does not open the vault, or the vault is unreadable.
    Vault(crate::Error),
    /// A process hardening step failed; the daemon refuses to run.
    Hardening(String),
    /// Local I/O failure without a socket path (stdin, listener flags).
    Io(io::Error),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(err) => write!(f, "{err}"),
            Self::KeyHandover(detail) => write!(f, "could not read the vault key: {detail}"),
            Self::Usage(detail) => write!(f, "{detail}"),
            Self::Vault(err) => write!(f, "cannot open the vault: {err}"),
            Self::Hardening(detail) => {
                write!(f, "refusing to start without process hardening: {detail}")
            }
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(err) => Some(err),
            Self::Vault(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::KeyHandover(_) | Self::Hardening(_) | Self::Usage(_) => None,
        }
    }
}

impl From<SocketError> for DaemonError {
    fn from(err: SocketError) -> Self {
        Self::Socket(err)
    }
}

impl From<crate::Error> for DaemonError {
    fn from(err: crate::Error) -> Self {
        Self::Vault(err)
    }
}

impl From<io::Error> for DaemonError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// The one and only copy of the vault key held by the daemon.
///
/// The key lives in a stable heap allocation for its whole lifetime, is
/// `mlock`ed on a best-effort basis, and is unlocked and zeroized on drop.
/// There is no accessor that returns ownership of the bytes.
pub struct LockedKey {
    key: Zeroizing<Vec<u8>>,
    mlocked: bool,
}

impl fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render key bytes, not even a length-dependent hint.
        f.debug_struct("LockedKey")
            .field("mlocked", &self.mlocked)
            .finish_non_exhaustive()
    }
}

impl LockedKey {
    /// Take ownership of an already-read key. The length is checked here.
    pub fn new(key: Zeroizing<Vec<u8>>) -> Result<Self, DaemonError> {
        if key.len() != KEY_LEN {
            return Err(DaemonError::KeyHandover(format!(
                "expected {KEY_LEN} bytes, got {}",
                key.len()
            )));
        }
        let mut locked = Self {
            key,
            mlocked: false,
        };
        locked.mlocked = lock_memory(locked.key.as_slice());
        Ok(locked)
    }

    /// Borrow the key for a decryption call. The bytes never leave this
    /// process.
    pub fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        if self.mlocked {
            // SAFETY: the allocation is still live and was locked above with
            // the same address and length. `Vec` is never resized after
            // `new`, so the address is stable.
            unsafe {
                libc::munlock(self.key.as_ptr().cast::<libc::c_void>(), self.key.len());
            }
            self.mlocked = false;
        }
        // `self.key` (Zeroizing) drops next and overwrites the bytes.
    }
}

/// Pin a memory range into RAM. Best effort: the daemon still works (with the
/// key only in ordinary, zeroized memory) if the kernel refuses.
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // SAFETY: `bytes` points at a live allocation of `bytes.len()` bytes.
    unsafe { libc::mlock(bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) == 0 }
}

/// What `unlock` hands the daemon over the inherited pipe: the vault key
/// followed by the session token, then EOF.
#[derive(Debug)]
pub struct Handover {
    key: LockedKey,
    token: SessionToken,
}

impl Handover {
    /// The derived vault key, locked in memory where possible.
    pub fn key(&self) -> &LockedKey {
        &self.key
    }

    /// The session token this daemon will require from clients.
    pub fn token(&self) -> &SessionToken {
        &self.token
    }
}

/// Read the handover: exactly [`KEY_LEN`] key bytes, [`TOKEN_BYTES`] token
/// bytes, then require EOF.
///
/// The pipe is the handover channel: accepting trailing bytes would let a
/// caller smuggle something else in behind the key. Partial buffers are
/// zeroized on error, and no error message contains key or token bytes.
pub fn read_handover<R: Read>(reader: &mut R) -> Result<Handover, DaemonError> {
    let mut bytes = Zeroizing::new(vec![0u8; KEY_LEN + TOKEN_BYTES]);
    reader
        .read_exact(bytes.as_mut_slice())
        .map_err(|err| DaemonError::KeyHandover(format!("{err}")))?;

    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(DaemonError::KeyHandover(
                "unexpected data after the key and token".into(),
            ));
        }
        Err(err) => return Err(DaemonError::KeyHandover(format!("{err}"))),
    }

    let (key, token) = bytes.split_at(KEY_LEN);
    let key = LockedKey::new(Zeroizing::new(key.to_vec()))?;
    let token =
        SessionToken::from_bytes(token).map_err(|err| DaemonError::KeyHandover(err.to_string()))?;
    Ok(Handover { key, token })
}

/// Disable core dumps and make the process non-dumpable where supported.
///
/// Fail closed: if `RLIMIT_CORE` cannot be cleared the daemon does not start.
/// On Linux `PR_SET_DUMPABLE=0` also keeps same-user processes from reading
/// `/proc/<pid>/mem` or ptracing the daemon. macOS has no `prctl`; the core
/// limit still applies, and the residual ptrace exposure is recorded in
/// `SECURITY.md`.
pub fn harden_process() -> Result<(), DaemonError> {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `no_core` is a fully initialized rlimit for RLIMIT_CORE.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        return Err(DaemonError::Hardening(format!(
            "could not disable core dumps: {}",
            io::Error::last_os_error()
        )));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_DUMPABLE takes an integer flag; no pointers involved.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(DaemonError::Hardening(format!(
                "could not clear the dumpable flag: {}",
                io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Detach from the controlling terminal when possible. Not fatal: a daemon
/// started from a terminal still works, it just shares the session.
pub fn detach_session() {
    // SAFETY: `setsid` takes no pointers and is safe to call in a single
    // threaded process. Failure (already a session leader) is harmless.
    unsafe {
        libc::setsid();
    }
}

extern "C" fn on_signal(_signal: libc::c_int) {
    // Only async-signal-safe operations here: an atomic store.
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install `SIGTERM`/`SIGINT` handlers that ask the loop to wipe and exit.
pub fn install_signal_handlers() -> Result<(), DaemonError> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: `on_signal` has the C signal-handler signature and only
        // performs an atomic store.
        let previous =
            unsafe { libc::signal(signal, on_signal as *const () as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            return Err(DaemonError::Hardening(format!(
                "could not install a handler for signal {signal}: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Whether a signal handler has asked the daemon to stop.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Run the daemon until `lock`, `SIGTERM`/`SIGINT`, or an idle timeout.
///
/// The key is verified against the vault *before* the socket is bound, so a
/// caller with the wrong key can never make `pmd` look alive. The daemon owns
/// `handover` for its whole lifetime: the key and the session token are
/// zeroized here, explicitly before a `lock` acknowledgement is written.
///
/// `idle_timeout` is measured from the last authorized, successfully decoded
/// request, not from the last byte received: a malformed, half-sent or
/// unauthorized frame must not extend the key's lifetime. Accepting a run
/// counts as activity, and the deadline is suspended while any run is in
/// flight, so a command longer than the remaining budget still finishes.
///
/// On every exit path the session file is removed, but only if it still holds
/// `token`: a newer session's file is never deleted.
pub fn run(
    vault_path: &Path,
    runtime_dir: &Path,
    handover: Handover,
    idle_timeout: Duration,
) -> Result<(), DaemonError> {
    let key = &handover.key;
    let token = &handover.token;
    let paths = RuntimePaths::at(runtime_dir);
    harden_process()?;
    install_signal_handlers()?;
    detach_session();

    // Prove the key opens this vault now, then drop the plaintext.
    drop(Vault::open_with_key(vault_path, key.as_slice())?);

    let socket = DaemonSocket::bind_at(RuntimePaths::at(runtime_dir))?;
    socket.listener().set_nonblocking(true)?;

    let mut last_activity = Instant::now();
    // A `lock` connection whose answer is deferred until the key is gone.
    let mut lock_ack: Option<UnixStream> = None;
    // Scoped threads let a `run` worker borrow the key and paths without
    // copying them; the scope cannot end until every worker has been joined.
    // `cancel` lives outside the scope so a worker closure may borrow it.
    let cancel = AtomicBool::new(false);
    let cancel_ref = &cancel;
    let fatal = std::thread::scope(|scope| {
        let mut runs: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
        let mut fatal = None;
        loop {
            // A finished run counts as a successfully handled request, and
            // joining it here means no worker outlives the loop.
            let mut index = 0;
            while index < runs.len() {
                if runs[index].is_finished() {
                    let handle = runs.swap_remove(index);
                    let _ = handle.join();
                    last_activity = Instant::now();
                } else {
                    index += 1;
                }
            }
            // A run that is still going suspends the idle deadline: a build
            // or test suite must not be killed because it outlived the
            // remaining budget. It is bounded by `lock`/signals (and, from
            // TODO 4.5, the run timeout) instead.
            let idle_expired = runs.is_empty() && last_activity.elapsed() >= idle_timeout;
            if shutdown_requested() || idle_expired {
                // Out of activity or asked to stop: wipe the key and exit.
                break;
            }
            match socket.accept_peer() {
                Ok((stream, _peer)) => {
                    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                    match handle_connection(stream, token) {
                        // `lock`: stop accepting, but answer only after the
                        // workers are joined and the key is zeroized below.
                        Handled::Locked(stream) => {
                            lock_ack = Some(stream);
                            break;
                        }
                        // Only a request that was decoded and answered counts
                        // as activity; garbage must not keep the key alive.
                        Handled::Served => last_activity = Instant::now(),
                        Handled::Rejected => {}
                        // The request is authenticated and parsed; the child
                        // runs on a worker so the accept loop can still serve
                        // `lock`, `ping` and a shutdown signal. Accepting a run
                        // is activity, and the idle timeout stays suspended
                        // until the last run finishes.
                        Handled::Run(mut stream, request) => {
                            // Refuse before decrypting anything. A refused
                            // request is not activity: it did no work and must
                            // not extend the key's lifetime.
                            if runs.len() >= MAX_CONCURRENT_RUNS {
                                let _ = write_run_frame(
                                    &mut stream,
                                    &RunFrame::Error(ResponseError::Busy),
                                );
                                continue;
                            }
                            // A spawn failure must not panic out of the scope
                            // (that would skip the join, the socket unlink and
                            // the key wipe). Keep a spare fd so the client
                            // still gets a terminal answer if no thread
                            // starts.
                            let fallback = stream.try_clone().ok();
                            let spawned = std::thread::Builder::new()
                                .name("passmgr-run".into())
                                .spawn_scoped(scope, move || {
                                    serve_run(stream, &request, vault_path, key, cancel_ref);
                                });
                            match spawned {
                                Ok(handle) => {
                                    last_activity = Instant::now();
                                    runs.push(handle);
                                }
                                Err(_) => {
                                    if let Some(mut stream) = fallback {
                                        let _ = write_run_frame(
                                            &mut stream,
                                            &RunFrame::Error(ResponseError::Busy),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(SocketError::Io { source, .. })
                    if source.kind() == io::ErrorKind::WouldBlock =>
                {
                    std::thread::sleep(POLL_INTERVAL);
                }
                // Another uid was rejected before any bytes were read. Keep
                // serving the owner.
                Err(SocketError::PeerRejected { .. } | SocketError::PeerCheckFailed(_)) => {}
                Err(err) => {
                    fatal = Some(err);
                    break;
                }
            }
        }

        // Cancel and reap every in-flight child before the key is dropped.
        // The runner kills the child's whole process group, so a grandchild
        // that holds the output pipes cannot make this join hang.
        cancel.store(true, Ordering::SeqCst);
        for handle in runs {
            let _ = handle.join();
        }
        fatal
    });

    // Dropping `socket` unlinks it and releases the instance lock. Only then
    // is a `lock` answered: by that point the children are gone, the files
    // are removed and the key below is zeroized.
    drop(socket);
    session::remove_if_matches(&paths, token);
    drop(handover);
    if let Some(mut stream) = lock_ack {
        let _ = write_response(&mut stream, &Response::Locked);
    }

    match fatal {
        Some(err) => Err(err.into()),
        None => Ok(()),
    }
}

/// What one connection amounted to.
#[derive(Debug)]
enum Handled {
    /// A well-formed request was decoded and answered. Refreshes the idle
    /// timer.
    Served,
    /// Nothing usable arrived; the client got `bad_request`.
    Rejected,
    /// A `lock` request passed authentication. The connection is answered by
    /// [`run`] once the key is wiped, not here.
    Locked(UnixStream),
    /// A `run` request that passed authorization and parsing. The socket is
    /// handed to a worker thread; the accept loop must not block on it.
    Run(UnixStream, protocol::RunRequest),
}

/// Read and authenticate one request, then answer or hand the socket off.
///
/// Nothing here can panic on attacker input: every parse failure becomes
/// `bad_request`, and write failures (client vanished) are ignored so one
/// aborted client cannot take the daemon down.
fn handle_connection(mut stream: UnixStream, token: &SessionToken) -> Handled {
    let authorized = match read_request(&mut stream) {
        Ok(authorized) => authorized,
        Err(_) => return reject(&mut stream, ResponseError::BadRequest),
    };
    // The token check comes first: a request that is not for this session
    // gets a fixed answer and cannot refresh the idle timer.
    if !authorized.token().matches(token) {
        return reject(&mut stream, ResponseError::Unauthorized);
    }
    match authorized.into_request() {
        Request::Ping => {
            let _ = write_response(&mut stream, &Response::Pong);
            Handled::Served
        }
        Request::Lock => Handled::Locked(stream),
        Request::Run(request) => Handled::Run(stream, request),
    }
}

/// Answer with a one-shot error and count the connection as rejected.
fn reject(stream: &mut UnixStream, error: ResponseError) -> Handled {
    let _ = write_response(stream, &Response::Error(error));
    Handled::Rejected
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    let frame = protocol::encode_response(response)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response is too large"))?;
    stream.write_all(&frame)?;
    stream.flush()
}

fn write_run_frame(stream: &mut UnixStream, frame: &RunFrame) -> io::Result<()> {
    let encoded = protocol::encode_run_frame(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is too large"))?;
    stream.write_all(&encoded)?;
    stream.flush()
}

/// Handle one `run`: decrypt, resolve, spawn, stream redacted output.
///
/// Runs on its own thread. Every failure becomes a terminal
/// [`RunFrame::Error`] after the request has been authenticated; nothing here
/// can kill the daemon, and the vault is closed again before the child starts.
/// `cancel` is shared with the accept loop and is set by `lock`, a signal or
/// the idle timeout; the runner kills and reaps the child when it observes it.
fn serve_run(
    mut stream: UnixStream,
    request: &protocol::RunRequest,
    vault_path: &Path,
    key: &LockedKey,
    cancel: &AtomicBool,
) {
    // The daemon may have started shutting down between accepting this
    // request and spawning the worker. Decrypting and spawning after a
    // `lock` was acknowledged would put the secret back in memory.
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    // The protocol guarantees these, but the daemon must not rely on a
    // client-side check for a security decision.
    let Ok(id) = EntryId::parse_ref(&request.reference) else {
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::BadRequest));
        return;
    };
    if runner::denied_env_name(&request.env) {
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::BadRequest));
        return;
    }

    let vault = match Vault::open_with_key(vault_path, key.as_slice()) {
        Ok(vault) => vault,
        Err(_) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::Internal));
            return;
        }
    };
    let Some(credential) = vault.get_by_ref(id) else {
        drop(vault);
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::NotFound));
        return;
    };
    // Copy only the one value, then drop the decrypted vault (which zeroizes
    // the rest) before the child can run.
    let secret = Zeroizing::new(credential.password().to_owned());
    drop(vault);

    let inherited = runner::inherited_env(std::env::vars_os());
    // Re-check after decrypting: a shutdown may have started while the vault
    // was open, and no child may be spawned once the key is being wiped.
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    let result = runner::execute(
        &request.command,
        &request.env,
        secret.as_str(),
        std::path::Path::new(&request.cwd),
        &inherited,
        cancel,
        |frame| write_run_frame(&mut stream, &frame),
    );
    match result {
        Ok(exit) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Exit(exit));
        }
        Err(runner::RunError::Spawn(_)) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::SpawnFailed));
        }
        // The caller vanished or the daemon is stopping: the child is gone
        // and there is nobody left to tell.
        Err(runner::RunError::Output(_) | runner::RunError::Cancelled) => {}
    }
}

/// Read one framed request from a stream, without unbounded allocation.
fn read_request(stream: &mut UnixStream) -> Result<protocol::AuthenticatedRequest, ProtocolError> {
    let mut decoder = FrameDecoder::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if let Some(request) = decoder.next_request()? {
            return Ok(request);
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                let buffered = decoder.buffered();
                return Err(if buffered == 0 {
                    ProtocolError::EmptyMessage
                } else {
                    ProtocolError::TruncatedFrame {
                        expected: buffered,
                        actual: buffered,
                    }
                });
            }
            Ok(read) => decoder.push(&chunk[..read])?,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ProtocolError::TruncatedFrame {
                    expected: decoder.buffered(),
                    actual: decoder.buffered(),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(ProtocolError::EmptyMessage);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handover_bytes(key: &[u8], token: &SessionToken) -> Vec<u8> {
        let mut bytes = key.to_vec();
        bytes.extend_from_slice(token.as_bytes());
        bytes
    }

    #[test]
    fn reads_exactly_one_key_and_token_and_rejects_short_input() {
        let key = [7u8; KEY_LEN];
        let token = SessionToken::from_bytes(&[0x42u8; TOKEN_BYTES]).expect("token");
        let bytes = handover_bytes(&key, &token);

        let mut reader = &bytes[..];
        let handover = read_handover(&mut reader).expect("valid handover");
        assert_eq!(handover.key().as_slice(), &key);
        assert!(handover.token().matches(&token));

        for length in [0usize, 1, KEY_LEN - 1, KEY_LEN, KEY_LEN + TOKEN_BYTES - 1] {
            let mut reader = &bytes[..length];
            assert!(
                matches!(read_handover(&mut reader), Err(DaemonError::KeyHandover(_))),
                "{length} bytes must be rejected"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes_after_the_key_and_token() {
        let key = [9u8; KEY_LEN];
        let token = SessionToken::from_bytes(&[1u8; TOKEN_BYTES]).expect("token");
        let mut bytes = handover_bytes(&key, &token);
        bytes.push(0);
        let mut reader = &bytes[..];
        assert!(matches!(
            read_handover(&mut reader),
            Err(DaemonError::KeyHandover(_))
        ));
    }

    #[test]
    fn handover_debug_never_contains_key_or_token_bytes() {
        let key = [0xABu8; KEY_LEN];
        let token = SessionToken::from_bytes(&[0xCDu8; TOKEN_BYTES]).expect("token");
        let bytes = handover_bytes(&key, &token);
        let mut reader = &bytes[..];
        let handover = read_handover(&mut reader).expect("valid handover");
        let text = format!("{handover:?}");
        assert!(!text.contains("171"), "{text}");
        assert!(!text.contains("205"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }

    #[test]
    fn locked_key_length_is_checked() {
        let key = Zeroizing::new(vec![0u8; KEY_LEN + 1]);
        assert!(matches!(
            LockedKey::new(key),
            Err(DaemonError::KeyHandover(_))
        ));
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let key = Zeroizing::new(vec![0xABu8; KEY_LEN]);
        let locked = LockedKey::new(key).expect("valid key");
        let text = format!("{locked:?}");
        assert!(!text.contains("AB") && !text.contains("171"), "{text}");
        assert!(text.contains("LockedKey"));
    }

    #[test]
    fn key_handover_errors_do_not_echo_bytes() {
        let mut reader = &b"short"[..];
        let error = read_handover(&mut reader).unwrap_err();
        assert!(!error.to_string().contains("short"));
    }

    #[test]
    fn idle_timeout_parser_accepts_positive_seconds_only() {
        assert_eq!(parse_idle_timeout("60").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_idle_timeout("1").unwrap(), Duration::from_secs(1));
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(900));

        for bad in ["0", "", "-1", "1.5", "15m", " 60"] {
            assert!(parse_idle_timeout(bad).is_err(), "'{bad}' must be rejected");
        }
    }
}
