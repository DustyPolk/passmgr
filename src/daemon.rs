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
//! of a long-lived process. When `run` lands (TODO 2.6) the daemon decrypts,
//! spawns the child, and drops the plaintext immediately. The key is locked in
//! memory where the platform allows it and is zeroized on drop.
//!
//! # No plaintext responses
//!
//! Every request is untrusted and any same-user process can connect. The
//! daemon therefore has no request type that returns a secret; see
//! [`crate::protocol`]. This iteration answers `ping` and `lock` and rejects
//! `run` (and every malformed frame) with a fixed error code.
//!
//! # Lifetime
//!
//! One request per connection. `SIGTERM`/`SIGINT`, a successful `lock`, or
//! [`DEFAULT_IDLE_TIMEOUT`] (configurable) without a successfully handled
//! request wipe the key, remove the socket and the session file, and exit.
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
use crate::protocol::{self, FrameDecoder, ProtocolError, Request, Response, ResponseError};
use crate::session;
use crate::socket::{DaemonSocket, RuntimePaths, SocketError};
use crate::token::{SessionToken, TOKEN_BYTES};
use crate::vault::Vault;

/// How long the accept loop sleeps between non-blocking accepts.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The default idle timeout: how long the daemon keeps the key without a
/// successfully handled request.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

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
/// caller with the wrong key can never make `pmd` look alive. `key` stays
/// borrowed: the caller drops (and therefore zeroizes) it after this returns.
///
/// `idle_timeout` is measured from the last authorized, successfully decoded
/// request, not from the last byte received: a malformed, half-sent or
/// unauthorized frame must not extend the key's lifetime.
///
/// On every exit path the session file is removed, but only if it still holds
/// `token`: a newer session's file is never deleted.
pub fn run(
    vault_path: &Path,
    runtime_dir: &Path,
    key: &LockedKey,
    token: &SessionToken,
    idle_timeout: Duration,
) -> Result<(), DaemonError> {
    let paths = RuntimePaths::at(runtime_dir);
    harden_process()?;
    install_signal_handlers()?;
    detach_session();

    // Prove the key opens this vault now, then drop the plaintext.
    drop(Vault::open_with_key(vault_path, key.as_slice())?);

    let socket = DaemonSocket::bind_at(RuntimePaths::at(runtime_dir))?;
    socket.listener().set_nonblocking(true)?;

    let mut last_activity = Instant::now();
    while !shutdown_requested() {
        if last_activity.elapsed() >= idle_timeout {
            // Out of activity: wipe the key, unlink the socket and exit.
            break;
        }
        match socket.accept_peer() {
            Ok((mut stream, _peer)) => {
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                match handle_connection(&mut stream, token) {
                    // `lock`: response is written, now wipe on the way out.
                    Handled::Locked => break,
                    // Only a request that was decoded and answered counts as
                    // activity; garbage must not keep the key alive.
                    Handled::Served => last_activity = Instant::now(),
                    Handled::Rejected => {}
                }
            }
            Err(SocketError::Io { source, .. }) if source.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            // Another uid was rejected before any bytes were read. Keep
            // serving the owner.
            Err(SocketError::PeerRejected { .. } | SocketError::PeerCheckFailed(_)) => {}
            Err(err) => return Err(err.into()),
        }
    }

    // Dropping `socket` unlinks the socket and releases the instance lock.
    session::remove_if_matches(&paths, token);
    Ok(())
}

/// What one connection amounted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handled {
    /// A well-formed request was decoded and answered. Refreshes the idle
    /// timer (the `lock` case is reported separately).
    Served,
    /// Nothing usable arrived; the client got `bad_request`.
    Rejected,
    /// A `lock` request was answered: wipe and stop.
    Locked,
}

/// Serve one connection.
///
/// Nothing here can panic on attacker input: every parse failure becomes
/// `bad_request`, and write failures (client vanished) are ignored so one
/// aborted client cannot take the daemon down.
fn handle_connection(stream: &mut UnixStream, token: &SessionToken) -> Handled {
    let (response, handled) = match read_request(stream) {
        // The token check comes first: a request that is not for this session
        // gets a fixed answer and cannot refresh the idle timer.
        Ok(authorized) if !authorized.token().matches(token) => (
            Response::Error(ResponseError::Unauthorized),
            Handled::Rejected,
        ),
        Ok(authorized) => match authorized.into_request() {
            Request::Ping => (Response::Pong, Handled::Served),
            Request::Lock => (Response::Locked, Handled::Locked),
            // `run` exists in the protocol but is TODO 2.6. Refuse it
            // explicitly rather than pretending a generic parse error.
            Request::Run(_) => (Response::Error(ResponseError::Unsupported), Handled::Served),
        },
        Err(_) => (
            Response::Error(ResponseError::BadRequest),
            Handled::Rejected,
        ),
    };

    if let Ok(frame) = protocol::encode_response(&response) {
        let _ = stream.write_all(&frame);
        let _ = stream.flush();
    }
    handled
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
