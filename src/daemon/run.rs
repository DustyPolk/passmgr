//! Serving one `run`: authorize the grant, record the use, spawn the child.
//!
//! This lives beside the accept loop so `src/daemon.rs` stays under the file
//! limit. Nothing here trusts the client: the reference, the environment name
//! and the program path are all re-checked, and the grant is looked up in the
//! vault that the daemon opens itself.

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::grant::{AccessRequest, Denied, GrantId, Target, UpdateError};
use crate::protocol::{self, FrameDecoder, ProtocolError, ResponseError, RunFrame};
use crate::runner;
use crate::store::EntryId;
use crate::vault::Vault;

use super::watermark::GrantWatermarks;
use super::{LockedKey, unix_now};

/// Read buffer for one connection. A request is bounded by
/// [`protocol::MAX_MESSAGE_BYTES`].
const READ_CHUNK: usize = 4096;

/// How many times a `run` retries recording its use when the vault write
/// fails.
///
/// One attempt is the normal path now that the vault is opened under the write
/// lock (TODO R.39), so a failed save is a real I/O or crypto failure and only
/// a retry that re-reads the vault could help. It is bounded so a broken vault
/// fails closed instead of spinning, and never runs a use the vault does not
/// know about.
const USE_RECORD_ATTEMPTS: usize = 3;

/// Why a use could not be recorded. Every variant fails closed.
enum RecordError {
    /// The grant is unknown, expired, revoked or used up, its command is not
    /// allowed, or it is out of scope and the reference exists.
    Denied,
    /// The credential reference does not exist, or it is outside the grant's
    /// scope and must answer exactly like a missing one.
    NotFound,
    /// The vault could not be read, locked or saved.
    Internal,
}

/// Handle one `run`: authorize, record the use, inject, stream redacted output.
///
/// Runs on its own thread. Every failure becomes a terminal
/// [`RunFrame::Error`] after the request has been authenticated; nothing here
/// can kill the daemon, and the vault is closed again before the child starts.
/// `cancel` is shared with the accept loop and is set by `lock`, a signal or
/// the idle timeout; the runner kills and reaps the child when it observes it.
pub(super) fn serve_run(
    mut stream: UnixStream,
    request: &protocol::RunRequest,
    vault_path: &Path,
    key: &LockedKey,
    cancel: &AtomicBool,
    watermarks: &GrantWatermarks,
) {
    // The daemon may have started shutting down between accepting this
    // request and spawning the worker. Decrypting and spawning after a
    // `lock` was acknowledged would put the secret back in memory.
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    // The run stream is write-driven from here on: the worker never reads
    // another request. Make it non-blocking so a client that stops reading
    // cannot park the daemon in a socket write; `write_client_frame` waits in
    // `poll` and checks the stop conditions instead (TODO R.49). A failure
    // here means the socket is unusable, so there is nobody to answer.
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    // A run ends when its client does. A host that times out a tool call drops
    // the connection; the child must not keep the secret in its environment,
    // and the idle timeout must not stay suspended, for as long as that child
    // happens to live.
    let fd = stream.as_raw_fd();
    let client_gone = || client_closed(fd);
    let stop = runner::Stop::new(cancel, &client_gone);
    // The protocol guarantees these, but the daemon must not rely on a
    // client-side check for a security decision.
    let Ok(id) = EntryId::parse_ref(&request.reference) else {
        let _ = write_client_frame(
            &mut stream,
            &RunFrame::Error(ResponseError::BadRequest),
            &stop,
        );
        return;
    };
    if runner::denied_env_name(&request.env) {
        let _ = write_client_frame(
            &mut stream,
            &RunFrame::Error(ResponseError::BadRequest),
            &stop,
        );
        return;
    }
    let Some(program) = request.command.first() else {
        let _ = write_client_frame(
            &mut stream,
            &RunFrame::Error(ResponseError::BadRequest),
            &stop,
        );
        return;
    };
    // Resolve the program before matching it against the grant, so a symlink
    // or `..` cannot name one program in the request and run another. The
    // canonical path is also what `runner::execute` spawns, so a link swapped
    // after this point cannot redirect the exec to an unlisted program.
    let Ok(program) = std::fs::canonicalize(program) else {
        // A program that cannot be resolved can never match a grant, and
        // saying so is not an oracle: the grant is checked on the same path.
        let _ = write_client_frame(&mut stream, &RunFrame::Error(ResponseError::Denied), &stop);
        return;
    };
    let secret = match record_use(vault_path, key, watermarks, request, id, &program) {
        Ok(secret) => secret,
        Err(RecordError::Denied) => {
            let _ = write_client_frame(&mut stream, &RunFrame::Error(ResponseError::Denied), &stop);
            return;
        }
        Err(RecordError::NotFound) => {
            let _ = write_client_frame(
                &mut stream,
                &RunFrame::Error(ResponseError::NotFound),
                &stop,
            );
            return;
        }
        Err(RecordError::Internal) => {
            let _ = write_client_frame(
                &mut stream,
                &RunFrame::Error(ResponseError::Internal),
                &stop,
            );
            return;
        }
    };

    let inherited = runner::inherited_env(std::env::vars_os());
    // Re-check after decrypting: a shutdown may have started while the vault
    // was open, and no child may be spawned once the key is being wiped.
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    let result = runner::execute(
        &program,
        &request.command[1..],
        &request.env,
        secret.as_str(),
        Path::new(&request.cwd),
        &inherited,
        &stop,
        |frame| write_client_frame(&mut stream, &frame, &stop),
    );
    match result {
        Ok(exit) => {
            let _ = write_client_frame(&mut stream, &RunFrame::Exit(exit), &stop);
        }
        Err(runner::RunError::Spawn(_)) => {
            let _ = write_client_frame(
                &mut stream,
                &RunFrame::Error(ResponseError::SpawnFailed),
                &stop,
            );
        }
        // The caller vanished or the daemon is stopping: the child is gone
        // and there is nobody left to tell.
        Err(runner::RunError::Output(_) | runner::RunError::Cancelled) => {}
    }
}

/// Write one frame to a run's client while observing the run's stop conditions.
///
/// The socket is non-blocking here, so a reader that stops reading never
/// trips a write timeout: the bytes wait until it reads again, the bounded
/// frame channel backs up, and the child blocks on its full output pipe (TODO
/// R.49). This is backpressure, not an unbounded buffer. The wait is in
/// [`runner::CANCEL_POLL`] slices, so `lock`, a signal or a closed connection
/// still cancels promptly.
fn write_client_frame(
    stream: &mut UnixStream,
    frame: &RunFrame,
    stop: &runner::Stop<'_>,
) -> io::Result<()> {
    let encoded = protocol::encode_run_frame(frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is too large"))?;
    let mut bytes = encoded.as_slice();
    while !bytes.is_empty() {
        if stop.requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the run was cancelled",
            ));
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the client accepted no bytes",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
        if bytes.is_empty() {
            break;
        }
        // Wait for room in the socket buffer, or for a stop. A peer that is
        // gone reports an error on the next write; `poll` only bounds the wait.
        let mut poll_fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one initialized `pollfd`; the timeout is the runner's cancel
        // slice, so the stop check above runs at least that often.
        let ready = unsafe {
            libc::poll(
                &mut poll_fd,
                1,
                runner::CANCEL_POLL.as_millis() as libc::c_int,
            )
        };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        } else if ready > 0
            && poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the run client is gone",
            ));
        }
    }
    Ok(())
}

/// Whether the run's client has closed its end of the socket.
///
/// A `run` client sends exactly one request and then only reads frames, so a
/// closed peer is visible without consuming anything: `poll` reports
/// `POLLHUP` for a connection the peer closed, and it keeps reporting it while
/// unread bytes remain. `POLLERR` is a reset and `POLLNVAL` a socket that is
/// no longer open; both mean the same thing here.
///
/// A client that shuts down only its write half is *not* gone: it is still
/// reading, so its run continues. Only a fully closed connection (the host
/// dropped it, or died) cancels the child.
fn client_closed(fd: RawFd) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    // SAFETY: one initialized `pollfd`; a zero timeout means do not block.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if ready <= 0 {
        return false;
    }
    poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Authorize the grant, record the use in the vault, then return the one
/// secret value to inject.
///
/// The use is written before the secret is copied and before the child can
/// start, so a crash or a bug cannot let a use-limited grant exceed its limit.
/// The vault is read **under the write lock**, so the grant that is authorized
/// and marked is the one on disk: a concurrent run recording its own use (or a
/// revocation) can never turn this into `internal` (TODO R.39).
///
/// A vault whose grant state went backwards (an older copy was put back) is
/// refused with `Denied` before anything is authorized or spawned, so a
/// rollback cannot resurrect a spent use or a cleared revocation while this
/// daemon is serving (TODO R.44). The mark is only raised after a successful
/// save, so a failed write does not claim a use the vault never recorded.
///
/// The clock is read **after** the write lock is acquired, never before: the
/// wait can last up to the lock timeout (and is repeated on a failed save), so
/// a time read earlier would authorize a grant that has since expired (TODO
/// R.45).
fn record_use(
    vault_path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: &protocol::RunRequest,
    id: EntryId,
    program: &Path,
) -> Result<Zeroizing<String>, RecordError> {
    let token_hash = request.grant.hash();
    for _ in 0..USE_RECORD_ATTEMPTS {
        let mut vault = Vault::open_with_key_for_update(vault_path, key.as_slice())
            .map_err(|_| RecordError::Internal)?;
        // Authorize with the time the vault was actually read, not with a
        // time from before the lock wait.
        let Some(now) = unix_now() else {
            return Err(RecordError::Internal);
        };
        if watermarks.check(vault.grants()).is_err() {
            // Fail closed without consuming anything: the file on disk has
            // regressed, so the daemon cannot trust its grant state.
            return Err(RecordError::Denied);
        }
        let Some(grant) = vault
            .grants()
            .iter()
            .find(|grant| grant.matches_token(&token_hash))
        else {
            return Err(RecordError::Denied);
        };
        // Decide everything that does not need the credential first. If the
        // lookup came first, a revoked, expired or exhausted grant would
        // answer differently for an existing and a nonexistent reference,
        // which is an existence oracle for a token that can never be used
        // (R.31).
        if grant.check_grant_for_run(program, now).is_err() {
            return Err(RecordError::Denied);
        }
        let Some(credential) = vault.get_by_ref(id) else {
            return Err(RecordError::NotFound);
        };
        let tags = credential.tags().to_vec();
        let target = Target::new(credential.id(), &tags);
        match grant.authorizes(&AccessRequest::run(target, None, program), now) {
            Ok(()) => {}
            // An existing reference outside the scope answers exactly like a
            // nonexistent one, or the daemon becomes an existence oracle for
            // every in-vault reference (DECISIONS.md).
            Err(Denied::OutOfScope) => return Err(RecordError::NotFound),
            Err(_) => return Err(RecordError::Denied),
        }
        let grant_id: GrantId = grant.id();

        let marked = vault
            .grant_mut(grant_id)
            .ok_or(RecordError::Internal)?
            .mark_used(now);
        match marked {
            Ok(()) => {}
            Err(UpdateError::Denied(_)) => return Err(RecordError::Denied),
            Err(UpdateError::TimestampOutOfRange) => return Err(RecordError::Internal),
        }
        if vault.save_with_key(key.as_slice()).is_err() {
            // The write failed, so the use was not recorded. Never run on a
            // use that the vault does not know about; re-read and re-authorize
            // from scratch instead of merging.
            continue;
        }
        watermarks.record(vault.grants());
        // Copy only the one value, then drop the decrypted vault (which
        // zeroizes the rest) before the child can run.
        let Some(credential) = vault.get_by_ref(id) else {
            return Err(RecordError::Internal);
        };
        return Ok(Zeroizing::new(credential.password().to_owned()));
    }
    Err(RecordError::Internal)
}

/// Read one framed request from a stream, without unbounded allocation.
pub(super) fn read_request(
    stream: &mut UnixStream,
) -> Result<protocol::AuthenticatedRequest, ProtocolError> {
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
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::client_closed;

    #[test]
    fn an_open_client_is_not_closed() {
        let (daemon, _client) = UnixStream::pair().expect("socketpair");
        assert!(!client_closed(daemon.as_raw_fd()));
    }

    #[test]
    fn a_client_that_shut_down_its_write_half_is_still_there() {
        // It may have sent its request and be reading frames; that client is
        // alive, so its run must not be cancelled.
        let (daemon, client) = UnixStream::pair().expect("socketpair");
        client.shutdown(Shutdown::Write).expect("shutdown");
        assert!(!client_closed(daemon.as_raw_fd()));
    }

    #[test]
    fn a_dropped_client_is_closed() {
        let (daemon, client) = UnixStream::pair().expect("socketpair");
        drop(client);
        assert!(client_closed(daemon.as_raw_fd()));
    }

    #[test]
    fn unread_bytes_do_not_hide_a_dropped_client() {
        let (mut daemon, mut client) = UnixStream::pair().expect("socketpair");
        client.write_all(b"left over").expect("write");
        drop(client);
        assert!(client_closed(daemon.as_raw_fd()));
        // Detection must not consume a byte: whatever the protocol layer
        // still has to read stays readable.
        let mut buf = [0u8; 4];
        assert_eq!(daemon.read(&mut buf).expect("read"), 4);
        assert_eq!(&buf, b"left");
    }
}
