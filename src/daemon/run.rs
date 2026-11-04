//! Serving one `run`: authorize the grant, record the use, spawn the child.
//!
//! This lives beside the accept loop so `src/daemon.rs` stays under the file
//! limit. Nothing here trusts the client: the reference, the environment name
//! and the program path are all re-checked, and the grant is looked up in the
//! vault that the daemon opens itself.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::audit;
use crate::grant::{AccessRequest, Denied, GrantId, Target, UpdateError};
use crate::protocol::{self, FrameDecoder, ProtocolError, ResponseError, RunFrame};
use crate::runner;
use crate::store::EntryId;
use crate::vault::Vault;

use super::watermark::GrantWatermarks;
use super::{LockedKey, READ_TIMEOUT, unix_now};

/// Read buffer for one connection. A request is bounded by
/// [`protocol::MAX_MESSAGE_BYTES`].
const READ_CHUNK: usize = 4096;

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
    stream: UnixStream,
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
    // cannot park the daemon in a socket write; `ClientStream::write` waits
    // in `poll` and checks the stop conditions instead (TODO R.49). A failure
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
    let mut client = ClientStream {
        stream,
        stop: &stop,
        pending: Vec::new(),
    };
    // Resolve and check the audit log before doing any work. A use that
    // cannot be recorded is refused: a run the human cannot see in the audit
    // trail is worse than a run that did not happen (TODO 3.8).
    let audit_path = match audit::default_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("pmd: refusing the run: {error}");
            let _ = client.write(&RunFrame::Error(ResponseError::Internal));
            return;
        }
    };
    if let Err(error) = audit::check_writable(&audit_path) {
        eprintln!("pmd: refusing the run: {error}");
        let _ = client.write(&RunFrame::Error(ResponseError::Internal));
        return;
    }
    // Metadata only: the first reference and argv the client sent, the grant
    // that authorized (if any) and how the run ended. No secret or token is in
    // scope here, and `Event` has no field that could carry one. The result is
    // returned, not swallowed: a run that reports success must have a record
    // on disk (TODO R.68). A multi-binding run has one record and names its
    // first binding; `run_with_credentials` (TODO 4.5d) is still one call, but
    // a follow-up should carry every reference.
    let first_reference = request
        .env
        .first()
        .map(|binding| binding.reference.as_str());
    let record = |outcome: audit::Outcome,
                  grant: Option<GrantId>,
                  command: Option<&str>,
                  termination: Option<audit::Termination>|
     -> Result<(), audit::AuditError> {
        let event = audit::Event {
            source: audit::Source::Daemon,
            outcome,
            grant,
            reference: first_reference,
            command,
            args: request.command.get(1..).unwrap_or(&[]),
            termination,
        };
        audit::append(&audit_path, &event)
    };
    // Branches that already report a failure keep their answer; only the
    // warning needs to be said out loud.
    let warn = |result: Result<(), audit::AuditError>| {
        if let Err(error) = result {
            eprintln!("pmd: could not append the audit record: {error}");
        }
    };
    // The protocol guarantees these, but the daemon must not rely on a
    // client-side check for a security decision. Parse every reference, and
    // refuse duplicate or loader/shell-hook names across both maps.
    let mut ids = Vec::with_capacity(request.env.len());
    let mut names = HashSet::with_capacity(request.env.len() + request.plain_env.len());
    let mut bad_env = request.env.is_empty();
    for binding in &request.env {
        let Ok(id) = EntryId::parse_ref(&binding.reference) else {
            bad_env = true;
            break;
        };
        ids.push(id);
        if !protocol::valid_env_name(&binding.name)
            || runner::denied_env_name(&binding.name)
            || !names.insert(binding.name.as_str())
        {
            bad_env = true;
            break;
        }
    }
    for (name, value) in &request.plain_env {
        if !protocol::valid_env_name(name)
            || runner::denied_env_name(name)
            || value.contains('\0')
            || !names.insert(name.as_str())
        {
            bad_env = true;
            break;
        }
    }
    if bad_env {
        warn(record(
            audit::Outcome::BadRequest,
            None,
            request.command.first().map(String::as_str),
            None,
        ));
        let _ = client.write(&RunFrame::Error(ResponseError::BadRequest));
        return;
    }
    let Some(program) = request.command.first() else {
        warn(record(audit::Outcome::BadRequest, None, None, None));
        let _ = client.write(&RunFrame::Error(ResponseError::BadRequest));
        return;
    };
    // Resolve the program before matching it against the grant, so a symlink
    // or `..` cannot name one program in the request and run another. The
    // canonical path is also what `runner::execute` spawns, so a link swapped
    // after this point cannot redirect the exec to an unlisted program.
    let Ok(program) = std::fs::canonicalize(program) else {
        // A program that cannot be resolved can never match a grant, and
        // saying so is not an oracle: the grant is checked on the same path.
        warn(record(
            audit::Outcome::Denied,
            None,
            request.command.first().map(String::as_str),
            None,
        ));
        let _ = client.write(&RunFrame::Error(ResponseError::Denied));
        return;
    };
    let program_text = program.to_string_lossy();
    let (grant_id, secrets) = match record_use(vault_path, key, watermarks, request, &ids, &program)
    {
        Ok(value) => value,
        Err(RecordError::Denied) => {
            warn(record(
                audit::Outcome::Denied,
                None,
                Some(program_text.as_ref()),
                None,
            ));
            let _ = client.write(&RunFrame::Error(ResponseError::Denied));
            return;
        }
        Err(RecordError::NotFound) => {
            warn(record(
                audit::Outcome::NotFound,
                None,
                Some(program_text.as_ref()),
                None,
            ));
            let _ = client.write(&RunFrame::Error(ResponseError::NotFound));
            return;
        }
        Err(RecordError::Internal) => {
            warn(record(
                audit::Outcome::Internal,
                None,
                Some(program_text.as_ref()),
                None,
            ));
            let _ = client.write(&RunFrame::Error(ResponseError::Internal));
            return;
        }
    };

    let inherited = runner::inherited_env(std::env::vars_os());
    // Re-check after decrypting: a shutdown may have started while the vault
    // was open, and no child may be spawned once the key is being wiped.
    if cancel.load(Ordering::SeqCst) {
        warn(record(
            audit::Outcome::Cancelled,
            Some(grant_id),
            Some(program_text.as_ref()),
            None,
        ));
        return;
    }
    let secret_env: Vec<(String, Zeroizing<String>)> = request
        .env
        .iter()
        .map(|binding| binding.name.clone())
        .zip(secrets)
        .collect();
    // The request was validated at decode time; clamp again so a future
    // caller of `serve_run` cannot hand a child an unbounded run.
    let limits = runner::Limits {
        timeout: Some(Duration::from_secs(u64::from(
            request
                .limits
                .timeout_secs
                .clamp(1, protocol::MAX_RUN_TIMEOUT_SECS),
        ))),
        max_output_bytes: Some(
            request
                .limits
                .max_output_bytes
                .clamp(1, protocol::MAX_RUN_OUTPUT_BYTES) as usize,
        ),
    };
    let result = runner::execute(
        &program,
        &request.command[1..],
        &secret_env,
        &request.plain_env,
        Path::new(&request.cwd),
        &inherited,
        limits,
        &stop,
        |frame| client.write(&frame),
    );
    // The terminal frame is the client's only account of how the run ended,
    // so it is written after a deadline that has already passed. It is still
    // bounded, by the run's budget plus one socket timeout: a client that was
    // reading when its child was killed collects it, and one that never reads
    // cannot hold the worker, its run slot and the suspended idle timer.
    stop.set_deadline(stop.deadline().map(|deadline| deadline + READ_TIMEOUT));
    match result {
        Ok(finished) => {
            let termination = match finished.exit {
                protocol::RunExit::Code(code) => audit::Termination::Code(code),
                protocol::RunExit::Signal(signal) => audit::Termination::Signal(signal),
            };
            // The child ran and the grant use is spent, but the client must
            // not be told the run succeeded when no record attests to it
            // (TODO R.68). `pmd`'s stderr is not relayed, so the error frame
            // is the only signal an agent receives.
            if let Err(error) = record(
                audit::Outcome::Allowed,
                Some(grant_id),
                Some(program_text.as_ref()),
                Some(termination),
            ) {
                eprintln!("pmd: the run finished but its record could not be written: {error}");
                let _ = client.write(&RunFrame::Error(ResponseError::Internal));
                return;
            }
            let _ = client.write(&RunFrame::Exit(finished));
        }
        Err(runner::RunError::Spawn(_)) => {
            warn(record(
                audit::Outcome::SpawnFailed,
                Some(grant_id),
                Some(program_text.as_ref()),
                None,
            ));
            let _ = client.write(&RunFrame::Error(ResponseError::SpawnFailed));
        }
        Err(runner::RunError::Output(_)) => {
            warn(record(
                audit::Outcome::OutputError,
                Some(grant_id),
                Some(program_text.as_ref()),
                None,
            ));
        }
        // The daemon is stopping: the child is gone and there is nobody left
        // to tell.
        Err(runner::RunError::Cancelled) => {
            warn(record(
                audit::Outcome::Cancelled,
                Some(grant_id),
                Some(program_text.as_ref()),
                None,
            ));
        }
    }
}

/// A run's client connection, written one frame at a time while the run's
/// stop conditions are observed.
struct ClientStream<'a> {
    stream: UnixStream,
    stop: &'a runner::Stop<'a>,
    /// Bytes a stopped write has not delivered. They go first on the next
    /// write, so the stream stays frame-aligned when the deadline cuts a
    /// frame in half and the terminal frame follows it.
    pending: Vec<u8>,
}

impl ClientStream<'_> {
    /// Write one frame, or give up with an error once the run must stop.
    ///
    /// The socket is non-blocking here, so a reader that stops reading never
    /// trips a write timeout: the bytes wait until it reads again, the bounded
    /// frame channel backs up, and the child blocks on its full output pipe
    /// (TODO R.49). This is backpressure, not an unbounded buffer. The wait is
    /// in [`runner::CANCEL_POLL`] slices, so `lock`, a signal, a closed
    /// connection or the run's deadline still ends it promptly.
    fn write(&mut self, frame: &RunFrame) -> io::Result<()> {
        let encoded = protocol::encode_run_frame(frame)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is too large"))?;
        self.pending.extend_from_slice(&encoded);
        while !self.pending.is_empty() {
            if self.stop.requested() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the run was stopped",
                ));
            }
            match self.stream.write(&self.pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the client accepted no bytes",
                    ));
                }
                Ok(written) => {
                    self.pending.drain(..written);
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
            if self.pending.is_empty() {
                break;
            }
            // Wait for room in the socket buffer, or for a stop. A peer that
            // is gone reports an error on the next write; `poll` only bounds
            // the wait.
            let mut poll_fd = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: one initialized `pollfd`; the timeout is the runner's
            // cancel slice, so the stop check above runs at least that often.
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

/// Authorize the grant, record the use in the vault, then return one secret
/// value per requested reference.
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
/// daemon is serving (TODO R.44). The state that was read is recorded first,
/// whatever the outcome, so a revocation seen only while denying a run is
/// remembered; the use itself is only recorded after a successful save, so a
/// failed write does not claim a use the vault never recorded.
///
/// The clock is read **after** the write lock is acquired, never before: the
/// wait can last up to the lock timeout, so a time read earlier would
/// authorize a grant that has since expired (TODO R.45).
///
/// The save is attempted exactly once. Since the vault is read under the write
/// lock a failed save cannot be a lost update that a retry would merge, and a
/// save that failed *after* its rename landed already holds the increment, so
/// a retry would burn a second use of a `max_uses` grant (TODO R.58). Failing
/// closed with `Internal` is the safe answer.
fn record_use(
    vault_path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: &protocol::RunRequest,
    ids: &[EntryId],
    program: &Path,
) -> Result<(GrantId, Vec<Zeroizing<String>>), RecordError> {
    record_use_with_save(
        vault_path,
        key,
        watermarks,
        request,
        ids,
        program,
        |vault| vault.save_with_key(key.as_slice()),
    )
}

/// [`record_use`] with the vault write supplied by the caller, so a test can
/// count attempts and prove that a failed save is never retried (TODO R.58).
fn record_use_with_save<F>(
    vault_path: &Path,
    key: &LockedKey,
    watermarks: &GrantWatermarks,
    request: &protocol::RunRequest,
    ids: &[EntryId],
    program: &Path,
    mut save: F,
) -> Result<(GrantId, Vec<Zeroizing<String>>), RecordError>
where
    F: FnMut(&Vault) -> crate::Result<()>,
{
    let token_hash = request.grant.hash();
    let mut vault = Vault::open_with_key_for_update(vault_path, key.as_slice())
        .map_err(|_| RecordError::Internal)?;
    // Authorize with the time the vault was actually read, not with a time
    // from before the lock wait.
    let Some(now) = unix_now() else {
        return Err(RecordError::Internal);
    };
    watermarks.record(vault.grants());
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
    // lookup came first, a revoked, expired or exhausted grant would answer
    // differently for an existing and a nonexistent reference, which is an
    // existence oracle for a token that can never be used (R.31).
    if grant.check_grant_for_run(program, now).is_err() {
        return Err(RecordError::Denied);
    }
    // Every binding must be in scope before the use is recorded, so a run
    // cannot inject the first value and then fail on the second after the
    // grant was already spent.
    for id in ids {
        let Some(credential) = vault.get_by_ref(*id) else {
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
    if save(&vault).is_err() {
        return Err(RecordError::Internal);
    }
    watermarks.record(vault.grants());
    // Copy only the requested values, then drop the decrypted vault (which
    // zeroizes the rest) before the child can run.
    let mut secrets = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(credential) = vault.get_by_ref(*id) else {
            return Err(RecordError::Internal);
        };
        secrets.push(Zeroizing::new(credential.password().to_owned()));
    }
    Ok((grant_id, secrets))
}

/// Read one framed request from a stream, without unbounded allocation.
///
/// The whole request must arrive within [`READ_TIMEOUT`] of this call. The
/// accept loop serves one connection at a time and only checks the idle
/// deadline and a shutdown signal between connections, so the bound is per
/// connection, not per `read`: a client that trickles one byte at a time
/// cannot hold the loop, and with it the key, for as long as it likes.
pub(super) fn read_request(
    stream: &mut UnixStream,
) -> Result<protocol::AuthenticatedRequest, ProtocolError> {
    let mut chunk = [0u8; READ_CHUNK];
    read_request_with_chunk(stream, &mut chunk, Instant::now() + READ_TIMEOUT)
}

/// [`read_request`]'s loop, with the read chunk and the deadline supplied by
/// the caller so a test can observe that the chunk is wiped on every exit, the
/// rejected ones included (TODO R.66), and that the deadline cuts a slow
/// client off. Nothing in production passes a different chunk or deadline.
fn read_request_with_chunk(
    stream: &mut UnixStream,
    chunk: &mut [u8],
    deadline: Instant,
) -> Result<protocol::AuthenticatedRequest, ProtocolError> {
    let mut decoder = FrameDecoder::new();
    let truncated = |decoder: &FrameDecoder| ProtocolError::TruncatedFrame {
        expected: decoder.buffered(),
        actual: decoder.buffered(),
    };
    loop {
        if let Some(request) = decoder.next_request()? {
            return Ok(request);
        }
        // `SO_RCVTIMEO` bounds one `read`; set it to what is left of the
        // connection's budget before each one so the bound is the deadline.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return Err(truncated(&decoder));
        }
        match stream.read(chunk) {
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
            Ok(read) => push_chunk(&mut decoder, &mut chunk[..read])?,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(truncated(&decoder));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(ProtocolError::EmptyMessage);
            }
        }
    }
}

/// Append one read chunk to `decoder` and wipe it.
///
/// The chunk holds the raw request — the session-token hex and, for `run`, the
/// grant-token hex — so it is wiped on *both* paths. `push` rejects an
/// oversized declared length or a full buffer, and the old
/// `decoder.push(&chunk[..read])?` returned before the wipe, leaving that chunk
/// in the caller's stack for the rest of the connection's life (TODO R.66).
fn push_chunk(decoder: &mut FrameDecoder, chunk: &mut [u8]) -> Result<(), ProtocolError> {
    let pushed = decoder.push(chunk);
    chunk.zeroize();
    pushed
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{
        GrantWatermarks, LockedKey, READ_CHUNK, RecordError, Vault, client_closed, push_chunk,
        read_request_with_chunk, record_use_with_save, unix_now,
    };
    use crate::protocol::{self, FrameDecoder, ProtocolError};

    #[test]
    fn a_rejected_read_chunk_is_wiped_before_the_error_returns() {
        // Drive the real read loop with a frame whose 4-byte prefix declares a
        // body over the cap. `push` rejects it as soon as the prefix arrives,
        // and the chunk holds the raw frame at that moment (TODO R.66).
        let (mut client, mut daemon) = UnixStream::pair().expect("socketpair");
        let mut frame = (protocol::MAX_MESSAGE_BYTES as u32 + 1)
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(b"session-token-hex-that-must-not-be-left-behind");
        client.write_all(&frame).expect("write");

        // Zeroed by the test, so any nonzero byte after the call was written
        // by the `read` under test and not wiped.
        let mut chunk = [0u8; READ_CHUNK];
        let err = read_request_with_chunk(
            &mut daemon,
            &mut chunk,
            Instant::now() + Duration::from_secs(5),
        )
        .expect_err("prefix rejected");

        assert!(
            matches!(err, ProtocolError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got {err:?}"
        );
        assert!(
            chunk.iter().all(|byte| *byte == 0),
            "the rejected read chunk was not wiped before the error returned"
        );
    }

    #[test]
    fn a_client_that_trickles_its_request_is_cut_off_at_the_connection_deadline() {
        // One byte at a time, each well inside a per-read timeout, into a frame
        // that will never complete. Only a deadline for the whole connection
        // ends this before the client chooses to hang up.
        let (mut daemon, mut client) = UnixStream::pair().expect("socketpair");
        let (hang_up, hung_up) = std::sync::mpsc::channel::<()>();
        let trickler = std::thread::spawn(move || {
            let _ = client.write_all(&1000u32.to_be_bytes());
            while hung_up.recv_timeout(Duration::from_millis(20)).is_err() {
                if client.write_all(b"x").is_err() {
                    break;
                }
            }
        });

        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let mut chunk = [0u8; READ_CHUNK];
        let err = read_request_with_chunk(&mut daemon, &mut chunk, deadline)
            .expect_err("a trickled request never completes");
        let elapsed = started.elapsed();
        let _ = hang_up.send(());
        trickler.join().expect("trickler");

        assert!(
            matches!(err, ProtocolError::TruncatedFrame { .. }),
            "expected TruncatedFrame, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the read outlived the connection deadline by {:?}",
            elapsed - Duration::from_millis(300)
        );
    }

    #[test]
    fn a_buffer_full_chunk_is_wiped_before_the_error_returns() {
        // `BufferFull` cannot be reached through `read_request_with_chunk`: it
        // drains a complete frame at the top of every iteration, so the buffer
        // never grows past one 64 KiB body plus one read chunk. The wipe must
        // still cover that error because it is the same `push` return path.
        let mut decoder = FrameDecoder::new();
        let mut chunk = vec![0xAAu8; protocol::MAX_BUFFERED_BYTES + 1];

        let err = push_chunk(&mut decoder, &mut chunk).expect_err("over the buffer cap");

        assert!(
            matches!(err, ProtocolError::BufferFull { .. }),
            "expected BufferFull, got {err:?}"
        );
        assert!(
            chunk.iter().all(|byte| *byte == 0),
            "the buffer-full chunk was not wiped before the error returned"
        );
    }

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

    #[test]
    fn a_failed_use_save_is_attempted_exactly_once() {
        // A save that fails *after* its rename landed leaves the increment on
        // disk. Retrying re-reads that vault and marks a second use, so a
        // `max_uses` grant would deny earlier than the human approved and the
        // audit chain would show two uses from one run (TODO R.58).
        use std::cell::Cell;

        use crate::crypto::{KdfParams, encrypt, unlock_key};
        use crate::grant::{Capabilities, Grant, GrantSpec, GrantToken, Scope, TokenHash};
        use crate::store::Credential;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("vault.dat");
        let master = "test master password";
        let now = unix_now().expect("clock");
        let credential = Credential::new(
            "svc".to_owned(),
            "user".to_owned(),
            zeroize::Zeroizing::new("canary-value".to_owned()),
        )
        .expect("credential");
        let id = credential.id();
        let token = GrantToken::generate().expect("token");
        let grant = Grant::create(
            GrantSpec {
                label: "once".to_owned(),
                scope: Scope::new(vec![id], Vec::new(), None).expect("scope"),
                commands: vec![Path::new("/usr/bin/true").to_path_buf()],
                capabilities: Capabilities::RUN,
                expires_at: now + 3_600,
                max_uses: Some(2),
            },
            TokenHash::of(token.as_bytes()),
            now,
        )
        .expect("grant");
        let grant_id = grant.id();
        let plaintext = crate::store::encode(
            std::slice::from_ref(&credential),
            std::slice::from_ref(&grant),
        )
        .expect("encode payload");
        // Cheap KDF parameters: this test is about the write attempt, not the
        // KDF.
        let container =
            encrypt(&plaintext, master, KdfParams::new(8 * 1024, 1, 1)).expect("encrypt vault");
        std::fs::write(&path, &container).expect("write vault");
        let key =
            LockedKey::new(unlock_key(&container, master).expect("derive key")).expect("lock key");

        let request = protocol::RunRequest {
            limits: Default::default(),
            env: vec![protocol::EnvBinding {
                name: "TOKEN".to_owned(),
                reference: id.to_ref(),
            }],
            plain_env: Vec::new(),
            command: vec!["/usr/bin/true".to_owned()],
            cwd: "/".to_owned(),
            grant: token,
        };

        let attempts = Cell::new(0u32);
        let watermarks = GrantWatermarks::new();
        let outcome = record_use_with_save(
            &path,
            &key,
            &watermarks,
            &request,
            &[id],
            Path::new("/usr/bin/true"),
            |_vault| {
                attempts.set(attempts.get() + 1);
                Err(crate::Error::Io(std::io::Error::other(
                    "injected save failure",
                )))
            },
        );

        assert!(
            matches!(outcome, Err(RecordError::Internal)),
            "a failed use save must fail closed"
        );
        assert_eq!(
            attempts.get(),
            1,
            "a failed use save must be attempted exactly once, not retried"
        );
        let vault = Vault::open_with_key(&path, key.as_slice()).expect("reopen");
        assert_eq!(
            vault.grant(grant_id).expect("grant").uses(),
            0,
            "a failed save must not claim a use the vault never recorded"
        );
    }
}
