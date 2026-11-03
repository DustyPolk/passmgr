//! Serving one `run`: authorize the grant, record the use, spawn the child.
//!
//! This lives beside the accept loop so `src/daemon.rs` stays under the file
//! limit. Nothing here trusts the client: the reference, the environment name
//! and the program path are all re-checked, and the grant is looked up in the
//! vault that the daemon opens itself.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::grant::{AccessRequest, GrantId, Target, UpdateError};
use crate::protocol::{self, FrameDecoder, ProtocolError, ResponseError, RunFrame};
use crate::runner;
use crate::store::EntryId;
use crate::vault::Vault;

use super::{LockedKey, unix_now, write_run_frame};

/// Read buffer for one connection. A request is bounded by
/// [`protocol::MAX_MESSAGE_BYTES`].
const READ_CHUNK: usize = 4096;

/// How many times a `run` retries when another writer changed the vault
/// between opening it and taking the write lock.
///
/// Concurrent runs each record a use, so one of them can lose that race. The
/// window is tiny and the fresh vault is re-authorized from scratch, so a
/// bounded retry is safe; after this many attempts the run fails closed.
const USE_RECORD_ATTEMPTS: usize = 8;

/// Why a use could not be recorded. Every variant fails closed.
enum RecordError {
    /// The grant is unknown, expired, revoked, used up or out of scope.
    Denied,
    /// The credential reference does not exist.
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
    let Some(program) = request.command.first() else {
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::BadRequest));
        return;
    };
    // Resolve the program before matching it against the grant, so a symlink
    // or `..` cannot name one program in the request and run another.
    let Ok(program) = std::fs::canonicalize(program) else {
        // A program that cannot be resolved can never match a grant, and
        // saying so is not an oracle: the grant is checked on the same path.
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::Denied));
        return;
    };
    let Some(now) = unix_now() else {
        let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::Internal));
        return;
    };

    let secret = match record_use(vault_path, key, request, id, &program, now) {
        Ok(secret) => secret,
        Err(RecordError::Denied) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::Denied));
            return;
        }
        Err(RecordError::NotFound) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::NotFound));
            return;
        }
        Err(RecordError::Internal) => {
            let _ = write_run_frame(&mut stream, &RunFrame::Error(ResponseError::Internal));
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
        &request.command,
        &request.env,
        secret.as_str(),
        Path::new(&request.cwd),
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

/// Authorize the grant, record the use in the vault, then return the one
/// secret value to inject.
///
/// The use is written before the secret is copied and before the child can
/// start, so a crash or a bug cannot let a use-limited grant exceed its limit.
/// If another process (or another run) changed the vault in between, the whole
/// decision is retried against the new state rather than merged.
fn record_use(
    vault_path: &Path,
    key: &LockedKey,
    request: &protocol::RunRequest,
    id: EntryId,
    program: &Path,
    now: u64,
) -> Result<Zeroizing<String>, RecordError> {
    let token_hash = request.grant.hash();
    for _ in 0..USE_RECORD_ATTEMPTS {
        let mut vault =
            Vault::open_with_key(vault_path, key.as_slice()).map_err(|_| RecordError::Internal)?;
        let Some(grant) = vault
            .grants()
            .iter()
            .find(|grant| grant.matches_token(&token_hash))
        else {
            return Err(RecordError::Denied);
        };
        let Some(credential) = vault.get_by_ref(id) else {
            return Err(RecordError::NotFound);
        };
        let tags = credential.tags().to_vec();
        let target = Target::new(credential.id(), &tags);
        if grant
            .authorizes(&AccessRequest::run(target, None, program), now)
            .is_err()
        {
            return Err(RecordError::Denied);
        }
        let grant_id: GrantId = grant.id();

        if vault.lock_for_update().is_err() {
            // Another writer won the race. Re-open and re-authorize.
            continue;
        }
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
            // use that the vault does not know about.
            continue;
        }
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
