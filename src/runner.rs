//! Spawn one child with a single secret injected and relay redacted output.
//!
//! This is the mechanism behind a daemon `run` request (TODO 2.6c) and, later,
//! a human `pm run` (TODO 3.7). The caller supplies an argv (never a shell
//! string), the environment variable name to fill, and the value. Everything
//! the child writes is passed through [`Redactor`] before it leaves this
//! module, so the value cannot reach the caller by ordinary output.
//!
//! # Child environment
//!
//! The child does not inherit the daemon's environment. It starts from a fixed
//! allowlist ([`INHERITED_ENV`] plus `LC_*`) and then gets exactly one more
//! variable, the injected secret. [`denied_env_name`] refuses loader and shell
//! hook names even if a request asks for them: injecting a value into
//! `LD_PRELOAD` or `BASH_ENV` would change which code the child runs.
//!
//! # Limits
//!
//! The child receives the value in its environment, so a deliberately hostile
//! child can still exfiltrate it by writing a file, opening a socket, or
//! letting another same-user process read `/proc/<pid>/environ`. Redaction
//! protects the *relayed output* only. Per-call timeouts belong to TODO 4.5.
//!
//! # Stopping a run
//!
//! The child is started in its own process group and every stop path signals
//! the whole group (SIGTERM, then SIGKILL). That reaches grandchildren that
//! inherited the output pipes: without it, a child that leaves a background
//! process behind makes the pipe never reach EOF and shutdown waits forever.
//! The readers also poll a stop flag while waiting for input, so a process
//! that somehow escaped the group still cannot make the join unbounded.
//!
//! Two external conditions stop a run, both checked in the relay loop and in
//! the wait-for-exit loop: the daemon is shutting down ([`Stop::on_cancel`]),
//! and the run's client is gone (`Stop::new`). The second matters because a
//! client that drops its connection is how an agent host reports a timed-out
//! tool call: without it the child keeps running with the secret in its
//! environment, and the idle timeout stays suspended for as long as the child
//! lives.
//!
//! A run that finishes normally also kills whatever is left in its process
//! group before returning: a child that backgrounds a daemon (`gradle`,
//! `ssh`'s `ControlPersist`, a credential cache) would otherwise keep the
//! injected value in its environment after the run, after `lock` and after
//! `pmd` exits. A descendant that leaves the group by starting a new session
//! (`setsid`) escapes that cleanup; that is an accepted limit, documented in
//! `SECURITY.md` limit 1.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::protocol::{MAX_CHUNK_BYTES, MAX_SIGNAL, RunExit, RunFrame};
use crate::redact::Redactor;

/// Environment variables the child inherits from the daemon's own environment.
///
/// Kept deliberately small: enough for `PATH` lookup, a home directory,
/// locale and a terminal, and nothing that carries unrelated secrets.
pub const INHERITED_ENV: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR", "TERM",
];

/// Prefixes of additional variables inherited from the daemon (locales).
const INHERITED_PREFIXES: &[&str] = &["LC_"];

/// How often the output loop, the pipe readers and a blocked run-stream write
/// check for a shutdown.
pub(crate) const CANCEL_POLL: Duration = Duration::from_millis(100);

/// How long a killed process group gets to act on SIGTERM before SIGKILL.
const TERM_GRACE: Duration = Duration::from_millis(100);

/// Read size per pipe read. Deliberately smaller than
/// [`MAX_CHUNK_BYTES`]: redaction can expand output (one marker per match),
/// and [`emit_chunks`] splits anything larger before it becomes a frame.
const READ_CHUNK: usize = 8 * 1024;

/// True when the daemon must never set this variable to a secret.
///
/// These names make a loader or shell execute something, so a value placed in
/// them is not just data. The list follows `MCP.md` for `run_with_credentials`.
pub fn denied_env_name(name: &str) -> bool {
    matches!(
        name,
        "BASH_ENV" | "ENV" | "PROMPT_COMMAND" | "IFS" | "PATH" | "HOME" | "SHELLOPTS" | "PS4"
    ) || name.starts_with("LD_")
        || name.starts_with("DYLD_")
}

/// Filter the daemon's environment down to the child's inherited allowlist.
///
/// Non-UTF-8 names are dropped: every allowed name is ASCII, and comparing
/// bytes would needlessly complicate the policy.
pub fn inherited_env<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter(|(name, _)| {
            let Some(name) = name.to_str() else {
                return false;
            };
            INHERITED_ENV.contains(&name)
                || INHERITED_PREFIXES
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
        })
        .collect()
}

/// Why [`execute`] did not produce an exit status.
#[derive(Debug)]
pub enum RunError {
    /// The child could not be started (missing program, permission, bad env
    /// name). Nothing ran.
    Spawn(io::Error),
    /// Output could not be delivered to the caller: the client is gone, or the
    /// daemon is shutting down. The child has been killed.
    Output(io::Error),
    /// The daemon is shutting down (signal or `lock`); the child was killed.
    Cancelled,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(err) => write!(f, "could not start the child: {err}"),
            Self::Output(err) => write!(f, "could not relay child output: {err}"),
            Self::Cancelled => f.write_str("the run was cancelled"),
        }
    }
}

impl std::error::Error for RunError {}

/// The external conditions that stop a run.
///
/// A run stops when the daemon is shutting down (`lock`, a signal, the idle
/// timeout) or when the caller that asked for it is gone. Both are polled by
/// the output loop and by the wait-for-exit loop, so neither a noisy child nor
/// a silent one can delay the kill.
///
/// The client predicate is a closure rather than a flag so the caller can
/// poll its own socket without a watchdog thread; it runs at most once per
/// [`CANCEL_POLL`] slice in the silent case (and once per relayed frame while
/// output flows).
pub struct Stop<'a> {
    cancel: &'a AtomicBool,
    client_gone: Option<&'a dyn Fn() -> bool>,
}

impl<'a> Stop<'a> {
    /// Stop only when `cancel` becomes true (no client to watch).
    pub fn on_cancel(cancel: &'a AtomicBool) -> Self {
        Self {
            cancel,
            client_gone: None,
        }
    }

    /// Also stop when `client_gone` reports that the caller disconnected.
    pub fn new(cancel: &'a AtomicBool, client_gone: &'a dyn Fn() -> bool) -> Self {
        Self {
            cancel,
            client_gone: Some(client_gone),
        }
    }

    /// Whether the run must stop now.
    ///
    /// Also polled by the daemon's run-stream writer, so a write that is
    /// waiting for a slow reader still observes `lock`, a signal or a vanished
    /// client (TODO R.49).
    pub(crate) fn requested(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || self.client_gone.is_some_and(|gone| gone())
    }
}

/// A message from a pipe reader to the output loop.
enum Message {
    Frame(RunFrame),
    /// This reader reached EOF (or stopped because the receiver went away).
    Done,
}

/// Run `program` with `args` and `env_name=secret` injected, streaming redacted
/// output.
///
/// `program` is executed exactly as given, and becomes `argv[0]` (the default
/// for [`Command`]). The daemon passes the same canonical path it checked
/// against the grant's allowlist, so the program that was authorized is the
/// program that runs: a symlink swapped between the check and the spawn can no
/// longer redirect the exec, and a multi-call binary is not handed a caller-
/// chosen `argv[0]`.
///
/// `inherited` is the already-filtered environment the child starts from
/// (usually [`inherited_env`] of the daemon's own variables). `stop` is polled
/// while the child runs; when it reports a shutdown or a vanished client the
/// child is killed and [`RunError::Cancelled`] is returned.
///
/// `cwd` is the caller's working directory. The child starts there, so a
/// relative argument means what the caller meant; the daemon never runs a
/// child in its own (unlock-time) directory.
///
/// `emit` is called on this thread only, in output order per stream, and must
/// write the frame before returning. Exactly one [`RunFrame::Exit`] is emitted
/// on success; an error is returned instead when the run could not finish.
/// No frame ever contains the un-redacted value.
// The arguments are the orthogonal inputs of a process spawn. Grouping them
// into a struct would only move the arity, and `program` must stay separate
// from `args` so the caller cannot accidentally let `argv[0]` pick the binary.
#[allow(clippy::too_many_arguments)]
pub fn execute<F>(
    program: &Path,
    args: &[String],
    env_name: &str,
    secret: &str,
    cwd: &Path,
    inherited: &[(OsString, OsString)],
    stop: &Stop<'_>,
    mut emit: F,
) -> Result<RunExit, RunError>
where
    F: FnMut(RunFrame) -> io::Result<()>,
{
    // A client that left between sending the request and the spawn gets no
    // child at all. The caller checks the same condition before decrypting,
    // but a request can be authorized and then wait behind the vault lock.
    if stop.requested() {
        return Err(RunError::Cancelled);
    }
    if program.as_os_str().is_empty() {
        return Err(RunError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the program is empty",
        )));
    }
    // The protocol already validates this, but `Command::env` must never be
    // handed a name it would panic on.
    if env_name.is_empty() || env_name.contains('=') || env_name.contains('\0') {
        return Err(RunError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the environment variable name is invalid",
        )));
    }

    let mut command = Command::new(program);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (name, value) in inherited {
        command.env(name, value);
    }
    // The value is copied into the child's environment block by the kernel;
    // this process keeps it only in `secret` (owned by the caller) and in the
    // two redactors below, which zeroize on drop.
    command.env(env_name, secret);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Give the child its own process group so a later stop can signal every
    // process it started, not just the child. `setpgid` is async-signal-safe,
    // which is the only thing allowed between `fork` and `exec`.
    // SAFETY: `pre_exec` runs after `fork` in the child; the closure only
    // calls `setpgid` and reads `errno` through `last_os_error`.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(RunError::Spawn)?;
    drop(command);
    let pgid = child.id() as libc::pid_t;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let (sender, receiver) = mpsc::sync_channel::<Message>(8);
    let readers_stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::with_capacity(2);
    for (reader, is_stderr) in [
        (Box::new(stdout) as Box<dyn OutputPipe + Send>, false),
        (Box::new(stderr) as Box<dyn OutputPipe + Send>, true),
    ] {
        let redactor = Redactor::new(secret.as_bytes());
        let reader_stop = Arc::clone(&readers_stop);
        match spawn_reader(reader, redactor, sender.clone(), is_stderr, reader_stop) {
            Ok(handle) => readers.push(handle),
            Err(err) => {
                drop(sender);
                abort(&mut child, receiver, readers, &readers_stop);
                return Err(RunError::Output(err));
            }
        }
    }
    drop(sender);

    let emit_result = relay(&receiver, stop, &mut emit);
    match emit_result {
        Relay::Finished => {
            // Both pipes reached EOF. The child may have closed them and kept
            // running, so keep waiting for it -- but poll the stop conditions
            // as well. A plain `wait()` here would make `lock`, `SIGTERM`, the
            // idle timeout and a vanished client wait for a child that closed
            // its output on purpose. `leader_exited` is a `waitid(WNOHANG)`
            // that leaves the leader unreaped; the reap happens after the
            // group below has been signalled.
            loop {
                match leader_exited(pgid) {
                    Ok(true) => {
                        // The leader has exited but is still an unreaped
                        // zombie, so its pid -- and the process-group id
                        // derived from it -- cannot be recycled: the group
                        // signal below can only reach this run. Everything
                        // left in the group inherited the injected value and
                        // the run is over (both pipes are at EOF), so none of
                        // it may outlive the run. Signal before reaping; a
                        // reaped pid could already belong to another group.
                        signal_group(pgid, libc::SIGKILL);
                        let status = child.wait();
                        join_all(readers);
                        return status.map(exit_status).map_err(RunError::Output);
                    }
                    Ok(false) => {
                        if stop.requested() {
                            abort(&mut child, receiver, readers, &readers_stop);
                            return Err(RunError::Cancelled);
                        }
                        std::thread::sleep(CANCEL_POLL);
                    }
                    Err(err) => {
                        abort(&mut child, receiver, readers, &readers_stop);
                        return Err(RunError::Output(err));
                    }
                }
            }
        }
        Relay::OutputError(err) => {
            abort(&mut child, receiver, readers, &readers_stop);
            Err(RunError::Output(err))
        }
        Relay::Cancelled => {
            abort(&mut child, receiver, readers, &readers_stop);
            Err(RunError::Cancelled)
        }
    }
}

/// How the output loop ended.
enum Relay {
    /// Both readers reported EOF.
    Finished,
    /// Writing a frame to the caller failed.
    OutputError(io::Error),
    /// The daemon is shutting down or the client is gone.
    Cancelled,
}

/// Forward frames until both readers are done, the caller fails, or the
/// daemon is shutting down.
///
/// Deliberately takes no `Child`: it must never reap the group leader. While
/// the leader is an unreaped zombie its pid (and the process-group id derived
/// from it) cannot be reused, so a later [`terminate`] cannot signal an
/// unrelated group. That matters when the leader exits while a grandchild
/// still holds the output pipes: the run must keep waiting for the pipes, and
/// a cancel may arrive minutes later. The `Finished` path below reaps the
/// child only after both pipes reached EOF.
fn relay<F>(receiver: &Receiver<Message>, stop: &Stop<'_>, emit: &mut F) -> Relay
where
    F: FnMut(RunFrame) -> io::Result<()>,
{
    let mut finished = 0usize;
    loop {
        // Observe a stop even while a noisy child keeps the channel full: a
        // `lock`, a signal or a vanished client must not wait for the output
        // to pause.
        if stop.requested() {
            return Relay::Cancelled;
        }
        match receiver.recv_timeout(CANCEL_POLL) {
            Ok(Message::Frame(frame)) => {
                if let Err(err) = emit(frame) {
                    return Relay::OutputError(err);
                }
            }
            Ok(Message::Done) => {
                finished += 1;
                if finished == 2 {
                    return Relay::Finished;
                }
            }
            // The sender side is gone: both readers stopped without a Done.
            Err(RecvTimeoutError::Disconnected) => return Relay::Finished,
            // A child that exited before closing a pipe held by a grandchild
            // is exactly the case TODO 4.5's timeout and process-group kill
            // handles; keep waiting for the pipe here. Do not poll the child
            // here: `try_wait` would reap a finished leader and free its pid
            // (and pgid) while the group is still in use.
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Whether the group leader has exited, without reaping it.
///
/// [`Child::try_wait`] reaps, which frees the pid and therefore the
/// process-group id while descendants may still be using it. `WNOWAIT`
/// observes the exit and leaves the zombie in place, so a following
/// `kill(-pgid)` cannot signal an unrelated group.
fn leader_exited(pid: libc::pid_t) -> io::Result<bool> {
    // SAFETY: `siginfo_t` is plain-old data; zeroing and passing it for the
    // kernel to fill is valid, and no pointer is stored in it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `P_PID` selects one child by pid; `infop` points at the valid
    // `siginfo_t` above. Failure is reported through `last_os_error`.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // `si_pid()` reads the leading pid field, which is the same offset in the
    // `SIGCHLD` and `kill` shapes of the union; 0 means nothing is reapable.
    // SAFETY: the kernel filled `info`.
    Ok(unsafe { info.si_pid() } == pid)
}

/// Kill the child and every process it started, then stop the readers.
fn abort(
    child: &mut Child,
    receiver: Receiver<Message>,
    readers: Vec<JoinHandle<()>>,
    stop: &AtomicBool,
) {
    // Tell the readers first: a process that escaped the group could still
    // hold a pipe open, and the reader must not wait for an EOF that never
    // comes. They observe the flag within one `CANCEL_POLL` slice.
    stop.store(true, Ordering::SeqCst);
    terminate(child);
    // Dropping the receiver unblocks readers waiting to send.
    drop(receiver);
    join_all(readers);
}

/// Kill the child's whole process group, then reap the child.
///
/// The group is the one `execute` created with `setpgid`; a negative pid
/// reaches every descendant that inherited the output pipes. SIGKILL follows
/// SIGTERM unconditionally after a short grace period.
///
/// The leader is deliberately not reaped between the two signals: while it is
/// a zombie its pid -- and therefore the process-group id -- cannot be reused,
/// so the group signal can never hit an unrelated group.
fn terminate(child: &mut Child) {
    let pgid = child.id() as libc::pid_t;
    signal_group(pgid, libc::SIGTERM);
    std::thread::sleep(TERM_GRACE);
    signal_group(pgid, libc::SIGKILL);
    // `setpgid` runs in the child, so a stop that races the spawn would miss
    // the group; kill the leader directly too so `wait` cannot block.
    let _ = child.kill();
    let _ = child.wait();
}

fn signal_group(pgid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: a negative pid signals the process group with that id; no
    // pointers are involved. Failure (ESRCH: already gone) is ignored.
    unsafe {
        libc::kill(-pgid, signal);
    }
}

fn join_all(readers: Vec<JoinHandle<()>>) {
    for reader in readers {
        let _ = reader.join();
    }
}

/// A relayed output pipe: readable, and pollable before a blocking read.
///
/// A trait alias would say this in one bound, but stable Rust has none.
trait OutputPipe: Read + AsRawFd {}

impl<T: Read + AsRawFd> OutputPipe for T {}

/// Start one pipe reader.
fn spawn_reader(
    mut reader: Box<dyn OutputPipe + Send>,
    mut redactor: Redactor,
    sender: SyncSender<Message>,
    is_stderr: bool,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    let fd = reader.as_raw_fd();
    std::thread::Builder::new()
        .name(if is_stderr {
            "pmd-run-stderr".into()
        } else {
            "pmd-run-stdout".into()
        })
        .spawn(move || {
            let mut buffer = [0u8; READ_CHUNK];
            loop {
                if !wait_readable(fd, &stop) {
                    // The run is being aborted: the client is gone or the
                    // daemon is stopping. There is no one to hand a tail to.
                    return;
                }
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        let output = redactor.push(&buffer[..read]);
                        if !emit_chunks(&sender, output, is_stderr) {
                            return;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let tail = redactor.finish();
            let _ = emit_chunks(&sender, tail, is_stderr);
            let _ = sender.send(Message::Done);
        })
}

/// Wait until the pipe has data, returning false when the run is aborted.
///
/// A plain blocking `read` cannot be interrupted, and a grandchild that
/// inherited the pipe keeps EOF away after the child exits. Polling in
/// `CANCEL_POLL` slices bounds how long an abort can wait for that reader.
fn wait_readable(fd: RawFd, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: exactly one initialized `pollfd` is passed, and the count
        // matches. `timeout` is a small positive number of milliseconds.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, CANCEL_POLL.as_millis() as libc::c_int) };
        if ready > 0 {
            // Readable, hung up or errored: `read` returns data, 0 or an
            // error without blocking, which is all the caller needs.
            return true;
        }
        if ready == 0 {
            continue;
        }
        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return false;
    }
}

/// Split redacted bytes into protocol-sized frames. Returns false when the
/// receiving side is gone, so the reader can stop.
fn emit_chunks(sender: &SyncSender<Message>, data: Vec<u8>, is_stderr: bool) -> bool {
    for chunk in data.chunks(MAX_CHUNK_BYTES) {
        let frame = if is_stderr {
            RunFrame::Stderr(chunk.to_vec())
        } else {
            RunFrame::Stdout(chunk.to_vec())
        };
        if sender.send(Message::Frame(frame)).is_err() {
            return false;
        }
    }
    true
}

/// Map a Unix exit status onto the protocol's exit representation.
fn exit_status(status: ExitStatus) -> RunExit {
    if let Some(code) = status.code() {
        return RunExit::Code(code as u8);
    }
    match status.signal() {
        Some(signal) if (1..=i32::from(MAX_SIGNAL)).contains(&signal) => {
            RunExit::Signal(signal as u8)
        }
        // Not representable; report a plain failure rather than inventing a
        // signal number the caller might interpret as something else.
        _ => RunExit::Code(1),
    }
}

#[cfg(test)]
mod tests;
