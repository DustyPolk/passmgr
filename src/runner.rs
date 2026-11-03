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
//! protects the *relayed output* only. Per-call timeouts and process-group
//! termination belong to TODO 4.5.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
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

/// How often the output loop checks for a daemon shutdown.
const CANCEL_POLL: Duration = Duration::from_millis(100);

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

/// A message from a pipe reader to the output loop.
enum Message {
    Frame(RunFrame),
    /// This reader reached EOF (or stopped because the receiver went away).
    Done,
}

/// Run `argv` with `env_name=secret` injected, streaming redacted output.
///
/// `inherited` is the already-filtered environment the child starts from
/// (usually [`inherited_env`] of the daemon's own variables). `cancel` is
/// polled while the child runs; when it becomes true the child is killed and
/// [`RunError::Cancelled`] is returned.
///
/// `emit` is called on this thread only, in output order per stream, and must
/// write the frame before returning. Exactly one [`RunFrame::Exit`] is emitted
/// on success; an error is returned instead when the run could not finish.
/// No frame ever contains the un-redacted value.
pub fn execute<F>(
    argv: &[String],
    env_name: &str,
    secret: &str,
    inherited: &[(OsString, OsString)],
    cancel: &AtomicBool,
    mut emit: F,
) -> Result<RunExit, RunError>
where
    F: FnMut(RunFrame) -> io::Result<()>,
{
    let Some(program) = argv.first() else {
        return Err(RunError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the command is empty",
        )));
    };
    // The protocol already validates this, but `Command::env` must never be
    // handed a name it would panic on.
    if env_name.is_empty() || env_name.contains('=') || env_name.contains('\0') {
        return Err(RunError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the environment variable name is invalid",
        )));
    }

    let mut command = Command::new(program);
    command.args(&argv[1..]);
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

    let mut child = command.spawn().map_err(RunError::Spawn)?;
    drop(command);

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let (sender, receiver) = mpsc::sync_channel::<Message>(8);
    let mut readers = Vec::with_capacity(2);
    for (reader, is_stderr) in [
        (Box::new(stdout) as Box<dyn Read + Send>, false),
        (Box::new(stderr) as Box<dyn Read + Send>, true),
    ] {
        let redactor = Redactor::new(secret.as_bytes());
        match spawn_reader(reader, redactor, sender.clone(), is_stderr) {
            Ok(handle) => readers.push(handle),
            Err(err) => {
                drop(sender);
                abort(&mut child, receiver, readers);
                return Err(RunError::Output(err));
            }
        }
    }
    drop(sender);

    let emit_result = relay(&receiver, cancel, &mut emit, &mut child);
    match emit_result {
        Relay::Finished => {
            // Both pipes reached EOF. The child may have closed them and kept
            // running, so keep waiting for it -- but poll the cancel flag as
            // well. A plain `wait()` here would make `lock`, `SIGTERM` and the
            // idle timeout wait for a child that closed its output on purpose.
            // `try_wait` is a `waitpid(WNOHANG)` internally.
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        join_all(readers);
                        return Ok(exit_status(status));
                    }
                    Ok(None) => {
                        if cancel.load(Ordering::SeqCst) {
                            abort(&mut child, receiver, readers);
                            return Err(RunError::Cancelled);
                        }
                        std::thread::sleep(CANCEL_POLL);
                    }
                    Err(err) => {
                        abort(&mut child, receiver, readers);
                        return Err(RunError::Output(err));
                    }
                }
            }
        }
        Relay::OutputError(err) => {
            abort(&mut child, receiver, readers);
            Err(RunError::Output(err))
        }
        Relay::Cancelled => {
            abort(&mut child, receiver, readers);
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
    /// The daemon asked the run to stop.
    Cancelled,
}

/// Forward frames until both readers are done, the caller fails, or the
/// daemon is shutting down.
fn relay<F>(
    receiver: &Receiver<Message>,
    cancel: &AtomicBool,
    emit: &mut F,
    child: &mut Child,
) -> Relay
where
    F: FnMut(RunFrame) -> io::Result<()>,
{
    let mut finished = 0usize;
    loop {
        // Observe cancellation even while a noisy child keeps the channel
        // full: a `lock` or signal must not wait for the output to pause.
        if cancel.load(Ordering::SeqCst) {
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
            Err(RecvTimeoutError::Timeout) => {
                // A child that exited before closing a pipe held by a
                // grandchild is exactly the case TODO 4.5's timeout and
                // process-group kill handles; keep waiting for the pipe here.
                let _ = child.try_wait();
            }
        }
    }
}

/// Kill the child, stop the readers and reap everything.
fn abort(child: &mut Child, receiver: Receiver<Message>, readers: Vec<JoinHandle<()>>) {
    let _ = child.kill();
    let _ = child.wait();
    // Dropping the receiver unblocks readers waiting to send; killing the
    // child closes its pipe ends for readers waiting to read.
    drop(receiver);
    join_all(readers);
}

fn join_all(readers: Vec<JoinHandle<()>>) {
    for reader in readers {
        let _ = reader.join();
    }
}

/// Start one pipe reader.
fn spawn_reader(
    mut reader: Box<dyn Read + Send>,
    mut redactor: Redactor,
    sender: SyncSender<Message>,
    is_stderr: bool,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name(if is_stderr {
            "pmd-run-stderr".into()
        } else {
            "pmd-run-stdout".into()
        })
        .spawn(move || {
            let mut buffer = [0u8; READ_CHUNK];
            loop {
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
mod tests {
    use super::*;

    fn inherited() -> Vec<(OsString, OsString)> {
        inherited_env([
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("HOME"), OsString::from("/tmp")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("LD_PRELOAD"), OsString::from("/tmp/x.so")),
            (OsString::from("UNRELATED"), OsString::from("value")),
        ])
    }

    fn collect(
        argv: &[&str],
        env_name: &str,
        secret: &str,
    ) -> (Vec<RunFrame>, Result<RunExit, RunError>) {
        let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
        let cancel = AtomicBool::new(false);
        let mut frames = Vec::new();
        let result = execute(&argv, env_name, secret, &inherited(), &cancel, |frame| {
            frames.push(frame);
            Ok(())
        });
        (frames, result)
    }

    fn stdout_bytes(frames: &[RunFrame]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for frame in frames {
            if let RunFrame::Stdout(data) = frame {
                bytes.extend_from_slice(data);
            }
        }
        bytes
    }

    #[test]
    fn the_inherited_environment_is_a_small_allowlist() {
        let names: Vec<String> = inherited()
            .into_iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["PATH", "HOME", "LC_ALL"]);
    }

    #[test]
    fn loader_and_shell_hook_names_are_denied() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "ENV",
            "PROMPT_COMMAND",
            "IFS",
            "PATH",
            "HOME",
            "SHELLOPTS",
            "PS4",
        ] {
            assert!(denied_env_name(name), "{name} must be denied");
        }
        for name in ["API_KEY", "GH_TOKEN", "LANG", "TZ", "LC_ALL", "X"] {
            assert!(!denied_env_name(name), "{name} must be allowed");
        }
    }

    #[test]
    fn the_child_sees_the_injected_variable() {
        let secret = "unit-test-secret-1234";
        let (frames, result) = collect(
            &["/bin/sh", "-c", "printf %s \"$PM_TEST\""],
            "PM_TEST",
            secret,
        );
        assert_eq!(result.expect("run"), RunExit::Code(0));
        assert_eq!(stdout_bytes(&frames), b"[REDACTED]");
        assert!(frames.iter().all(|frame| match frame {
            RunFrame::Stdout(data) | RunFrame::Stderr(data) =>
                !String::from_utf8_lossy(data).contains(secret),
            _ => true,
        }));
    }

    #[test]
    fn the_injected_variable_is_the_only_secret_and_the_env_is_not_inherited() {
        // SECRET_FROM_TEST is set in this test process but must not reach the
        // child; only the fixed allowlist and the injected name do.
        // SAFETY: tests in this module do not read this variable concurrently.
        unsafe { std::env::set_var("PASSMGR_RUNNER_TEST_ONLY", "leaked-if-inherited") };
        let (frames, result) = collect(
            &[
                "/bin/sh",
                "-c",
                "printf %s \"$PASSMGR_RUNNER_TEST_ONLY|$PM_TEST\"",
            ],
            "PM_TEST",
            "unit-test-secret-5678",
        );
        assert_eq!(result.expect("run"), RunExit::Code(0));
        let output = String::from_utf8(stdout_bytes(&frames)).expect("utf8");
        assert_eq!(output, "|[REDACTED]");
    }

    #[test]
    fn a_secret_split_across_pipe_reads_is_redacted() {
        // Larger than READ_CHUNK, so the value cannot arrive in one read.
        let secret = format!("prefix-{}-suffix", "a".repeat(10_000));
        let (frames, result) = collect(
            &["/bin/sh", "-c", "printf %s \"$BIG_SECRET\""],
            "BIG_SECRET",
            &secret,
        );
        assert_eq!(result.expect("run"), RunExit::Code(0));
        let output = stdout_bytes(&frames);
        assert_eq!(output, b"[REDACTED]");
        assert!(
            !output
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }

    #[test]
    fn large_output_is_split_into_protocol_sized_frames() {
        let (frames, result) = collect(
            &[
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=1024 count=40 2>/dev/null | tr '\\000' x; printf %s \"$PM_TEST\"",
            ],
            "PM_TEST",
            "unit-test-secret-9012",
        );
        assert_eq!(result.expect("run"), RunExit::Code(0));
        let stdout: Vec<&Vec<u8>> = frames
            .iter()
            .filter_map(|frame| match frame {
                RunFrame::Stdout(data) => Some(data),
                _ => None,
            })
            .collect();
        assert!(stdout.len() > 1, "expected more than one chunk");
        assert!(
            stdout.iter().all(|chunk| chunk.len() <= MAX_CHUNK_BYTES),
            "every chunk must fit the protocol"
        );
        let total: usize = stdout.iter().map(|chunk| chunk.len()).sum();
        let bytes = stdout_bytes(&frames);
        assert_eq!(total, 40 * 1024 + b"[REDACTED]".len());
        assert_eq!(&bytes[40 * 1024..], b"[REDACTED]");
    }

    #[test]
    fn the_exit_code_is_propagated() {
        let (_frames, result) = collect(&["/bin/sh", "-c", "exit 7"], "PM_TEST", "secret-1234");
        assert_eq!(result.expect("run"), RunExit::Code(7));
    }

    #[test]
    fn a_signalled_child_is_not_reported_as_an_exit_code() {
        let (_frames, result) = collect(
            &["/bin/sh", "-c", "kill -TERM $$"],
            "PM_TEST",
            "secret-1234",
        );
        assert_eq!(result.expect("run"), RunExit::Signal(libc::SIGTERM as u8));
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let (_frames, result) = collect(
            &["/nonexistent/passmgr-runner-test"],
            "PM_TEST",
            "secret-1234",
        );
        assert!(matches!(result, Err(RunError::Spawn(_))));
    }

    #[test]
    fn an_invalid_environment_name_is_refused_before_spawning() {
        let cancel = AtomicBool::new(false);
        let argv = ["/bin/true".to_string()];
        let err = execute(
            &argv,
            "BAD=NAME",
            "secret-1234",
            &inherited(),
            &cancel,
            |_| Ok(()),
        )
        .expect_err("invalid env name");
        assert!(matches!(err, RunError::Spawn(_)));
    }

    #[test]
    fn output_errors_and_cancellation_stop_the_child() {
        // One chunk first, then stay alive: the failing emit must kill the
        // child instead of waiting for it.
        let noisy = [
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf x; sleep 30".to_string(),
        ];
        let quiet = [
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 30".to_string(),
        ];
        let argv = noisy;

        let cancel = AtomicBool::new(false);
        let err = execute(
            &argv,
            "PM_TEST",
            "secret-1234",
            &inherited(),
            &cancel,
            |_| Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone")),
        )
        .expect_err("output failed");
        assert!(matches!(err, RunError::Output(_)));

        let argv = quiet;
        let cancel = AtomicBool::new(true);
        let err = execute(
            &argv,
            "PM_TEST",
            "secret-1234",
            &inherited(),
            &cancel,
            |_| Ok(()),
        )
        .expect_err("cancelled");
        assert!(matches!(err, RunError::Cancelled));
    }
}
