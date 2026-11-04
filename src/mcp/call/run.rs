//! The `run_with_credentials` tool: validate the input, run the request
//! through `pmd` and map its frames to the tool result (TODO 4.5d).
//!
//! This module is the same kind of boundary as its parent: untrusted JSON in,
//! a validated daemon request out. It never sees a secret -- the daemon
//! decrypts, injects and redacts -- so the only child bytes it can turn into a
//! result are the already-redacted, already-capped ones it collected from the
//! run stream. Nothing here can read a vault file, and there is no code path
//! from here to a plaintext-returning request because `pmd` has none.
//!
//! The daemon decides every authorization question: the grant's scope, its
//! command allowlist, its expiry and uses. Validating here only means a
//! malformed request never costs a round trip, and the agent gets a fixable
//! message instead of a protocol error.

use std::ffi::OsStr;
use std::path::Path;

use serde_json::{Value, json};

use crate::client::RunOutcome;
use crate::grant::GrantToken;
use crate::protocol::{
    DEFAULT_RUN_OUTPUT_BYTES, DEFAULT_RUN_TIMEOUT_SECS, EnvBinding, MAX_ARG_BYTES, MAX_ARGS,
    MAX_ENV_BINDINGS, MAX_ENV_VALUE_BYTES, MAX_PATH_BYTES, MAX_REFERENCE_BYTES,
    MAX_RUN_OUTPUT_BYTES, MAX_RUN_TIMEOUT_SECS, ResponseError, RunExit, RunFinished, RunFrame,
    RunLimits, RunRequest, valid_env_name,
};
use crate::runner::denied_env_name;
use crate::store::EntryId;

use super::{clipped, daemon_error, error_result, session_token};

/// The reference errors of this tool. They never echo the supplied value.
const INVALID_ENV_REF: &str =
    "'env' values must be canonical pm:// references from list_credentials";
/// Refusals for the two injections that have no daemon path yet.
const STDIN_UNAVAILABLE: &str = "'stdin_ref' is not available in this build; pass the value in an environment variable with \
     'env' instead";
const FILES_UNAVAILABLE: &str = "'files' is not available in this build; pass the value in an environment variable with \
     'env' instead";

/// A validated `run_with_credentials` argument object.
pub struct RunArgs {
    /// Program and arguments. `command[0]` is resolved before the request is
    /// built, so what leaves this module is absolute.
    pub command: Vec<String>,
    /// Secret bindings: variable name to canonical `pm://` reference.
    pub env: Vec<EnvBinding>,
    /// Non-secret bindings: variable name to literal value.
    pub plain_env: Vec<(String, String)>,
    /// Absolute working directory for the child.
    pub cwd: String,
    /// The deadline and per-stream cap the daemon will apply.
    pub limits: RunLimits,
}

/// `plain_env` holds caller-supplied text, and a caller may not have read the
/// warning that it is not secret. The hand-written form prints the variable
/// names (which a human can match against their own grant) and never the
/// values.
impl std::fmt::Debug for RunArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self
            .plain_env
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        formatter
            .debug_struct("RunArgs")
            .field("command", &self.command)
            .field("env", &self.env)
            .field("plain_env_names", &names)
            .field("cwd", &self.cwd)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Validate the `run_with_credentials` argument object against the schema and
/// the daemon's own bounds.
///
/// Every failure is an `isError` message: the schema promises that only a run
/// that could not start is an error, so argument problems stay inside the
/// result rather than becoming a JSON-RPC protocol error the host may render
/// without the fixable text.
pub fn run_args(arguments: Option<&Value>, default_cwd: Option<&Path>) -> Result<RunArgs, String> {
    let object = match arguments {
        Some(value) => value
            .as_object()
            .ok_or_else(|| "arguments must be an object".to_owned())?,
        None => return Err("run_with_credentials requires 'command'".to_owned()),
    };
    if let Some(unknown) = object.keys().find(|key| {
        !matches!(
            key.as_str(),
            "command"
                | "env"
                | "plain_env"
                | "stdin_ref"
                | "files"
                | "cwd"
                | "timeout_secs"
                | "max_output_bytes"
        )
    }) {
        return Err(format!(
            "unknown run_with_credentials argument '{}'",
            clipped(unknown)
        ));
    }

    // Refused before anything else is used, so an agent learns immediately
    // that this build cannot inject these, instead of after a grant round
    // trip. Both are implemented by 5.1/5.2.
    match object.get("stdin_ref") {
        None | Some(Value::Null) => {}
        Some(_) => {
            return Err(STDIN_UNAVAILABLE.to_owned());
        }
    }
    // Absent, `null` and `{}` mean "no files". Anything else is refused
    // rather than ignored, which would run the command without the file the
    // caller expected.
    match object.get("files") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) if map.is_empty() => {}
        Some(Value::Object(_)) => return Err(FILES_UNAVAILABLE.to_owned()),
        Some(_) => return Err("'files' must be an object".to_owned()),
    }

    let command = command_argv(object.get("command"))?;
    let env = env_bindings(object.get("env"))?;
    let plain_env = plain_bindings(object.get("plain_env"))?;
    if env.is_empty() {
        // `pmd` refuses a run with no secret binding, so refusing here turns a
        // daemon `BadRequest` into a message the agent can act on.
        return Err("'env' must name at least one credential reference".to_owned());
    }
    let mut names = std::collections::HashSet::with_capacity(env.len() + plain_env.len());
    for binding in &env {
        if !names.insert(binding.name.as_str()) {
            return Err(format!(
                "'{}' is set more than once across 'env' and 'plain_env'",
                binding.name
            ));
        }
    }
    for (name, _) in &plain_env {
        if !names.insert(name.as_str()) {
            return Err(format!(
                "'{name}' is set more than once across 'env' and 'plain_env'"
            ));
        }
    }

    Ok(RunArgs {
        command,
        env,
        plain_env,
        cwd: cwd(object.get("cwd"), default_cwd)?,
        limits: RunLimits {
            timeout_secs: counter(
                object.get("timeout_secs"),
                "timeout_secs",
                DEFAULT_RUN_TIMEOUT_SECS,
                MAX_RUN_TIMEOUT_SECS,
            )?,
            max_output_bytes: counter(
                object.get("max_output_bytes"),
                "max_output_bytes",
                DEFAULT_RUN_OUTPUT_BYTES,
                MAX_RUN_OUTPUT_BYTES,
            )?,
        },
    })
}

/// The tool schema is stricter than the daemon: `^[A-Z_][A-Z0-9_]{0,127}$`.
///
/// `pmd` accepts lower-case names too, but accepting one here would hand the
/// agent an argument its own schema calls invalid, so the boundary applies the
/// stricter rule.
fn schema_env_name(name: &str) -> bool {
    valid_env_name(name) && !name.chars().any(|character| character.is_ascii_lowercase())
}

/// The schema check, then `pmd`'s loader/shell-hook denylist, so a name the
/// daemon would refuse as malformed gets a message naming the variable.
fn check_env_name(field: &str, name: &str) -> Result<(), String> {
    if !schema_env_name(name) {
        return Err(format!(
            "'{field}' name '{}' is not a valid environment variable name \
             (the schema allows ^[A-Z_][A-Z0-9_]{{0,127}}$)",
            clipped(name)
        ));
    }
    if denied_env_name(name) {
        return Err(format!(
            "'{field}' name '{}' is not allowed: a loader or shell would execute its value; \
             use another variable name",
            clipped(name)
        ));
    }
    Ok(())
}

fn command_argv(value: Option<&Value>) -> Result<Vec<String>, String> {
    let value = value.ok_or_else(|| "run_with_credentials requires 'command'".to_owned())?;
    let values = value
        .as_array()
        .ok_or_else(|| "'command' must be an array of strings".to_owned())?;
    if values.is_empty() {
        return Err("'command' must name at least one program".to_owned());
    }
    if values.len() > MAX_ARGS {
        return Err(format!("'command' accepts at most {MAX_ARGS} arguments"));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let argument = value
                .as_str()
                .ok_or_else(|| format!("'command[{index}]' must be a string"))?;
            if argument.is_empty() {
                return Err(format!("'command[{index}]' must not be empty"));
            }
            if argument.len() > MAX_ARG_BYTES {
                return Err(format!("'command[{index}]' exceeds {MAX_ARG_BYTES} bytes"));
            }
            if argument.contains('\0') {
                return Err(format!("'command[{index}]' must not contain a NUL byte"));
            }
            Ok(argument.to_owned())
        })
        .collect()
}

/// Parse and canonicalize one `pm://` reference.
///
/// Parsing to an [`EntryId`] and re-rendering rejects upper-case hex, which the
/// parser would accept, so the reference forwarded to `pmd` is exactly the
/// canonical form the schema promises. The error never contains the value.
fn canonical_ref(text: &str, invalid: &str) -> Result<String, String> {
    if text.len() > MAX_REFERENCE_BYTES {
        return Err(format!("a reference exceeds {MAX_REFERENCE_BYTES} bytes"));
    }
    let id = EntryId::parse_ref(text).map_err(|_| invalid.to_owned())?;
    if id.to_ref() != text {
        return Err(invalid.to_owned());
    }
    Ok(text.to_owned())
}

fn env_bindings(value: Option<&Value>) -> Result<Vec<EnvBinding>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "'env' must be an object".to_owned())?;
    if object.len() > MAX_ENV_BINDINGS {
        return Err(format!("'env' accepts at most {MAX_ENV_BINDINGS} bindings"));
    }
    object
        .iter()
        .map(|(name, value)| {
            check_env_name("env", name)?;
            let reference = value
                .as_str()
                .ok_or_else(|| format!("'env.{name}' must be a pm:// reference string"))?;
            // A caller that pasted the secret itself gets a message naming the
            // member, never the value it pasted.
            if !reference.starts_with("pm://") {
                return Err(format!(
                    "'env.{name}' must be a pm:// reference from list_credentials, not a literal \
                     value"
                ));
            }
            Ok(EnvBinding {
                name: name.clone(),
                reference: canonical_ref(reference, INVALID_ENV_REF)?,
            })
        })
        .collect()
}

fn plain_bindings(value: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "'plain_env' must be an object".to_owned())?;
    if object.len() > MAX_ENV_BINDINGS {
        return Err(format!(
            "'plain_env' accepts at most {MAX_ENV_BINDINGS} bindings"
        ));
    }
    object
        .iter()
        .map(|(name, value)| {
            check_env_name("plain_env", name)?;
            let text = value
                .as_str()
                .ok_or_else(|| format!("'plain_env.{name}' must be a string"))?;
            if text.len() > MAX_ENV_VALUE_BYTES {
                return Err(format!(
                    "'plain_env.{name}' exceeds {MAX_ENV_VALUE_BYTES} bytes"
                ));
            }
            if text.contains('\0') {
                return Err(format!("'plain_env.{name}' must not contain a NUL byte"));
            }
            Ok((name.clone(), text.to_owned()))
        })
        .collect()
}

/// The child's working directory: the caller's when given, the server's
/// otherwise, always absolute and bounded.
fn cwd(value: Option<&Value>, default_cwd: Option<&Path>) -> Result<String, String> {
    let text = match value {
        None => {
            let default = default_cwd.ok_or_else(|| {
                "cannot determine the server's working directory; pass an absolute 'cwd'".to_owned()
            })?;
            default
                .to_str()
                .ok_or_else(|| {
                    "the server's working directory is not valid UTF-8; pass an absolute 'cwd'"
                        .to_owned()
                })?
                .to_owned()
        }
        Some(value) => value
            .as_str()
            .ok_or_else(|| "'cwd' must be a string".to_owned())?
            .to_owned(),
    };
    if text.is_empty() {
        return Err("'cwd' must not be empty".to_owned());
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(format!("'cwd' exceeds {MAX_PATH_BYTES} bytes"));
    }
    if text.contains('\0') {
        return Err("'cwd' must not contain a NUL byte".to_owned());
    }
    if !text.starts_with('/') {
        return Err("'cwd' must be an absolute path".to_owned());
    }
    Ok(text)
}

/// Parse one bounded, non-zero integer limit.
fn counter(value: Option<&Value>, field: &str, default: u32, maximum: u32) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let number = value
        .as_u64()
        .ok_or_else(|| format!("'{field}' must be an integer between 1 and {maximum}"))?;
    if !(1..=u64::from(maximum)).contains(&number) {
        return Err(format!("'{field}' must be between 1 and {maximum}"));
    }
    Ok(number as u32)
}

/// Resolve `command[0]` to an absolute path through the agent's `PATH` and
/// `cwd`, as `passmgr run` does.
///
/// The result is untrusted input to the daemon, which canonicalizes it and
/// checks the canonical path against the grant's command allowlist. The error
/// is fixed text: the program name is agent input, and the pointers it might
/// contain are not worth echoing.
pub fn resolve_command(mut args: RunArgs, path_var: &OsStr) -> Result<RunArgs, String> {
    let program = args
        .command
        .first()
        .ok_or_else(|| "'command' must name at least one program".to_owned())?;
    let resolved = crate::program::resolve_program(program, Path::new(&args.cwd), path_var)
        .map_err(|_| {
            "the program in 'command[0]' was not found: use an absolute path or a name on PATH"
                .to_owned()
        })?;
    let text = resolved
        .to_str()
        .ok_or_else(|| "the resolved program path is not valid UTF-8".to_owned())?;
    args.command[0] = text.to_owned();
    Ok(args)
}

/// Build the daemon request for validated arguments.
pub fn run_request(grant: GrantToken, args: RunArgs) -> RunRequest {
    RunRequest {
        env: args.env,
        limits: args.limits,
        plain_env: args.plain_env,
        command: args.command,
        cwd: args.cwd,
        grant,
    }
}

/// Run the command through `pmd` and hand each frame to `on_frame`.
///
/// The session token comes from the runtime directory, never from the agent.
/// A failed connection or a stream that ends without a terminal frame is an
/// error the agent must not mistake for a completed run.
pub fn request_run(
    grant: &GrantToken,
    args: RunArgs,
    mut on_frame: impl FnMut(&RunFrame),
) -> Result<RunOutcome, String> {
    let request = run_request(grant.clone(), args);
    let paths = crate::socket::RuntimePaths::resolve();
    let token = session_token(&paths)?;
    crate::client::run(&paths, &token, &request, |frame| {
        on_frame(frame);
        Ok(())
    })
    .map_err(|error| {
        format!(
            "the run did not finish ({error}); check that the passmgr daemon is running and ask \
             the human to run `pm unlock` if it is not"
        )
    })
}

/// The relayed, redacted streams of one run, bounded by the request's cap.
///
/// The daemon already enforces the cap after redaction. This second bound is
/// defence in depth: a buggy or older daemon cannot make this process hold an
/// unbounded amount of child output.
pub struct RunSink {
    cap: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RunSink {
    /// A sink that keeps at most `cap` bytes per stream.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    /// Collect the payload of an output frame; terminal frames are ignored.
    pub fn push(&mut self, frame: &RunFrame) {
        match frame {
            RunFrame::Stdout(data) => extend(&mut self.stdout, data, self.cap),
            RunFrame::Stderr(data) => extend(&mut self.stderr, data, self.cap),
            RunFrame::Exit(_) | RunFrame::Error(_) => {}
        }
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

fn extend(buffer: &mut Vec<u8>, data: &[u8], cap: usize) {
    let room = cap.saturating_sub(buffer.len());
    buffer.extend_from_slice(&data[..data.len().min(room)]);
}

/// Map a finished run stream to a tool result.
pub fn run_response(outcome: RunOutcome, sink: &RunSink) -> Value {
    match outcome {
        RunOutcome::Exited(finished) => run_output(&finished, sink),
        RunOutcome::Refused(error) => error_result(&run_error(error)),
    }
}

/// The run refusals whose metadata-tool wording would mislead.
fn run_error(error: ResponseError) -> String {
    match error {
        ResponseError::Denied => "the daemon denied this run: the grant is not active (it may be \
             expired, revoked or used up) or does not allow this program; ask the human for a \
             grant that covers it"
            .to_owned(),
        ResponseError::SpawnFailed => "the program could not be started".to_owned(),
        ResponseError::Unsupported => {
            "the daemon does not support credential runs in this build".to_owned()
        }
        other => daemon_error(other),
    }
}

/// A successful run result: short summary plus the schema's structured content.
///
/// The streams are the ones the daemon relayed, so they are redacted and
/// capped. `redactions` and `duration_ms` are the daemon's own statistics; they
/// are counts, never values.
pub fn run_output(finished: &RunFinished, sink: &RunSink) -> Value {
    let (exit_code, signal) = match finished.exit {
        RunExit::Code(code) => (json!(code), Value::Null),
        RunExit::Signal(signal) => (Value::Null, json!(signal_name(signal))),
    };
    let mut summary = if finished.timed_out {
        "the command timed out and was killed".to_owned()
    } else {
        match finished.exit {
            RunExit::Code(code) => format!("the command exited with status {code}"),
            RunExit::Signal(signal) => {
                format!("the command was killed by {}", signal_name(signal))
            }
        }
    };
    if finished.stdout_truncated || finished.stderr_truncated {
        summary.push_str("; the relayed output hit its cap and was truncated");
    }
    json!({
        "content": [{"type": "text", "text": summary}],
        "structuredContent": {
            "exit_code": exit_code,
            "signal": signal,
            "timed_out": finished.timed_out,
            "stdout": String::from_utf8_lossy(sink.stdout()),
            "stderr": String::from_utf8_lossy(sink.stderr()),
            "stdout_truncated": finished.stdout_truncated,
            "stderr_truncated": finished.stderr_truncated,
            "redactions": finished.redactions,
            "duration_ms": finished.duration_ms,
        },
        "isError": false,
    })
}

/// The conventional name of a signal number.
///
/// The daemon's `exit` frame carries the number, because that is what the
/// kernel reports; this is the one place it becomes a name for a human or an
/// agent. A number with no portable name stays `SIG<number>`.
pub fn signal_name(signal: u8) -> String {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        other => return format!("SIG{other}"),
    };
    name.to_owned()
}
