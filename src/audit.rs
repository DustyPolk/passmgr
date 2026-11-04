//! The append-only, hash-chained audit log (TODO 3.8).
//!
//! Every credential request that reaches `pmd`, and every human local `run`,
//! appends exactly one JSON object per line to
//! `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback `~/.local/state`). A record
//! holds metadata only: the timestamp, where the request came from, the
//! outcome, the grant id, the reference, the canonical program and its
//! arguments, and how the child ended. It never holds a secret value, a grant
//! token or a session token.
//!
//! # Chain
//!
//! Each line carries `prev`: the lowercase SHA-256 of the **previous line's
//! bytes, without its terminating newline**. The first line uses 64 zeros.
//! Appending reads only the last line under an exclusive `flock` on the audit
//! file, so concurrent daemon workers and local CLI runs cannot fork the
//! chain. A last line that is not newline-terminated, or is larger than
//! [`MAX_RECORD_BYTES`], is refused instead of extended: a torn write must be
//! visible, not silently repaired.
//!
//! # File handling
//!
//! The file is created 0600 inside a 0700 `passmgr` state directory, opened
//! with `O_NOFOLLOW`, and refused if it is a symlink, is not a regular file,
//! is not owned by the current user, or has any group/world permission bit.
//! Writes use `O_APPEND` under the lock and are `fsync`ed before the caller
//! continues, so a recorded use is durable.
//!
//! A failed audit write must not be silent. Callers check
//! [`check_writable`] before they decrypt or spawn, and report a failure to
//! their own diagnostic stream. The audit log is metadata; it cannot make a
//! request that was already refused succeed.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Write as FmtWrite;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::grant::GrantId;
use crate::timestamp;

mod read;

pub use read::{Filter, MAX_LOG_BYTES, Record, VerifyError, load, select};

/// Directory under the state home that passmgr owns.
pub const STATE_DIR_NAME: &str = "passmgr";
/// The audit file inside [`STATE_DIR_NAME`].
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";
/// `prev` of the first record: 64 lowercase hex zeros.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The only `event` value this format version defines.
pub const EVENT_RUN: &str = "run";
/// Largest line this build writes or accepts as the previous line.
///
/// The per-field caps below keep every record well under this even when JSON
/// escaping expands control characters; the cap exists so a tampered file
/// cannot make the append read an unbounded last line.
pub const MAX_RECORD_BYTES: usize = 32 * 1024;

const MAX_REFERENCE_CHARS: usize = 256;
const MAX_COMMAND_CHARS: usize = 256;
const MAX_ARG_CHARS: usize = 128;
const MAX_ARGS: usize = 16;
const AUDIT_FILE_MODE: u32 = 0o600;
const STATE_DIR_MODE: u32 = 0o700;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(10);

/// Where a request came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A `run` request served by `pmd`.
    Daemon,
    /// A human `run` against a local vault, without a grant.
    Local,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Local => "local",
        }
    }
}

/// How a credential request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The child ran (or was started); its termination is in the record.
    Allowed,
    /// The grant did not authorize the request.
    Denied,
    /// The reference does not exist or is out of scope.
    NotFound,
    /// The request was malformed before any grant was checked.
    BadRequest,
    /// The vault or the audit log could not be read or written.
    Internal,
    /// The authorized program could not be started.
    SpawnFailed,
    /// The daemon or the human cancelled the run.
    Cancelled,
    /// The child's output could no longer be relayed.
    OutputError,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::BadRequest => "bad_request",
            Self::Internal => "internal",
            Self::SpawnFailed => "spawn_failed",
            Self::Cancelled => "cancelled",
            Self::OutputError => "output_error",
        }
    }
}

/// How a child ended, kept distinct so a signal is not mistaken for exit 128+N.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Code(u8),
    Signal(u8),
}

/// One audit record, as the caller knows it before encoding.
///
/// `args` are the arguments after `argv[0]`; the canonical program is separate
/// so a reader never has to split a command line.
#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
    pub source: Source,
    pub outcome: Outcome,
    pub grant: Option<GrantId>,
    pub reference: Option<&'a str>,
    pub command: Option<&'a str>,
    pub args: &'a [String],
    pub termination: Option<Termination>,
}

/// Resolve the default audit path from the process environment.
///
/// `$XDG_STATE_HOME` wins when it is set and non-empty; otherwise
/// `$HOME/.local/state` is used. A relative or missing base is refused rather
/// than resolved against the caller's working directory, which would let a
/// different `cd` choose where audit records land.
pub fn default_path() -> Result<PathBuf, AuditError> {
    let state_home = env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty());
    let home = env::var_os("HOME").filter(|value| !value.is_empty());
    path_from(state_home.as_deref(), home.as_deref())
}

/// Pure form of [`default_path`], so the rules are unit-testable without
/// mutating the process environment.
pub fn path_from(state_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf, AuditError> {
    let base = match state_home {
        Some(value) => PathBuf::from(value),
        None => match home {
            Some(value) => PathBuf::from(value).join(".local").join("state"),
            None => return Err(AuditError::NoStateDir),
        },
    };
    if !base.is_absolute() {
        return Err(AuditError::Insecure {
            path: base,
            detail: "the state home must be an absolute path".into(),
        });
    }
    Ok(base.join(STATE_DIR_NAME).join(AUDIT_FILE_NAME))
}

/// Append one record, chaining it to the last line.
///
/// The lock is held across reading `prev`, writing the line and `fsync`ing it.
/// A failure means the record is not on disk; the caller must say so.
pub fn append(path: &Path, event: &Event<'_>) -> Result<(), AuditError> {
    let now = now_unix()?;
    let mut file = open_locked(path)?;
    let prev = match last_line(&mut file, path)? {
        Some(line) => chain_hash(&line),
        None => GENESIS_PREV.to_owned(),
    };
    let line = encode_line(&prev, event, now);
    if line.len() > MAX_RECORD_BYTES {
        return Err(AuditError::Malformed(format!(
            "the audit record is larger than {MAX_RECORD_BYTES} bytes"
        )));
    }
    let mut record = line.into_bytes();
    record.push(b'\n');
    // One write, so a crash cannot leave a whole record without its newline.
    file.write_all(&record)
        .and_then(|()| file.sync_data())
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// Open, validate and lock the audit file, and check that its tail can be
/// extended, without writing a record.
///
/// Callers use this before decrypting or spawning, so a log that [`append`]
/// would refuse refuses the use instead of letting it happen unrecorded. It
/// does create the state directory and the empty audit file (0600).
pub fn check_writable(path: &Path) -> Result<(), AuditError> {
    let mut file = open_locked(path)?;
    last_line(&mut file, path)?;
    Ok(())
}

/// The lowercase SHA-256 of one record line, without its newline.
///
/// Exposed so `pm audit verify` and tests use exactly the rule the writer
/// used.
pub fn chain_hash(line: &[u8]) -> String {
    let digest = Sha256::digest(line);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Encode one record line without the trailing newline.
///
/// `now` is passed in rather than read here so the encoding is deterministic
/// in tests. Every string field is bounded on a character boundary and JSON
/// escaping keeps control characters (including newlines) inside one line.
pub fn encode_line(prev: &str, event: &Event<'_>, now: u64) -> String {
    let mut object = Map::new();
    object.insert("v".into(), json!(1));
    object.insert("ts".into(), json!(timestamp::format_utc(now)));
    object.insert("source".into(), json!(event.source.as_str()));
    object.insert("event".into(), json!(EVENT_RUN));
    object.insert("outcome".into(), json!(event.outcome.as_str()));
    object.insert(
        "grant".into(),
        match event.grant {
            Some(grant) => json!(grant.to_hex()),
            None => Value::Null,
        },
    );
    object.insert(
        "ref".into(),
        match event.reference {
            Some(reference) => json!(truncate_chars(reference, MAX_REFERENCE_CHARS)),
            None => Value::Null,
        },
    );
    object.insert(
        "command".into(),
        match event.command {
            Some(command) => json!(truncate_chars(command, MAX_COMMAND_CHARS)),
            None => Value::Null,
        },
    );
    object.insert("args".into(), json!(bounded_args(event.args)));
    let (exit, signal) = match event.termination {
        Some(Termination::Code(code)) => (json!(code), Value::Null),
        Some(Termination::Signal(signal)) => (Value::Null, json!(signal)),
        None => (Value::Null, Value::Null),
    };
    object.insert("exit".into(), exit);
    object.insert("signal".into(), signal);
    object.insert("prev".into(), json!(prev));
    serde_json::to_string(&Value::Object(object)).expect("an audit record always serializes")
}

fn bounded_args(args: &[String]) -> Vec<Value> {
    args.iter()
        .take(MAX_ARGS)
        .map(|arg| json!(truncate_chars(arg, MAX_ARG_CHARS)))
        .collect()
}

fn truncate_chars(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

fn now_unix() -> Result<u64, AuditError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuditError::Clock)
}

/// Prepare and lock the audit file, validating every property we rely on.
fn open_locked(path: &Path) -> Result<File, AuditError> {
    let directory = path
        .parent()
        .ok_or_else(|| AuditError::Malformed("the audit path has no parent directory".into()))?;
    ensure_directory(directory)?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .truncate(false)
        .mode(AUDIT_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| AuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file(&metadata, path)?;
    lock(&file, path, libc::LOCK_EX)?;
    Ok(file)
}

/// Check that an already-open descriptor is the private regular file we wrote.
fn validate_file(metadata: &fs::Metadata, path: &Path) -> Result<(), AuditError> {
    if !metadata.is_file() {
        return Err(AuditError::Insecure {
            path: path.to_path_buf(),
            detail: "not a regular file".into(),
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != AUDIT_FILE_MODE {
        return Err(AuditError::Insecure {
            path: path.to_path_buf(),
            detail: format!("permissions {mode:04o}, expected 0600"),
        });
    }
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(AuditError::Insecure {
            path: path.to_path_buf(),
            detail: "not owned by the current user".into(),
        });
    }
    Ok(())
}

/// Validate a directory without creating it. `Ok(false)` means it does not
/// exist yet; a reader treats that as an empty log, a writer creates it.
fn validate_directory(directory: &Path) -> Result<bool, AuditError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AuditError::Insecure {
                    path: directory.to_path_buf(),
                    detail: "not a real directory".into(),
                });
            }
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(AuditError::Insecure {
                    path: directory.to_path_buf(),
                    detail: format!("permissions {mode:04o}, expected no group/world bits"),
                });
            }
            // SAFETY: `geteuid` takes no arguments and cannot fail.
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(AuditError::Insecure {
                    path: directory.to_path_buf(),
                    detail: "not owned by the current user".into(),
                });
            }
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(AuditError::Io {
            path: directory.to_path_buf(),
            source,
        }),
    }
}

fn ensure_directory(directory: &Path) -> Result<(), AuditError> {
    if validate_directory(directory)? {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(STATE_DIR_MODE)
        .create(directory)
        .map_err(|source| AuditError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
    // Re-check rather than trusting the umask or a racing creator.
    if !validate_directory(directory)? {
        return Err(AuditError::Io {
            path: directory.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "the directory disappeared"),
        });
    }
    Ok(())
}

fn lock(file: &File, path: &Path, operation: i32) -> Result<(), AuditError> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        // SAFETY: `as_raw_fd` returns a descriptor owned by `file`, which
        // outlives this call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(AuditError::Io {
                path: path.to_path_buf(),
                source: err,
            });
        }
        if Instant::now() >= deadline {
            return Err(AuditError::Busy(path.to_path_buf()));
        }
        thread::sleep(LOCK_RETRY);
    }
}

/// Read the last complete line, or `None` for an empty file.
///
/// Only the tail window is read. A file whose last record is longer than the
/// window, or that does not end in a newline, is refused: appending would
/// either concatenate two records or accept a torn write as if it were whole.
fn last_line(file: &mut File, path: &Path) -> Result<Option<Vec<u8>>, AuditError> {
    let length = file
        .metadata()
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if length == 0 {
        return Ok(None);
    }
    let window = (MAX_RECORD_BYTES as u64 + 2).min(length);
    let start = length - window;
    file.seek(SeekFrom::Start(start))
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut buffer = vec![0u8; window as usize];
    file.read_exact(&mut buffer)
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if buffer.last() != Some(&b'\n') {
        return Err(AuditError::Malformed(
            "the audit log does not end with a newline".into(),
        ));
    }
    let body = &buffer[..buffer.len() - 1];
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => &body[position + 1..],
        None if start == 0 => body,
        None => {
            return Err(AuditError::Malformed(format!(
                "the last audit record is larger than {MAX_RECORD_BYTES} bytes"
            )));
        }
    };
    if line.is_empty() {
        return Err(AuditError::Malformed(
            "the audit log ends with an empty record".into(),
        ));
    }
    Ok(Some(line.to_vec()))
}

/// Why the audit log could not be located, read or written.
///
/// Messages contain paths and fixed reasons only, never record contents or
/// secret material.
#[derive(Debug)]
pub enum AuditError {
    /// Neither `XDG_STATE_HOME` nor `HOME` gives an absolute state home.
    NoStateDir,
    /// Local file I/O failure.
    Io { path: PathBuf, source: io::Error },
    /// The path is not a plain 0600 file in a 0700 directory owned by us.
    Insecure { path: PathBuf, detail: String },
    /// Another process held the audit lock for longer than the timeout.
    Busy(PathBuf),
    /// The existing file cannot be extended safely.
    Malformed(String),
    /// The system clock is before the Unix epoch.
    Clock,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoStateDir => {
                f.write_str("neither XDG_STATE_HOME nor HOME names an absolute state directory")
            }
            Self::Io { path, source } => {
                write!(f, "cannot access '{}': {source}", path.display())
            }
            Self::Insecure { path, detail } => {
                write!(f, "refusing the audit path '{}': {detail}", path.display())
            }
            Self::Busy(path) => write!(
                f,
                "the audit log '{}' is locked by another process; nothing was recorded",
                path.display()
            ),
            Self::Malformed(detail) => write!(f, "malformed audit log: {detail}"),
            Self::Clock => f.write_str("the system clock is before the Unix epoch"),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn event<'a>(args: &'a [String]) -> Event<'a> {
        Event {
            source: Source::Daemon,
            outcome: Outcome::Allowed,
            grant: None,
            reference: Some("pm://0123456789abcdef0123456789abcdef"),
            command: Some("/usr/bin/true"),
            args,
            termination: Some(Termination::Code(0)),
        }
    }

    fn audit_file(directory: &Path) -> PathBuf {
        directory.join(STATE_DIR_NAME).join(AUDIT_FILE_NAME)
    }

    #[test]
    fn the_path_honours_xdg_then_home_and_refuses_relative_bases() {
        let xdg = OsStr::new("/var/state");
        let home = OsStr::new("/home/alice");
        assert_eq!(
            path_from(Some(xdg), Some(home)).expect("xdg"),
            PathBuf::from("/var/state/passmgr/audit.jsonl")
        );
        assert_eq!(
            path_from(None, Some(home)).expect("home"),
            PathBuf::from("/home/alice/.local/state/passmgr/audit.jsonl")
        );
        assert!(matches!(path_from(None, None), Err(AuditError::NoStateDir)));
        let relative = OsStr::new("state");
        let error = path_from(Some(relative), Some(home)).expect_err("relative");
        assert!(matches!(error, AuditError::Insecure { .. }), "{error:?}");
    }

    #[test]
    fn a_record_is_one_json_line_with_the_genesis_prev_and_no_secret() {
        let args = vec!["--flag".to_owned(), "canary-not-a-secret".to_owned()];
        let line = encode_line(GENESIS_PREV, &event(&args), 1_735_689_600);
        assert!(!line.contains('\n'), "{line}");
        let value: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(value["v"], 1);
        assert_eq!(value["ts"], "2025-01-01T00:00:00Z");
        assert_eq!(value["source"], "daemon");
        assert_eq!(value["event"], "run");
        assert_eq!(value["outcome"], "allowed");
        assert_eq!(value["ref"], "pm://0123456789abcdef0123456789abcdef");
        assert_eq!(value["command"], "/usr/bin/true");
        assert_eq!(value["args"][0], "--flag");
        assert_eq!(value["exit"], 0);
        assert!(value["signal"].is_null());
        assert_eq!(value["prev"], GENESIS_PREV);
    }

    #[test]
    fn control_characters_stay_inside_one_line_and_fields_are_bounded() {
        let long = "x".repeat(MAX_REFERENCE_CHARS + 100);
        let newline = "evil\nrecord\u{202e}";
        let args: Vec<String> = (0..MAX_ARGS + 10)
            .map(|index| format!("{index}-{}", "a".repeat(MAX_ARG_CHARS + 10)))
            .collect();
        let mut event = event(&args);
        event.reference = Some(&long);
        event.command = Some(newline);
        let line = encode_line(GENESIS_PREV, &event, 0);
        assert!(!line.contains('\n'), "a record must never span lines");
        assert!(
            line.len() <= MAX_RECORD_BYTES,
            "record is {} bytes",
            line.len()
        );
        let value: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(
            value["ref"].as_str().expect("ref").chars().count(),
            MAX_REFERENCE_CHARS
        );
        assert_eq!(value["args"].as_array().expect("args").len(), MAX_ARGS);
        assert!(
            value["command"].as_str().expect("command").contains('\n'),
            "JSON escaping must preserve the value, not the line break"
        );
    }

    #[test]
    fn appends_chain_records_and_never_leave_a_secret() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = audit_file(directory.path());
        let canary = "canary-secret-value-8f3a1c";
        // A secret is not part of `Event`; put one in an argument to prove the
        // writer does not invent or copy values from anywhere else.
        let args = vec![format!("--token={canary}")];
        for exit in [0u8, 3] {
            let mut event = event(&args);
            event.termination = Some(Termination::Code(exit));
            append(&path, &event).expect("append");
        }

        let text = fs::read_to_string(&path).expect("read audit");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).expect("first JSON");
        let second: Value = serde_json::from_str(lines[1]).expect("second JSON");
        assert_eq!(first["prev"], GENESIS_PREV);
        assert_eq!(
            second["prev"].as_str().expect("prev"),
            chain_hash(lines[0].as_bytes())
        );
        assert_eq!(first["exit"], 0);
        assert_eq!(second["exit"], 3);

        let metadata = fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let state = directory.path().join(STATE_DIR_NAME);
        assert_eq!(
            fs::metadata(&state).expect("state metadata").mode() & 0o777,
            0o700
        );

        // The argument is metadata the caller chose to record; the writer
        // must not add any secret-bearing field of its own.
        assert!(text.contains(canary), "the test put it there on purpose");
        assert!(!text.contains("grant_token"));
    }

    #[test]
    fn a_loose_file_or_directory_is_refused_instead_of_repaired() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = audit_file(directory.path());
        append(&path, &event(&[])).expect("append");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod file");
        let error = check_writable(&path).expect_err("loose file");
        assert!(matches!(error, AuditError::Insecure { .. }), "{error:?}");
        assert!(error.to_string().contains("0644"), "{error}");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod file");
        check_writable(&path).expect("tight file");
        let state = directory.path().join(STATE_DIR_NAME);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let error = check_writable(&path).expect_err("loose directory");
        assert!(matches!(error, AuditError::Insecure { .. }), "{error:?}");
        assert!(error.to_string().contains("0755"), "{error}");
    }

    #[test]
    fn a_torn_last_line_is_refused_rather_than_concatenated() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = audit_file(directory.path());
        append(&path, &event(&[])).expect("append");
        let mut text = fs::read_to_string(&path).expect("read");
        text.pop(); // drop the newline, as a crash mid-write would
        fs::write(&path, text).expect("write torn log");

        let error = append(&path, &event(&[])).expect_err("torn log");
        assert!(matches!(error, AuditError::Malformed(_)), "{error:?}");
        assert!(error.to_string().contains("newline"), "{error}");
    }

    #[test]
    fn the_preflight_refuses_a_torn_or_oversized_tail_that_append_would_refuse() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = audit_file(directory.path());
        append(&path, &event(&[])).expect("append");
        check_writable(&path).expect("a whole log passes the preflight");

        let mut torn = fs::read(&path).expect("read");
        torn.extend_from_slice(br#"{"v":1"#);
        fs::write(&path, &torn).expect("write torn log");
        let error = check_writable(&path).expect_err("torn tail");
        assert!(error.to_string().contains("newline"), "{error}");

        let mut oversized = vec![b'x'; MAX_RECORD_BYTES + 16];
        oversized.push(b'\n');
        fs::write(&path, oversized).expect("write oversized log");
        let error = check_writable(&path).expect_err("oversized tail");
        assert!(matches!(error, AuditError::Malformed(_)), "{error:?}");
    }

    #[test]
    fn an_oversized_last_line_is_refused_without_reading_it_all() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = audit_file(directory.path());
        let state = directory.path().join(STATE_DIR_NAME);
        fs::create_dir_all(&state).expect("state dir");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let mut oversized = vec![b'x'; MAX_RECORD_BYTES + 16];
        oversized.push(b'\n');
        fs::write(&path, oversized).expect("write oversized log");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod file");

        let error = append(&path, &event(&[])).expect_err("oversized last line");
        assert!(matches!(error, AuditError::Malformed(_)), "{error:?}");
    }
}
