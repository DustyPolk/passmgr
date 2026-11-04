//! Reading and verifying the audit log (TODO 3.9).
//!
//! This is the untrusted-input side of the audit log. A record on disk may
//! have been edited, reordered, truncated or replaced by any process running
//! as the user, so every field is parsed and bounded again here; nothing is
//! trusted because the writer once produced it.
//!
//! # What the chain proves
//!
//! Each record carries `prev`, the SHA-256 of the previous line's bytes, so a
//! single modified, inserted, deleted or reordered record breaks the link
//! between it and its successor. [`verify`] reports the first line whose
//! `prev` does not match, which is the earliest point the log stops being the
//! log the writer produced.
//!
//! Three things the chain cannot detect, all accepted and documented in
//! `SECURITY.md`: a change to the **last** record (nothing follows it to
//! disagree), deletion of the last record, and deletion of the whole file.
//! Detecting those needs an external anchor, which is out of scope.
//!
//! Reading takes a shared `flock` so a reader never sees a line mid-append,
//! and validates the file and its directory with the same rules as the
//! writer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde_json::{Map, Value, json};

use super::{
    AuditError, EVENT_RUN, GENESIS_PREV, MAX_ARG_CHARS, MAX_ARGS, MAX_COMMAND_CHARS,
    MAX_RECORD_BYTES, MAX_REFERENCE_CHARS, Outcome, Source, Termination, chain_hash, lock,
    validate_directory, validate_file,
};
use crate::grant::GrantId;
use crate::timestamp;

/// Largest audit log [`load`] reads in one call (64 MiB).
///
/// The log is append-only and unbounded today, so without a cap an inflated
/// file would be read into memory whole. At the writer's record size this is
/// hundreds of thousands of uses; hitting it means the log needs rotation
/// (not implemented yet), and the error says so instead of failing vaguely.
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// One validated audit record.
///
/// Fields are typed after parsing, so a consumer cannot accidentally print an
/// arbitrary string where the writer only ever stored a known outcome. There
/// is no secret in this type: the writer never stores one and the parser
/// rejects unknown fields only for the values it does store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Whole seconds since the Unix epoch, from `ts`.
    pub timestamp: u64,
    pub source: Source,
    pub outcome: Outcome,
    pub grant: Option<GrantId>,
    pub reference: Option<String>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub termination: Option<Termination>,
    /// The lowercase SHA-256 of the previous line (or the genesis value).
    pub prev: String,
}

impl Record {
    /// The record in the shape it has on disk, for `--json`.
    pub fn to_json(&self) -> Value {
        let (exit, signal) = match self.termination {
            Some(Termination::Code(code)) => (json!(code), Value::Null),
            Some(Termination::Signal(signal)) => (Value::Null, json!(signal)),
            None => (Value::Null, Value::Null),
        };
        json!({
            "v": 1,
            "ts": timestamp::format_utc(self.timestamp),
            "source": self.source.as_str(),
            "event": EVENT_RUN,
            "outcome": self.outcome.as_str(),
            "grant": match self.grant {
                Some(grant) => json!(grant.to_hex()),
                None => Value::Null,
            },
            "ref": self.reference,
            "command": self.command,
            "args": self.args,
            "exit": exit,
            "signal": signal,
            "prev": self.prev,
        })
    }

    /// Parse one line. `number` is 1-based and used only in error messages.
    fn parse(line: &[u8], number: usize) -> Result<Self, VerifyError> {
        if line.len() > MAX_RECORD_BYTES {
            return Err(VerifyError::Schema {
                line: number,
                detail: format!("the record is larger than {MAX_RECORD_BYTES} bytes"),
            });
        }
        let text = std::str::from_utf8(line).map_err(|_| VerifyError::Schema {
            line: number,
            detail: "the record is not UTF-8".into(),
        })?;
        let value: Value = serde_json::from_str(text).map_err(|error| VerifyError::Json {
            line: number,
            detail: error.to_string(),
        })?;
        let object = value.as_object().ok_or_else(|| VerifyError::Schema {
            line: number,
            detail: "the record is not a JSON object".into(),
        })?;

        match object.get("v").and_then(Value::as_u64) {
            Some(1) => {}
            Some(other) => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: format!("unsupported format version {other}"),
                });
            }
            None => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: "missing or non-numeric 'v'".into(),
                });
            }
        }

        let timestamp =
            timestamp::parse_utc(string_field(object, "ts", number)?).ok_or_else(|| {
                VerifyError::Schema {
                    line: number,
                    detail: "'ts' is not a valid UTC timestamp".into(),
                }
            })?;

        let source = match string_field(object, "source", number)? {
            "daemon" => Source::Daemon,
            "local" => Source::Local,
            other => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: format!("unknown 'source' {other:?}"),
                });
            }
        };

        if string_field(object, "event", number)? != EVENT_RUN {
            return Err(VerifyError::Schema {
                line: number,
                detail: "'event' is not a known event".into(),
            });
        }

        let outcome = match string_field(object, "outcome", number)? {
            "allowed" => Outcome::Allowed,
            "denied" => Outcome::Denied,
            "not_found" => Outcome::NotFound,
            "bad_request" => Outcome::BadRequest,
            "internal" => Outcome::Internal,
            "spawn_failed" => Outcome::SpawnFailed,
            "cancelled" => Outcome::Cancelled,
            "output_error" => Outcome::OutputError,
            other => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: format!("unknown 'outcome' {other:?}"),
                });
            }
        };

        let grant = match optional_string(object, "grant", number)? {
            Some(text) => Some(GrantId::from_hex(text).map_err(|_| VerifyError::Schema {
                line: number,
                detail: "'grant' is not a grant id".into(),
            })?),
            None => None,
        };

        let reference = optional_string(object, "ref", number)?.map(|text| {
            if text.chars().count() > MAX_REFERENCE_CHARS
                || !text.starts_with("pm://")
                || text.chars().any(char::is_control)
            {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: "'ref' is not a reference".into(),
                });
            }
            Ok(text.to_owned())
        });
        let reference = match reference {
            Some(Ok(reference)) => Some(reference),
            Some(Err(error)) => return Err(error),
            None => None,
        };

        let command = optional_string(object, "command", number)?;
        if command.is_some_and(|text| text.chars().count() > MAX_COMMAND_CHARS) {
            return Err(VerifyError::Schema {
                line: number,
                detail: "'command' is too long".into(),
            });
        }

        let args = match object.get("args").map(Value::as_array) {
            Some(Some(values)) if values.len() <= MAX_ARGS => {
                let mut args = Vec::with_capacity(values.len());
                for value in values {
                    let arg = value.as_str().ok_or_else(|| VerifyError::Schema {
                        line: number,
                        detail: "'args' contains a non-string".into(),
                    })?;
                    if arg.chars().count() > MAX_ARG_CHARS {
                        return Err(VerifyError::Schema {
                            line: number,
                            detail: "'args' contains an over-long argument".into(),
                        });
                    }
                    args.push(arg.to_owned());
                }
                args
            }
            Some(Some(_)) => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: format!("'args' has more than {MAX_ARGS} entries"),
                });
            }
            _ => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: "missing or non-array 'args'".into(),
                });
            }
        };

        let exit = u8_field(object, "exit", 255, number)?;
        let signal = u8_field(object, "signal", 127, number)?;
        let termination = match (exit, signal) {
            (Some(code), None) => Some(Termination::Code(code)),
            (None, Some(signal)) => Some(Termination::Signal(signal)),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(VerifyError::Schema {
                    line: number,
                    detail: "'exit' and 'signal' cannot both be set".into(),
                });
            }
        };

        let prev = string_field(object, "prev", number)?;
        if !is_chain_hash(prev) {
            return Err(VerifyError::Schema {
                line: number,
                detail: "'prev' is not a lowercase SHA-256".into(),
            });
        }

        Ok(Self {
            timestamp,
            source,
            outcome,
            grant,
            reference,
            command: command.map(str::to_owned),
            args,
            termination,
            prev: prev.to_owned(),
        })
    }
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    line: usize,
) -> Result<&'a str, VerifyError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::Schema {
            line,
            detail: format!("missing or non-string '{name}'"),
        })
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    line: usize,
) -> Result<Option<&'a str>, VerifyError> {
    match object.get(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(VerifyError::Schema {
            line,
            detail: format!("'{name}' is neither a string nor null"),
        }),
        None => Err(VerifyError::Schema {
            line,
            detail: format!("missing '{name}'"),
        }),
    }
}

/// A `null` or a small unsigned integer, bounded by `max`.
fn u8_field(
    object: &Map<String, Value>,
    name: &str,
    max: u64,
    line: usize,
) -> Result<Option<u8>, VerifyError> {
    match object.get(name) {
        Some(Value::Null) => Ok(None),
        Some(value) => match value.as_u64() {
            Some(number) if number <= max => Ok(Some(number as u8)),
            _ => Err(VerifyError::Schema {
                line,
                detail: format!("'{name}' is not an integer between 0 and {max}"),
            }),
        },
        None => Err(VerifyError::Schema {
            line,
            detail: format!("missing '{name}'"),
        }),
    }
}

fn is_chain_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Why a log failed verification, with the 1-based line of the first problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The line is not valid JSON.
    Json { line: usize, detail: String },
    /// The line is JSON but not a record this version accepts.
    Schema { line: usize, detail: String },
    /// `prev` does not commit to the previous line.
    Chain {
        line: usize,
        /// 0 when the record should follow the genesis value.
        previous_line: usize,
        expected: String,
        found: String,
    },
    /// The file does not end with a newline, so the last record is torn.
    Torn { line: usize },
    /// The file is larger than [`MAX_LOG_BYTES`].
    TooLarge { bytes: u64 },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { line, detail } => write!(f, "line {line}: invalid JSON: {detail}"),
            Self::Schema { line, detail } => write!(f, "line {line}: {detail}"),
            Self::Chain {
                line,
                previous_line: 0,
                expected,
                found,
            } => write!(
                f,
                "line {line}: prev does not match the genesis value \
                 (expected {expected}, found {found})"
            ),
            Self::Chain {
                line,
                previous_line,
                expected,
                found,
            } => write!(
                f,
                "line {line}: prev does not match line {previous_line} \
                 (expected {expected}, found {found})"
            ),
            Self::Torn { line } => {
                write!(f, "line {line}: the last record is not newline-terminated")
            }
            Self::TooLarge { bytes } => write!(
                f,
                "the audit log is {bytes} bytes, larger than the {MAX_LOG_BYTES} byte limit"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify every line of `bytes` and return the parsed records in order.
///
/// Empty input is a valid, empty log. The first line must carry
/// [`GENESIS_PREV`], and every later line must carry the SHA-256 of the exact
/// bytes of the line before it.
pub fn verify(bytes: &[u8]) -> Result<Vec<Record>, VerifyError> {
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(VerifyError::TooLarge {
            bytes: bytes.len() as u64,
        });
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        let line = bytes.iter().filter(|byte| **byte == b'\n').count() + 1;
        return Err(VerifyError::Torn { line });
    }
    let mut records = Vec::new();
    let mut expected = GENESIS_PREV.to_owned();
    for (index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let number = index + 1;
        let record = Record::parse(line, number)?;
        if record.prev != expected {
            return Err(VerifyError::Chain {
                line: number,
                previous_line: index,
                expected,
                found: record.prev.clone(),
            });
        }
        expected = chain_hash(line);
        records.push(record);
    }
    Ok(records)
}

/// Read and verify the log at `path`.
///
/// A missing file or state directory is an empty log, not an error: the
/// reader must work before the first recorded use. Anything else that is
/// wrong (loose permissions, a symlink, a broken chain) is refused, so
/// `pm audit verify` can never report success on a log it could not trust.
pub fn load(path: &Path) -> Result<Vec<Record>, AuditError> {
    let mut file = match open_read_only(path)? {
        Some(file) => file,
        None => return Ok(Vec::new()),
    };
    let length = file.metadata().map_err(|source| AuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if length.len() > MAX_LOG_BYTES {
        return Err(AuditError::Malformed(
            VerifyError::TooLarge {
                bytes: length.len(),
            }
            .to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(length.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    verify(&bytes).map_err(|error| AuditError::Malformed(error.to_string()))
}

/// Open and shared-lock the log for reading, or `None` if nothing exists yet.
fn open_read_only(path: &Path) -> Result<Option<File>, AuditError> {
    let directory = path
        .parent()
        .ok_or_else(|| AuditError::Malformed("the audit path has no parent directory".into()))?;
    if !validate_directory(directory)? {
        return Ok(None);
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AuditError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| AuditError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_file(&metadata, path)?;
    lock(&file, path, libc::LOCK_SH)?;
    Ok(Some(file))
}

/// Which records a listing shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Filter {
    /// Keep records authorized by exactly this grant.
    pub grant: Option<GrantId>,
    /// Keep records at or after this Unix second.
    pub since: Option<u64>,
}

impl Filter {
    pub fn matches(&self, record: &Record) -> bool {
        self.grant.is_none_or(|grant| record.grant == Some(grant))
            && self.since.is_none_or(|since| record.timestamp >= since)
    }
}

/// Select the most recent `limit` records that match, plus the number that
/// matched before the limit.
///
/// The tail is kept (not the head) so the default listing shows recent uses,
/// while `total` lets the caller say that older records were omitted.
pub fn select<'a>(
    records: &'a [Record],
    filter: &Filter,
    limit: usize,
) -> (Vec<&'a Record>, usize) {
    let matched: Vec<&Record> = records
        .iter()
        .filter(|record| filter.matches(record))
        .collect();
    let total = matched.len();
    let skip = total.saturating_sub(limit.max(1));
    (matched.into_iter().skip(skip).collect(), total)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::super::{AUDIT_FILE_NAME, Event, STATE_DIR_NAME, append, encode_line};
    use super::*;

    const GRANT: &str = "00112233445566778899aabbccddeeff";
    const OTHER_GRANT: &str = "ffeeddccbbaa99887766554433221100";
    const REFERENCE: &str = "pm://0123456789abcdef0123456789abcdef";
    const START: u64 = 1_735_689_600;

    fn grant(text: &str) -> GrantId {
        GrantId::from_hex(text).expect("grant id")
    }

    fn event<'a>(args: &'a [String]) -> Event<'a> {
        Event {
            source: Source::Daemon,
            outcome: Outcome::Allowed,
            grant: Some(grant(GRANT)),
            reference: Some(REFERENCE),
            command: Some("/usr/bin/true"),
            args,
            termination: Some(Termination::Code(0)),
        }
    }

    fn log_path(directory: &Path) -> PathBuf {
        directory.join(STATE_DIR_NAME).join(AUDIT_FILE_NAME)
    }

    /// Write records directly with controlled timestamps and outcomes, so the
    /// tests do not depend on the wall clock. The chain is built with the same
    /// public rules the writer uses.
    fn write_log(directory: &Path, records: &[(u64, Option<&str>, Outcome)]) -> PathBuf {
        let path = log_path(directory);
        let state = directory.join(STATE_DIR_NAME);
        fs::create_dir_all(&state).expect("state dir");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let mut text = String::new();
        let mut prev = GENESIS_PREV.to_owned();
        for (timestamp, grant_id, outcome) in records {
            let args = vec!["--flag".to_owned()];
            let mut event = event(&args);
            event.grant = grant_id.map(grant);
            event.outcome = *outcome;
            let line = encode_line(&prev, &event, *timestamp);
            prev = chain_hash(line.as_bytes());
            text.push_str(&line);
            text.push('\n');
        }
        fs::write(&path, text).expect("write log");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod file");
        path
    }

    fn rewrite(path: &Path, text: &str) {
        fs::write(path, text).expect("rewrite log");
    }

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .expect("read log")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_written_log_verifies_and_round_trips_every_field() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = log_path(directory.path());
        append(&path, &event(&["--flag".to_owned()])).expect("append");
        append(&path, &event(&[])).expect("append");

        let records = load(&path).expect("load");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].source, Source::Daemon);
        assert_eq!(records[0].outcome, Outcome::Allowed);
        assert_eq!(records[0].grant, Some(grant(GRANT)));
        assert_eq!(records[0].reference.as_deref(), Some(REFERENCE));
        assert_eq!(records[0].command.as_deref(), Some("/usr/bin/true"));
        assert_eq!(records[0].args, vec!["--flag".to_owned()]);
        assert_eq!(records[0].termination, Some(Termination::Code(0)));
        assert_eq!(
            records[1].to_json()["prev"].as_str(),
            Some(records[1].prev.as_str())
        );
        assert_eq!(records[1].prev.len(), 64);

        let json = records[0].to_json();
        assert_eq!(json["v"], 1);
        assert_eq!(json["event"], EVENT_RUN);
        assert_eq!(json["grant"], GRANT);
        assert_eq!(json["exit"], 0);
        assert!(json["signal"].is_null());
    }

    #[test]
    fn an_empty_or_missing_log_is_an_empty_list() {
        let directory = tempfile::tempdir().expect("tempdir");
        assert_eq!(load(&log_path(directory.path())).expect("missing"), vec![]);

        let path = write_log(directory.path(), &[]);
        assert_eq!(load(&path).expect("empty"), vec![]);
        assert_eq!(verify(b"").expect("empty bytes"), vec![]);
    }

    #[test]
    fn a_modified_record_breaks_the_chain_at_the_next_line() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(
            directory.path(),
            &[
                (START, Some(GRANT), Outcome::Allowed),
                (START + 1, Some(GRANT), Outcome::Denied),
                (START + 2, Some(OTHER_GRANT), Outcome::Allowed),
            ],
        );
        let mut text = lines(&path);
        // Same byte length, so only the chain can notice.
        text[1] = text[1].replace("\"denied\"", "\"allowed\"");
        assert!(!text[1].contains("denied"));
        rewrite(&path, &(text.join("\n") + "\n"));

        let error = load(&path).expect_err("modified log");
        let detail = error.to_string();
        assert!(
            detail.contains("line 3") && detail.contains("line 2"),
            "the first impossible link names both lines: {detail}"
        );
    }

    #[test]
    fn a_deleted_record_breaks_the_chain() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(
            directory.path(),
            &[
                (START, Some(GRANT), Outcome::Allowed),
                (START + 1, Some(GRANT), Outcome::Allowed),
                (START + 2, Some(GRANT), Outcome::Allowed),
            ],
        );
        let text = lines(&path);
        rewrite(&path, &(format!("{}\n{}\n", text[0], text[2])));

        let error = load(&path).expect_err("deleted record");
        assert!(error.to_string().contains("line 2"), "{error}");
    }

    #[test]
    fn reordered_records_break_the_chain() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(
            directory.path(),
            &[
                (START, Some(GRANT), Outcome::Allowed),
                (START + 1, Some(GRANT), Outcome::Allowed),
                (START + 2, Some(GRANT), Outcome::Allowed),
            ],
        );
        let text = lines(&path);
        rewrite(&path, &(format!("{}\n{}\n{}\n", text[1], text[0], text[2])));

        let error = load(&path).expect_err("reordered records");
        assert!(error.to_string().contains("line 1"), "{error}");
    }

    #[test]
    fn a_torn_last_record_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(directory.path(), &[(START, Some(GRANT), Outcome::Allowed)]);
        let mut text = fs::read_to_string(&path).expect("read");
        text.pop();
        rewrite(&path, &text);

        let error = load(&path).expect_err("torn log");
        assert!(
            matches!(verify(text.as_bytes()), Err(VerifyError::Torn { .. })),
            "{error}"
        );
        assert!(error.to_string().contains("newline"), "{error}");
    }

    #[test]
    fn a_record_with_an_unknown_or_invalid_field_is_refused() {
        let line = encode_line(GENESIS_PREV, &event(&[]), START);
        let value: Value = serde_json::from_str(&line).expect("json");
        for (field, replacement) in [
            ("v", json!(2)),
            ("ts", json!("2025-02-30T00:00:00Z")),
            ("source", json!("elsewhere")),
            ("event", json!("unlock")),
            ("outcome", json!("mostly")),
            ("grant", json!("not-a-grant-id")),
            ("ref", json!("https://example.com")),
            ("args", json!("not-an-array")),
            ("exit", json!(256)),
            ("signal", json!(0)),
            ("prev", json!("ABC")),
        ] {
            let mut object = value.as_object().expect("object").clone();
            object.insert(field.into(), replacement);
            let text = serde_json::to_string(&Value::Object(object)).expect("json");
            let error = verify(format!("{text}\n").as_bytes())
                .expect_err(&format!("a bad '{field}' must be refused"));
            assert!(
                matches!(error, VerifyError::Schema { line: 1, .. }),
                "{field}: {error:?}"
            );
        }

        // Both a code and a signal is contradictory, not a preference.
        let mut object = value.as_object().expect("object").clone();
        object.insert("signal".into(), json!(9));
        let text = serde_json::to_string(&Value::Object(object)).expect("json");
        assert!(verify(format!("{text}\n").as_bytes()).is_err());
    }

    #[test]
    fn a_log_that_is_not_private_is_refused_instead_of_read() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(directory.path(), &[(START, Some(GRANT), Outcome::Allowed)]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod file");
        let error = load(&path).expect_err("loose file");
        assert!(matches!(error, AuditError::Insecure { .. }), "{error:?}");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod file");
        let state = path.parent().expect("parent");
        fs::set_permissions(state, fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let error = load(&path).expect_err("loose directory");
        assert!(matches!(error, AuditError::Insecure { .. }), "{error:?}");
    }

    #[test]
    fn the_filter_selects_by_grant_and_time_and_keeps_the_recent_tail() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_log(
            directory.path(),
            &[
                (START, Some(GRANT), Outcome::Allowed),
                (START + 10, Some(OTHER_GRANT), Outcome::Denied),
                (START + 20, None, Outcome::Denied),
                (START + 30, Some(GRANT), Outcome::Allowed),
            ],
        );
        let records = load(&path).expect("load");

        let all = Filter::default();
        assert_eq!(select(&records, &all, 10).1, 4);
        let (shown, total) = select(&records, &all, 2);
        assert_eq!(total, 4);
        assert_eq!(
            shown
                .iter()
                .map(|record| record.timestamp)
                .collect::<Vec<_>>(),
            vec![START + 20, START + 30],
            "the tail is the most recent records"
        );

        let by_grant = Filter {
            grant: Some(grant(GRANT)),
            since: None,
        };
        let (shown, total) = select(&records, &by_grant, 10);
        assert_eq!(total, 2);
        assert!(
            shown
                .iter()
                .all(|record| record.grant == Some(grant(GRANT)))
        );

        let since = Filter {
            grant: None,
            since: Some(START + 20),
        };
        let (shown, total) = select(&records, &since, 10);
        assert_eq!(total, 2);
        assert!(shown.iter().all(|record| record.timestamp >= START + 20));

        // A pairing that matches nothing is empty, not everything.
        let none = Filter {
            grant: Some(grant(OTHER_GRANT)),
            since: Some(START + 30),
        };
        assert_eq!(select(&records, &none, 10).1, 0);
    }
}
