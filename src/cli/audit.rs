//! `audit`: read and verify the hash-chained audit log (TODO 3.9).
//!
//! Both subcommands are metadata-only. Reading does not need the master
//! password because a record never holds a secret, a grant token or a session
//! token; it holds the time, the outcome, the grant id, the reference, the
//! program, its arguments and how the child ended.
//!
//! `verify` reports the first line whose `prev` does not commit to the line
//! before it, and exits 6. That covers an edited, inserted, deleted (except
//! the last) or reordered record. A change to the final record, deletion of
//! the final record and deletion of the whole file are not detectable without
//! an external anchor; `SECURITY.md` records that limit.

use std::fmt::Write as _;

use passmgr::Error;
use passmgr::audit::{self, Filter, Record, Termination};
use passmgr::text::escape_hidden;
use passmgr::timestamp;

use super::args::{AuditCommand, AuditListOptions};
use super::commands::write_json;
use super::grant::unix_now;
use super::stdout_write;

pub(crate) fn command_audit(command: AuditCommand) -> Result<(), Error> {
    match command {
        AuditCommand::List(options) => command_audit_list(options),
        AuditCommand::Verify => command_audit_verify(),
    }
}

fn command_audit_list(options: AuditListOptions) -> Result<(), Error> {
    let path = audit::default_path()?;
    let records = audit::load(&path)?;
    let since = match options.since {
        Some(duration) => Some(unix_now()?.saturating_sub(duration.as_secs())),
        None => None,
    };
    let filter = Filter {
        grant: options.grant,
        since,
    };
    let (shown, total) = audit::select(&records, &filter, options.limit);

    if options.json {
        let records: Vec<_> = shown.iter().map(|record| record.to_json()).collect();
        return write_json(&serde_json::json!({ "records": records }));
    }

    if total == 0 {
        let message = if options.grant.is_some() || options.since.is_some() {
            "No audit records match the filter.\n"
        } else {
            "No audit records.\n"
        };
        return stdout_write(format_args!("{message}"));
    }
    let mut text = format!("Audit records (showing {} of {total}):\n", shown.len());
    for record in shown {
        text.push_str(&describe(record));
        text.push('\n');
    }
    stdout_write(format_args!("{text}"))
}

fn command_audit_verify() -> Result<(), Error> {
    let path = audit::default_path()?;
    let records = audit::load(&path)?;
    let noun = if records.len() == 1 {
        "record"
    } else {
        "records"
    };
    stdout_write(format_args!(
        "Audit log verified: {} {noun}.\n",
        records.len()
    ))
}

/// One human-readable record line. Every string comes from the log and is
/// escaped, so a tampered (but chain-consistent) record cannot move the
/// terminal cursor or forge a new line.
fn describe(record: &Record) -> String {
    let mut line = format!(
        "{}  {}  {}",
        timestamp::format_utc(record.timestamp),
        record.outcome.as_str(),
        record.source.as_str()
    );
    if let Some(grant) = record.grant {
        push_field(&mut line, "grant", &grant.to_hex());
    }
    if let Some(reference) = &record.reference {
        push_field(&mut line, "ref", reference);
    }
    if let Some(command) = &record.command {
        push_field(&mut line, "command", command);
    }
    if !record.args.is_empty() {
        let args: Vec<String> = record.args.iter().map(|arg| escape_hidden(arg)).collect();
        push_field(&mut line, "args", &format!("[{}]", args.join(", ")));
    }
    match record.termination {
        Some(Termination::Code(code)) => push_field(&mut line, "exit", &code.to_string()),
        Some(Termination::Signal(signal)) => push_field(&mut line, "signal", &signal.to_string()),
        None => {}
    }
    line
}

fn push_field(line: &mut String, name: &str, value: &str) {
    write!(line, "  {name}={}", escape_hidden(value)).expect("writing to a String cannot fail");
}

#[cfg(test)]
mod tests {
    use super::*;
    use passmgr::audit::{Outcome, Source};
    use passmgr::grant::GrantId;

    fn record(grant: Option<GrantId>) -> Record {
        Record {
            timestamp: 1_735_689_600,
            source: Source::Daemon,
            outcome: Outcome::Allowed,
            grant,
            reference: Some("pm://0123456789abcdef0123456789abcdef".into()),
            command: Some("/usr/bin/true".into()),
            args: vec!["--flag".into(), "two words".into()],
            termination: Some(Termination::Code(0)),
            prev: "0".repeat(64),
        }
    }

    #[test]
    fn a_line_names_the_time_outcome_and_metadata_but_no_prev() {
        let text = describe(&record(Some(
            GrantId::from_hex("00112233445566778899aabbccddeeff").expect("id"),
        )));
        assert!(
            text.starts_with("2025-01-01T00:00:00Z  allowed  daemon"),
            "{text}"
        );
        assert!(
            text.contains("grant=00112233445566778899aabbccddeeff"),
            "{text}"
        );
        assert!(
            text.contains("ref=pm://0123456789abcdef0123456789abcdef"),
            "{text}"
        );
        assert!(text.contains("command=/usr/bin/true"), "{text}");
        assert!(text.contains("args=[--flag, two words]"), "{text}");
        assert!(text.contains("exit=0"), "{text}");
        assert!(
            !text.contains("prev="),
            "the chain hash is not interesting to a human"
        );
    }

    #[test]
    fn hidden_characters_in_a_record_are_escaped() {
        let mut record = record(None);
        record.command = Some("evil\u{1b}[31m\nforged".into());
        let text = describe(&record);
        assert!(!text.contains('\n'), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(
            text.contains("\\u{1b}") || text.contains("\\x1b") || text.contains("U+001B"),
            "{text}"
        );
    }

    #[test]
    fn a_denial_without_a_command_or_exit_still_renders() {
        let mut record = record(None);
        record.outcome = Outcome::Denied;
        record.command = None;
        record.args.clear();
        record.termination = None;
        record.reference = None;
        let text = describe(&record);
        assert_eq!(text, "2025-01-01T00:00:00Z  denied  daemon");
    }

    #[test]
    fn a_signal_is_not_rendered_as_an_exit_code() {
        let mut record = record(None);
        record.termination = Some(Termination::Signal(9));
        let text = describe(&record);
        assert!(text.contains("signal=9"), "{text}");
        assert!(!text.contains("exit="), "{text}");
    }
}
