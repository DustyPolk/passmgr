//! Argument parsing for `audit` (TODO 3.9).
//!
//! Syntax only: the grant filter is parsed as an id, `--since` as a duration
//! and `--limit` as a positive count. Nothing here reads the log or decides
//! whether a record is shown.

use std::ffi::OsString;
use std::time::Duration;

use passmgr::grant::GrantId;

use super::Command;

/// Records shown when `--limit` is absent.
pub(crate) const DEFAULT_AUDIT_LIMIT: usize = 50;
/// Largest accepted `--limit`, so a typo cannot ask for an unbounded listing.
pub(crate) const MAX_AUDIT_LIMIT: usize = 1_000_000;

#[derive(Debug)]
pub(crate) enum AuditCommand {
    List(AuditListOptions),
    Verify,
}

/// `audit [--json] [--grant ID] [--since DUR] [--limit N]`.
#[derive(Debug)]
pub(crate) struct AuditListOptions {
    pub(crate) json: bool,
    /// Show only records authorized by this grant.
    pub(crate) grant: Option<GrantId>,
    /// Show only records at or after `now - since`.
    pub(crate) since: Option<Duration>,
    pub(crate) limit: usize,
}

/// `audit` (list) and `audit verify`.
pub(crate) fn parse_audit(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'audit' usage: passmgr audit [--json] [--grant <id>] \
                         [--since <30s|15m|1h|7d>] [--limit <n>] \
                         | passmgr audit verify";

    let mut json = false;
    let mut grant = None;
    let mut since = None;
    let mut limit = DEFAULT_AUDIT_LIMIT;
    let mut index = 0;
    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "verify" if index == 0 => {
                if args.len() != 1 {
                    return Err("'audit verify' takes no arguments".to_owned());
                }
                return Ok(Command::Audit(AuditCommand::Verify));
            }
            "--json" => json = true,
            "--grant" => {
                let value = super::flag_value(&args, index, "--grant")?;
                grant = Some(GrantId::from_hex(&value).map_err(|error| error.to_string())?);
                index += 1;
            }
            "--since" => {
                let value = super::flag_value(&args, index, "--since")?;
                since = Some(parse_since(&value)?);
                index += 1;
            }
            "--limit" => {
                let value = super::flag_value(&args, index, "--limit")?;
                limit = parse_limit(&value)?;
                index += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}' for 'audit'"));
            }
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'audit'; {USAGE}"
                ));
            }
        }
        index += 1;
    }
    Ok(Command::Audit(AuditCommand::List(AuditListOptions {
        json,
        grant,
        since,
        limit,
    })))
}

/// Parse `--since`: a positive whole number of seconds, minutes, hours or days.
///
/// Seconds are included here (unlike `--expires`) because "the last few
/// minutes" is a common question; the unit is always explicit so a bare number
/// cannot silently mean the wrong scale.
pub(crate) fn parse_since(text: &str) -> Result<Duration, String> {
    let digits = text
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    let (number, unit) = text.split_at(digits);
    if number.is_empty() {
        return Err(format!(
            "invalid --since '{text}' (expected a duration such as 30s, 15m, 1h or 7d)"
        ));
    }
    let value = number
        .parse::<u64>()
        .map_err(|_| format!("invalid --since '{text}' (the number is too large)"))?;
    let seconds_per_unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => {
            return Err(format!(
                "invalid --since '{text}' (use seconds 's', minutes 'm', hours 'h' or days 'd')"
            ));
        }
    };
    let seconds = value
        .checked_mul(seconds_per_unit)
        .ok_or_else(|| format!("invalid --since '{text}' (the duration is too large)"))?;
    if seconds == 0 {
        return Err("--since must be at least 1s".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_limit(text: &str) -> Result<usize, String> {
    let value = text
        .parse::<usize>()
        .map_err(|_| format!("invalid --limit '{text}' (expected a positive integer)"))?;
    if value == 0 {
        return Err("--limit must be at least 1".to_owned());
    }
    if value > MAX_AUDIT_LIMIT {
        return Err(format!("--limit may be at most {MAX_AUDIT_LIMIT}"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn options(args: &[&str]) -> AuditListOptions {
        match parse_audit(os(args)).expect("audit parses") {
            Command::Audit(AuditCommand::List(options)) => options,
            other => panic!("expected audit list, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_audit_lists_fifty_records_as_human_output() {
        let options = options(&[]);
        assert!(!options.json);
        assert!(options.grant.is_none());
        assert!(options.since.is_none());
        assert_eq!(options.limit, DEFAULT_AUDIT_LIMIT);
    }

    #[test]
    fn list_flags_parse_into_a_filter() {
        let options = options(&[
            "--json",
            "--grant",
            "00112233445566778899aabbccddeeff",
            "--since",
            "90m",
            "--limit",
            "7",
        ]);
        assert!(options.json);
        assert_eq!(
            options.grant,
            Some(GrantId::from_hex("00112233445566778899aabbccddeeff").expect("id"))
        );
        assert_eq!(options.since, Some(Duration::from_secs(90 * 60)));
        assert_eq!(options.limit, 7);
    }

    #[test]
    fn verify_is_its_own_subcommand_with_no_flags() {
        assert!(matches!(
            parse_audit(os(&["verify"])).expect("verify parses"),
            Command::Audit(AuditCommand::Verify)
        ));
        assert!(
            parse_audit(os(&["verify", "--json"])).is_err(),
            "verify takes no arguments, so it cannot be asked for JSON"
        );
        assert!(
            parse_audit(os(&["--json", "verify"])).is_err(),
            "verify must be the first word, or it is an unexpected argument"
        );
    }

    #[test]
    fn invalid_filters_are_refused_before_the_log_is_read() {
        for args in [
            vec!["--grant", "0011"],
            vec!["--grant"],
            vec!["--since", "10"],
            vec!["--since", "0s"],
            vec!["--since", "1w"],
            vec!["--since", "m"],
            vec!["--since"],
            vec!["--limit", "0"],
            vec!["--limit", "many"],
            vec!["--limit"],
            vec!["--bogus"],
            vec!["list"],
        ] {
            assert!(parse_audit(os(&args)).is_err(), "{args:?} must be refused");
        }
    }

    #[test]
    fn durations_use_explicit_units() {
        assert_eq!(parse_since("30s").expect("s"), Duration::from_secs(30));
        assert_eq!(parse_since("15m").expect("m"), Duration::from_secs(900));
        assert_eq!(parse_since("2h").expect("h"), Duration::from_secs(7_200));
        assert_eq!(parse_since("7d").expect("d"), Duration::from_secs(604_800));
        assert!(parse_since("99999999999999999999d").is_err());
    }
}
