//! Argument parsing for the `grant` subcommands (TODO 3.5 split out of
//! `src/cli/args/mod.rs` to keep that file under the line limit).
//!
//! Everything here is syntax: refs become ids, tags are left to be normalized
//! by `Scope::new`, and commands are resolved against the real filesystem by
//! the command itself. Nothing touches the vault or a secret, and parsing
//! never decides whether a caller is allowed to do something.

use std::ffi::OsString;
use std::path::PathBuf;

use passmgr::grant::GrantId;
use passmgr::store::EntryId;

use super::{Command, flag_value};

#[derive(Debug)]
pub(crate) enum GrantCommand {
    Create(GrantCreateOptions),
    List(GrantListOptions),
    Show(GrantShowOptions),
    Revoke(GrantRevokeOptions),
}

/// `grant list [--json]`: metadata for every stored grant.
#[derive(Debug)]
pub(crate) struct GrantListOptions {
    pub(crate) json: bool,
}

/// `grant show <id> [--json]`: metadata for one grant.
#[derive(Debug)]
pub(crate) struct GrantShowOptions {
    pub(crate) id: GrantId,
    pub(crate) json: bool,
}

/// `grant revoke <id>|--all [--json]`: mark grants revoked. Takes no
/// password: it only removes access, so the human or their agent may do it.
#[derive(Debug)]
pub(crate) struct GrantRevokeOptions {
    /// `None` with `all == true` means every active grant.
    pub(crate) id: Option<GrantId>,
    pub(crate) all: bool,
    pub(crate) json: bool,
}

#[derive(Debug)]
pub(crate) struct GrantCreateOptions {
    pub(crate) label: String,
    pub(crate) references: Vec<EntryId>,
    pub(crate) tags: Vec<String>,
    /// Paths exactly as given; `grant create` resolves them before use.
    pub(crate) commands: Vec<String>,
    pub(crate) expires: std::time::Duration,
    pub(crate) max_uses: Option<u32>,
    pub(crate) allow_interpreter: bool,
    pub(crate) out: PathBuf,
}

/// `grant create` and the other `grant` subcommands.
pub(crate) fn parse_grant(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'grant' usage: passmgr grant create|list|show|revoke ...";

    if args.len() == 1 {
        if let Some(flag) = args[0].to_str() {
            if flag == "-h" || flag == "--help" {
                return Ok(Command::Help);
            }
        }
    }

    let mut args = args.into_iter();
    let subcommand = args
        .next()
        .ok_or_else(|| format!("'grant' requires a subcommand; {USAGE}"))?
        .into_string()
        .map_err(|_| "the 'grant' subcommand must be valid UTF-8".to_owned())?;
    let rest: Vec<OsString> = args.collect();
    match subcommand.as_str() {
        "create" => parse_grant_create(rest),
        "list" => parse_grant_list(rest),
        "show" => parse_grant_show(rest),
        "revoke" => parse_grant_revoke(rest),
        other => Err(format!(
            "unknown 'grant' subcommand '{other}' (try 'passmgr help')"
        )),
    }
}

/// `grant create --label <text> (--ref <pm://...> | --tag <tag>)...
/// --command <path>... --expires <duration> --out <file>`.
///
/// Everything here is syntax: refs are parsed as ids, tags are left to be
/// normalized by `Scope::new`, and commands are resolved against the real
/// filesystem by the command itself. Nothing touches the vault or a secret.
pub(crate) fn parse_grant_create(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'grant create' usage: passmgr grant create --label <text> \
                         (--ref <pm://...> | --tag <tag>) --command <path> \
                         --expires <1h|30m|7d> --out <file> \
                         [--max-uses N] [--allow-interpreter]";

    let mut label = None;
    let mut references = Vec::new();
    let mut tags = Vec::new();
    let mut commands = Vec::new();
    let mut expires = None;
    let mut max_uses = None;
    let mut allow_interpreter = false;
    let mut out = None;

    let mut index = 0;
    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "--label" => {
                label = Some(flag_value(&args, index, "--label")?);
                index += 2;
                continue;
            }
            other if other.starts_with("--label=") => {
                label = Some(other["--label=".len()..].to_owned());
            }
            "--ref" => {
                let value = flag_value(&args, index, "--ref")?;
                references.push(EntryId::parse_ref(&value).map_err(|error| error.to_string())?);
                index += 2;
                continue;
            }
            other if other.starts_with("--ref=") => {
                references.push(
                    EntryId::parse_ref(&other["--ref=".len()..])
                        .map_err(|error| error.to_string())?,
                );
            }
            "--tag" => {
                tags.push(flag_value(&args, index, "--tag")?);
                index += 2;
                continue;
            }
            other if other.starts_with("--tag=") => {
                tags.push(other["--tag=".len()..].to_owned());
            }
            "--command" => {
                commands.push(flag_value(&args, index, "--command")?);
                index += 2;
                continue;
            }
            other if other.starts_with("--command=") => {
                commands.push(other["--command=".len()..].to_owned());
            }
            "--expires" => {
                let value = flag_value(&args, index, "--expires")?;
                expires = Some(super::super::grant::parse_expiry(&value)?);
                index += 2;
                continue;
            }
            other if other.starts_with("--expires=") => {
                expires = Some(super::super::grant::parse_expiry(
                    &other["--expires=".len()..],
                )?);
            }
            "--max-uses" => {
                let value = flag_value(&args, index, "--max-uses")?;
                max_uses = Some(parse_max_uses(&value)?);
                index += 2;
                continue;
            }
            other if other.starts_with("--max-uses=") => {
                max_uses = Some(parse_max_uses(&other["--max-uses=".len()..])?);
            }
            "--allow-interpreter" => allow_interpreter = true,
            "--out" => {
                out = Some(PathBuf::from(flag_value(&args, index, "--out")?));
                index += 2;
                continue;
            }
            other if other.starts_with("--out=") => {
                out = Some(PathBuf::from(&other["--out=".len()..]));
            }
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'grant create' (see '{USAGE}')"
                ));
            }
        }
        index += 1;
    }

    let label = label.ok_or("'grant create' requires --label <text>")?;
    let expires = expires.ok_or_else(|| {
        "'grant create' requires --expires <duration> (for example 1h)".to_owned()
    })?;
    let out = out.ok_or("'grant create' requires --out <file>")?;
    if out.as_os_str().is_empty() {
        return Err("'grant create' --out must not be empty".to_owned());
    }
    if references.is_empty() && tags.is_empty() {
        return Err("'grant create' needs at least one --ref or --tag".to_owned());
    }
    if commands.is_empty() {
        return Err("'grant create' needs at least one --command <path>".to_owned());
    }

    Ok(Command::Grant(GrantCommand::Create(GrantCreateOptions {
        label,
        references,
        tags,
        commands,
        expires,
        max_uses,
        allow_interpreter,
        out,
    })))
}

/// `grant list [--json]`.
pub(crate) fn parse_grant_list(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    for arg in &args {
        let text = arg
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "--json" => json = true,
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'grant list' \
                     (only --json is accepted)"
                ));
            }
        }
    }
    Ok(Command::Grant(GrantCommand::List(GrantListOptions {
        json,
    })))
}

/// `grant show <id> [--json]`. Substring or label matching is deliberately
/// not supported: an id names exactly one grant, so a typo cannot select a
/// neighbouring grant.
pub(crate) fn parse_grant_show(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    let mut id = None;
    for arg in &args {
        let text = arg
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "--json" => json = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}' for 'grant show'"));
            }
            _ if id.is_some() => {
                return Err("'grant show' takes exactly one grant id".to_owned());
            }
            other => {
                id = Some(GrantId::from_hex(other).map_err(|error| error.to_string())?);
            }
        }
    }
    let id = id.ok_or("'grant show' requires a grant id (see 'passmgr grant list')")?;
    Ok(Command::Grant(GrantCommand::Show(GrantShowOptions {
        id,
        json,
    })))
}

/// `grant revoke <id> [--json]` or `grant revoke --all [--json]`. Exactly one
/// target is required, so a bare `grant revoke` cannot revoke everything.
pub(crate) fn parse_grant_revoke(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    let mut all = false;
    let mut id = None;
    for arg in &args {
        let text = arg
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "-h" | "--help" => return Ok(Command::Help),
            "--json" => json = true,
            "--all" => all = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}' for 'grant revoke'"));
            }
            _ if id.is_some() => {
                return Err("'grant revoke' takes one grant id or --all, not both".to_owned());
            }
            other => {
                id = Some(GrantId::from_hex(other).map_err(|error| error.to_string())?);
            }
        }
    }
    if all && id.is_some() {
        return Err("'grant revoke' takes one grant id or --all, not both".to_owned());
    }
    if !all && id.is_none() {
        return Err("'grant revoke' requires a grant id or --all".to_owned());
    }
    Ok(Command::Grant(GrantCommand::Revoke(GrantRevokeOptions {
        id,
        all,
        json,
    })))
}

fn parse_max_uses(value: &str) -> Result<u32, String> {
    let uses = value
        .parse::<u32>()
        .map_err(|_| format!("invalid --max-uses '{value}' (expected a positive integer)"))?;
    if uses == 0 {
        return Err("--max-uses must be at least 1".to_owned());
    }
    Ok(uses)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::cli::args::refuse_daemon_vault_selection;

    fn grant_id() -> GrantId {
        GrantId::from_hex("00112233445566778899aabbccddeeff").expect("grant id")
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn grant_list_and_show_parse_to_metadata_commands() {
        match parse_grant(os(&["list", "--json"])).expect("list parses") {
            Command::Grant(GrantCommand::List(options)) => assert!(options.json),
            other => panic!("expected grant list, got {other:?}"),
        }
        match parse_grant(os(&["show", "00112233445566778899aabbccddeeff"])).expect("show parses") {
            Command::Grant(GrantCommand::Show(options)) => {
                assert_eq!(options.id, grant_id());
                assert!(!options.json);
            }
            other => panic!("expected grant show, got {other:?}"),
        }
        // Flags may precede the positional id.
        match parse_grant(os(&["show", "--json", "00112233445566778899aabbccddeeff"]))
            .expect("show parses")
        {
            Command::Grant(GrantCommand::Show(options)) => assert!(options.json),
            other => panic!("expected grant show, got {other:?}"),
        }
        assert!(parse_grant(os(&["show"])).is_err(), "show needs an id");
        assert!(
            parse_grant(os(&["show", "0011"])).is_err(),
            "a short id is not a grant id"
        );
        assert!(
            parse_grant(os(&[
                "show",
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100"
            ]))
            .is_err(),
            "show takes exactly one id"
        );
    }

    #[test]
    fn grant_revoke_requires_exactly_one_target() {
        match parse_grant(os(&["revoke", "00112233445566778899aabbccddeeff"]))
            .expect("revoke parses")
        {
            Command::Grant(GrantCommand::Revoke(options)) => {
                assert_eq!(options.id, Some(grant_id()));
                assert!(!options.all);
                assert!(!options.json);
            }
            other => panic!("expected grant revoke, got {other:?}"),
        }
        match parse_grant(os(&["revoke", "--all", "--json"])).expect("revoke --all parses") {
            Command::Grant(GrantCommand::Revoke(options)) => {
                assert_eq!(options.id, None);
                assert!(options.all);
                assert!(options.json);
            }
            other => panic!("expected grant revoke --all, got {other:?}"),
        }

        // An empty `grant revoke` must never mean "everything".
        let error = parse_grant(os(&["revoke"])).expect_err("a bare revoke is refused");
        assert!(error.contains("--all"), "{error}");
        let error = parse_grant(os(&["revoke", "--all", "00112233445566778899aabbccddeeff"]))
            .expect_err("id and --all together are refused");
        assert!(error.contains("not both"), "{error}");
        assert!(
            parse_grant(os(&["revoke", "--nope"])).is_err(),
            "unknown flags are refused"
        );
        assert!(
            parse_grant(os(&["revoke", "zzzz"])).is_err(),
            "a non-hex id is refused"
        );
    }

    #[test]
    fn grant_revoke_refuses_an_explicit_db_flag() {
        let command = parse_grant(os(&["revoke", "--all"])).expect("revoke parses");
        let error =
            refuse_daemon_vault_selection(&command, Some(Path::new("/tmp/other.dat")), None)
                .expect_err("--db must be refused for grant revoke");
        assert!(error.contains("grant revoke"), "{error}");
        assert!(error.contains("--db"), "{error}");

        // `grant list` reads the vault locally, so it keeps `--db`.
        let list = parse_grant(os(&["list"])).expect("list parses");
        assert!(
            refuse_daemon_vault_selection(&list, Some(Path::new("/tmp/other.dat")), None).is_ok()
        );
    }
}
