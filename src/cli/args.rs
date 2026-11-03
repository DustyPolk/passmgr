//! Command-line argument parsing.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use passmgr::password::{MAX_LEN, MIN_LEN, Preset};
use passmgr::store;
use passmgr::store::EntryId;

pub(crate) const DEFAULT_DB: &str = "passwords.dat";

#[derive(Debug)]
pub(crate) struct Parsed {
    pub(crate) db_path: PathBuf,
    /// The global `--agent` flag. It can only add refusal, never remove it.
    pub(crate) agent: bool,
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) enum Command {
    Add(AddOptions),
    Get {
        service: String,
        reveal: bool,
    },
    Delete(String),
    Edit(EditOptions),
    List {
        json: bool,
        tags: Vec<String>,
    },
    Show {
        reference: String,
        json: bool,
    },
    Generate(GenerateOptions),
    Unlock {
        /// `None` means [`passmgr::daemon::DEFAULT_IDLE_TIMEOUT`].
        idle_timeout: Option<std::time::Duration>,
    },
    Lock,
    Run(RunOptions),
    Grant(GrantCommand),
    Help,
    Version,
}

#[derive(Debug)]
pub(crate) enum GrantCommand {
    Create(GrantCreateOptions),
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

#[derive(Debug)]
pub(crate) struct RunOptions {
    /// Environment variable the daemon injects the secret into.
    pub(crate) env: String,
    /// Credential reference (`pm://...`) the daemon resolves.
    pub(crate) reference: String,
    /// argv for the child. Never joined into a shell string.
    pub(crate) command: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct AddOptions {
    pub(crate) service: String,
    pub(crate) username: String,
    pub(crate) generate: bool,
    pub(crate) preset: Preset,
    pub(crate) length: usize,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct GenerateOptions {
    pub(crate) preset: Preset,
    pub(crate) length: usize,
}

#[derive(Debug)]
pub(crate) struct EditOptions {
    pub(crate) service: String,
    pub(crate) username: Option<String>,
    pub(crate) rename: Option<String>,
    pub(crate) generate: bool,
    pub(crate) preset: Preset,
    pub(crate) length: usize,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) clear_tags: bool,
}

pub(crate) fn parse_args(args: Vec<OsString>) -> Result<Parsed, String> {
    let mut args = args.into_iter().peekable();
    let mut db_override = None;
    let mut agent = false;
    let env_db = env::var_os("PASSMGR_DB")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    let (command, rest) = loop {
        let argument = args
            .next()
            .ok_or_else(|| "missing command (try 'passmgr --help')".to_owned())?;
        let Some(text) = argument.to_str() else {
            return Err("arguments must be valid UTF-8".to_owned());
        };
        match text {
            "--" => {
                let command = args
                    .next()
                    .ok_or_else(|| "missing command after '--'".to_owned())?;
                break (command, args.collect());
            }
            "-h" | "--help" => {
                return Ok(finish_parsing(db_override, env_db, agent, Command::Help));
            }
            "-V" | "--version" => {
                return Ok(finish_parsing(db_override, env_db, agent, Command::Version));
            }
            // A boolean flag, so repeating it is harmless.
            "--agent" => agent = true,
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--db requires a path".to_owned())?;
                set_db(&mut db_override, PathBuf::from(value))?;
            }
            other if other.starts_with("--db=") => {
                let value = &other["--db=".len()..];
                if value.is_empty() {
                    return Err("--db requires a path".to_owned());
                }
                set_db(&mut db_override, PathBuf::from(value))?;
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown global option '{other}'"));
            }
            _ => break (argument, args.collect()),
        }
    };

    let command = parse_command(command, rest)?;
    refuse_run_vault_selection(&command, db_override.as_deref(), env_db.as_deref())?;
    Ok(finish_parsing(db_override, env_db, agent, command))
}

pub(crate) fn finish_parsing(
    db_override: Option<PathBuf>,
    env_db: Option<PathBuf>,
    agent: bool,
    command: Command,
) -> Parsed {
    let db_path = db_override
        .or(env_db)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB));
    Parsed {
        db_path,
        agent,
        command,
    }
}

/// `run` talks to whichever daemon owns the runtime socket, and that daemon
/// holds the key for the vault it was unlocked with. Honouring `--db` here
/// would be a lie (the path is never sent) and ignoring it could inject a
/// value from a vault the human did not choose, so the combination is a usage
/// error before any connection is made. `PASSMGR_DB` counts too: an exported
/// variable would otherwise be silently ignored for this one command.
fn refuse_run_vault_selection(
    command: &Command,
    flag_db: Option<&Path>,
    env_db: Option<&Path>,
) -> Result<(), String> {
    if !matches!(command, Command::Run(_)) {
        return Ok(());
    }
    let Some(source) = flag_db.map(|_| "--db").or(env_db.map(|_| "PASSMGR_DB")) else {
        return Ok(());
    };
    Err(format!(
        "'run' always uses the vault of the running unlock daemon and does not accept \
         {source}; unset {source} (or unlock the daemon with the vault you want)"
    ))
}

pub(crate) fn set_db(slot: &mut Option<PathBuf>, path: PathBuf) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("--db requires a non-empty path".to_owned());
    }
    if slot.replace(path).is_some() {
        return Err("--db may only be specified once".to_owned());
    }
    Ok(())
}

pub(crate) fn parse_command(command: OsString, rest: Vec<OsString>) -> Result<Command, String> {
    let command = command
        .into_string()
        .map_err(|_| "command must be valid UTF-8".to_owned())?;

    if rest.len() == 1 {
        if let Some(flag) = rest[0].to_str() {
            if flag == "-h" || flag == "--help" {
                return Ok(Command::Help);
            }
        }
    }

    match command.as_str() {
        "add" => parse_add(rest),
        "get" => parse_get(rest),
        "delete" | "rm" => parse_single_argument(&command, rest).map(Command::Delete),
        "edit" => parse_edit(rest),
        "list" => parse_list(rest),
        "show" => parse_show(rest),
        "generate" => parse_generate(rest),
        "help" => {
            require_no_arguments("help", &rest)?;
            Ok(Command::Help)
        }
        "version" => {
            require_no_arguments("version", &rest)?;
            Ok(Command::Version)
        }
        "unlock" => parse_unlock(rest),
        "lock" => {
            require_no_arguments("lock", &rest)?;
            Ok(Command::Lock)
        }
        "run" => parse_run(rest),
        "grant" => parse_grant(rest),
        other => Err(format!("unknown command '{other}' (try 'passmgr --help')")),
    }
}

pub(crate) fn parse_single_argument(command: &str, args: Vec<OsString>) -> Result<String, String> {
    let mut args = args;
    if args.len() != 1 {
        return Err(format!(
            "'{command}' requires exactly one <service> argument"
        ));
    }
    args.pop()
        .expect("length was checked")
        .into_string()
        .map_err(|_| "service must be valid UTF-8".to_owned())
}

pub(crate) fn require_no_arguments(command: &str, args: &[OsString]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("'{command}' takes no arguments"))
    }
}

/// `run --env NAME=<ref> -- <command> [args...]`.
///
/// The command is everything after `--`; it is never re-parsed or joined into
/// a shell string. Exactly one `--env` is accepted because the daemon protocol
/// injects one secret per run.
pub(crate) fn parse_run(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'run' usage: passmgr run --env NAME=<ref> -- <command> [args...]";

    let mut env_spec = None;
    let mut index = 0;
    let command_start = loop {
        let Some(argument) = args.get(index) else {
            return Err(format!("{USAGE} (missing '--')"));
        };
        let Some(text) = argument.to_str() else {
            return Err("arguments must be valid UTF-8".to_owned());
        };
        if text == "--" {
            break index + 1;
        }
        if text == "--env" {
            let value = flag_value(&args, index, "--env")?;
            set_run_env(&mut env_spec, value)?;
            index += 2;
            continue;
        }
        if let Some(value) = text.strip_prefix("--env=") {
            set_run_env(&mut env_spec, value.to_owned())?;
            index += 1;
            continue;
        }
        return Err(format!("unexpected argument '{text}' for 'run'; {USAGE}"));
    };

    let spec = env_spec.ok_or_else(|| format!("{USAGE} (missing --env)"))?;
    let (env, reference) = spec
        .split_once('=')
        .ok_or_else(|| "--env expects NAME=<ref>, with one '=' between them".to_owned())?;
    if !passmgr::protocol::valid_env_name(env) {
        return Err(format!(
            "--env name '{env}' is invalid: use 1-{} ASCII letters, digits or '_', \
             not starting with a digit",
            passmgr::protocol::MAX_ENV_NAME_BYTES
        ));
    }
    if reference.is_empty() {
        return Err("--env reference is empty".to_owned());
    }
    if reference.len() > passmgr::protocol::MAX_REFERENCE_BYTES {
        return Err(format!(
            "--env reference exceeds {} bytes",
            passmgr::protocol::MAX_REFERENCE_BYTES
        ));
    }
    if passmgr::store::EntryId::parse_ref(reference).is_err() {
        return Err(format!(
            "--env reference '{reference}' is not a pm:// reference (see 'passmgr list')"
        ));
    }

    let command: Vec<String> = args[command_start..]
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "command arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<_, _>>()?;
    if command.is_empty() {
        return Err(format!("{USAGE} (missing command after '--')"));
    }
    if command.len() > passmgr::protocol::MAX_ARGS {
        return Err(format!(
            "command has more than {} arguments",
            passmgr::protocol::MAX_ARGS
        ));
    }
    for (position, argument) in command.iter().enumerate() {
        if argument.len() > passmgr::protocol::MAX_ARG_BYTES {
            return Err(format!(
                "command argument {position} exceeds {} bytes",
                passmgr::protocol::MAX_ARG_BYTES
            ));
        }
    }
    if command[0].is_empty() {
        return Err("the command path must not be empty".to_owned());
    }

    Ok(Command::Run(RunOptions {
        env: env.to_owned(),
        reference: reference.to_owned(),
        command,
    }))
}

fn set_run_env(slot: &mut Option<String>, spec: String) -> Result<(), String> {
    if slot.replace(spec).is_some() {
        return Err("'run' accepts exactly one --env (one secret per command)".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn parse_unlock(args: Vec<OsString>) -> Result<Command, String> {
    let mut idle_timeout = None;
    let mut index = 0;

    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "--idle-timeout" => {
                let value = flag_value(&args, index, "--idle-timeout")?;
                idle_timeout = Some(passmgr::daemon::parse_idle_timeout(&value)?);
                index += 2;
                continue;
            }
            other if other.starts_with("--idle-timeout=") => {
                let value = &other["--idle-timeout=".len()..];
                idle_timeout = Some(passmgr::daemon::parse_idle_timeout(value)?);
            }
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'unlock' (only --idle-timeout is accepted)"
                ));
            }
        }
        index += 1;
    }

    Ok(Command::Unlock { idle_timeout })
}

#[cfg(not(unix))]
pub(crate) fn parse_unlock(args: Vec<OsString>) -> Result<Command, String> {
    if args.is_empty() {
        Ok(Command::Unlock { idle_timeout: None })
    } else {
        // The daemon does not exist here; refuse the flag rather than accept
        // a setting that can never take effect.
        Err(format!(
            "'unlock' {} on this platform",
            super::DAEMON_UNSUPPORTED
        ))
    }
}

pub(crate) fn parse_list(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    let mut tags = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "--json" => json = true,
            "--tag" => {
                tags.push(flag_value(&args, index, "--tag")?);
                index += 2;
                continue;
            }
            other if other.starts_with("--tag=") => {
                tags.push(other["--tag=".len()..].to_owned());
            }
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'list' (only --json and --tag are accepted)"
                ));
            }
        }
        index += 1;
    }

    let tags = store::normalize_tags(tags).map_err(|err| err.to_string())?;
    Ok(Command::List { json, tags })
}

pub(crate) fn parse_show(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    let mut reference = None;
    let mut only_positional = false;

    for argument in args {
        let text = argument
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;

        if !only_positional && text.starts_with('-') && text != "-" {
            match text {
                "--" => only_positional = true,
                "-h" | "--help" => return Ok(Command::Help),
                "--json" => json = true,
                other => {
                    return Err(format!(
                        "unknown flag '{other}' (use '--' before values beginning with '-')"
                    ));
                }
            }
            continue;
        }

        if reference.replace(text.to_owned()).is_some() {
            return Err("'show' requires exactly one <ref> argument".to_owned());
        }
    }

    let reference =
        reference.ok_or_else(|| "'show' requires exactly one <ref> argument".to_owned())?;
    Ok(Command::Show { reference, json })
}

pub(crate) fn parse_get(args: Vec<OsString>) -> Result<Command, String> {
    let mut reveal = false;
    let mut service = None;
    let mut only_positional = false;

    for argument in args {
        let text = argument
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;

        if !only_positional && text.starts_with('-') && text != "-" {
            match text {
                "--" => only_positional = true,
                "-h" | "--help" => return Ok(Command::Help),
                "--reveal" => reveal = true,
                other => {
                    return Err(format!(
                        "unknown flag '{other}' (use '--' before values beginning with '-')"
                    ));
                }
            }
            continue;
        }

        if service.replace(text.to_owned()).is_some() {
            return Err("'get' requires exactly one <service> argument".to_owned());
        }
    }

    let service =
        service.ok_or_else(|| "'get' requires exactly one <service> argument".to_owned())?;
    Ok(Command::Get { service, reveal })
}

pub(crate) fn parse_add(args: Vec<OsString>) -> Result<Command, String> {
    let mut generate = false;
    let mut preset = Preset::Strong;
    let mut length = None;
    let mut tags = Vec::new();
    let mut positional = Vec::new();
    let mut only_positional = false;
    let mut index = 0;

    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;

        if !only_positional && text.starts_with('-') && text != "-" {
            match text {
                "--" => {
                    only_positional = true;
                    index += 1;
                    continue;
                }
                "-h" | "--help" => return Ok(Command::Help),
                "--generate" => generate = true,
                "--strong" => preset = Preset::Strong,
                "--simple" => preset = Preset::Simple,
                "--pin" => preset = Preset::Pin,
                "--tag" => {
                    tags.push(flag_value(&args, index, "--tag")?);
                    index += 2;
                    continue;
                }
                "--length" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--length requires a number".to_owned())?;
                    let value = value
                        .to_str()
                        .ok_or_else(|| "--length value must be valid UTF-8".to_owned())?;
                    length = Some(parse_length(value)?);
                    index += 2;
                    continue;
                }
                other if other.starts_with("--length=") => {
                    length = Some(parse_length(&other["--length=".len()..])?);
                }
                other if other.starts_with("--tag=") => {
                    tags.push(other["--tag=".len()..].to_owned());
                }
                other => {
                    return Err(format!(
                        "unknown flag '{other}' (use '--' before values beginning with '-')"
                    ));
                }
            }
            index += 1;
            continue;
        }

        positional.push(text.to_owned());
        index += 1;
    }

    if positional.len() != 2 {
        return Err("'add' requires <service> and <username>".to_owned());
    }
    let username = positional.pop().expect("length was checked");
    let service = positional.pop().expect("length was checked");

    Ok(Command::Add(AddOptions {
        service,
        username,
        generate,
        preset,
        length: length.unwrap_or_else(|| preset.default_length()),
        tags: store::normalize_tags(tags).map_err(|err| err.to_string())?,
    }))
}

pub(crate) fn flag_value(args: &[OsString], index: usize, name: &str) -> Result<String, String> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{name} value must be valid UTF-8"))
}

pub(crate) fn parse_edit(args: Vec<OsString>) -> Result<Command, String> {
    let mut generate = false;
    let mut preset = Preset::Strong;
    let mut length = None;
    let mut username = None;
    let mut rename = None;
    let mut tags = Vec::new();
    let mut clear_tags = false;
    let mut service = None;
    let mut only_positional = false;
    let mut index = 0;

    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;

        if !only_positional && text.starts_with('-') && text != "-" {
            match text {
                "--" => {
                    only_positional = true;
                    index += 1;
                    continue;
                }
                "-h" | "--help" => return Ok(Command::Help),
                "--generate" => generate = true,
                "--strong" => preset = Preset::Strong,
                "--simple" => preset = Preset::Simple,
                "--pin" => preset = Preset::Pin,
                "--clear-tags" => clear_tags = true,
                "--tag" => {
                    tags.push(flag_value(&args, index, "--tag")?);
                    index += 2;
                    continue;
                }
                "--length" => {
                    let value = flag_value(&args, index, "--length")?;
                    length = Some(parse_length(&value)?);
                    index += 2;
                    continue;
                }
                "--username" => {
                    username = Some(flag_value(&args, index, "--username")?);
                    index += 2;
                    continue;
                }
                "--rename" => {
                    rename = Some(flag_value(&args, index, "--rename")?);
                    index += 2;
                    continue;
                }
                other if other.starts_with("--length=") => {
                    length = Some(parse_length(&other["--length=".len()..])?);
                }
                other if other.starts_with("--tag=") => {
                    tags.push(other["--tag=".len()..].to_owned());
                }
                other if other.starts_with("--username=") => {
                    username = Some(other["--username=".len()..].to_owned());
                }
                other if other.starts_with("--rename=") => {
                    rename = Some(other["--rename=".len()..].to_owned());
                }
                other => {
                    return Err(format!(
                        "unknown flag '{other}' (use '--' before values beginning with '-')"
                    ));
                }
            }
            index += 1;
            continue;
        }

        if service.replace(text.to_owned()).is_some() {
            return Err("'edit' requires exactly one <service> argument".to_owned());
        }
        index += 1;
    }

    let service =
        service.ok_or_else(|| "'edit' requires exactly one <service> argument".to_owned())?;
    if clear_tags && !tags.is_empty() {
        return Err("'--clear-tags' cannot be combined with '--tag'".to_owned());
    }
    let tags = if tags.is_empty() {
        None
    } else {
        Some(store::normalize_tags(tags).map_err(|err| err.to_string())?)
    };
    Ok(Command::Edit(EditOptions {
        service,
        username,
        rename,
        generate,
        preset,
        length: length.unwrap_or_else(|| preset.default_length()),
        tags,
        clear_tags,
    }))
}

pub(crate) fn parse_generate(args: Vec<OsString>) -> Result<Command, String> {
    let mut preset = Preset::Strong;
    let mut length = None;
    let mut only_positional = false;
    let mut index = 0;

    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;

        if !only_positional && text.starts_with('-') && text != "-" {
            match text {
                "--" => {
                    only_positional = true;
                    index += 1;
                    continue;
                }
                "-h" | "--help" => return Ok(Command::Help),
                "--strong" => preset = Preset::Strong,
                "--simple" => preset = Preset::Simple,
                "--pin" => preset = Preset::Pin,
                "--length" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--length requires a number".to_owned())?;
                    let value = value
                        .to_str()
                        .ok_or_else(|| "--length value must be valid UTF-8".to_owned())?;
                    length = Some(parse_length(value)?);
                    index += 2;
                    continue;
                }
                other if other.starts_with("--length=") => {
                    length = Some(parse_length(&other["--length=".len()..])?);
                }
                other => return Err(format!("unknown flag '{other}'")),
            }
            index += 1;
            continue;
        }

        return Err(format!(
            "'generate' takes no positional arguments (found '{text}')"
        ));
    }

    Ok(Command::Generate(GenerateOptions {
        preset,
        length: length.unwrap_or_else(|| preset.default_length()),
    }))
}

/// `grant create` and, later, the other `grant` subcommands.
pub(crate) fn parse_grant(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'grant' usage: passmgr grant create --label <text> \
                         (--ref <pm://...> | --tag <tag>) --command <path> \
                         --expires <1h|30m|7d> --out <file>";

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
                expires = Some(super::grant::parse_expiry(&value)?);
                index += 2;
                continue;
            }
            other if other.starts_with("--expires=") => {
                expires = Some(super::grant::parse_expiry(&other["--expires=".len()..])?);
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

fn parse_max_uses(value: &str) -> Result<u32, String> {
    let uses = value
        .parse::<u32>()
        .map_err(|_| format!("invalid --max-uses '{value}' (expected a positive integer)"))?;
    if uses == 0 {
        return Err("--max-uses must be at least 1".to_owned());
    }
    Ok(uses)
}

pub(crate) fn parse_length(value: &str) -> Result<usize, String> {
    let length = value
        .parse::<usize>()
        .map_err(|_| format!("invalid length '{value}' (expected a number)"))?;
    if !(MIN_LEN..=MAX_LEN).contains(&length) {
        return Err(format!("length must be between {MIN_LEN} and {MAX_LEN}"));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN_REF: &str = "pm://00112233445566778899aabbccddeeff";

    fn run_command() -> Command {
        Command::Run(RunOptions {
            env: "API_KEY".into(),
            reference: RUN_REF.into(),
            command: vec!["/bin/true".into()],
        })
    }

    #[test]
    fn run_refuses_an_explicit_db_flag() {
        let error =
            refuse_run_vault_selection(&run_command(), Some(Path::new("/tmp/other.dat")), None)
                .expect_err("--db must be refused for run");
        assert!(error.contains("--db"), "{error}");
        assert!(error.contains("does not accept"), "{error}");
    }

    #[test]
    fn run_refuses_the_db_environment_variable() {
        // `PASSMGR_DB` is checked here rather than through `parse_args`, so
        // the test does not mutate the process environment (which would race
        // with every other test in the binary).
        let error =
            refuse_run_vault_selection(&run_command(), None, Some(Path::new("/tmp/other.dat")))
                .expect_err("PASSMGR_DB must be refused for run");
        assert!(error.contains("PASSMGR_DB"), "{error}");
    }

    #[test]
    fn other_commands_accept_an_explicit_db() {
        for command in [
            Command::List {
                json: false,
                tags: Vec::new(),
            },
            Command::Lock,
            Command::Help,
        ] {
            assert!(
                refuse_run_vault_selection(
                    &command,
                    Some(Path::new("/tmp/other.dat")),
                    Some(Path::new("/tmp/other.dat"))
                )
                .is_ok(),
                "{command:?}"
            );
        }
    }
}
