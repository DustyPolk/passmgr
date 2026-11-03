//! Command-line argument parsing.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use passmgr::password::{MAX_LEN, MIN_LEN, Preset};
use passmgr::store;

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
    Help,
    Version,
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
                return Ok(finish_parsing(db_override, agent, Command::Help));
            }
            "-V" | "--version" => {
                return Ok(finish_parsing(db_override, agent, Command::Version));
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
    Ok(finish_parsing(db_override, agent, command))
}

pub(crate) fn finish_parsing(
    db_override: Option<PathBuf>,
    agent: bool,
    command: Command,
) -> Parsed {
    let db_path = db_override
        .or_else(|| {
            env::var_os("PASSMGR_DB")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB));
    Parsed {
        db_path,
        agent,
        command,
    }
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

pub(crate) fn parse_length(value: &str) -> Result<usize, String> {
    let length = value
        .parse::<usize>()
        .map_err(|_| format!("invalid length '{value}' (expected a number)"))?;
    if !(MIN_LEN..=MAX_LEN).contains(&length) {
        return Err(format!("length must be between {MIN_LEN} and {MAX_LEN}"));
    }
    Ok(length)
}
