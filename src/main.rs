//! Command-line interface for the password manager.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use passmgr::Error;
use passmgr::agent;
use passmgr::error::{EXIT_OK, EXIT_USAGE};
use passmgr::password::{self, MAX_LEN, MIN_LEN, Preset};
use passmgr::store::{self, Credential};
use passmgr::terminal;
use passmgr::vault::{self, Vault};
use zeroize::Zeroizing;

const DEFAULT_DB: &str = "passwords.dat";

const USAGE: &str = "Usage: passmgr [--db PATH] [--agent] <command> [arguments]
Try 'passmgr --help' for more information.";

const HELP: &str = r#"Simple Secure Password Manager (Rust)

Usage: passmgr [--db PATH] [--agent] <command> [arguments]

Commands:
  add [options] <service> <username>
                             Add a credential. The credential password is
                             prompted (and confirmed) unless --generate is used.
                             With --generate the password is stored but never
                             printed; only the entry name is confirmed.
  get [--reveal] <service>   Show credential metadata. Allowed flags:
                               --reveal   Print the password. Human use only:
                                          stdin and stdout must both be a
                                          terminal and no agent environment
                                          marker (PASSMGR_AGENT, CLAUDECODE,
                                          CURSOR_AGENT, CODEX_SANDBOX) may be
                                          set, and --agent must not be passed.
                                          Otherwise the command is refused
                                          with exit code 5. There is no
                                          bypass flag.
  delete <service>           Remove a credential permanently.
  rm <service>               Alias for delete.
  edit [options] <service>   Update a credential. Without --username or
                             --rename the password is rotated: the new value
                             is prompted twice and never printed. Allowed
                             flags:
                               --username U   Set the username.
                               --rename NAME  Rename the service.
                               --generate     Generate a new password instead
                                              of prompting (implies rotation).
                               --strong, --simple, --pin, --length N
                                              Generation options for --generate.
  list [--json]             List stored services, usernames and references.
                             With --json, print {"entries":[...]} where each
                             entry has only "ref", "service" and "username".
  show [--json] <ref>        Show one credential by its pm:// reference.
                             Metadata only, no password. --json prints the
                             entry object directly.
  generate [options]         Generate a secure random password.
  help                       Show this help.
  version                    Show version information.

Global options:
  --db PATH                  Vault file (default: ./passwords.dat, or $PASSMGR_DB).
  --agent                    Force agent mode. This can only make the tool more
                             restrictive: 'get --reveal' is refused even on a
                             terminal. It never reveals a secret by itself.
  -h, --help                 Show this help.
  -V, --version              Show version information.

Password generation options (add/edit/generate):
  --generate                 Generate the password instead of prompting (add/edit only).
  --strong                   Uppercase, lowercase, digits, symbols (default).
  --simple                   Uppercase, lowercase, digits only.
  --pin                      Digits only.
  --length N                 Length 4-128 (defaults: strong 20, simple 16, pin 6).

Examples:
  passmgr add github.com octocat
  passmgr add --generate --simple --length 24 github.com octocat
  passmgr edit --generate github.com
  passmgr edit --rename github.example github.com
  passmgr generate --pin --length 8
  passmgr get github.com
  passmgr list
  passmgr list --json
  passmgr show pm://0123456789abcdef0123456789abcdef
  passmgr --db ~/.secrets/work.dat list

Notes:
  - The master password is required for every command except generate/help/version.
  - Prompts are written to stderr; command data is written to stdout.
  - 'add --generate' never prints the generated password; read it back with
    the TTY-gated 'get --reveal'.
  - Every credential has a stable reference 'pm://<32 hex characters>', shown
    by 'list' and 'get'. A reference identifies an entry for agents and tools
    without revealing any secret, and survives renames. 'show' accepts only a
    full reference, never a service name.
  - 'list --json' and 'show --json' emit references and metadata only; there
    is no JSON field that carries a password.
  - 'edit' never prints the new password either; rotating prompts for it
    twice, and a generated one is only confirmed by name.
  - Creating a new vault asks for the master password twice.
  - global options (--db, --agent) must come before the command.
  - Exit codes are stable: 0 success, 1 runtime failure, 2 usage or invalid
    input, 3 not found, 4 wrong master password, 5 refused (for example
    'get --reveal' without a terminal, in an agent context, or with --agent),
    6 malformed, truncated or unsupported vault file.
  - Vaults are encrypted with Argon2id and AES-256-GCM.
  - The legacy C vault format is not readable; this version uses a new format.
"#;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::from(EXIT_OK),
        Err(CliError::Usage(message)) => {
            eprintln!("passmgr: {message}");
            eprintln!();
            eprintln!("{USAGE}");
            std::process::ExitCode::from(EXIT_USAGE)
        }
        Err(CliError::Runtime(Error::Io(error))) if error.kind() == io::ErrorKind::BrokenPipe => {
            std::process::ExitCode::from(EXIT_OK)
        }
        Err(CliError::Runtime(error)) => {
            report_runtime_error(&error);
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

enum CliError {
    Usage(String),
    Runtime(Error),
}

impl From<Error> for CliError {
    fn from(error: Error) -> Self {
        Self::Runtime(error)
    }
}

fn run() -> Result<(), CliError> {
    let parsed = parse_args(env::args_os().skip(1).collect()).map_err(CliError::Usage)?;
    let path = parsed.db_path;
    let agent_mode = parsed.agent;

    match parsed.command {
        Command::Help => stdout_write(format_args!("{}", HELP))?,
        Command::Version => stdout_write(format_args!("passmgr {}\n", env!("CARGO_PKG_VERSION")))?,
        Command::Generate(options) => command_generate(options)?,
        Command::Add(options) => command_add(options, &path)?,
        Command::Get { service, reveal } => command_get(&service, reveal, agent_mode, &path)?,
        Command::Delete(service) => command_delete(&service, &path)?,
        Command::Edit(options) => command_edit(options, &path)?,
        Command::List { json } => command_list(json, &path)?,
        Command::Show { reference, json } => command_show(&reference, json, &path)?,
    }
    Ok(())
}

#[derive(Debug)]
struct Parsed {
    db_path: PathBuf,
    /// The global `--agent` flag. It can only add refusal, never remove it.
    agent: bool,
    command: Command,
}

#[derive(Debug)]
enum Command {
    Add(AddOptions),
    Get { service: String, reveal: bool },
    Delete(String),
    Edit(EditOptions),
    List { json: bool },
    Show { reference: String, json: bool },
    Generate(GenerateOptions),
    Help,
    Version,
}

#[derive(Debug)]
struct AddOptions {
    service: String,
    username: String,
    generate: bool,
    preset: Preset,
    length: usize,
}

#[derive(Debug)]
struct GenerateOptions {
    preset: Preset,
    length: usize,
}

#[derive(Debug)]
struct EditOptions {
    service: String,
    username: Option<String>,
    rename: Option<String>,
    generate: bool,
    preset: Preset,
    length: usize,
}

fn parse_args(args: Vec<OsString>) -> Result<Parsed, String> {
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

fn finish_parsing(db_override: Option<PathBuf>, agent: bool, command: Command) -> Parsed {
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

fn set_db(slot: &mut Option<PathBuf>, path: PathBuf) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("--db requires a non-empty path".to_owned());
    }
    if slot.replace(path).is_some() {
        return Err("--db may only be specified once".to_owned());
    }
    Ok(())
}

fn parse_command(command: OsString, rest: Vec<OsString>) -> Result<Command, String> {
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
        other => Err(format!("unknown command '{other}' (try 'passmgr --help')")),
    }
}

fn parse_single_argument(command: &str, args: Vec<OsString>) -> Result<String, String> {
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

fn require_no_arguments(command: &str, args: &[OsString]) -> Result<(), String> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("'{command}' takes no arguments"))
    }
}

fn parse_list(args: Vec<OsString>) -> Result<Command, String> {
    let mut json = false;
    for argument in args {
        let text = argument
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match text {
            "--json" => json = true,
            other => {
                return Err(format!(
                    "unexpected argument '{other}' for 'list' (only --json is accepted)"
                ));
            }
        }
    }
    Ok(Command::List { json })
}

fn parse_show(args: Vec<OsString>) -> Result<Command, String> {
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

fn parse_get(args: Vec<OsString>) -> Result<Command, String> {
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

fn parse_add(args: Vec<OsString>) -> Result<Command, String> {
    let mut generate = false;
    let mut preset = Preset::Strong;
    let mut length = None;
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
    }))
}

fn flag_value(args: &[OsString], index: usize, name: &str) -> Result<String, String> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{name} value must be valid UTF-8"))
}

fn parse_edit(args: Vec<OsString>) -> Result<Command, String> {
    let mut generate = false;
    let mut preset = Preset::Strong;
    let mut length = None;
    let mut username = None;
    let mut rename = None;
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
    Ok(Command::Edit(EditOptions {
        service,
        username,
        rename,
        generate,
        preset,
        length: length.unwrap_or_else(|| preset.default_length()),
    }))
}

fn parse_generate(args: Vec<OsString>) -> Result<Command, String> {
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

fn parse_length(value: &str) -> Result<usize, String> {
    let length = value
        .parse::<usize>()
        .map_err(|_| format!("invalid length '{value}' (expected a number)"))?;
    if !(MIN_LEN..=MAX_LEN).contains(&length) {
        return Err(format!("length must be between {MIN_LEN} and {MAX_LEN}"));
    }
    Ok(length)
}

fn command_generate(options: GenerateOptions) -> Result<(), Error> {
    let generated = password::generate_password(options.preset, options.length)?;
    stdout_write(format_args!("{}\n", generated.as_str()))
}

fn command_add(options: AddOptions, path: &Path) -> Result<(), Error> {
    store::validate_identity(&options.service, &options.username)?;

    let generated = if options.generate {
        Some(password::generate_password(options.preset, options.length)?)
    } else {
        None
    };

    let creating = !path.exists();
    warn_insecure(path)?;
    let master = prompt_master(creating)?;
    let mut vault = Vault::open_for_add(path, &master)?;

    if vault.get(&options.service).is_some() {
        return Err(Error::DuplicateService(options.service.clone()));
    }

    let credential_password = match generated {
        Some(generated) => generated,
        None => prompt_credential_password(&options.service)?,
    };

    let service = options.service;
    vault.add(Credential::new(
        service.clone(),
        options.username,
        credential_password,
    )?)?;
    vault.save(&master)?;

    if options.generate {
        // Never print the generated password: the only way to read it back is
        // the TTY-gated `get --reveal`. Only metadata goes to the terminal.
        eprintln!("Credential '{service}' added successfully with a generated password.");
    } else {
        eprintln!("Credential added successfully.");
    }
    Ok(())
}

fn command_get(service: &str, reveal: bool, agent_mode: bool, path: &Path) -> Result<(), Error> {
    if reveal {
        // Refuse before touching the vault or prompting for the master
        // password: a pipe or an agent context must never reach the plaintext.
        // `--agent` can only add refusal; it never removes the TTY rule.
        agent::check_reveal(agent_mode).map_err(|refusal| Error::Refused(refusal.message()))?;
    }
    let (vault, _) = unlock(path)?;
    let credential = vault
        .get(service)
        .ok_or_else(|| Error::ServiceNotFound(service.to_owned()))?;
    let name = credential.service();
    let username = credential.username();
    let reference = credential.reference();
    // The reference is metadata (an id, not a secret) and is safe to print in
    // both modes: agents need it to name the entry.
    if reveal {
        stdout_write(format_args!(
            "Ref: {reference}\nService: {name}\nUsername: {username}\nPassword: {}\n",
            credential.password()
        ))
    } else {
        stdout_write(format_args!(
            "Ref: {reference}\nService: {name}\nUsername: {username}\nPassword: <redacted>\n"
        ))
    }
}

/// An edit rotates the password unless it is a metadata-only change
/// (`--username` and/or `--rename` without `--generate`).
fn edit_rotates_password(options: &EditOptions) -> bool {
    options.generate || (options.username.is_none() && options.rename.is_none())
}

fn command_edit(options: EditOptions, path: &Path) -> Result<(), Error> {
    // Validate everything that is not a secret before unlocking, so a typo
    // fails without a prompt.
    if let Some(rename) = &options.rename {
        store::validate_service(rename)?;
    }
    if let Some(username) = &options.username {
        store::validate_username(username)?;
    }
    let rotate = edit_rotates_password(&options);

    let (mut vault, master) = unlock(path)?;
    if vault.get(&options.service).is_none() {
        return Err(Error::ServiceNotFound(options.service.clone()));
    }

    if let Some(rename) = &options.rename {
        vault.rename(&options.service, rename)?;
    }
    let service = options.rename.as_deref().unwrap_or(&options.service);

    if let Some(username) = options.username {
        vault
            .get_mut(service)
            .expect("the credential was just found or renamed")
            .set_username(username)?;
    }

    if rotate {
        let password = if options.generate {
            password::generate_password(options.preset, options.length)?
        } else {
            prompt_credential_password(service)?
        };
        vault
            .get_mut(service)
            .expect("the credential was just found or renamed")
            .set_password(password)?;
    }

    vault.save(&master)?;

    if options.generate {
        // Never print the generated password; read it back with the
        // TTY-gated `get --reveal`.
        eprintln!("Credential '{service}' updated with a generated password.");
    } else {
        eprintln!("Credential '{service}' updated.");
    }
    Ok(())
}

fn command_delete(service: &str, path: &Path) -> Result<(), Error> {
    let (mut vault, master) = unlock(path)?;
    vault.delete(service)?;
    vault.save(&master)?;
    eprintln!("Credential deleted successfully.");
    Ok(())
}

fn command_list(json: bool, path: &Path) -> Result<(), Error> {
    let (vault, _) = unlock(path)?;
    if json {
        let entries: Vec<_> = vault.list().iter().map(entry_metadata).collect();
        return write_json(&serde_json::json!({ "entries": entries }));
    }
    if vault.is_empty() {
        eprintln!("No credentials stored.");
        return Ok(());
    }

    use std::fmt::Write as _;

    let mut output = String::from("Stored Services:\n");
    for credential in vault.list() {
        writeln!(
            output,
            "- {} ({}) [{}]",
            credential.service(),
            credential.username(),
            credential.reference()
        )
        .expect("writing to a String cannot fail");
    }
    stdout_write(format_args!("{}", output))
}

/// The JSON form of an entry: references and metadata only. A credential's
/// password has no accessor here, so serializing an entry cannot leak it.
fn entry_metadata(credential: &Credential) -> serde_json::Value {
    serde_json::json!({
        "ref": credential.reference(),
        "service": credential.service(),
        "username": credential.username(),
    })
}

fn write_json(value: &serde_json::Value) -> Result<(), Error> {
    let mut text = serde_json::to_string(value)
        .map_err(|error| Error::InvalidInput(format!("cannot encode JSON: {error}")))?;
    text.push('\n');
    stdout_write(format_args!("{text}"))
}

fn command_show(reference: &str, json: bool, path: &Path) -> Result<(), Error> {
    // Parse the reference before unlocking: a malformed reference is a usage
    // error and must not cost the user a master-password prompt.
    let id = store::EntryId::parse_ref(reference)?;
    let (vault, _) = unlock(path)?;
    let credential = vault
        .get_by_ref(id)
        .ok_or_else(|| Error::EntryNotFound(reference.to_owned()))?;
    if json {
        write_json(&entry_metadata(credential))
    } else {
        stdout_write(format_args!(
            "Ref: {}\nService: {}\nUsername: {}\n",
            credential.reference(),
            credential.service(),
            credential.username()
        ))
    }
}

fn unlock(path: &Path) -> Result<(Vault, Zeroizing<String>), Error> {
    warn_insecure(path)?;
    let master = prompt_master(false)?;
    let vault = Vault::open(path, &master)?;
    Ok((vault, master))
}

fn prompt_master(confirm: bool) -> Result<Zeroizing<String>, Error> {
    let master = terminal::prompt_password("Enter Master Password: ")?;
    if master.is_empty() {
        return Err(Error::InvalidInput(
            "master password cannot be empty".to_owned(),
        ));
    }
    if confirm {
        let confirmation = terminal::prompt_password("Confirm Master Password: ")?;
        if master.as_str() != confirmation.as_str() {
            return Err(Error::InvalidInput(
                "master passwords do not match".to_owned(),
            ));
        }
    }
    Ok(master)
}

fn prompt_credential_password(service: &str) -> Result<Zeroizing<String>, Error> {
    let password = terminal::prompt_password(&format!("Enter password for {service}: "))?;
    if password.is_empty() {
        return Err(Error::InvalidInput(
            "credential password cannot be empty".to_owned(),
        ));
    }
    let confirmation = terminal::prompt_password("Confirm password: ")?;
    if password.as_str() != confirmation.as_str() {
        return Err(Error::InvalidInput("passwords do not match".to_owned()));
    }
    Ok(password)
}

fn warn_insecure(path: &Path) -> Result<(), Error> {
    if let Some(mode) = vault::insecure_permissions(path) {
        eprintln!(
            "warning: '{}' has permissions {mode:04o}; other users may be able to read it",
            path.display()
        );
        eprintln!("         fix with: chmod 600 '{}'", path.display());
    }
    Ok(())
}

fn stdout_write(arguments: std::fmt::Arguments<'_>) -> Result<(), Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_fmt(arguments)?;
    output.flush()?;
    Ok(())
}

fn report_runtime_error(error: &Error) {
    eprintln!("passmgr: {error}");
    match error {
        Error::VaultNotFound(_) => {
            eprintln!("hint: create a vault with 'passmgr add <service> <username>'.");
        }
        Error::AuthenticationFailed => {
            eprintln!("hint: check the master password and that the vault was not modified.");
        }
        Error::LegacyVault => {
            eprintln!(
                "hint: the old C format is not supported; use a different --db path for a new vault."
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Command, String> {
        let arguments = values.iter().map(|value| OsString::from(*value)).collect();
        parse_args(arguments).map(|parsed| parsed.command)
    }

    #[test]
    fn parses_add_with_generation_options() {
        let Command::Add(options) = parse(&[
            "add",
            "--generate",
            "--simple",
            "--length",
            "24",
            "svc",
            "user",
        ])
        .unwrap() else {
            panic!("expected add command");
        };
        assert_eq!(options.service, "svc");
        assert_eq!(options.username, "user");
        assert!(options.generate);
        assert_eq!(options.preset, Preset::Simple);
        assert_eq!(options.length, 24);
    }

    #[test]
    fn add_flags_may_follow_positionals() {
        let Command::Add(options) = parse(&["add", "svc", "user", "--generate", "--pin"]).unwrap()
        else {
            panic!("expected add command");
        };
        assert!(options.generate);
        assert_eq!(options.preset, Preset::Pin);
        assert_eq!(options.length, 6);
    }

    #[test]
    fn double_dash_allows_dash_prefixed_values() {
        let Command::Add(options) = parse(&["add", "--", "-svc", "-user"]).unwrap() else {
            panic!("expected add command");
        };
        assert_eq!(options.service, "-svc");
        assert_eq!(options.username, "-user");
        assert!(!options.generate);
        assert_eq!(options.length, 20);
    }

    #[test]
    fn generate_defaults_and_overrides() {
        let Command::Generate(options) = parse(&["generate"]).unwrap() else {
            panic!("expected generate command");
        };
        assert_eq!(options.preset, Preset::Strong);
        assert_eq!(options.length, 20);

        let Command::Generate(options) = parse(&["generate", "--pin", "--length=8"]).unwrap()
        else {
            panic!("expected generate command");
        };
        assert_eq!(options.preset, Preset::Pin);
        assert_eq!(options.length, 8);
    }

    #[test]
    fn rejects_bad_lengths_and_flags() {
        assert!(parse(&["generate", "--length", "3"]).is_err());
        assert!(parse(&["generate", "--length", "129"]).is_err());
        assert!(parse(&["generate", "--length", "abc"]).is_err());
        assert!(parse(&["generate", "--length"]).is_err());
        assert!(parse(&["add", "--bogus", "svc", "user"]).is_err());
        assert!(parse(&["add", "svc"]).is_err());
        assert!(parse(&["add", "svc", "user", "extra"]).is_err());
    }

    #[test]
    fn parses_global_options_and_commands() {
        let parsed = parse_args(vec![
            OsString::from("--db"),
            OsString::from("/tmp/example.dat"),
            OsString::from("list"),
        ])
        .unwrap();
        assert_eq!(parsed.db_path, PathBuf::from("/tmp/example.dat"));
        assert!(matches!(parsed.command, Command::List { json: false }));

        let parsed = parse_args(vec![
            OsString::from("--db=/tmp/other.dat"),
            OsString::from("get"),
            OsString::from("svc"),
        ])
        .unwrap();
        assert_eq!(parsed.db_path, PathBuf::from("/tmp/other.dat"));
        assert!(!parsed.agent, "--agent defaults to off");
        assert!(
            matches!(parsed.command, Command::Get { service, reveal } if service == "svc" && !reveal)
        );
    }

    #[test]
    fn parses_the_agent_flag_before_the_command() {
        let parsed = parse_args(vec![
            OsString::from("--agent"),
            OsString::from("--db=/tmp/example.dat"),
            OsString::from("get"),
            OsString::from("--reveal"),
            OsString::from("svc"),
        ])
        .unwrap();
        assert!(parsed.agent);
        assert_eq!(parsed.db_path, PathBuf::from("/tmp/example.dat"));
        assert!(
            matches!(parsed.command, Command::Get { service, reveal } if service == "svc" && reveal)
        );

        // Repeating the flag is harmless, and help/version accept it too.
        let parsed = parse_args(vec![
            OsString::from("--agent"),
            OsString::from("--agent"),
            OsString::from("list"),
        ])
        .unwrap();
        assert!(parsed.agent);
        assert!(matches!(parsed.command, Command::List { json: false }));
        assert!(
            parse_args(vec![OsString::from("--agent"), OsString::from("--help")])
                .unwrap()
                .agent
        );
    }

    #[test]
    fn parses_list_and_show_json() {
        assert!(matches!(
            parse(&["list", "--json"]).unwrap(),
            Command::List { json: true }
        ));
        assert!(parse(&["list", "svc"]).is_err());
        assert!(parse(&["list", "--bogus"]).is_err());

        let reference = "pm://0123456789abcdef0123456789abcdef";
        assert_eq!(
            reference,
            store::EntryId::parse_ref(reference).unwrap().to_ref()
        );
        assert!(matches!(
            parse(&["show", reference]).unwrap(),
            Command::Show { reference: r, json: false } if r == reference
        ));
        assert!(matches!(
            parse(&["show", "--json", reference]).unwrap(),
            Command::Show { json: true, .. }
        ));
        assert!(matches!(
            parse(&["show", reference, "--json"]).unwrap(),
            Command::Show { json: true, .. }
        ));
        assert!(parse(&["show"]).is_err());
        assert!(parse(&["show", reference, reference]).is_err());
        assert!(parse(&["show", "--reveal", reference]).is_err());
    }

    #[test]
    fn the_agent_flag_is_a_bare_global_flag() {
        assert!(parse(&["--agent"]).is_err(), "a command is still required");
        assert!(parse(&["--agent=yes", "list"]).is_err());
        assert!(
            parse(&["get", "--agent", "svc"]).is_err(),
            "--agent is global and must precede the command"
        );
    }

    #[test]
    fn help_and_version_are_commands() {
        assert!(matches!(parse(&["--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["add", "--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["get", "--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["--version"]).unwrap(), Command::Version));
        assert!(parse(&["unknown"]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn service_commands_require_one_argument() {
        assert!(
            matches!(parse(&["get", "svc"]).unwrap(), Command::Get { service, .. } if service == "svc")
        );
        assert!(parse(&["get"]).is_err());
        assert!(parse(&["get", "a", "b"]).is_err());
        assert!(parse(&["list", "extra"]).is_err());
    }

    #[test]
    fn get_reveals_only_with_the_flag() {
        let Command::Get { reveal, .. } = parse(&["get", "svc"]).unwrap() else {
            panic!("expected get command");
        };
        assert!(!reveal, "plain get must never reveal the password");

        let Command::Get { service, reveal } = parse(&["get", "--reveal", "svc"]).unwrap() else {
            panic!("expected get command");
        };
        assert!(reveal);
        assert_eq!(service, "svc");

        let Command::Get { service, reveal } = parse(&["get", "svc", "--reveal"]).unwrap() else {
            panic!("expected get command");
        };
        assert!(reveal);
        assert_eq!(service, "svc");
    }

    #[test]
    fn get_rejects_bad_arguments() {
        assert!(parse(&["get", "--bogus", "svc"]).is_err());
        assert!(parse(&["get", "--reveal"]).is_err());
        assert!(parse(&["get", "a", "b"]).is_err());
    }

    #[test]
    fn parses_edit_metadata_and_generation_options() {
        let Command::Edit(options) = parse(&["edit", "svc"]).unwrap() else {
            panic!("expected edit command");
        };
        assert_eq!(options.service, "svc");
        assert!(options.username.is_none());
        assert!(options.rename.is_none());
        assert!(!options.generate);
        assert_eq!(options.preset, Preset::Strong);
        assert_eq!(options.length, 20);
        assert!(
            edit_rotates_password(&options),
            "a bare edit rotates the password"
        );

        let Command::Edit(options) = parse(&[
            "edit",
            "--username",
            "bob",
            "--rename=new.example",
            "--generate",
            "--pin",
            "--length=8",
            "svc",
        ])
        .unwrap() else {
            panic!("expected edit command");
        };
        assert_eq!(options.username.as_deref(), Some("bob"));
        assert_eq!(options.rename.as_deref(), Some("new.example"));
        assert!(options.generate);
        assert_eq!(options.preset, Preset::Pin);
        assert_eq!(options.length, 8);
        assert!(edit_rotates_password(&options));

        // Metadata-only edits leave the password alone.
        let Command::Edit(options) = parse(&["edit", "svc", "--username", "bob"]).unwrap() else {
            panic!("expected edit command");
        };
        assert!(!edit_rotates_password(&options));
        let Command::Edit(options) = parse(&["edit", "svc", "--rename", "new.example"]).unwrap()
        else {
            panic!("expected edit command");
        };
        assert!(!edit_rotates_password(&options));
    }

    #[test]
    fn edit_rejects_bad_arguments() {
        assert!(parse(&["edit"]).is_err());
        assert!(parse(&["edit", "a", "b"]).is_err());
        assert!(parse(&["edit", "--bogus", "svc"]).is_err());
        assert!(parse(&["edit", "--username", "svc"]).is_err());
        assert!(parse(&["edit", "--username"]).is_err());
        assert!(parse(&["edit", "--rename"]).is_err());
        assert!(parse(&["edit", "--length", "abc", "svc"]).is_err());
    }

    #[test]
    fn rm_is_an_alias_for_delete() {
        assert!(
            matches!(parse(&["rm", "svc"]).unwrap(), Command::Delete(service) if service == "svc")
        );
        assert!(parse(&["rm"]).is_err());
        assert!(parse(&["rm", "a", "b"]).is_err());
        assert!(HELP.contains("rm <service>"));
        assert!(HELP.contains("edit [options]"));
    }
}
