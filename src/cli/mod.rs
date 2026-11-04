//! Command-line interface: parsing, dispatch and output.
//!
//! `src/main.rs` is only the process entry point; everything else lives here.

mod args;
mod audit;
mod commands;
mod grant;
mod grant_summary;
mod help;
mod mcp;
mod run;
mod unlock;

pub(crate) use args::*;
pub(crate) use audit::*;
pub(crate) use commands::*;
pub(crate) use grant::*;
pub(crate) use help::*;
pub(crate) use mcp::*;
pub(crate) use run::*;
pub(crate) use unlock::*;

use std::env;
use std::io::{self, Write};

use passmgr::Error;
use passmgr::error::{EXIT_OK, EXIT_USAGE};
use passmgr::text::escape_hidden;

// Only the unit tests in this module use these; the command modules import
// their own copies.
#[cfg(test)]
use passmgr::password::Preset;
#[cfg(test)]
use passmgr::store;
#[cfg(test)]
use std::ffi::OsString;
#[cfg(test)]
use std::path::PathBuf;

pub(crate) fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code,
        Err(CliError::Usage(message)) => {
            eprintln!("passmgr: {}", escape_hidden(&message));
            eprintln!();
            eprintln!("{USAGE}");
            std::process::ExitCode::from(EXIT_USAGE)
        }
        // A closed stdout/stderr pipe is not a failure (`passmgr list | head
        // -1` must not report one). Every other write error is a real error:
        // socket writes map to `Error::Daemon` in `client` (TODO R.60), and a
        // run's relayed-output pipe is turned into exit 141 in `cli::run`.
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

fn run() -> Result<std::process::ExitCode, CliError> {
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
        Command::List { json, tags } => command_list(json, &tags, &path)?,
        Command::Show { reference, json } => command_show(&reference, json, &path)?,
        Command::Unlock { idle_timeout } => command_unlock(agent_mode, &path, idle_timeout)?,
        Command::Lock => command_lock()?,
        Command::Run(options) => return Ok(command_run(options, agent_mode, &path)?),
        Command::Grant(command) => command_grant(command, agent_mode, &path)?,
        Command::Mcp(command) => command_mcp(command)?,
        Command::Audit(command) => command_audit(command)?,
    }
    Ok(std::process::ExitCode::SUCCESS)
}
pub(crate) fn stdout_write(arguments: std::fmt::Arguments<'_>) -> Result<(), Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_fmt(arguments)?;
    output.flush()?;
    Ok(())
}

fn report_runtime_error(error: &Error) {
    // Every field is already escaped at its own boundary; escaping the rendered
    // line again is a no-op for that text and a backstop for a message added
    // later that forgets to.
    eprintln!("passmgr: {}", escape_hidden(&error.to_string()));
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
        assert!(matches!(parsed.command, Command::List { json: false, .. }));

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
        assert!(matches!(parsed.command, Command::List { json: false, .. }));
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
            Command::List { json: true, .. }
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
    fn parses_and_validates_tags() {
        let Command::Add(options) =
            parse(&["add", "--tag", "work", "--tag=prod", "github.com", "alice"]).unwrap()
        else {
            panic!("expected add command");
        };
        assert_eq!(options.tags, ["prod", "work"]);

        let Command::Edit(options) = parse(&["edit", "--tag", "work", "github.com"]).unwrap()
        else {
            panic!("expected edit command");
        };
        assert_eq!(options.tags, Some(vec!["work".to_owned()]));
        assert!(!options.clear_tags);

        let Command::Edit(options) = parse(&["edit", "--clear-tags", "github.com"]).unwrap() else {
            panic!("expected edit command");
        };
        assert_eq!(options.tags, None);
        assert!(options.clear_tags);

        let Command::List { json, tags } = parse(&["list", "--tag=prod", "--tag", "work"]).unwrap()
        else {
            panic!("expected list command");
        };
        assert!(!json);
        assert_eq!(tags, ["prod", "work"]);

        assert!(parse(&["list", "--tag"]).is_err());
        assert!(parse(&["add", "--tag", "", "svc", "user"]).is_err());
        assert!(parse(&["add", "--tag", "Prod", "svc", "user"]).is_err());
        assert!(parse(&["edit", "--clear-tags", "--tag", "work", "svc"]).is_err());
    }

    #[test]
    fn help_and_version_are_commands() {
        assert!(matches!(parse(&["--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["add", "--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["get", "--help"]).unwrap(), Command::Help));
        assert!(matches!(parse(&["--version"]).unwrap(), Command::Version));
        assert!(matches!(
            parse(&["unlock"]).unwrap(),
            Command::Unlock { .. }
        ));
        assert!(matches!(parse(&["lock"]).unwrap(), Command::Lock));
        assert!(parse(&["unlock", "extra"]).is_err());
        assert!(parse(&["lock", "extra"]).is_err());
        assert!(parse(&["unknown"]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn parses_the_unlock_idle_timeout() {
        let Command::Unlock { idle_timeout } = parse(&["unlock"]).unwrap() else {
            panic!("expected unlock command");
        };
        assert_eq!(idle_timeout, None, "default is applied at spawn time");

        #[cfg(unix)]
        {
            let Command::Unlock { idle_timeout } =
                parse(&["unlock", "--idle-timeout", "60"]).unwrap()
            else {
                panic!("expected unlock command");
            };
            assert_eq!(idle_timeout, Some(std::time::Duration::from_secs(60)));

            let Command::Unlock { idle_timeout } =
                parse(&["unlock", "--idle-timeout=120"]).unwrap()
            else {
                panic!("expected unlock command");
            };
            assert_eq!(idle_timeout, Some(std::time::Duration::from_secs(120)));

            assert!(parse(&["unlock", "--idle-timeout", "0"]).is_err());
            assert!(parse(&["unlock", "--idle-timeout", "soon"]).is_err());
            assert!(parse(&["unlock", "--idle-timeout"]).is_err());
        }
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
    fn generation_flags_without_generate_are_refused() {
        for args in [
            &["edit", "--length", "30", "svc"][..],
            &["edit", "--pin", "svc"],
            &["edit", "--simple", "--username", "bob", "svc"],
            &["add", "--length=30", "svc", "user"],
            &["add", "--strong", "svc", "user"],
        ] {
            let error = parse(args).expect_err("must be refused");
            assert!(error.contains("--generate"), "{args:?}: {error}");
        }
    }

    #[test]
    fn rm_is_an_alias_for_delete() {
        assert!(
            matches!(parse(&["rm", "svc"]).unwrap(), Command::Delete(service) if service == "svc")
        );
        assert!(parse(&["rm"]).is_err());
        assert!(parse(&["rm", "a", "b"]).is_err());
        for name in ["--help", "-svc", "--"] {
            assert!(
                matches!(parse(&["delete", "--", name]).unwrap(), Command::Delete(service) if service == name),
                "{name}"
            );
        }
        assert!(parse(&["rm", "--"]).is_err());
        assert!(parse(&["rm", "--", "a", "b"]).is_err());
        assert!(HELP.contains("rm <service>"));
        assert!(HELP.contains("edit [options]"));
    }

    /// Build a store version 4 payload by hand, so a test can choose the stored
    /// timestamps (including the `0` = unknown case the public API never makes).
    fn store_v4_payload(created: u64, last_rotated: u64) -> Vec<u8> {
        let mut out = vec![4];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&[0x11; 16]);
        out.extend_from_slice(&created.to_le_bytes());
        out.extend_from_slice(&last_rotated.to_le_bytes());
        for field in ["example.com", "alice", "correct horse battery"] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&1u32.to_le_bytes());
        let tag = "prod";
        out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
        out.extend_from_slice(tag.as_bytes());
        out
    }

    #[test]
    fn json_entry_exposes_tags_and_utc_timestamps_but_no_password() {
        let payload = store::decode(&store_v4_payload(951_782_400, 1_735_689_600)).unwrap();
        let credentials = payload.credentials;
        let entry = entry_metadata(&credentials[0]);
        assert_eq!(entry["ref"], serde_json::json!(credentials[0].reference()));
        assert_eq!(entry["service"], serde_json::json!("example.com"));
        assert_eq!(entry["username"], serde_json::json!("alice"));
        assert_eq!(entry["tags"], serde_json::json!(["prod"]));
        assert_eq!(entry["created"], serde_json::json!("2000-02-29T00:00:00Z"));
        assert_eq!(
            entry["last_rotated"],
            serde_json::json!("2025-01-01T00:00:00Z")
        );
        assert!(entry.get("password").is_none());
        let text = serde_json::to_string(&entry).unwrap();
        assert!(!text.contains("correct horse battery"));
    }

    #[test]
    fn json_entry_renders_unknown_timestamps_as_null() {
        // Pre-v4 payloads migrate with 0 in both fields; that absence must stay
        // visible as `null` instead of being rendered as 1970-01-01.
        let payload = store::decode(&store_v4_payload(0, 0)).unwrap();
        let credentials = payload.credentials;
        let entry = entry_metadata(&credentials[0]);
        assert_eq!(entry["created"], serde_json::Value::Null);
        assert_eq!(entry["last_rotated"], serde_json::Value::Null);
        let text = serde_json::to_string(&entry).unwrap();
        assert!(!text.contains("1970-0"));
        assert!(!text.contains("correct horse battery"));
    }
    const RUN_REF: &str = "pm://00112233445566778899aabbccddeeff";

    #[test]
    fn parses_run_env_and_command_argv() {
        let Command::Run(options) = parse(&[
            "run",
            "--env",
            &format!("API_KEY={RUN_REF}"),
            "--",
            "/usr/bin/printenv",
            "API_KEY",
            "--flag",
        ])
        .unwrap() else {
            panic!("expected run command");
        };
        assert_eq!(options.env, "API_KEY");
        assert_eq!(options.reference, RUN_REF);
        // Everything after `--` is argv: flags and values are not re-parsed.
        assert_eq!(options.command, ["/usr/bin/printenv", "API_KEY", "--flag"]);

        let Command::Run(options) = parse(&[
            "run",
            &format!("--env=GH_TOKEN={RUN_REF}"),
            "--",
            "gh",
            "api",
            "user",
        ])
        .unwrap() else {
            panic!("expected run command");
        };
        assert_eq!(options.env, "GH_TOKEN");
        assert_eq!(options.command, ["gh", "api", "user"]);
    }

    #[test]
    fn run_rejects_malformed_specs_before_connecting() {
        for values in [
            vec!["run", "--", "true"],                     // no --env
            vec!["run", "--env", "--", "true"],            // --env without value
            vec!["run", "--env", "API_KEY", "--", "true"], // no '='
            vec!["run", "--env", "=pm://x", "--", "true"], // empty name
            vec![
                "run",
                "--env",
                "1BAD=pm://00112233445566778899aabbccddeeff",
                "--",
                "true",
            ],
            vec![
                "run",
                "--env",
                "BAD-NAME=pm://00112233445566778899aabbccddeeff",
                "--",
                "true",
            ],
            vec!["run", "--env", "API_KEY=not-a-ref", "--", "true"], // bad reference
            vec!["run", "--env", "API_KEY=pm://x", "--", "true"],    // short reference
            vec![
                "run",
                "--env",
                "API_KEY=pm://00112233445566778899aabbccddeeff",
            ],
            vec![
                "run",
                "--env",
                "API_KEY=pm://00112233445566778899aabbccddeeff",
                "--",
            ],
            vec![
                "run",
                "--env",
                "A=pm://00112233445566778899aabbccddeeff",
                "--env",
                "B=pm://00112233445566778899aabbccddeeff",
                "--",
                "true",
            ],
            vec!["run", "--bogus", "--", "true"],
            vec![
                "run",
                "API_KEY=pm://00112233445566778899aabbccddeeff",
                "--",
                "true",
            ],
            vec![
                "run",
                "--env",
                "API_KEY=pm://00112233445566778899aabbccddeeff",
                "--",
                "",
            ],
        ] {
            assert!(parse(&values).is_err(), "should reject {values:?}");
        }
        // A missing command after `--` is a usage error, not a run of nothing.
        let error = parse(&[
            "run",
            "--env",
            "API_KEY=pm://00112233445566778899aabbccddeeff",
            "--",
        ])
        .unwrap_err();
        assert!(error.contains("missing command"), "{error}");
    }

    #[test]
    fn run_only_adds_refusal_in_agent_mode() {
        let parsed = parse_args(vec![
            OsString::from("--agent"),
            OsString::from("run"),
            OsString::from("--env"),
            OsString::from("API_KEY=pm://00112233445566778899aabbccddeeff"),
            OsString::from("--"),
            OsString::from("true"),
        ])
        .unwrap();
        assert!(parsed.agent);
        assert!(matches!(parsed.command, Command::Run(_)));
    }

    #[test]
    fn parses_grant_create_fields() {
        let Command::Grant(GrantCommand::Create(options)) = parse(&[
            "grant",
            "create",
            "--label",
            "deploy prod",
            "--tag",
            "prod",
            "--ref",
            RUN_REF,
            "--command",
            "/usr/bin/gh",
            "--expires",
            "1h",
            "--max-uses",
            "2",
            "--allow-interpreter",
            "--out",
            "/tmp/token",
        ])
        .unwrap() else {
            panic!("expected grant create");
        };
        assert_eq!(options.label, "deploy prod");
        assert_eq!(options.references.len(), 1);
        assert_eq!(options.references[0].to_ref(), RUN_REF);
        assert_eq!(options.tags, ["prod"]);
        assert_eq!(options.commands, ["/usr/bin/gh"]);
        assert_eq!(options.expires, std::time::Duration::from_secs(3_600));
        assert_eq!(options.max_uses, Some(2));
        assert!(options.allow_interpreter);
        assert_eq!(options.out, PathBuf::from("/tmp/token"));
    }

    #[test]
    fn grant_create_accepts_equals_flags_and_help() {
        let Command::Grant(GrantCommand::Create(options)) = parse(&[
            "grant",
            "create",
            "--label=deploy",
            "--tag=prod",
            "--command=/usr/bin/gh",
            "--expires=30m",
            "--out=/tmp/token",
        ])
        .unwrap() else {
            panic!("expected grant create");
        };
        assert_eq!(options.label, "deploy");
        assert_eq!(options.expires, std::time::Duration::from_secs(1_800));

        assert!(matches!(
            parse(&["grant", "create", "--help"]).unwrap(),
            Command::Help
        ));
        assert!(matches!(
            parse(&["grant", "--help"]).unwrap(),
            Command::Help
        ));
    }

    #[test]
    fn grant_create_rejects_missing_or_bad_flags() {
        let base = [
            "grant",
            "create",
            "--label",
            "deploy",
            "--tag",
            "prod",
            "--command",
            "/usr/bin/gh",
            "--expires",
            "1h",
            "--out",
            "/tmp/token",
        ];
        for missing in ["--label", "--tag", "--command", "--expires", "--out"] {
            let values: Vec<&str> = base
                .iter()
                .copied()
                .enumerate()
                .filter(|(index, _)| {
                    *index / 2 != base.iter().position(|v| *v == missing).unwrap() / 2
                })
                .map(|(_, value)| value)
                .collect();
            assert!(parse(&values).is_err(), "missing {missing}: {values:?}");
        }
        for extra in [
            vec!["--expires", "0m"],
            vec!["--expires", "31d"],
            vec!["--max-uses", "0"],
            vec!["--ref", "not-a-ref"],
            vec!["--unknown"],
        ] {
            let mut values = base.to_vec();
            values.extend(extra.iter().copied());
            assert!(parse(&values).is_err(), "accepted {extra:?}");
        }
    }
}
