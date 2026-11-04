//! Argument parsing for `pm mcp` (TODO 4.3, 4.4a).
//!
//! One subcommand, `serve`, which speaks MCP on the process's stdin and
//! stdout and never opens the vault. It accepts one optional `--grant-file`
//! so the agent host can name the grant it may use; without the flag the
//! server falls back to `PASSMGR_GRANT_FILE`, exactly like `run`.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{Command, flag_value};

#[derive(Debug)]
pub(crate) enum McpCommand {
    Serve { grant_file: Option<PathBuf> },
}

pub(crate) fn parse_mcp(args: Vec<OsString>) -> Result<Command, String> {
    const USAGE: &str = "'mcp serve' usage: passmgr mcp serve [--grant-file FILE]";

    let mut args = args.into_iter();
    let Some(subcommand) = args.next() else {
        return Err("'mcp' requires a subcommand; usage: passmgr mcp serve".to_owned());
    };
    let subcommand = subcommand
        .into_string()
        .map_err(|_| "mcp subcommand must be valid UTF-8".to_owned())?;
    let rest: Vec<OsString> = args.collect();
    match subcommand.as_str() {
        "serve" => parse_serve(rest, USAGE).map(Command::Mcp),
        other => Err(format!(
            "unknown 'mcp' subcommand '{other}' (try 'passmgr help')"
        )),
    }
}

fn parse_serve(args: Vec<OsString>, usage: &str) -> Result<McpCommand, String> {
    let mut grant_file = None;
    let mut index = 0;
    while index < args.len() {
        let text = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        if text == "--grant-file" {
            let value = flag_value(&args, index, "--grant-file")?;
            set_grant_file(&mut grant_file, value)?;
            index += 2;
            continue;
        }
        if let Some(value) = text.strip_prefix("--grant-file=") {
            set_grant_file(&mut grant_file, value.to_owned())?;
            index += 1;
            continue;
        }
        return Err(format!(
            "unexpected argument '{text}' for 'mcp serve'; {usage}"
        ));
    }
    Ok(McpCommand::Serve {
        grant_file: grant_file.map(PathBuf::from),
    })
}

fn set_grant_file(slot: &mut Option<String>, value: String) -> Result<(), String> {
    if value.is_empty() {
        return Err("--grant-file must not be empty".to_owned());
    }
    if slot.replace(value).is_some() {
        return Err("'mcp serve' accepts exactly one --grant-file".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(words: &[&str]) -> Result<McpCommand, String> {
        let args = words.iter().map(OsString::from).collect();
        match parse_mcp(args)? {
            Command::Mcp(command) => Ok(command),
            other => panic!("expected an mcp command, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_one_grant_file_in_both_spellings() {
        for words in [
            vec!["serve", "--grant-file", "/run/user/1000/grant.token"],
            vec!["serve", "--grant-file=/run/user/1000/grant.token"],
        ] {
            let command = parse(&words).expect("valid");
            match command {
                McpCommand::Serve { grant_file } => assert_eq!(
                    grant_file,
                    Some(PathBuf::from("/run/user/1000/grant.token"))
                ),
            }
        }
        match parse(&["serve"]).expect("no grant is allowed") {
            McpCommand::Serve { grant_file } => assert_eq!(grant_file, None),
        }
    }

    #[test]
    fn serve_refuses_duplicate_empty_and_unknown_arguments() {
        for (words, expected) in [
            (
                vec!["serve", "--grant-file", "a", "--grant-file", "b"],
                "'mcp serve' accepts exactly one --grant-file",
            ),
            (
                vec!["serve", "--grant-file"],
                "--grant-file requires a value",
            ),
            (
                vec!["serve", "--grant-file="],
                "--grant-file must not be empty",
            ),
            (
                vec!["serve", "--db", "vault.dat"],
                "unexpected argument '--db'",
            ),
        ] {
            let error = parse(&words).expect_err("must be refused");
            assert!(error.contains(expected), "{error}");
        }
    }
}
