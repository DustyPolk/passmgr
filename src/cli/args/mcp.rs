//! Argument parsing for `pm mcp` (TODO 4.3).
//!
//! One subcommand, `serve`, which takes no arguments: it speaks MCP on the
//! process's stdin and stdout and never opens the vault.

use std::ffi::OsString;

use super::{Command, require_no_arguments};

#[derive(Debug)]
pub(crate) enum McpCommand {
    Serve,
}

pub(crate) fn parse_mcp(args: Vec<OsString>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(subcommand) = args.next() else {
        return Err("'mcp' requires a subcommand; usage: passmgr mcp serve".to_owned());
    };
    let subcommand = subcommand
        .into_string()
        .map_err(|_| "mcp subcommand must be valid UTF-8".to_owned())?;
    let rest: Vec<OsString> = args.collect();
    match subcommand.as_str() {
        "serve" => {
            require_no_arguments("mcp serve", &rest)?;
            Ok(Command::Mcp(McpCommand::Serve))
        }
        other => Err(format!(
            "unknown 'mcp' subcommand '{other}' (try 'passmgr help')"
        )),
    }
}
