//! `pm mcp serve`: the stdio MCP server (TODO 4.3).
//!
//! The transport lives in [`passmgr::mcp::server`]; this module only adapts
//! the process's own stdin/stdout. A closed stdout is not an error: the agent
//! host may have gone away, exactly like `passmgr list | head -1`. The
//! top-level `BrokenPipe` handling in `cli::main` turns it into exit 0.

use std::io;

use passmgr::Error;

use super::args::McpCommand;

pub(crate) fn command_mcp(command: McpCommand) -> Result<(), Error> {
    match command {
        McpCommand::Serve => {
            passmgr::mcp::server::serve(io::stdin().lock(), io::stdout().lock())?;
            Ok(())
        }
    }
}
