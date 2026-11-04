//! `pm mcp serve`: the stdio MCP server (TODO 4.3, 4.4a).
//!
//! The transport lives in [`passmgr::mcp::server`]; this module only adapts
//! the process's own stdin/stdout and reads the grant token the agent host was
//! given. A closed stdout is not an error: the agent host may have gone away,
//! exactly like `passmgr list | head -1`. The top-level `BrokenPipe` handling
//! in `cli::main` turns it into exit 0.

use std::io;
use std::path::PathBuf;

use passmgr::Error;
use passmgr::grant::{GrantToken, read_grant_token};

use super::args::McpCommand;

pub(crate) fn command_mcp(command: McpCommand) -> Result<(), Error> {
    match command {
        McpCommand::Serve { grant_file } => {
            let grant = read_initial_grant(grant_file)?;
            passmgr::mcp::server::serve(io::stdin().lock(), io::stdout().lock(), grant)?;
            Ok(())
        }
    }
}

/// Resolve the grant token exactly like `run`: the flag wins over the
/// environment. No file at all is not an error — handshake and `tools/list`
/// work without a grant, and every credential tool refuses later.
///
/// The token is a bearer secret. It is only ever read through
/// [`read_grant_token`] (which checks the file on the opened descriptor), and
/// the refusal text names the path and reason but never the token.
fn read_initial_grant(flag: Option<PathBuf>) -> Result<Option<GrantToken>, Error> {
    let path = flag.or_else(|| std::env::var_os("PASSMGR_GRANT_FILE").map(PathBuf::from));
    let Some(path) = path else {
        return Ok(None);
    };
    read_grant_token(&path).map(Some).map_err(|error| {
        Error::Refused(format!(
            "{error}; ask the human who approved the grant for its token file"
        ))
    })
}
