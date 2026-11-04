//! The Model Context Protocol server (`pm mcp serve`).
//!
//! `pm mcp serve` runs in **agent context**: the agent host starts it as a
//! stdio subprocess, so it never prompts, never holds the vault key and has no
//! code path that can return a secret. Every credential operation is a
//! request to `pmd`, which holds the key and does the injecting. `MCP.md` is
//! the contract this module implements.
//!
//! Five pieces exist today. The transport codec ([`jsonrpc`]) frames, parses
//! and serializes JSON-RPC 2.0 lines; the era module ([`era`]) decides which
//! protocol era a request belongs to, validates its `_meta`, and owns the
//! `initialize` and `server/discover` results; [`server`] runs the sequential
//! stdio loop; [`tools`] holds the tool catalogue (`tools/list`); and [`call`]
//! validates a `tools/call` argument object and maps the daemon's answer. All
//! are deliberately separate from the daemon so each can be unit tested
//! without a pipe or a socket, and none of them can reach reveal code.

pub mod call;
pub mod era;
pub mod jsonrpc;
pub mod server;
pub mod tools;
