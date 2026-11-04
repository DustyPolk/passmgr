//! The Model Context Protocol server (`pm mcp serve`).
//!
//! `pm mcp serve` runs in **agent context**: the agent host starts it as a
//! stdio subprocess, so it never prompts, never holds the vault key and has no
//! code path that can return a secret. Every credential operation is a
//! request to `pmd`, which holds the key and does the injecting. `MCP.md` is
//! the contract this module implements.
//!
//! The only piece that exists today is the transport codec
//! ([`jsonrpc`]): framing, parsing and serializing JSON-RPC 2.0 lines. It is
//! deliberately separate from the tool implementations so both can be unit
//! tested without a pipe or a daemon.

pub mod jsonrpc;
