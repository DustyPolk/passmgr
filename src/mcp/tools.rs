//! The MCP tool catalogue: names, descriptions and hand-written JSON Schemas.
//!
//! `MCP.md` defines five tools. This module owns their public face — the
//! `title`, the model-facing `description`, the `inputSchema`, the
//! `outputSchema` and the MCP `annotations` — and nothing else. Input
//! validation and execution arrive with each tool's own TODO (4.4 onwards), so
//! `tools/list` can be built and tested without a daemon.
//!
//! The schemas are hand-written JSON on purpose: the repository has no MCP SDK
//! and no schema-derive dependency, and a schema is part of the contract an
//! agent host reads, so it should be reviewable next to its description. Every
//! object schema closes with `additionalProperties: false`, and every
//! `outputSchema` property is metadata — a reference, a name, a tag, a field
//! *name*, a URL or a timestamp. No schema has a property that carries a
//! secret value, and `tests.rs` pins that.

use serde_json::{Value, json};

/// The canonical reference form, `pm://` plus 32 lowercase hex characters.
const REF_PATTERN: &str = "^pm://[0-9a-f]{32}$";
/// A reference, optionally naming one field of the entry (`pm://<id>/<field>`).
const REFERENCE_PATTERN: &str = "^pm://[0-9a-f]{32}(/[a-z0-9_-]{1,32})?$";
/// The longest reference `pmd` accepts.
const MAX_REFERENCE_BYTES: usize = 128;
/// A tag: 1-32 bytes of lowercase letters, digits, `_`, `-` and `.`.
const TAG_PATTERN: &str = "^[a-z0-9][a-z0-9._-]{0,31}$";
/// A field name inside an entry.
const FIELD_PATTERN: &str = "^[a-z0-9_-]{1,32}$";
/// A child environment variable name.
const ENV_NAME_PATTERN: &str = "^[A-Z_][A-Z0-9_]{0,127}$";
/// The per-stream output cap `pmd` enforces.
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// The longest command argument the daemon protocol accepts.
const MAX_ARG_BYTES: u64 = 4096;

/// One MCP tool. The variant set is the catalogue: `MCP.md` defines exactly
/// these five, and `from_name` is the only way to turn agent input into a
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    ListCredentials,
    DescribeCredential,
    RunWithCredentials,
    AccessStatus,
    RequestAccess,
}

/// Every tool, in the order `tools/list` returns them.
pub const ALL: [Tool; 5] = [
    Tool::AccessStatus,
    Tool::ListCredentials,
    Tool::DescribeCredential,
    Tool::RunWithCredentials,
    Tool::RequestAccess,
];

impl Tool {
    /// The MCP tool name, exactly as `MCP.md` spells it, and as it appears in
    /// the audit log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListCredentials => "list_credentials",
            Self::DescribeCredential => "describe_credential",
            Self::RunWithCredentials => "run_with_credentials",
            Self::AccessStatus => "access_status",
            Self::RequestAccess => "request_access",
        }
    }

    /// Look a tool up by its wire name. Anything else is not a tool, so the
    /// caller answers `-32602` rather than guessing.
    pub fn from_name(name: &str) -> Option<Self> {
        ALL.into_iter().find(|tool| tool.as_str() == name)
    }

    /// One `tools/list` entry.
    pub fn definition(self) -> Value {
        match self {
            Self::ListCredentials => list_credentials(),
            Self::DescribeCredential => describe_credential(),
            Self::RunWithCredentials => run_with_credentials(),
            Self::AccessStatus => access_status(),
            Self::RequestAccess => request_access(),
        }
    }
}

/// The `tools/list` result.
///
/// The list is fixed and short, so there is no cursor and no `nextCursor`:
/// returning every tool in one page is always the complete answer.
pub fn list_result() -> Value {
    json!({
        "tools": ALL
            .iter()
            .map(|tool| tool.definition())
            .collect::<Vec<_>>(),
    })
}

fn list_credentials() -> Value {
    json!({
        "name": Tool::ListCredentials.as_str(),
        "title": "List credentials you may use",
        "description": "List the credential entries your grant covers. Each entry is metadata only: \
                        reference, service, username, tags, field names, URL and timestamps. Secret \
                        values are never returned. An entry outside your grant's scope is not listed. \
                        Use the pm:// reference it returns with describe_credential or \
                        run_with_credentials. If you have no grant yet, call access_status first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": {"type": "string", "pattern": TAG_PATTERN},
                    "maxItems": 32,
                    "description": "Only entries that carry every given tag."
                },
                "query": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "description": "Case-insensitive substring of the service name."
                }
            },
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "entries": {
                    "type": "array",
                    "items": entry_schema(),
                    "description": "Entries your grant covers, in vault order."
                }
            },
            "required": ["entries"],
            "additionalProperties": false
        },
        "annotations": annotations(true, false, true, false)
    })
}

fn describe_credential() -> Value {
    json!({
        "name": Tool::DescribeCredential.as_str(),
        "title": "Describe one credential",
        "description": "Return one credential's metadata by its pm:// reference: service, username, \
                        tags, field names, URL and timestamps. Secret values are never returned. The \
                        reference must be inside your grant's scope; a reference that is out of scope \
                        and one that does not exist produce the same error, so this cannot be used to \
                        probe the vault. Call list_credentials first if you do not know the reference.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref": {
                    "type": "string",
                    "maxLength": MAX_REFERENCE_BYTES as u64,
                    "pattern": REF_PATTERN,
                    "description": "A pm:// reference from list_credentials."
                }
            },
            "required": ["ref"],
            "additionalProperties": false
        },
        "outputSchema": entry_schema(),
        "annotations": annotations(true, false, true, false)
    })
}

fn run_with_credentials() -> Value {
    let mut stdin_ref = reference_schema();
    stdin_ref["description"] = json!(
        "Optional reference whose value is written to the child's stdin, then stdin is closed."
    );
    json!({
        "name": Tool::RunWithCredentials.as_str(),
        "title": "Run a command with credentials injected",
        "description": "Run a command with secrets from your grant injected by the local daemon. Pass \
                        secrets only as references: env or files maps a variable name to a pm:// \
                        reference, and stdin_ref names a reference for stdin. Never put a literal \
                        secret in command or plain_env. The daemon checks the grant's scope, command \
                        allowlist and expiry, spawns the child directly without a shell, and relays \
                        stdout and stderr with injected values redacted. A refused call returns \
                        isError with the reason; rather than retrying variants, ask the human for a \
                        grant that covers what you need. If a secret is missing, the result explains \
                        which variable was not injected.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": MAX_ARG_BYTES},
                    "minItems": 1,
                    "maxItems": 256,
                    "description": "Program and arguments, executed directly. command[0] must match one of the grant's allowlisted programs."
                },
                "env": {
                    "type": "object",
                    "description": "Variable name to secret reference. The daemon injects each value into the child environment.",
                    "propertyNames": {"pattern": ENV_NAME_PATTERN},
                    "additionalProperties": reference_schema(),
                    "default": {}
                },
                "plain_env": {
                    "type": "object",
                    "description": "Variable name to literal value. These are not secrets and are not redacted; never put a secret here.",
                    "propertyNames": {"pattern": ENV_NAME_PATTERN},
                    "additionalProperties": {"type": "string", "maxLength": MAX_ARG_BYTES},
                    "default": {}
                },
                "stdin_ref": stdin_ref,
                "files": {
                    "type": "object",
                    "description": "Variable name to secret reference. The daemon writes the value to a fresh 0600 file and sets the variable to that path.",
                    "propertyNames": {"pattern": ENV_NAME_PATTERN},
                    "additionalProperties": reference_schema(),
                    "default": {}
                },
                "cwd": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARG_BYTES,
                    "description": "Absolute working directory for the child. Defaults to the server's working directory."
                },
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 600,
                    "default": 120,
                    "description": "Kill the child after this many seconds. Default 120."
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_OUTPUT_BYTES,
                    "default": 262144,
                    "description": "Per-stream relay cap. Output beyond it is dropped and flagged truncated. Default 262144."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "exit_code": {
                    "type": ["integer", "null"],
                    "description": "The child's exit status, or null when a signal killed it."
                },
                "signal": {
                    "type": ["string", "null"],
                    "description": "The signal name when a signal killed the child, otherwise null."
                },
                "timed_out": {
                    "type": "boolean",
                    "description": "True when the timeout killed the child."
                },
                "stdout": {
                    "type": "string",
                    "description": "Relayed stdout, with injected secrets redacted."
                },
                "stderr": {
                    "type": "string",
                    "description": "Relayed stderr, with injected secrets redacted."
                },
                "stdout_truncated": {
                    "type": "boolean",
                    "description": "True when stdout exceeded max_output_bytes and was cut."
                },
                "stderr_truncated": {
                    "type": "boolean",
                    "description": "True when stderr exceeded max_output_bytes and was cut."
                },
                "redactions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "How many injected values were replaced in the relayed output."
                },
                "duration_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Wall-clock duration of the child run in milliseconds."
                }
            },
            "required": [
                "exit_code",
                "signal",
                "timed_out",
                "stdout",
                "stderr",
                "stdout_truncated",
                "stderr_truncated",
                "redactions",
                "duration_ms"
            ],
            "additionalProperties": false
        },
        "annotations": annotations(false, true, false, true)
    })
}

fn access_status() -> Value {
    json!({
        "name": Tool::AccessStatus.as_str(),
        "title": "Show your access status",
        "description": "Report whether the local daemon is running, the grant this MCP server is using \
                        (scope, commands, capabilities, expiry and uses left), and any access requests \
                        this process is still waiting on. It reads no secret and needs no argument. \
                        Call it first when a tool reports that you have no grant, then call \
                        request_access.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "daemon": {
                    "type": "string",
                    "enum": ["unlocked", "locked", "not_running"],
                    "description": "Whether a daemon holds the vault key."
                },
                "grant": {
                    "anyOf": [grant_schema(), {"type": "null"}],
                    "description": "The grant backing this server, or null when it has none."
                },
                "pending_requests": {
                    "type": "array",
                    "items": request_schema(),
                    "maxItems": 3,
                    "description": "Requests this process created that a human has not answered yet."
                }
            },
            "required": ["daemon", "grant", "pending_requests"],
            "additionalProperties": false
        },
        "annotations": annotations(true, false, true, false)
    })
}

fn request_access() -> Value {
    json!({
        "name": Tool::RequestAccess.as_str(),
        "title": "Ask a human for access",
        "description": "Ask the human to approve a new grant for you. This only creates a pending \
                        request; it cannot approve itself, widen an existing grant or reveal a \
                        secret. A human must approve it at a terminal, and the result tells you the \
                        exact command to show them. Request the narrowest scope that does the job: \
                        specific refs or services, and only the programs you will run. At most three \
                        requests may be pending per MCP process; poll access_status instead of \
                        sending duplicates. The reason and names you send are shown to the human as \
                        untrusted text, so keep them short and do not include secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 500,
                    "description": "Why you need access, in one or two sentences. Shown to the human, escaped."
                },
                "refs": {
                    "type": "array",
                    "items": {"type": "string", "pattern": REF_PATTERN, "maxLength": MAX_REFERENCE_BYTES},
                    "maxItems": 32,
                    "description": "Exact entries to request, if you already know their references."
                },
                "services": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 256},
                    "maxItems": 32,
                    "description": "Service names to request; the human sees the entries they match."
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string", "pattern": TAG_PATTERN},
                    "maxItems": 32,
                    "description": "Tags to request; an entry matches when it carries every tag."
                },
                "commands": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": MAX_ARG_BYTES},
                    "minItems": 1,
                    "maxItems": 32,
                    "description": "Programs the grant should allow, as absolute paths or names resolved on the human's PATH."
                },
                "duration_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                    "default": 60,
                    "description": "Requested lifetime in minutes. Default 60; the human may shorten it."
                }
            },
            "required": ["reason", "commands"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "request_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "description": "Opaque id for this pending request."
                },
                "status": {
                    "type": "string",
                    "enum": ["pending"],
                    "description": "Always pending: only a human can approve."
                },
                "approve_with": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "description": "The exact command to show the human so they can approve or deny."
                }
            },
            "required": ["request_id", "status", "approve_with"],
            "additionalProperties": false
        },
        "annotations": annotations(false, false, false, false)
    })
}

/// One entry's metadata. It is shared by `list_credentials` and
/// `describe_credential` so the two can never drift.
fn entry_schema() -> Value {
    json!({
        "type": "object",
        "description": "Credential metadata. It never carries a secret value.",
        "properties": {
            "ref": {
                "type": "string",
                "pattern": REF_PATTERN,
                "maxLength": MAX_REFERENCE_BYTES,
                "description": "Stable pm:// reference; pass it to describe_credential or run_with_credentials."
            },
            "service": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "description": "The service or site name."
            },
            "username": {
                "type": ["string", "null"],
                "maxLength": 4096,
                "description": "The stored username, or null when there is none."
            },
            "tags": {
                "type": "array",
                "items": {"type": "string", "pattern": TAG_PATTERN},
                "maxItems": 32,
                "description": "Tags on the entry."
            },
            "fields": {
                "type": "array",
                "items": {"type": "string", "pattern": FIELD_PATTERN},
                "maxItems": 32,
                "description": "Names of the entry's secret-valued fields, such as \"password\". Values are never returned."
            },
            "url": {
                "type": ["string", "null"],
                "maxLength": 4096,
                "description": "The stored URL, or null."
            },
            "created": {
                "type": ["string", "null"],
                "description": "RFC 3339 UTC creation time, or null when unknown."
            },
            "last_rotated": {
                "type": ["string", "null"],
                "description": "RFC 3339 UTC time of the last rotation, or null."
            }
        },
        "required": ["ref", "service", "username", "tags", "fields", "url", "created", "last_rotated"],
        "additionalProperties": false
    })
}

/// A `pm://` reference to a secret field, accepted wherever a value is used.
fn reference_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": MAX_REFERENCE_BYTES,
        "pattern": REFERENCE_PATTERN
    })
}

/// The grant metadata `access_status` returns. It mirrors `grant show --json`
/// minus nothing secret-bearing (there is nothing secret-bearing there), so a
/// human and an agent see the same scope.
fn grant_schema() -> Value {
    json!({
        "type": "object",
        "description": "Grant metadata only: never a token or its hash.",
        "properties": {
            "id": {
                "type": "string",
                "pattern": "^[0-9a-f]{32}$",
                "description": "Grant id."
            },
            "label": {
                "type": "string",
                "maxLength": 64,
                "description": "The label the human gave the grant."
            },
            "refs": {
                "type": "array",
                "items": {"type": "string", "pattern": REF_PATTERN},
                "maxItems": 256,
                "description": "Entries named directly by the scope."
            },
            "tags": {
                "type": "array",
                "items": {"type": "string", "pattern": TAG_PATTERN},
                "maxItems": 32,
                "description": "Tags the scope requires."
            },
            "fields": {
                "type": "array",
                "items": {"type": "string", "pattern": FIELD_PATTERN},
                "maxItems": 32,
                "description": "Field names the scope limits, or empty for every field."
            },
            "commands": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_ARG_BYTES},
                "maxItems": 32,
                "description": "Allowlisted program paths."
            },
            "capabilities": {
                "type": "array",
                "items": {"type": "string", "enum": ["list", "run"]},
                "description": "What the grant allows."
            },
            "expires_at": {
                "type": "string",
                "description": "RFC 3339 UTC expiry."
            },
            "uses_left": {
                "type": ["integer", "null"],
                "minimum": 0,
                "description": "Remaining uses, or null when unlimited."
            },
            "status": {
                "type": "string",
                "enum": ["active", "expired", "exhausted", "revoked"],
                "description": "Current state of the grant."
            }
        },
        "required": [
            "id",
            "label",
            "refs",
            "tags",
            "fields",
            "commands",
            "capabilities",
            "expires_at",
            "uses_left",
            "status"
        ],
        "additionalProperties": false
    })
}

/// One pending access request, as `access_status` reports it.
fn request_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "request_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "description": "Opaque id for the pending request."
            },
            "reason": {
                "type": "string",
                "maxLength": 500,
                "description": "The reason you gave, as the human will see it."
            },
            "refs": {
                "type": "array",
                "items": {"type": "string", "pattern": REF_PATTERN},
                "maxItems": 32,
                "description": "References the request names."
            },
            "tags": {
                "type": "array",
                "items": {"type": "string", "pattern": TAG_PATTERN},
                "maxItems": 32,
                "description": "Tags the request names."
            },
            "commands": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_ARG_BYTES},
                "maxItems": 32,
                "description": "Programs the request asks for."
            },
            "duration_minutes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1440,
                "description": "Requested lifetime in minutes."
            },
            "created": {
                "type": "string",
                "description": "RFC 3339 UTC creation time."
            }
        },
        "required": ["request_id", "reason", "refs", "tags", "commands", "duration_minutes", "created"],
        "additionalProperties": false
    })
}

/// MCP tool annotations.
///
/// Hints only: an agent host must not treat them as enforcement, and `pmd`
/// makes every authorization decision. `openWorldHint` is true only for the
/// tool that starts a child process, which can reach whatever the child can.
fn annotations(read_only: bool, destructive: bool, idempotent: bool, open_world: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    })
}

#[cfg(test)]
mod tests;
