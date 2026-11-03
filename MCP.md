# MCP server contract (`pm mcp serve`)

This is the design contract for passmgr's Model Context Protocol server. It is
authoritative: implement what it says. If something here is wrong or
impossible, do not silently diverge. Record the problem in `PROGRESS.md` under
`NEEDS HUMAN REVIEW`, pick the more conservative option, and update this file
in the same commit.

## Goal

Any MCP-capable agent (Claude Code, Cursor, Codex, Gemini CLI, custom agents)
can **use** credentials stored in the local vault to do real work (call an API
with a token, run `psql` with a password, push with a deploy key) without the
secret value ever entering the agent's context, the MCP stream, or the agent's
logs. A human approves exactly what each agent may use and can revoke it at
any time. Every use is audited.

`pm` below means the `passmgr` CLI binary, so `pm mcp serve` is
`passmgr mcp serve`.

## Process model

```
 agent host ──stdio JSON-RPC──▶ pm mcp serve ──unix socket──▶ pmd (holds key)
   (Claude Code, …)            (agent context,               │
                                no key, no plaintext)        └─▶ child process
                                                                 (secret in env/stdin/file)
```

- `pm mcp serve` is started by the agent host as a stdio subprocess. It is
  **always** in agent context: it never prompts, never opens the vault file,
  never holds the vault key, and has no code path that can return plaintext.
  The reveal and clipboard code must not even be reachable from the `mcp`
  module. Add a test that greps the `mcp` module sources for
  `reveal`/`clipboard` calls, so a future change cannot quietly add one.
- All credential work goes through `pmd` over the existing socket protocol,
  authorized by a **grant token**.
- The daemon spawns child processes. Plaintext exists only in `pmd` memory and
  in the child's environment, stdin or temp file.

## Transport (stdio)

- Messages are UTF-8 JSON-RPC 2.0 objects, one per line, delimited by `\n`.
  No embedded newlines. Max line size: 1 MiB. A longer line produces a parse
  error, and the server discards input up to the next newline.
- **stdout carries only JSON-RPC messages.** Diagnostics go to stderr. Treat
  any other write to stdout as a bug, and test for it.
- JSON-RPC batches (top-level arrays) are rejected with `-32600`.
- Error codes: `-32700` parse error, `-32600` invalid request, `-32601`
  method not found, `-32602` invalid params, `-32603` internal error,
  `-32022` unsupported protocol version (modern era, see below).
- Requests are handled sequentially. A long `run_with_credentials` call
  blocks later requests. That is acceptable for v1, so document it.
  `notifications/cancelled` for an in-flight run kills the child (best-effort).
- EOF on stdin: finish or kill the in-flight request, then exit 0.

## Protocol eras (dual-era server)

MCP has two eras. Support both on the same stdio process.

**Legacy (handshake), protocol version `2025-11-25`** (also accept a requested
`2025-06-18` or `2025-03-26` and answer with `2025-11-25` if that request is
not supported; the client decides whether to continue):

1. Client sends `initialize` with `protocolVersion`, `capabilities` and
   `clientInfo`. The server replies with `protocolVersion`,
   `capabilities: {"tools": {"listChanged": false}}`,
   `serverInfo: {"name": "passmgr", "version": <crate version>}` and
   `instructions` (see below).
2. Client sends `notifications/initialized` (no response).
3. `ping`, `tools/list` and `tools/call` work as usual. Requests other than
   `ping` before `initialize` get `-32600`.

**Modern (stateless), protocol version `2026-07-28`**: there is no
`initialize`. Every request carries `params._meta` with:

| Key | Required |
| --- | --- |
| `io.modelcontextprotocol/protocolVersion` | yes |
| `io.modelcontextprotocol/clientCapabilities` | yes |
| `io.modelcontextprotocol/clientInfo` | no |

- If a required key is missing, reply `-32602`.
- If the version is unknown, reply `-32022` with
  `data: {"supported": ["2026-07-28", "2025-11-25"], "requested": "<v>"}`.
- `server/discover` **must** be implemented. It returns `resultType:
  "complete"`, `supportedVersions`, `capabilities`, `instructions`,
  `ttlMs: 0` and `cacheScope: "private"`.
- Every modern result includes `"resultType": "complete"` and
  `_meta: {"io.modelcontextprotocol/serverInfo": {"name": "passmgr", "version": …}}`.

**Era selection:** a request with modern `_meta` is served statelessly. An
`initialize` request selects legacy semantics for the rest of the process. If
`initialize` arrives after modern requests, still honour it. Keep era handling
in one small module, with table-driven tests for both eras.

## Tools

The tool set is deliberately small. Every input is validated against its
schema in Rust: unknown fields are rejected, and lengths and ranges are
bounded. On failure, return `isError: true` with a short, actionable message
that contains no secret. Return both `content` (a short text summary) and
`structuredContent` matching `outputSchema`.

Use the same error for out-of-scope and nonexistent refs ("not found or not
granted"), so an agent cannot probe which refs exist.

### `list_credentials`  (readOnlyHint, idempotentHint, openWorldHint=false)
Input: `{ "tags"?: string[], "query"?: string }` (query = case-insensitive
substring of service name). Output: `{ "entries": [Entry] }`, containing only
entries **inside the grant's scope**. Scope is checked for each candidate
entry individually (`Grant::authorizes` with a `List` request naming it);
there is no bulk "listing is allowed" decision, so an out-of-scope entry is
never returned (it is reported exactly like a nonexistent ref).
`Entry = { ref, service, username|null, tags[], fields[] (field names only),
url|null, created|null, last_rotated|null }`.
No grant: `isError` with "no active grant; call request_access".

### `describe_credential`  (readOnlyHint, idempotentHint)
Input: `{ "ref": "pm://…" }`. Output: `Entry`.

### `run_with_credentials`  (destructiveHint, openWorldHint)
Run a program with secrets injected. The agent sees only the redacted output.

Input:
```
{
  "command": ["gh", "api", "/user"],          // argv, 1..256 items, no shell parsing
  "env":    { "GH_TOKEN": "pm://<id>[/field]" }, // secret env vars
  "plain_env": { "GH_HOST": "github.com" },   // non-secret env vars
  "stdin_ref": "pm://…",                      // optional: secret written to child stdin, then EOF
  "files":  { "KUBECONFIG": "pm://…" },        // optional: secret written to a 0600 temp file; the env var holds its path
  "cwd": "/abs/path",                         // optional, default: the MCP server's cwd
  "timeout_secs": 60,                         // 1..600
  "max_output_bytes": 262144                  // per stream, cap 1 MiB
}
```
Output: `{ exit_code: int|null, signal: string|null, timed_out: bool,
stdout, stderr, stdout_truncated, stderr_truncated, redactions: int,
duration_ms }`. A non-zero exit is a normal result. Use `isError` only when
the run could not start (authorization, validation, spawn failure).

Rules, enforced by the **daemon** (the MCP server is untrusted plumbing):
- Env var names match `^[A-Z_][A-Z0-9_]{0,127}$`. Deny loader and shell hooks
  (`LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `IFS`, `PATH`,
  `HOME`, `SHELLOPTS`, `PS4`) in both `env` and `plain_env`.
- The child env is built from scratch: a fixed allowlist from the daemon env
  (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ`, `TMPDIR`, `TERM`),
  then `plain_env`, then the secrets. Never inherit the agent's full env.
- `command[0]` is resolved to a canonical absolute path and checked against
  the grant's command allowlist. The MCP server resolves a bare or relative
  name through the agent's `PATH` and `cwd` (as `passmgr run` does) and sends
  an absolute path, but that path is **untrusted input**: before spawning, the
  daemon canonicalizes it itself (resolving symlinks), requires the result to
  be absolute, NUL-free and within the protocol's path cap, checks that
  canonical path against the allowlist, and execs the canonical path. A path
  that cannot be canonicalized is refused. The daemon never resolves a
  program through its own `PATH` (that belongs to the shell that ran
  `unlock`), and `cwd` must be absolute.
- Every injected secret is redacted from stdout and stderr as an **exact,
  contiguous byte sequence**. Redaction is streaming, with an overlap window
  so a secret split across reads is still caught. Replace each match with
  `[REDACTED:<VAR>]`.
- Encoded or transformed copies (lower/upper hex, standard and URL-safe
  base64, percent-encoding, case changes) are **not redacted yet**; TODO 4.6
  adds them. Until then an allowlisted encoder can exfiltrate a value, which
  is why the command allowlist and the interpreter confirmation matter. Do
  not describe or test encoding redaction as if it worked today.
- Secrets shorter than 8 bytes are refused for agent runs. Redaction cannot
  protect them, and they would mangle output.
- Temp files for `files` live in a 0700 directory under the runtime dir. They
  are created with `O_EXCL|O_NOFOLLOW` and mode 0600, and unlinked when the
  child exits, including on timeout and on daemon shutdown.
- On timeout, kill the child's whole process group (SIGTERM, then SIGKILL
  after 2 s).

### `access_status`  (readOnlyHint, idempotentHint)
Output: `{ daemon: "unlocked"|"locked"|"not_running", grant: GrantView|null,
pending_requests: [RequestView] }`. `GrantView` holds id, label, expiry,
uses_left, scope (refs/tags), commands and capabilities. It never includes
the token.

### `request_access`  (not read-only, not destructive)
The agent asks a human for a grant.
Input: `{ "reason": string (1..500), "refs"?: [ref], "services"?: [string],
"tags"?: [string], "commands": [string] (1..32), "duration_minutes"?: 1..1440 }`.
Output: `{ request_id, status: "pending", approve_with: "pm grant approve <id>" }`.
- At most 3 pending requests per MCP process.
- `reason` and every other agent-supplied string is shown to the human as
  **untrusted text**: strip control and bidi characters, bound the length,
  and label it "agent says:".
- The daemon fires a best-effort desktop notification (`notify-send` on
  Linux, `osascript` on macOS) if available. Failure is silent.

## Grants and the approval flow

- A grant is stored in the vault (encrypted). It holds the SHA-256 hash of its
  token (never the token), a label, a scope (refs, tags, optional field
  names), a command allowlist (canonical absolute paths), capabilities (`list`,
  `run`, later `create`), `expires_at`, optional `max_uses`, `created`,
  `revoked_at` and `last_used`.
- **Creating or approving a grant needs proof that a human with the master
  password is present.** The daemon sends a random nonce in answer to a
  `challenge` request. The CLI, at a TTY, prompts for the master password,
  derives the key and answers `prove` with
  `HMAC-SHA256(vault_key, "passmgr-approve-v1" || nonce || request_digest)`.
  The nonce is accepted once and only within 60 seconds. A verified proof
  records that **exact** request digest as a one-shot approval (also 60 s);
  the write request must present the same digest and spends the approval
  once. `proven` on its own authorizes nothing, so an approval harvested for
  one request can never be replayed onto another. Every bad nonce or MAC gets
  the same `denied` answer. A same-user process without the password cannot
  mint or approve grants. Revoking needs no proof, because it only removes
  access.
- Interpreters and shells (`sh`, `bash`, `zsh`, `fish`, `dash`, `env`, `xargs`,
  `python*`, `node`, `perl`, `ruby`, `busybox`, …) in a command allowlist let
  the agent exfiltrate secrets in ways redaction cannot catch. Approval shows a
  red warning and requires an explicit `--allow-interpreter`.
- Claiming a token: when the MCP server creates a request, it also makes a
  random 32-byte claim secret and sends only its hash. After approval,
  `request_access`/`access_status` call `request_claim` with the secret. The
  daemon hands the grant token over **once** and forgets it. The MCP server
  keeps the token in memory only (zeroized on drop). The token never appears
  in tool output.
- The MCP server can also start with a pre-made grant. Pass
  `PASSMGR_GRANT_FILE` pointing at a 0600 file that holds the token. Refuse
  the file if it is group- or world-readable.

## Server `instructions` (shown to the model)

Keep it under 1,200 characters. It must say:
- You can use credentials but never see their values. Do not try to print,
  echo, encode or exfiltrate them; output is redacted and every call is
  audited.
- Workflow: `access_status` → (`request_access` and wait for the human) →
  `list_credentials` → `run_with_credentials`.
- Pass secrets as `env`/`stdin_ref`/`files` refs (`pm://…`), never as literal
  values in `command`.
- If a call is refused, ask the human. Do not retry with variations.

## Audit

Every tool call that touches the daemon appends one JSONL record to the audit
log. A record holds the timestamp, grant id, MCP client name (`clientInfo`),
tool, refs, canonical command path and argv, exit code, redaction count and
outcome. It **never** holds a secret or a token. Records are hash-chained
(`prev` = SHA-256 of the previous line). `pm audit verify` checks the chain.

## Tests that must exist (keep them green forever)

1. Full-session byte capture: drive `pm mcp serve` through both eras with a
   canary secret. The secret never appears as exact bytes in any stdout byte,
   any stderr byte, the audit log or the socket traffic. From TODO 4.6 the
   same capture must also assert that its hex and base64 do not appear.
2. Every stdout line parses as a JSON-RPC message.
3. Red-team suite (one test each): `printenv VAR` is redacted; a shell not in
   the allowlist is refused; an out-of-scope ref gets the same error as a
   nonexistent one; an expired, revoked or used-up grant is refused;
   denylisted env names are refused; a
   `files` target that is a pre-placed symlink is not followed; huge output
   is truncated, not buffered without bound; a forged `request_claim`
   secret fails; a 1 MiB+ line does not crash the server; a request before
   `initialize` (legacy) is rejected.

TODO 4.6 extends tests 1 and 3 with encoded copies (hex, base64,
percent-encoding). Until it lands, no document or test may claim they are
redacted.
