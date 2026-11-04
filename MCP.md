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
  authorized by a **grant token**. `run` carries that token in its request;
  `pmd` checks it against the vault grant before reading any secret.
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

Implementation notes (`src/mcp/era.rs`, TODO 4.2):

- A legacy `initialize` always answers `2025-11-25`, whatever version was
  requested, and never answers `-32022`: the legacy spec leaves the decision
  to the client. A second `initialize` on the same process is `-32600`, since
  it would silently renegotiate state the first handshake already fixed.
- `params._meta` must be an object; its presence (even a malformed one) means
  modern traffic, never a fallback to the legacy era. `protocolVersion` is a
  string of at most 64 bytes. `clientCapabilities` must be an object; its
  contents are not read. `clientInfo` is optional, but when present must be an
  object with a `name` string of 1..=128 bytes; the name is kept for the audit
  record.
- A `_meta` version other than `2026-07-28` is `-32022` with
  `{"supported": ["2026-07-28", "2025-11-25"], "requested": "<v>"}`, even
  when it names a legacy version: only `2026-07-28` can be served statelessly,
  and a client that wants `2025-11-25` must use `initialize`. A version longer
  than 64 bytes is `-32602` before anything is echoed.
- The era module owns the `initialize` and `server/discover` results, so a
  tool handler never has to remember which era it is answering in. Every
  other result is passed through the same decorator, which adds
  `resultType`/`_meta` for modern and nothing for legacy.

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
  canonical path against the allowlist, and execs the canonical path as
  `argv[0]` (the request's path and name are never used to spawn). A path
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
  is why the command allowlist and the program-runner confirmation matter. Do
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
  The nonce is accepted once and only within 60 seconds. The daemon holds at
  most 16 unspent nonces and always issues a new one, dropping the oldest, so
  a client that hoards challenges cannot lock a human out of asking for one.
  Spending a nonce keeps the remaining ones in issue order, so the oldest is
  still the one dropped when two approvals overlap (TODO R.19).
  A verified proof records that **exact** request digest as a one-shot
  approval (also 60 s);
  the write request must present the same digest and spends the approval
  once. `proven` on its own authorizes nothing, so an approval harvested for
  one request can never be replayed onto another. Every bad nonce or MAC gets
  the same `denied` answer. A same-user process without the password cannot
  mint or approve grants. Revoking needs no proof, because it only removes
  access.
- The daemon never writes a grant. After the proof, the approving CLI sends a
  `grant_create` request carrying the already-normalized grant (label, scope,
  command paths, capabilities, expiry, optional use limit) and the token's
  SHA-256 — never the token. The daemon re-normalizes it with the same
  constructor the CLI used, refuses one whose expiry is past or more than 30
  days out *without* spending the approval, and otherwise spends the digest
  and answers a bare `grant_approved`, which carries no token, hash, grant id
  or label. The CLI that holds the raw token assigns the id and writes the
  vault. The daemon cannot see the vault's limits, because it never opens the
  vault for this request: the approving CLI checks them against the vault it
  already decrypted (`MAX_GRANTS`, payload size) **before it asks for a
  proof**, so a full vault cannot consume an approval (TODO R.22).
  The exact body of that frame (the 4-byte length prefix is omitted) for a
  grant labelled `deploy prod`, scoped to the tag `prod` and the field
  `password`, allowing `/usr/bin/gh` with capability `run` (bit 2), expiring
  at 1700003600 and limited to 2 uses:

  ```json
  {"request":{"capabilities":2,"commands":["/usr/bin/gh"],"expires_at":1700003600,"fields":["password"],"label":"deploy prod","max_uses":2,"refs":[],"tags":["prod"],"token_hash":"6d2bfc0147054b3d0ad9dac8d06b6f65bf79270378498f8a20cb87db6f07e3b6","type":"grant_create"},"token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","version":4}
  ```

  Every key above is present in every frame, with `null` for an unset
  `fields` or `max_uses`; a scope needs at least one ref or tag, so `refs`
  and `tags` are never both empty. The body carries no credential value:
  `token` is the unlock session token and `token_hash` is the SHA-256 of the
  grant token, never the token itself.
- The one write the daemon *does* perform is `grant_revoke`. It names exactly
  one target, either `{"type":"grant_revoke","id":"<32 hex>"}` or
  `{"type":"grant_revoke","all":true}`; both keys at once, `"all": false`, a
  non-boolean `all` or a bad id is `bad_request`, never a guess. The daemon
  takes the vault's write lock *before* reading it, so a `run` that is
  recording its use at that moment cannot make the revocation fail with
  `internal`; it then opens the vault with the key it already holds, sets
  `revoked_at` (the first timestamp wins, so revoking twice changes nothing),
  saves it with the same salt and KDF parameters, and answers
  `{"type":"grant_revoked","revoked":N}`
  with the number of grants it newly revoked. An unknown id is `not_found`;
  `--all` targets only grants active at that instant, so expired, exhausted and
  already-revoked grants are left untouched, and `--all` with nothing active
  answers `revoked: 0`. No proof is required:
  revocation only removes access, so an agent may revoke for itself, and the
  next request that checks the grant sees it revoked (the daemon re-reads the
  vault for every request). The answer carries no id, label or hash.
- `pm grant list` and `pm grant show` are local reads, like `pm list`: they
  prompt for the master password, accept `--db`, and print metadata only
  (id, label, scope, allowlisted command paths, capabilities, timestamps,
  uses, status). `--json` emits `{"grants":[...]}` or one grant object with
  the same keys and no `token`, `token_hash` or secret field. `pm grant
  revoke` needs no password and no terminal, and like `pm run` it refuses
  `--db`/`PASSMGR_DB`: it always acts on the running daemon's vault.
- Interpreters, shells and program runners (`sh`, `bash`, `zsh`, `fish`,
  `dash`, `env`, `xargs`, `python*`, `node`, `perl`, `ruby`, `busybox`, `git`,
  `gh`, `find`, `sed`, `tar`, `ssh`, `docker`, `podman`, `kubectl`, `make`,
  `cargo`, editors, pagers, …) in a command allowlist let the agent run code,
  so it can exfiltrate secrets in ways redaction cannot catch. `pm grant
  create` prompts for the master password first, then prints the whole request
  (label, the service name and username behind every `--ref`, every entry each
  `--tag` currently matches, commands, expiry, use limit) and a red warning
  per allowed runner, then requires an explicit `y` or `yes`; anything else
  writes nothing. The names come from the encrypted vault, which is why the
  password precedes the summary; an unknown ref is refused before it. Allowing
  one still requires `--allow-interpreter`. The name list is best-effort: a
  grant binds only `argv[0]`, so allowing any program is a decision to trust
  what it can run.
- Minting a token: the daemon never holds a grant token, so it cannot hand
  one over. The MCP server mints it itself when it creates a request: a
  random 32-byte secret that *is* the future grant token, sent to the daemon
  only as its SHA-256 (`token_hash`, exactly like `pm grant create`). The
  server keeps the raw token in memory only (zeroized on drop). The human
  approves that exact hash with `pm grant approve <id>`; afterwards
  `request_access`/`access_status` call `request_claim` with the raw token,
  and the daemon answers whether the matching grant exists and is active
  (plus metadata) by comparing hashes. `request_claim` never returns a token,
  and the token never appears in tool output.
- The MCP server can also start with a pre-made grant. Pass
  `PASSMGR_GRANT_FILE` pointing at a regular file owned by you with no group
  or world permission bits (0600 or 0400 in practice); a group- or
  world-readable file is refused.

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

The log and its chain exist from TODO 3.8 for `run` (daemon and human local
runs, distinguished by the `source` field). `pm audit` lists those records
and `pm audit verify` checks the chain (TODO 3.9); neither needs a password
because a record holds no secret. The MCP-specific fields above (client name,
tool, redaction count) are added with TODO 4.11.

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
