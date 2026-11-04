## 2026-11-04 — Review of `47c64ac..7fd2997`

- 7 findings: **2 Medium, 0 High, 5 Low**. Categories: audit
  fail-closed/record integrity (R.68, R.73), missing security test (R.69),
  MCP audit input (R.70), grant-file doc drift (R.71), doc wording (R.72),
  terminal escaping (R.74).
- Medium R.68: a `run` whose audit append fails *after* the startup
  preflight still injects the secret, consumes the grant use and reports
  `Exit(0)` (pmd and local `pm run`); confirmed in a scratch copy with a
  child that `chmod 0400`s the audit file. Contradicts `SECURITY.md` and
  `DECISIONS.md`. The only existing test covers the preflight failure.
- Medium R.69: `MCP.md:33-35` requires a source-grep test proving `mcp`
  cannot reach reveal/clipboard; it was never written (TODO 4.3 is checked
  off), so a High-class property rests on prose. No current leak:
  `tools/call` is `-32601`.
- Low: R.70 audited client name is unsanitized and replaceable mid-session;
  R.71 grant-file code accepts modes `MCP.md` says are refused and
  `trim_end()` whitespace; R.72 `DECISIONS.md` says the audit reader rejects
  control characters when only `ref` is checked; R.73 the audit canary
  test's "no secret" assertion (`!text.contains("grant_token")`) cannot
  fail; R.74 `pmd` prints an `AuditError` path derived from `XDG_STATE_HOME`
  without `escape_hidden`.
- Looked at and judged fine (do not redo): grant-file reading
  (`O_NOFOLLOW`, fstat-on-fd, owner/regular-file checks, no content in
  errors, zeroized token read); `mcp serve` refusing `--db`/`PASSMGR_DB`
  before reading a line and never falling back to the local vault path;
  local `run`'s TTY gate (stdin+stdout terminal, agent flag/markers) and
  its master-password prompt; `GrantToken`/`Server` `Debug` redaction and
  zeroizing; JSON-RPC line reader over-long-line accounting/resync and
  empty-line handling; no request-smuggling via `\r\n` or multiple objects
  per line; `tools/call` still `-32601` so no tool argument is dereferenced;
  audit reader schema/chain/torn/64 MiB handling and `select` tail
  filtering; `pm audit`/`audit verify` escaping and the one-record-per-run
  chaining tests; `src/timestamp.rs` panic-free parsing; R.58/R.60/R.61 and
  R.64–R.66 tests are genuine. `serve_run`'s invalid-`ref` branch is
  unreachable because `src/protocol/mod.rs:552` validates references during
  decode (scratch test confirmed), so it is defensive only.
- No code, test or doc files were changed; the scratch experiment ran in a
  `/tmp` copy with its own target dir.

## 2026-11-04 — `pm mcp serve` binds the agent's grant file (TODO 4.4a)

- Split TODO 4.4 into 4.4a–4.4e (binding, daemon list, daemon describe, MCP
  `list_credentials`, MCP `describe_credential`) so each stays one iteration;
  only 4.4a is implemented here.
- `src/cli/args/mcp.rs`: `mcp serve` accepts exactly one `--grant-file FILE`
  or `--grant-file=FILE`; duplicate/empty/unknown arguments are usage errors
  (exit 2). `McpCommand::Serve` now carries `grant_file: Option<PathBuf>`.
- `src/cli/mcp.rs`: resolves the flag, else `PASSMGR_GRANT_FILE` (same
  precedence as `run`) and reads it through `grant::read_grant_token` before
  serving; a refusal is `Error::Refused` (exit 5) and names only path/reason.
  No file is not an error: the handshake and catalogue still work.
- `src/mcp/server.rs`: `Server` holds `Option<GrantToken>` (zeroized, redacted
  `Debug`); `with_grant`/`grant` accessors; `serve(input, output, grant)`.
  The token is only reduced to a hash when a later daemon request is built.
- Tests: 2 argument-parsing tests; a server test proving the bound token's
  hash matches, no grant is `None`, and `Debug` prints only
  `GrantToken(<redacted>)`; 3 e2e tests in `tests/mcp_serve.rs` (0600 via flag
  and env with empty stderr, 0644/malformed/missing refused with exit 5, and a
  hex/content canary absent from both streams).
- Help text and `tests/fixtures/help.txt` now show `mcp serve [--grant-file
  FILE]`; `MCP.md` documents the flag alongside the env variable.
- **Next iteration must know:** `tools/call` is still `-32601`; 4.4e replaces
  that branch. `Server::grant()` returns the raw token reference — do not
  format it, hash it. The e2e helper `grant_file` writes real random tokens;
  reuse it instead of hand-writing hex.

## 2026-11-04 — MCP stdio loop and tool catalogue (TODO 4.3)

- `src/mcp/server.rs`: sequential stdio loop over `LineReader`/`parse_line`,
  era `admit` before dispatch, era-owned replies verbatim, `decorate` on every
  own result, silent handling of notifications and peer responses. `tools/list`
  and `ping` need no daemon; `tools/call` is `-32601` until 4.4. A malformed,
  oversized or non-object-params line answers exactly once and the loop
  resynchronizes; stdout is only JSON-RPC and flushed per batch.
- `src/mcp/tools.rs`: pure catalogue of the five MCP tools with hand-written
  schemas plus `list_result()`. Every object schema sets
  `additionalProperties: false` (map inputs use `propertyNames`), no property
  is named like a secret, output schemas carry references/metadata only, and
  the whole catalogue is tested to fit one JSON-RPC line.
- CLI: `passmgr mcp serve` (`src/cli/args/mcp.rs`, `src/cli/mcp.rs`), with
  `--db`/`PASSMGR_DB` refused (exit 2) even though the server never opens a
  vault. Help/golden file, README, MCP.md and DECISIONS updated.
- Tests: 13 new unit tests (server) and 8 for the catalogue; a new
  `tests/mcp_serve.rs` drives the binary over real pipes in both eras, parses
  every stdout line with the crate codec, and pins empty stderr, the not-found
  branches and the vault-selection refusal.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass. The diff is larger than the usual ~400-line budget
  (mostly hand-written JSON Schemas and their tests); the loop and catalogue
  were kept in this one item because `tools/list` is not useful without it.
- **Next iteration must know:** TODO 4.4 must replace the `tools/call`
  `-32601` branch in `Server::dispatch` (and its test
  `tools_call_reports_that_it_is_not_available_yet`). `tools.rs` has schemas
  but no input validation or execution yet. The catalogue order in `ALL`
  (access_status first) is what the e2e test asserts; MCP.md's Tools section
  is the reference for arguments. The MCP module still has no test grepping
  it for `reveal`/`clipboard` reachability (MCP.md asks for one; not done).

## 2026-11-04 — MCP protocol era handling (TODO 4.2)

- New `src/mcp/era.rs` (+ `src/mcp/era/tests.rs`, 20 tests). Pure, no I/O:
  `Session::admit(&Request) -> Result<Admitted, Rejected>` picks the era, so
  the loop in 4.3 only routes by `Admitted { era, reply }`. `_meta` present
  means modern; it must be an object with a `protocolVersion` string (≤64
  bytes) and an object `clientCapabilities` (contents unread); `clientInfo`
  is optional but, when present, needs a 1..=128 byte `name`, kept for the
  audit record. A malformed `_meta` is `-32602`, never a legacy fallback.
- Legacy: `initialize` validates `protocolVersion`/`capabilities`/`clientInfo`,
  always answers `2025-11-25` (never `-32022`, per `MCP.md` negotiation), and
  a second `initialize` is `-32600`. Non-`ping` requests before the handshake
  are `-32600`. `ping` is era-agnostic.
- Modern: a `_meta` version other than `2026-07-28` is `-32022` with
  `{"supported": [...], "requested": "<v>"}`; that includes `2025-11-25`,
  because only the modern version can be served statelessly (a legacy client
  must use `initialize`). `server/discover` is answered only in the modern
  era; in legacy it stays -32601 from the dispatcher.
- `initialize_result()`, `discover()` and `decorate(era, result)` own every
  era-specific shape (`resultType`, `_meta.serverInfo`), so handlers and the
  loop never duplicate them. The instructions text (≤1200 bytes) is pinned by
  a test on the workflow phrases `MCP.md` promises.
- `MCP.md` gained implementation notes under "Era selection"; `DECISIONS.md`
  records the three choices above.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -D warnings` and
  `cargo test` pass.
- **Next iteration must know:** 4.3 must call `admit` before dispatch, send
  `Rejected.id` with `Rejected.error` (`Message::error`), use
  `Admitted.reply` instead of dispatching for `initialize`/`server/discover`,
  and wrap every other result in `decorate(era, result)`. `notifications/
  initialized` is a notification, so the codec never turns it into a
  `Request`; if a client sends it with an id anyway, the dispatcher will
  answer `-32601` — acceptable, but say so in `MCP.md` if a test pins it.

## 2026-11-04 — JSON-RPC 2.0 line codec (TODO 4.1)

- New `src/mcp/mod.rs` (contract summary + `pub mod jsonrpc`) and
  `src/mcp/jsonrpc.rs` with `src/mcp/jsonrpc/tests.rs`. Pure, no I/O:
  `LineReader::push`/`finish` turn a byte stream into `LineEvent::Line` /
  `LineEvent::TooLong { bytes }`; `parse_line` validates one line into
  `Message::{Request, Notification, Response}`; `encode_line` produces exactly
  one newline-terminated line. `Rejected { error, id }` carries the JSON-RPC
  error to send and the id to address it to (the six `ErrorCode` values are
  `-32700/-32600/-32601/-32602/-32603/-32022`).
- Rules: a line longer than `MAX_LINE_BYTES` (1 MiB) is dropped while it is
  read and the reader resynchronizes on its newline, so it never holds more
  than the cap; batches (top-level arrays) are `-32600`; `jsonrpc` must be the
  string `"2.0"`; ids are `i64` or strings of at most 128 bytes, and
  `"id": null` on a call is refused instead of guessed; a response needs
  exactly one of `result`/`error` and may use `id: null`; method names are
  1..=128 bytes; params must be an object, an array or `null` (absent).
- Chose to keep a peer's `error.code` as its raw `i32` (an unknown code is
  not rewritten into a wrong meaning), to bound `error.message` at 1024 bytes,
  and to accept a final line without a trailing newline at EOF. No rejection
  message echoes any input byte. Added `pub mod mcp;` to `src/lib.rs`.
- Tests: 42 units. Message shapes and round trips, every rejection code,
  prefix fuzzing of a valid line (no panic), a parse error that must not echo
  a canary, `-32700` vs `-32600` boundaries, and the reader under the cap,
  over it, split across pushes, across several lines per push, CRLF, empty
  lines and `finish`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green; `cargo audit` skipped (not installed).
- **Next iteration must know:** 4.2 (`era.rs`) sits on top of this: era
  decisions are *semantic*, so `parse_line` deliberately has no notion of
  `initialize`, `_meta` or result decoration. A rejection's `id` is `None`
  whenever the id itself was unusable (including an oversized or float id),
  so the answer uses `"id": null`; the server loop must send `Rejected`
  as-is rather than re-deriving an id. `tests/layout.rs` keeps files under
  1,000 lines: `src/mcp/jsonrpc.rs` is 628, so the server loop belongs in a
  sibling module (`src/mcp/server.rs`), not here.

## 2026-11-04 — `pm audit` listing and `pm audit verify` (TODO 3.9)

- `src/audit/read.rs` (new; `audit.rs` re-exports it): strict `Record` parser
  for the writer's schema, `verify` walking `prev` from the all-zero genesis,
  `load`/`select` for listings. The first impossible link is named
  (`line N: prev does not match line N-1`), and a file not ending in `\n` is
  refused.
- `pm audit [--json] [--grant ID] [--since 30s|15m|1h|7d] [--limit N]` lists
  oldest first, newest N (default 50) of the filtered set, header
  `Audit records (showing N of M):`, `{"records":[...]}` for `--json`.
  `pm audit verify` prints `Audit log verified: N records.` and exits 6 on a
  broken chain. Neither needs a password: records hold no secret or token.
- `Error::Audit` (exit 1) is an unreadable/loose log; `Error::AuditBroken`
  (exit 6) a broken chain. Reads take a shared `flock` (a concurrent append
  cannot look like tampering) and refuse over 64 MiB. `timestamp::parse_utc`
  parses exactly the 20-byte format `format_utc` writes.
- Tests: 8 units in `src/audit/read.rs` (edited/deleted/reordered/torn, schema
  matrix, loose path, filter/tail) and 12 in `tests/audit_cli.rs` (listing,
  JSON shape, filters, edited→exit 6 naming lines 3 and 2, deleted→line 2,
  reordered→line 1, torn tail, empty log, 0644 refused, no prompt, `$HOME`
  fallback). `tests/docs.rs` pins the new tail limit.
- Docs: SECURITY limit 8 (Out of scope → 9), README, HELP (+ golden file),
  DECISIONS, MCP, TODO. Gate: fmt, clippy `-D warnings`, full `cargo test`
  green; `cargo audit` skipped (not installed).
- **Next iteration must know:** `--since` is an age, not a date. A denial whose
  token matched an expired/out-of-scope grant still has `grant: null` (3.8
  note), so `--grant` misses it; returning the matched id from `record_use` is
  a follow-up. Verify cannot see a changed/deleted final record or the file's
  deletion (SECURITY limit 8).

## 2026-11-04 — Hash-chained audit log for daemon and local runs (TODO 3.8)

- New `src/audit.rs`: `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback
  `~/.local/state`), one JSON line with `v`, `ts`, `source`, `event`,
  `outcome`, `grant`, `ref`, `command`, `args`, `exit`/`signal`, `prev`.
  `prev` = SHA-256 of the previous line without its newline; first is 64 zeros.
- Appends hold an exclusive `flock`, read only the last line, refuse a torn or
  oversized (>32 KiB) last line, write `O_APPEND`, and `fsync`. The file is
  0600 in a 0700 `passmgr` dir; `O_NOFOLLOW`, regular-file, owner and exact-mode
  checks refuse a loose path instead of repairing it.
- `src/daemon/run.rs` preflights the log before parsing and records every path
  (bad request, denied, not found, internal, cancelled, spawn/output failure,
  allowed); `record_use` now returns the authorizing `GrantId` for the record.
  An unrecordable run is refused with `internal` before decrypting or spawning.
- `src/cli/run.rs` audits the grant-less local path too (`source: local`, no
  grant) with the same outcomes and fail-closed preflight (exit 5 before the
  password prompt when the log is unusable).
- Tests: `src/audit.rs` units (path rules, one-line JSON, control-char bounds,
  chain + 0600/0700, loose file/dir refusal, torn/oversized last line) and new
  `tests/audit.rs` (real daemon: allowed/denied records free of the secret and
  both tokens, two-record chain, unrecordable log refuses the run, modes).
  `tests/run_local.rs` asserts the local record. Tests set `XDG_STATE_HOME` per
  fixture/binary so they never touch the real log. SECURITY, README, MCP,
  DECISIONS and `tests/docs.rs` updated.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, full
  `cargo test` green; `cargo audit` skipped (not installed).
- **Next iteration must know:** denied records carry `grant: null` even when a
  token matched an expired/out-of-scope grant (`record_use` returns only the
  error); TODO 3.9's `--grant` filter should accept that or a follow-up should
  return the matched id. `args` are capped at 16 × 128 chars (truncated).
- NEEDS HUMAN REVIEW: the record is appended after the child ends, so a crash
  mid-run can lose the line even though the secret was injected. The preflight
  only proves writability. A pre-run "started" record would double every use;
  left for a human decision.

## 2026-11-04 — `run` for humans without a grant (TODO 3.7)

- `src/cli/run.rs`: `command_run(options, agent_mode, db_path)` now has two
  paths. A grant token (`--grant-file` or `PASSMGR_GRANT_FILE`) keeps the old
  daemon path unchanged. With neither, the CLI first applies
  `agent::check_human` (stdin **and** stdout TTYs, no marker/`--agent`), parses
  the reference, prompts for the master password and opens `--db`/the default
  vault, drops the decrypted vault before spawning, and calls the same
  `runner::execute` + streaming redactor used by `pmd`. The grant path never
  falls back to local injection when the daemon is missing.
- `src/cli/args/mod.rs`: the `--db`/`PASSMGR_DB` usage error now applies only
  when a grant selects the daemon; a grant-less local run accepts the vault
  flag like other commands. `src/cli/mod.rs` passes agent mode and the parsed
  vault path into `command_run`.
- Chose the reveal gate (both streams TTY) rather than stdin-only: a local run
  hands a secret to a command chosen at the terminal, so a piped stdout is
  refused even though relayed output is redacted. Documented in help, README,
  DECISIONS and SECURITY.
- Tests: new `tests/run_local.rs` (7 tests, PTY-driven) proves injection plus
  redaction of both streams and exit-status pass-through; refusal for every
  agent marker, for `--agent`, for non-TTY stdin **and** stdout; unknown ref =
  exit 3; and a grant token always selects the daemon path. `tests/run.rs`
  tests that assumed no-grant meant "daemon without a token" now pass a grant
  or assert the local refusal. `tests/cli_support` also clears
  `PASSMGR_DB`/`PASSMGR_GRANT_FILE` for hermetic runs.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` suite green; `cargo audit` skipped (not installed).
- NEEDS HUMAN REVIEW: a grant-less local `run` is not audited yet because the
  hash-chained audit log is still TODO 3.8. The TODO now explicitly requires
  3.8 to cover local runs; until then only the vault's `last_used` field
  records the use.
- **Next iteration must know:** a grant token in the environment selects the
  daemon path at parse time too, so `--db` is refused even if the daemon is
  down; there is deliberately no local fallback. `tests/run.rs` is now 985
  lines: put new run e2e coverage in `tests/run_local.rs` or split it first.

## 2026-11-04 — Measure grant growth headroom from the codec (TODO R.61)

- `src/store/payload.rs`: deleted the public `GRANT_GROWTH_BYTES` (production
  never read it; only the test and the `src/store.rs` re-export did) and its
  re-export. The private `grant_growth_bytes` is now `pub(super)` and stays the
  single accounting `encode` subtracts from the encoded size. No behavior
  change: `content` and `MAX_PAYLOAD_BYTES` are unchanged.
- `src/store/tests.rs`: rewrote `grant_growth_headroom_covers_the_whole_grant_cap`
  to measure the growth instead of restating a constant. The fixture sets
  every optional field (max_uses, a listed field scope, two tags, two refs,
  two commands), then encodes the one-grant payload before `mark_used`, after
  it and after `revoke`; the delta is the measured growth. Asserts:
  `measured == grant_growth_bytes(&grant)` (encoder drift fails),
  the attributed content size is identical before and after the transitions,
  and `measured * MAX_GRANTS <= MAX_PLAINTEXT_GROWTH_BYTES`.
- Mutation-checked: removing the `last_used` term from `grant_growth_bytes`
  fails it (16 vs 8). The exact-cap daemon test
  (`a_revocation_fits_a_vault_written_at_the_payload_cap`) still covers the
  end-to-end save.
- `DECISIONS.md`: the payload-limit bullet now names the private helper and the
  measured test instead of a public constant.
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** Phase R is now empty of `- [ ]` items; the next
  unchecked item is **3.7** (`pm run` for humans — local path without a
  grant). This matters for the test suite: `tests/run.rs` is near the 1,000
  line limit, so split before adding e2e coverage there.

## 2026-11-04 — Never let a failed request write look like success (TODO R.60)

- `src/client.rs`: the new private `send_request` is the only request-frame
  write, used by `request()` and `run()`; every `write_all`/`flush` failure
  becomes `Error::Daemon` ("the unlock daemon went away before it received the
  request"). Before, the `io::Error` became `Error::Io`, and `main` maps a bare
  `BrokenPipe` to exit 0 — so a `pmd` that exited after accepting (lock, idle
  timeout, crash) made `run` and `grant revoke --all` report success for a
  request it never received. `read_response` does the same for the answer
  (empty read, reset, any other error), because the stub socket race can lose
  on either side: the first full-suite run after the cherry-pick failed with
  `I/O error: Connection reset by peer` from the read, which still exited 1 but
  did not name the daemon; after a connect, a lost daemon is a daemon error on
  every transport path.
- `main`'s arm is unchanged; its comment now says it covers only this
  process's own stdout/stderr writes. `src/cli/run.rs`'s `relay` comment no
  longer claims a socket `BrokenPipe` takes the generic mapping.
- Tests: `client::tests::a_failed_request_write_is_a_daemon_error_not_a_broken_pipe`
  and `a_closed_connection_without_an_answer_is_a_daemon_error` (dropped
  `UnixStream` peer, deterministic EPIPE/EOF, assert the variant, the nonzero
  exit code and that the message names the daemon);
  `tests/daemon_gone.rs` (new file) and
  `tests/grant_manage_cli.rs::grant_revoke_all_fails_when_the_daemon_goes_away_before_the_request`
  use an accept-then-close stub and require exit 1 with stderr naming the
  daemon. Mutation-checked: they fail with the old `?` (exit 0 vs 1).
- `DECISIONS.md` "Exit codes" records the rule: the `BrokenPipe` -> 0 arm is
  only for this process's own output.
- Earlier attempt (iteration 116, branch `failed/iter-116-20261103-234729`)
  failed the gate on a test-harness flake, not on this change:
  `tests/cli_support/mod.rs` wrote the scripted stdin and `.expect`ed it,
  so a child that refuses before prompting (`--agent`, non-TTY reveal) could
  exit first and turn the setup write into an EPIPE panic. The piped-stdin
  writes in `tests/cli_support/mod.rs` (both helpers) and `tests/unlock.rs`'s
  piped `run` now tolerate exactly `BrokenPipe` (any other error still fails)
  and the outcome is still asserted from the child's output.
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** next unchecked item is R.61 (`GRANT_GROWTH_BYTES`
  is restated rather than measured). `tests/run.rs` is back to 972 lines, so a
  new e2e there needs a split first; R.60's socket tests live in
  `tests/daemon_gone.rs`.

## 2026-11-04 — loop note: gate failed (iteration 116)

- Commits from this work iteration (TODO R.60) failed the gate and were rolled back.
- The work is kept on branch failed/iter-116-20261103-234729; you may cherry-pick from it and fix it.
- gate: `agent_flag_blocks_reveal_over_pipes --- FAILED`
- gate: `thread 'agent_flag_blocks_reveal_over_pipes' (1476829) panicked at tests/cli_support/mod.rs:58:14:`
- gate: `test result: FAILED. 8 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.06s`
- gate: `error: test failed, to rerun pass `--test cli_reveal``

## 2026-11-04 — Attempt a run's use save exactly once (TODO R.58)

- `src/daemon/run.rs`: deleted `USE_RECORD_ATTEMPTS` and the retry loop.
  `record_use` now delegates to a private
  `record_use_with_save(..., save: impl FnMut(&Vault) -> crate::Result<()>)`
  and answers `RecordError::Internal` after a single failed `save_with_key`;
  the child never runs.
- Chose delete over document: since R.39 every attempt reads under the write
  lock, so a retry cannot merge a lost update, and a save that failed *after*
  its rename landed already holds the increment — a retry charges a second
  use of a `max_uses` grant. `DECISIONS.md` records the one-attempt rule and
  drops "re-reads it on every retry"; R.39's "(retry loop gone)" is now true.
- Test: `src/daemon/run.rs::tests::a_failed_use_save_is_attempted_exactly_once`
  injects a failing save through the seam and asserts one attempt,
  `Internal`, and `uses() == 0` after reopening the vault. Mutation-checked:
  with a 3-attempt loop patched in it fails (attempts 3 vs 1).
- Gate: fmt, clippy, full `cargo test` green (first full run hit a
  non-reproducing `tests/cli_support/mod.rs:58` stdin BrokenPipe in
  `tags_are_stored_filtered_and_metadata_only`; that test passed alone and
  the second full run was green). `cargo audit` skipped.
- **Next iteration must know:** next unchecked item is R.60 (a socket
  `BrokenPipe` mapped to exit 0 in `src/cli/mod.rs:47`).
  `record_use_with_save` is production code with a test seam; keep `save` as
  `FnMut` so a future test can count attempts.

## 2026-11-04 — Widen and pin the terminal-safety claim now that R.48 landed (TODO R.55)

- R.55's premise was stale: R.48 landed first. `store::validate_service`/
  `validate_username` refuse the whole hidden table (`src/text.rs`) and every
  human-facing line escapes a stored name, so the universal claim in
  `SECURITY.md` is true again. Confirmed on the built binary: `add` with
  U+202E exits 2 before any prompt; the old "narrow it" fix was not applied.
- `SECURITY.md` "What passmgr protects" terminal-safety bullet now says: what
  is escaped (every error line and every argv value the CLI echoes, now
  including `--out`; plus stored names in `list`/`get`/`show`/approval
  summary), that new names/usernames/labels/commands/tags/field names are
  refused at validation, that a legacy vault may hold one and it is escaped
  where printed, that the CLI printer escapes an error line twice, and that
  `--json` is a data channel that keeps stored bytes.
- `tests/docs.rs::security_documents_terminal_safety_for_its_own_output` pins
  those clauses inside `## What passmgr protects` only (R.5's lesson), so an
  unrelated sentence cannot satisfy it. Mutation-checked: replacing the
  backstop sentence with "escapes errors" fails it; the old bullet fails it.
  Per-site behavior still lives in `tests/cli_args_escape.rs`.
- `DECISIONS.md` records that the bullet is doc-test-pinned (not a new policy:
  the existing escaping rules are unchanged).
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** next unchecked item is R.58 (`record_use`'s
  three-attempt loop vs R.39's "retry loop gone" claim). The loop is real and
  every attempt reads under the lock, so the failure it describes (double
  increment after a post-rename save error) is live; decide delete vs
  document before touching `src/daemon/run.rs`.

## 2026-11-03 — Make the agent-source unit tests independent of inherited markers (TODO R.52)

- `src/agent.rs`: `agent_source(agent_flag)` now delegates to a private
  `agent_source_from(agent_flag, is_set)`, the same seam `marker_from` already
  gave `agent_marker`. The env lookup happens only in the real caller, so a
  `cargo test` run from a Claude Code (or Cursor/Codex) shell is deterministic.
- Tests: `the_agent_flag_refuses_even_with_two_terminals` and
  `the_agent_flag_cannot_weaken_the_check` use a new `clean_source` helper
  (predicate always false). Added
  `an_inherited_marker_wins_over_the_flag_in_the_real_detection` so the
  precedence of a real marker over `--agent` stays pinned through the new core.
- Reproduced first: `CLAUDECODE=1 AI_AGENT=1 cargo test --lib agent::` failed
  both tests with `Some(Env("CLAUDECODE"))`; after the change all nine lib
  tests pass with all five `AGENT_MARKERS` set in the environment.
- No behavior change to the real gates (`check_human`, `check_reveal`):
  `agent_source` reads the same variables in the same order.
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** the next unchecked item is R.55
  (`SECURITY.md`'s terminal-safety bullet vs R.48). R.48 has landed since that
  finding was written, so re-check whether R.55 is now satisfied or only needs
  a reword; do not assume the finding is still accurate.

- 62 of ~90 work iterations had gone to review findings while Phase 4 (the MCP
  server, the reason passmgr exists) had none started. Reviews now tag each
  finding High/Medium/Low (`REVIEW.md` "Severity"); only High and Medium go to
  the top Phase R. Low findings go to `## Phase L`, just above Phase 9.
- Moved the open Low items there: R.53, R.54, R.56, R.57, R.59, R.62, R.63,
  R.67 (memory-residue coverage, timing-flaky tests, comment/doc wording, file
  layout). Kept at the top: R.52 (tests fail under Claude Code), R.55, R.58,
  R.60, R.61.
- `loop.sh` reviews every 12 productive iterations instead of 6.
- **Next iteration must know:** order is Phase R, then Phase 3, then Phase 4.
  Do not pull Phase L items forward. When a feature item would push a file
  past the line limit, split that file as part of the item (R.54 stays in L).

