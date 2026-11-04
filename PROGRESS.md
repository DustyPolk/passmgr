## 2026-11-04 — MCP `describe_credential` wired to the daemon (TODO 4.4e)

- `src/mcp/call.rs` gains `describe_ref` (exactly one `ref` member, string,
  ≤128 bytes, parsed to an `EntryId` and re-rendered, so upper-case hex and a
  field suffix are refused before `pmd` sees them), `describe_request`,
  `request_describe` and `describe_response`/`describe_output`.
  `request_list` and `request_describe` now share one `send` helper that loads
  the session token and reports "daemon down" vs "cannot authenticate".
- `src/mcp/server.rs` dispatches the new arm. `structuredContent` is the
  `Entry` object itself (the tool's declared `outputSchema`), not a wrapper.
  A daemon `not_found` maps to "not found or not granted" — the same text for
  a missing ref and one outside the grant. `ResponseError` wording was
  generalized from "list request" to "credential metadata request".
- Never echo an agent-supplied ref: every bad-reference path uses one fixed
  message (`INVALID_REF`), so `store::EntryId::parse_ref`'s quoted input never
  reaches the error. Unit test with a canary reference pins it.
- Tests: 4 new unit tests in `src/mcp/call/tests.rs` (canonical form and every
  refusal, verbatim request, output shape, `Entry`/`not_found`/unexpected
  mapping). `src/mcp/server/tests.rs` covers no-grant for both tools and a bad
  describe ref. 3 e2e tests in `tests/mcp_serve.rs`: list+describe in one
  stdio session, a missing reference, and a RUN-only grant denial; each
  asserts the fixture secret is absent from stdout and stderr.
- `MCP.md`, `SECURITY.md`, `README.md` and `DECISIONS.md` updated; TODO 4.4e
  checked. No wire, vault or dependency change.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` skipped: not installed).
- **Next iteration must know:** 4.5 is `run_with_credentials` through the
  daemon (`Request::Run` already exists, `src/daemon/run.rs`); `call.rs` has
  the `send` helper to reuse for a streaming run, but a run is not one
  request/one response, so it needs its own client path. `src/daemon.rs` is
  still 991 lines and must be split before it grows.

## 2026-11-04 — MCP `list_credentials` via the daemon (TODO 4.4d)

- New `src/mcp/call.rs`: the `tools/call` boundary. `call_parts` validates the
  envelope (`name`/`arguments`/`_meta` only, name ≤64 bytes), `list_filters`
  applies the schema's bounds (≤32 tags through `store::validate_tag`, query
  1..=256 bytes with no control characters), and `list_request` builds
  `Request::List` with the session grant. `request_list` loads the session
  token from `$XDG_RUNTIME_DIR/passmgr`, distinguishes "daemon not running"
  from "cannot authenticate", and calls `client::request`.
- `list_response` accepts only `Response::Entries`; `Entry` metadata is
  projected with RFC 3339 timestamps (`timestamp::format_utc`), and the
  output is `{content, structuredContent:{entries,truncated}, isError:false}`.
  Every daemon refusal and every transport failure is `isError` with a short
  message, so "no grant"/"daemon down" can never look like an empty list.
  No grant is exactly `no active grant; call request_access`.
- `Server::dispatch` now calls `tools_call`; `tools/call` no longer answers
  `-32601`. Unknown tool names are `-32602` "unknown tool"; argument errors
  are `-32602` before the grant check. `list_credentials` output schema now
  requires `truncated`.
- Decisions: keep validation/results in the pure-ish `call` module, not in
  `server.rs`; never reuse the protocol's integer timestamps in MCP; never
  echo an agent-supplied filter value in an error (only a 32-char,
  control-stripped member name is quoted). Added to `DECISIONS.md`.
- Tests: 8 unit tests in `src/mcp/call/tests.rs` (bounds, `_meta`, pass-through,
  RFC 3339, truncation, every `ResponseError`, unexpected response, exact
  no-grant text). `src/mcp/server/tests.rs` now proves the no-grant result and
  unknown-tool/argument refusals. Four e2e tests in `tests/mcp_serve.rs`:
  no grant, LIST-grant metadata (ref/service/username/no fields/no URL, no
  canary secret on either stream), RUN-only denial, and no-daemon error.
- Test-support change: `tests/support/mod.rs` now creates its runtime at
  `<temp>/passmgr` (so `RuntimePaths::resolve()` under the test's
  `XDG_RUNTIME_DIR` finds it) and has `Fixture::with_capabilities`.
- Also updated `MCP.md`, `SECURITY.md`, `README.md` and the 4.4e note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` skipped: not installed). No dependency.
- **Next iteration must know:** 4.4e adds the `describe_credential` arm in
  `tools_call` and can reuse `response`/`entry_json`; the dispatcher already
  refuses unknown tools, so its TODO text was adjusted. `src/daemon.rs` is
  still 991 lines and needs a split before it grows.

## 2026-11-04 — Daemon `describe` request: one entry, same collapsing as `list` (TODO 4.4c)

- `Request::Describe(DescribeRequest { reference, grant })` and
  `Response::Entry(Entry)`; wire `{"type":"describe","ref":...,"grant":...}`
  and `{"type":"entry","entry":{...}}`. The reference is bounded (≤128 bytes)
  and canonicalized through `EntryId::parse_ref` on encode, on decode and
  again in `pmd`; `validate_reference` also replaced the inline `run.ref`
  check.
- `pmd::describe_entry` reuses a new `metadata_grant` helper with `list`:
  grant token -> `Grant::check_grant_for_metadata` (active + `List`) ->
  watermark -> per-candidate `AccessRequest::list(target, None)`. A missing
  reference and an out-of-scope one both answer the same `not_found`; every
  other denial is `denied`. The grant is checked *before* the lookup, so a
  dead token cannot probe which refs exist.
- Decision (also in `DECISIONS.md`): `describe` joins protocol version 4, no
  vault change, no migration. Like `list`, it returns metadata only; a
  `field`-scoped grant does not cover `None`, so it cannot describe a
  credential (conservative, deliberate).
- Tests: 6 daemon tests (in-scope metadata, canary and out-of-scope name
  absent from the socket bytes, byte-identical missing/out-of-scope answer,
  tag scope per candidate, upper-case ref canonicalized, no/revoked/expired/
  run-only grant denied, revoked grant refused before lookup) and 4 protocol
  tests (wire shape, bounded refs, decoder refusal, missing grant token).
  New tests live in `src/daemon/tests/describe.rs` and
  `src/protocol/tests/describe.rs` to stay under the layout limit.
- `SECURITY.md` current status lists `describe`; `src/client.rs` maps the new
  response to `"entry"`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` skipped: not installed). No dependency.
- **Next iteration must know:** 4.4d wires `list_credentials` in
  `src/mcp/tools.rs`; it can then share the `"entries"`/`"entry"` mapping with
  4.4e. `src/daemon.rs` is 991 lines — split it (e.g. `list`/`describe` into
  `src/daemon/metadata.rs`) before it crosses 1,000.

## 2026-11-04 — Daemon `list` request: metadata only, per-candidate grants (TODO 4.4b)

- New `src/protocol/entry.rs` (500 lines): `Entry` (`ref`, `service`,
  `username`, `tags`, `fields`, `url`, `created`, `last_rotated`),
  `from_credential` (never reads the password; `fields` is `[]` and `url` is
  `null` until TODO 6.1), a strict `from_json` (ref canonicalized through
  `EntryId::parse_ref`, tags/fields re-validated, timestamps bounded),
  `matches_filters` (all tags + case-insensitive service substring) and
  `fit_entries` (drops the tail so the answer fits one frame, reports
  `truncated`).
- `Request::List(ListRequest { tags, query, grant })` and
  `Response::Entries { entries, truncated }`; `list` joins
  `REQUEST_WIRE_NAMES`, the module doc and the codec, and `validate_list`
  bounds tags (≤32, valid tags) and query (≤256 bytes, no control chars) on
  encode *and* decode. `Response` lost `Copy`.
- `pmd::list_entries`: grant token -> `Grant::check_grant_for_list` (active +
  `List`) -> watermark -> per-candidate `AccessRequest::list` (OutOfScope is
  skipped, any other denial is `Denied`) -> filters -> truncation. The grant
  is checked before enumeration, so a revoked grant is denied even on an
  empty vault. No protocol version bump: an old daemon answers `unknown
  request type`, a refusal (recorded in `DECISIONS.md`).
- Tests: 5 daemon tests (scope, filters that cannot widen it, missing /
  revoked / expired / run-only grant denied, empty vault) with per-test canary
  passwords asserted absent from the encoded response; protocol tests pin the
  wire shape, the bounded filters and every `Entry` decoder refusal.
- `src/daemon/tests.rs` and `src/protocol/tests.rs` crossed 1,000 lines, so
  the new tests live in `src/{daemon,protocol}/tests/list.rs` (the layout test
  enforces the limit).
- `SECURITY.md` and `MCP.md` describe `list` (metadata only, `truncated`).
  The docs test requiring every request name in "Current status" passed only
  because "allowlist" contains "list"; it now requires a word boundary
  (`mentions_word`), and `SECURITY.md` no longer claims `pm mcp serve` is
  unimplemented code.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` pass (`cargo audit` skipped, not installed). No new dependency.
- **Next iteration must know:** 4.4c (`describe`) should reuse
  `protocol::Entry` and the same grant-first-then-candidate order; 4.4d must
  map `truncated` into the tool output (`src/mcp/tools.rs` currently allows
  only `entries`).

## 2026-11-04 — Source guard for reveal/clipboard in `mcp` (TODO R.69)

- New `tests/mcp_source_guard.rs`: recursively scans every `.rs` file under
  `src/mcp/`, strips comments (line, nested block) and string/char/raw-string
  contents with a small line-spanning lexer, then rejects any remaining
  **identifier** containing `reveal` or `clipboard`. Broader than literal
  call shapes on purpose: `use crate::agent::reveal_refusal;`, `mod reveal;`,
  `reveal::print(…)` and an `as` rename are all caught.
- The detector is a pure `scan_source` helper, tested on synthetic sources
  for both the dangerous routes and the benign cases (docs, comments, tool
  description, raw strings, `'"'`, `'\''`, lifetimes). The real-tree test
  first asserts the expected five files were found, so a bad path cannot
  make it vacuously pass.
- Verified the guard fails as required: a scratch append of
  `use crate::agent::reveal_refusal;` to `src/mcp/mod.rs` made it report
  `src/mcp/mod.rs:23: reveal_refusal`; the file was restored afterwards.
- `MCP.md` now names the test instead of asking for one; `TODO.md` R.69 is
  checked with a note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` skipped, not installed).
- **Next iteration must know:** future code or test identifiers under
  `src/mcp/` must avoid the substrings `reveal`/`clipboard` entirely (even a
  local variable like `revealed`); put such names in strings or comments, or
  in a test outside `src/mcp/`. Next unchecked item is 4.4b (daemon `list`).

## 2026-11-04 — A run that cannot be recorded never reports success (TODO R.68)

- `src/daemon/run.rs`: the metadata `record` closure now returns
  `Result<(), audit::AuditError>`. The allowed branch appends *before*
  sending `RunFrame::Exit`; a failure logs `pmd: the run finished but its
  record could not be written: …` and sends `RunFrame::Error(Internal)`
  instead. Branches that already report a failure (bad request, denied, not
  found, spawn failure, output error, cancel) keep their answer and log the
  append error through a small `warn` closure.
- `src/cli/run.rs` mirrors this for the local path: a failed append after the
  child exits returns `Error::Refused`, so the human gets exit 5 and a message
  naming the log. Decision: the child's status is deliberately not passed
  through; `Refused` reuses the preflight wording/escaping and exit 5.
- Tests: `tests/audit.rs::a_run_whose_audit_append_fails_is_not_reported_as_success`
  and
  `tests/run_local.rs::a_local_run_whose_audit_append_fails_exits_non_zero`.
  Both let the child `chmod 400` the log the preflight created, then assert
  the child did run, no `Exit` frame / exit 5, and stderr names the log.
  Both were run against the pre-fix code and fail there.
- Docs: `SECURITY.md`, `DECISIONS.md`, and `README.md` (local-run paragraph
  and the exit-code 5 row) state the post-run rule.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` skipped, not installed).
- **Next iteration must know:** pre-spawn denials still record best-effort; a
  failed append there keeps the denial answer and only warns, because no use
  happened. The local path now masks the child's exit status when the append
  fails — that is the conservative choice, not an accident.

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

