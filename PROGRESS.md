## 2026-11-04 — Whole-codebase review and fixes (human-requested, not a TODO item)

- Five read-only reviewers (one per subsystem), then one fix branch per file
  seam; every Medium finding was confirmed against the code before fixing.
  Each fix is its own commit with a test that failed before it.
- Medium fixes: Argon2 memory and AES key schedules wiped (crate `zeroize`
  features, `Zeroizing` KDF blocks); per-connection request deadline (a
  trickling client held the key past idle and SIGTERM); the run deadline is
  enforced while the client is not reading; watermarks raised on every vault
  read; the pre-run audit check validates the tail and a record is one write;
  symlinked vault refused (single `O_NOFOLLOW|O_NONBLOCK` open); pre-1970
  timestamps refused instead of overflowing; `passmgr run` reports caps and
  timeouts on stderr; `pm audit` quotes ref, command and args.
- Low fixes and cleanup: FIFO grant/session files refused, `run --env` no
  longer echoes a literal, run-specific MCP refusal texts, glibc loader vars
  denied, NUL argv refused, a gone client spends no use, unlock race fixed,
  stale help/MCP/model text corrected, one `src/hex.rs`, `subtle` for
  constant-time compares, one `validate_shape`, dead code removed.
- New direct dependencies `aes` (only to enable `zeroize`) and `subtle` (vetted
  RustCrypto, constant-time compare); both were already in the tree.
- Test changes explained: the help golden file and the SECURITY limit 8 pin
  now match corrected text that had overclaimed; `a_tag_is_shown_with_every_
  credential_it_matches` asserted a misleading union and was replaced.
- Gate: fmt, clippy `-D warnings`, full `cargo test` (cargo audit not
  installed).
- **Next iteration must know:** deferred findings are R.75-R.79 in Phase L;
  4.6b carries a note on base64 at an offset; 9.4's per-connection deadline
  is done. The loop's review marker (`logs/state/last-review`) was moved to
  this commit, because the whole codebase was reviewed today; the next review
  iteration covers only work after it.

## 2026-11-04 — Encoders for redaction variants (TODO 4.6a)

- 4.6 was split in `TODO.md`: encoded redaction is three concepts (generate
  variants, redact them, a length policy) plus property tests. 4.6a is the
  pure encoders; 4.6b wires them into `Redactor`/`src/runner.rs`, 4.6c adds
  the 8-byte minimum for agent runs, 4.6d the property tests and the encoded
  MCP canary session.
- New `src/redact/encoding.rs`: `Encoding` covers hex lower/upper, base64
  standard and URL-safe (padded and unpadded), and RFC 3986 percent-encoding
  (`A-Za-z0-9-._~` literal, every other byte `%XX`, upper-case hex).
  `Encoding::encode(&[u8]) -> Vec<u8>` and `variants(&[u8]) -> Vec<Vec<u8>>`
  (deduplicated; a form equal to the raw secret is dropped, because an
  all-unreserved value percent-encodes to itself). Hand-written: no new
  dependency.
- Declared `pub mod encoding;` inside the already-public `redact` module so
  the items are live crate API; a private module's `pub` items would trip
  `dead_code` until 4.6b starts using them.
- Tests (9, all in `src/redact/encoding.rs`): fixed vectors for every form
  including both alphabets and all three padding lengths; RFC 3986 cases;
  exactly seven distinct forms for a discriminating secret; dedupe and
  raw-drop; empty secret; ASCII-only output for all 256 byte values; and
  test-local hex/base64/percent decoders round-tripping deterministic bytes
  for lengths 0..=40 across four seeds.
- Docs: `DECISIONS.md` records the fixed encoding list, the no-dependency
  choice, and that the daemon still redacts only raw occurrences until 4.6b.
  Behavior is unchanged, so README/SECURITY/MCP stay as they are.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` pass (`cargo audit` skipped: not installed).
- **Next iteration must know:** 4.6b must build the redactor value set as raw
  + `encoding::variants` per secret (encoded forms alone would miss the raw
  value), keep one marker for the whole expanded set, and update the two
  `tests/docs.rs` pins (`docs_agree_that_redaction_does_not_follow_encodings`,
  `mcp_documents_the_exact_bytes_redaction_limit`) with the docs in the same
  commit. `choose_marker_many`'s doc proof must be restated for the expanded
  set (every variant is ASCII, raw endpoints stay bounded, so the forbidden
  byte set cannot reach 256).

## 2026-11-04 — MCP `run_with_credentials` (TODO 4.5d)

- New `src/mcp/call/run.rs` owns the tool boundary: `run_args` (closed key set,
  argv/env/plain_env/cwd/limit bounds, canonical refs, schema-stricter env
  names, duplicate refusal, `stdin_ref`/non-empty `files` refused with a
  "not available in this build, use env" message), `resolve_command` (reuses
  the CLI's `resolve_program`, now `src/program.rs`), `request_run` (session
  token from the runtime dir, `client::run`, frames into a `RunSink` bounded by
  the requested cap) and `run_output` (the nine schema fields).
- `RunFinished` gained `redactions: u64` and `duration_ms: u64`, computed in
  `src/runner.rs` (a shared `AtomicU64` summed over both readers, `Instant` at
  the spawn) and encoded in the `exit` frame; absent fields decode to 0, so an
  old daemon or client still works. `src/mcp/server.rs` holds the agent's cwd
  and `PATH` (manual `Default`) so `command[0]` is resolved before the request.
- `src/mcp/tools.rs`: the `timeout_secs` default/description said 120; it is
  600, matching MCP.md and `RunLimits::default()` (it now imports the constant).
- Tests: 13 unit tests in `src/mcp/call/tests.rs` (validation, refusals, Debug
  hides `plain_env` values, cap, signal names, exit mapping, refusal mapping),
  two runner tests for the new statistics, and four `tests/mcp_serve.rs`
  end-to-end sessions: canary injected into both streams, redacted, exit 3 and
  `redactions >= 2` with the canary absent from all output; no grant; a
  list-only grant denied as `isError`; `stdin_ref` refused.
- `tests/support/mod.rs` grew `exit_frame`/`is_exited`/`assert_exited`: 16
  existing assertions compared a whole `RunFinished` and now cannot, because a
  real run's `duration_ms` varies.
- MCP.md: implementation note, the run section's implementation status, the
  documented marker is `[REDACTED]` (it said `[REDACTED:<VAR>]`), and the
  older-daemon paragraph now covers all four terminal fields.
- Decisions: the daemon is the only source of run statistics (DECISIONS.md);
  run argument errors are `isError`, metadata tools keep `-32602`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass.
- **Next iteration must know:** `files`/`stdin_ref` validation is deliberately
  in `run_args` and must be deleted there when 5.1/5.2 land; `run_args`
  requires at least one `env` binding because `pmd` refuses a run without one;
  field-path refs (`pm://…/field`) are refused by `EntryId::parse_ref`
  everywhere, so 6.1 has to add that to the parser, not to the MCP layer.

## 2026-11-04 — Run timeout and per-stream output caps (TODO 4.5c)

- `RunRequest` gained `limits: {timeout_secs, max_output_bytes}` (defaults 600 s,
  256 KiB; checked 1..=600 and 1..=1 MiB on encode *and* decode; missing/null
  fields decode to the defaults, so older clients keep working without a
  protocol-version bump). `src/daemon/run.rs` clamps again before handing
  `runner::Limits` to the runner.
- `src/runner.rs`: `Limits {timeout, max_output_bytes}` plus `Limits::NONE`.
  The deadline starts at the spawn and is checked while relaying and while
  waiting for the leader; expiry aborts like a cancel (SIGTERM, then poll
  `leader_exited` for up to a 2 s grace, then SIGKILL the group) and returns a
  finished run instead of an error. `terminate` now polls with
  `CANCEL_POLL` rather than sleeping the whole grace.
- Output is capped in `emit_chunks` **after** redaction, per stream; the
  reader keeps draining and discarding until EOF, so a capped child cannot
  block on a full pipe. `RunFrame::Exit` now carries `RunFinished`
  (`exit` + `timed_out` + both truncated flags); decode treats absent flags as
  false, so an older peer's terminal frame still decodes.
- The local human run (`src/cli/run.rs`) passes `Limits::NONE`: it must not
  silently kill or truncate a command the human is watching. Only the daemon
  path, which serves agents, is bounded.
- Tests: protocol limits round-trip/defaults/bounds/non-numeric; exit-flag
  round-trip, legacy frames, non-boolean flags; runner timeout flags + polled
  grace (< 2.5 s for a 1 s deadline), grandchild killed, per-stream caps,
  post-redaction cut of a repeating canary, and 200 KB past the cap still
  drained (child exits 3, no SIGPIPE); daemon e2e that a capped run relays 16
  bytes with the flag and a 30 s child times out in ~1 s while `pmd` stays up.
  Moved response tests to `src/protocol/response/tests.rs` and the wire-shape
  test to `src/protocol/tests/wire.rs` to stay under 1,000 lines.
  `tests/run_backpressure.rs` now asks for the 1 MiB cap; its 4 MiB child is
  intentionally capped, and the test still proves paused-reader playback and
  that `lock` interrupts a stalled run.
- Docs: `MCP.md` (defaults, post-redaction cap, timed-out terminal frame) and
  `README.md` (daemon runs bounded, local human run not). `DECISIONS.md` records
  both lasting choices.
- Gate: fmt, clippy `-D warnings`, `cargo test` pass (`cargo audit` skipped:
  not installed).
- **Next iteration must know:** TODO 4.5d builds the MCP tool on top of these
  fields; `RunOutcome::Exited` now holds `RunFinished`, so read `.exit` before
  matching `RunExit`. A slow client that stops reading can delay the deadline
  because daemon emit blocks on the socket write (pre-existing backpressure
  edge, bounded by the daemon's write timeout); a timeout that fires after the
  leader already exited still reports `timed_out: true` with the real status.
- NEEDS HUMAN REVIEW: none.

## 2026-11-04 — Daemon env injection for several credentials (TODO 4.5b)

- `RunRequest.env` is now `Vec<EnvBinding>` (`{name, ref}`) plus
  `plain_env: Vec<(String, String)>` (`src/protocol/mod.rs`). `src/protocol/codec.rs`
  encodes only the array form; decode still accepts the old `env: "NAME"` +
  top-level `ref` as one binding, so an old client works while an old daemon
  refuses the array with `bad_request` (no protocol-version bump).
- Boundary validation: at least one and at most `MAX_ENV_BINDINGS = 32` secret
  bindings, names valid, refs canonical, unique names across `env` and
  `plain_env`, plain values <= 4096 bytes and NUL-free. `src/daemon/run.rs`
  repeats the name/deny-list/duplicate check and parses every reference before
  it decides anything. Every binding is authorized before the grant's use is
  marked, so a missing/out-of-scope second binding denies the whole run and
  spends nothing.
- `src/runner.rs` now takes `secret_env` and `plain_env`: child env is the
  inherited allowlist, then plain values, then secrets; the whole secret set
  goes to one `Redactor::new_many`. Plain values are deliberately not redacted.
  `src/cli/run.rs` still sends/serves exactly one `--env` binding.
- Tests: protocol round-trip/order, legacy decode, malformed shapes, empty /
  duplicate / >32 / oversized names (new `src/protocol/tests/run_env.rs`);
  runner multi-secret + plain env; daemon e2e two vars visible and both
  redacted, out-of-scope binding denied + audited + no use spent, duplicate
  names `bad_request` (new `tests/daemon_run_multi.rs`). Split both test files
  to keep every file under 1,000 lines.
- Gate: fmt, clippy `-D warnings`, `cargo test` pass (`cargo audit` skipped:
  not installed).
- **Next iteration must know:** a multi-binding run still writes **one** audit
  record and names its first reference; TODO 4.11 can widen the audit schema.
  `plain_env` is agent input and is never redacted. `MAX_ENV_BINDINGS = 32`
  is load-bearing for the redactor's marker proof (4.5a); do not raise it
  without revisiting `choose_marker_many`. TODO 4.5c (timeout/output caps) and
  4.5d (`run_with_credentials`) are next.

## 2026-11-04 — Multi-secret streaming redaction (TODO 4.5a)

- `RunRequest` carries one env name today, but `run_with_credentials` must
  inject a whole env block, so the redactor has to remove every injected
  value. 4.5 was split in `TODO.md` into 4.5a (this, pure redaction), 4.5b
  (protocol + daemon env set), 4.5c (timeout and output caps) and 4.5d (the
  MCP tool). This iteration did only 4.5a.
- `src/redact.rs`: `Redactor::new_many(&[&[u8]])` sorts values longest first
  (so a value containing another is removed whole), holds back `max_len - 1`
  bytes mid-stream, and at EOF scans the tail instead of emitting it, so a
  short value complete inside the tail is still replaced. Only a tail shorter
  than *every* value is emitted raw. Added `redactions()` and
  `redact_many(secrets, data)`; `Redactor::new` and `redact` are unchanged
  wrappers, so `src/runner.rs` and `tests/secret_copies.rs` did not move.
- `choose_marker_many` picks one marker for the set: the default when safe for
  every value, else a run of a byte at neither end of any value, one byte
  longer than the longest run of it. Fixes the old doc/behavior mismatch in
  `marker_is_safe`'s every-byte-value case (the old marker was `len + 1` bytes
  and needlessly contained the secret's bytes). Panics (fail closed) if no
  safe marker exists; impossible below 127 distinct endpoint bytes and the
  daemon will cap a run at 32 values.
- Fixed the false R.56 sentence in `finish`'s doc: the held tail is *not*
  always a proper prefix of the secret once a set has values of different
  lengths. New doc states the real argument.
- Tests: 7 new unit tests — every value at every two-way split and byte at a
  time; contained and overlapping values leave no complete occurrence; the
  window is sized by the longest value; a short value inside the held tail is
  replaced at EOF; one marker is safe for both colliding values incl. a
  streamed case; the count covers three substitutions; empty sets pass
  through. `debug_never_contains_the_value` now covers two values.
- Gate: fmt, clippy `-D warnings`, `cargo test` pass (`cargo audit` skipped:
  not installed).
- **Next iteration must know:** 4.5b starts by changing the `env` field shape
  (`src/protocol/mod.rs:345`, `src/protocol/codec.rs` encode/decode) — keep
  decoding the legacy string as a one-element list, and pass the *whole* value
  set to one `Redactor::new_many` in `src/runner.rs:305`. No other caller
  changes until then. Do not add a second redactor per value: overlapping
  markers would let one value's marker complete another value.

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

