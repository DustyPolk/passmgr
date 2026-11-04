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

## 2026-11-03 — Wipe the read chunk before a rejected push returns (TODO R.66)

- `src/daemon/run.rs`: `read_request` is now a wrapper over
  `read_request_with_chunk(stream, &mut chunk)`; every successful `read` goes
  through `push_chunk`, which wipes the chunk *before* propagating `push`'s
  error. The old `decoder.push(&chunk[..read])?` returned first, leaving the
  raw frame — session-token hex, and the grant hex for `run` — in the chunk.
- Passing the chunk in is the test seam: a unit test can observe the wipe after
  the call without an allocator scan (a stack array is invisible to
  `tests/secret_copies.rs`), which is the pattern R.67 needs.
- `BufferFull` is unreachable through the loop: `next_request` runs at the top
  of every iteration, so the buffer never passes 4 + 64 KiB + one 4 KiB chunk,
  far under `MAX_BUFFERED_BYTES` (131080). The item's ">128 KiB of
  unterminated bytes" case cannot happen; a second test covers `BufferFull`
  through `push_chunk` directly. Both tests (`src/daemon/run.rs`) assert the
  error and an all-zero chunk and fail when the wipe is moved back after `?`.
- Gate exposed a pre-existing flake in `tests/secret_copies.rs`: the four
  wire-codec tests shared one token needle and one counter, and the scan sees
  *every* thread's frees while a window is open, so a token-bearing buffer one
  test freed outside its window was counted against whichever test's window
  was open (5/12 `cargo test --test secret_copies` failures at HEAD, 8 hits).
  Each wire test now holds a new `WIRE_SERIAL` mutex for its whole body; the
  module doc says why. 20/20 green after.
- `DECISIONS.md` and `SECURITY.md` now say the read chunk is wiped on the
  rejected path too.
- Gate: fmt, clippy, full `cargo test` green three times; `cargo audit` skipped.
- Iteration 112 hit the 45 min timeout while running the gate a third time;
  the work was recovered from the loop's stash, re-gated green and committed
  by hand. Running the full gate once is enough.
- **Next iteration must know:** R.67 is the harder half: the reader's
  raw-output buffer (`src/runner.rs:528`) is still a stack array, invisible to
  the scan, and its run canary asserts `<= baseline` (3 vs 3). Copy the
  `push_chunk` pattern (buffer as a parameter, or heap-own it) and assert the
  wipe on every path. Any new `tests/secret_copies.rs` test whose buffers carry
  another test's needle needs the same serialization.

## 2026-11-03 — Wipe the parsed envelope on a rejected request (TODO R.65)

- `src/protocol/codec.rs`: `decode_body` now holds the `serde_json::Value` in
  a `WipingJson` guard whose `Drop` calls `zeroize_json`. Before, the wipe ran
  only after the request match, so the version check, a missing/invalid
  `token`, a malformed `run`/`prove`/`grant_create`/`grant_revoke`, and the
  unknown-type arm all freed the tree with the session-token hex (and the
  grant hex for `run`) still in it. A guard, not a trailing call, so a future
  `?` cannot reopen the hole.
- No behavior change for valid requests; `decode` and `FrameDecoder::
  next_request` both go through `decode_body`.
- Tests: `tests/secret_copies.rs::a_rejected_request_leaves_no_copy_of_the_
  token_in_freed_memory` decodes an unknown type, a `grant_create` missing
  `label`, and a `version` 3 envelope under the freed-block scan; 3 hits
  before the fix, 0 after. The existing valid-path wire tests still pass.
- `DECISIONS.md` and `SECURITY.md` now say the wipe covers every decode path,
  including a rejection.
- Gate: fmt, clippy, full test suite pass.
- **Next iteration must know:** R.66 is the remaining half of the same review
  (`src/daemon/run.rs:397-401` wipes its read chunk only after `push`'s `?`),
  then R.67 (the reader-thread stack wipe has no test). Both are independent
  of this change: R.66 is a stack buffer, so the heap-scanning allocator in
  `tests/secret_copies.rs` will not see it; that test needs a different seam.

## 2026-11-03 — Wipe the wire codec's growing buffers (TODO R.64)

- `src/protocol/codec.rs`: `FrameDecoder::push` now reserves through
  `grow_for`/`grow_wiped`, which allocate a fresh buffer, copy, zeroize the
  old one and only then drop it. `Vec`'s own growth freed the previous
  allocation with the token hex still in it.
- The same leak scan found two *encoder* copies, fixed in the same item
  because the new tests must assert 0 hits including encode:
  `serde_json::to_vec` grew its writer after the grant hex was written, and
  `json!` deep-copied the request `Value` through `to_value`, leaving a second
  tree (with the grant hex) to be dropped unwiped. `encode_body` now moves the
  request into the envelope and serializes through `BodyWriter`, which grows
  with `grow_wiped` and wipes on drop.
- Correction to the review finding: a 20 KiB frame pushed in 4 KiB chunks
  does *not* leak via `push`. The envelope puts `request` first, so the token
  hex (and, for `run`, the grant hex) is in the last ~250 bytes of the body;
  the final chunk brings it in and no later growth happens. The push leak is
  real but only when the last chunk crosses the 64 KiB cap, i.e. a body of
  65533..65536 bytes. The review's 3 hits were the encoder's copies.
- Tests (`tests/secret_copies.rs`): `a_frame_at_the_size_cap_leaves_no_copy_
  of_the_token_in_freed_memory` (sizes the body to exactly
  `MAX_MESSAGE_BYTES` by measuring one encoding; 3 hits old, 0 new) and
  `encoding_a_large_run_request_leaves_no_copy_of_the_token_in_freed_memory`
  (16.7 KiB body chunk-pushed; 2 hits old, 0 new). Both use the session and
  grant hex as needles and run under the freed-block scan.
- Gate: fmt, clippy and the full test suite pass.
- **Next iteration must know:** R.65 (`decode_body` error paths skip
  `zeroize_json`) and R.66 (`read_request` `?` before the chunk wipe) are
  still open and independent of this change. If you add a test that encodes
  inside a scan window, remember the probe's own unwiped frees on the *old*
  code inflate the count; always confirm the count on the old code with the
  encode outside the window before attributing hits to `push`.

## 2026-11-03 — Review of c83c9b3..47c64ac

- 4 findings: secret exposure / residue 3 (R.64, R.65, R.66), tests 1
  (R.67). Authorization, unsafe input handling, crypto misuse, drift and
  maintainability: 0 new items.
- R.64: `src/protocol/codec.rs:118` `FrameDecoder::push` grows with
  `extend_from_slice`, so every request over `READ_CHUNK` (4 KiB) frees a
  buffer fronted by the token hex. Reproduced with a scanning allocator: 3
  hits for a 20 KiB frame pushed in 4 KiB chunks, 0 for the single-push
  `Ping` the existing test uses.
- R.65: `decode_body` (`src/protocol/codec.rs:306`) wipes the parsed tree only
  at `:376`; every `?` in between (version mismatch, missing token, unknown
  `type` at `:369`, malformed `run`/`prove`/`grant_create`) frees the tree
  with the token hex intact. Reproduced: 1 hit for an unknown request type.
- R.66: `src/daemon/run.rs:397` propagates `push` errors with `?` before
  `chunk[..read].zeroize()` at `:401`.
- R.67: the `spawn_reader` stack wipe (`src/runner.rs:528-542`) is invisible
  to the heap-scanning allocator, so `tests/secret_copies.rs` would stay
  green if it were deleted; the run canary also only asserts `<= baseline`
  (measured 3 vs 3).
- Looked at and judged fine (no need to redo): R.48's hidden-character
  refusal (`src/store.rs:437-473`, `src/text.rs:46-48`), including the
  legacy-read rule and the `--rename`/`--username` validation at
  `src/cli/commands.rs:137-142`; terminal escaping after the re-export
  (`src/grant.rs:963`, `escape_hidden` in `src/cli/grant.rs:276,291` and
  `src/cli/grant_summary.rs:52-62,103`); the R.48 tests in
  `src/store/tests.rs` and `src/grant/tests.rs`; R.49's non-blocking `write_client_frame` (`src/daemon/run.rs:188-250`),
  `client_closed` (`:264-278`) and `tests/run_backpressure.rs`; R.50a's
  `Zeroizing`-before-size-check in `src/crypto.rs:407-448` and its
  allocator test; R.50c's `Zeroizing` encoder, `next_frame` tail wipe and
  `Drop`; R.51's doc pins (`tests/docs.rs` exit table, README/FORMAT/MCP
  wording). MCP.md carries no claim about the old 5 s write timeout.
- R.55 (open) is the only stale doc left in this area: after R.48 landed,
  `SECURITY.md:52-57` is accurate except "validators escape the value they
  reject" — `reject_hidden_identity` deliberately names only the character
  class and never echoes the value. Close or reword R.55 rather than opening
  a duplicate.
- Environment note: the first `cargo test --bin passmgr cli::grant::tests`
  after checkout failed the two tests recorded by the iteration-108 rollback
  note below; after `touch src/text.rs` forced a rebuild both pass. Stale
  `target/` artifacts from the rolled-back branch, not a source bug. Full
  `cargo test`, `cargo fmt --check` and `cargo clippy --all-targets -- -D
  warnings` are green at 47c64ac.

## 2026-11-03 — loop note: gate failed (iteration 108)

- Commits from this review iteration failed the gate and were rolled back.
- The work is kept on branch failed/iter-108-20261103-204341; you may cherry-pick from it and fix it.
- gate: `cli::grant::tests::a_token_path_with_hidden_characters_is_rendered_as_text --- FAILED`
- gate: `cli::grant::tests::credential_names_are_escaped_in_the_summary --- FAILED`
- gate: `thread 'cli::grant::tests::a_token_path_with_hidden_characters_is_rendered_as_text' (696774) panicked at src/cli/grant/tests.rs:45:5:`
- gate: `thread 'cli::grant::tests::credential_names_are_escaped_in_the_summary' (696778) panicked at src/cli/grant/tests.rs:274:5:`
- gate: `test result: FAILED. 54 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s`
- gate: `error: test failed, to rerun pass `--bin passmgr``

## 2026-11-03 — Pin the docs that had drifted since grants landed (TODO R.51)

- Corrected every stale claim in the item: the daemon's vault writes are
  `grant_revoke` (`revoked_at`) and `run` (`uses`/`last_used`), in
  `DECISIONS.md`, the protocol module doc and the `daemon.rs` comment;
  `FORMAT.md` names `pmd` as a key-reuse writer; `src/client.rs` no longer
  says grants are TODO 3.1 or that the session token can use secrets;
  `protocol::mod` lists `grant_revoke` (with JSON), its run-stream error list
  names `denied`/`internal`/`busy` and says authentication failures are
  one-shot responses; `ResponseError::Busy` drops the removed nonce-pool case.
- `help.rs` and `README.md`: the password exceptions now include `lock`,
  `run` and `grant revoke`; `--db` is refused by both `run` and
  `grant revoke`; `run` with an unknown ref exits 3 (5 is only a grant
  refusal). README exit rows 3 and 5 now list unknown ref/grant id and every
  refusal cause. TODO.md's Done notes for 3.5/3.6 were corrected too, since
  they carried the same wrong claims.
- Added `protocol::REQUEST_WIRE_NAMES` and an exhaustive
  `Request::wire_name` as the single published list. Unit test
  `request_wire_names_match_the_encoder_for_every_variant` reads the emitted
  `"type"` back out, so an encoder rename cannot pass by editing only
  `wire_name`. `tests/docs.rs` derives the SECURITY session-token list from it
  (minus `run`), checks the module doc names every entry, and parses the README
  exit table against `Error::exit_code` (exact code set, every variant, and the
  rows R.51 found incomplete). `tests/fixtures/help.txt` was regenerated from
  the new binary; the golden test still pins every byte of `--help`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, full
  `cargo test` all pass; `cargo audit` unavailable (skipped).
- **Next iteration must know:** the new docs tests read source text
  (`include_str!` of `src/protocol/mod.rs`) and the raw README table, so
  rewording the module doc must keep each wire name present, and a new
  `Request` variant needs its name in `REQUEST_WIRE_NAMES`, `wire_name` and
  the module doc before the docs test passes. No behavior changed.

## 2026-11-03 — Wipe every buffer the wire codec copies a request into (TODO R.50c)

- `src/protocol/codec.rs`: `encode`/`encode_body` return `Zeroizing<Vec<u8>>`.
  A new `zeroize_json` overwrites every `String` in the encoder's `Value`
  envelope and in the decoder's parsed tree before either is freed; object keys
  are deliberately skipped (protocol field names, never a secret, and
  `serde_json::Map` exposes no mutable access). The decoded `run.grant` hex
  lives in a `Zeroizing<String>`.
- `FrameDecoder`: `next_frame` copies the body out, then moves any following
  frame down with `copy_within` and zeroizes the stale tail before truncating.
  `Vec::drain` left the taken frame's bytes in the allocation whenever nothing
  followed it — the common single-request-per-connection case. `Drop` now
  zeroizes the buffer. A `#[cfg(test)] written` high-water mark and
  `written_bytes()` accessor let a test read the region past `len` without UB.
- `src/daemon/run.rs::read_request`: the reused 4 KiB stack chunk is wiped
  after each `push`; it held the raw request including the grant-token hex.
- `src/client.rs` needed no edit: it only ever used the returned frame.
- Tests: `src/protocol/tests.rs` adds `a_taken_frame_is_wiped_from_the_decoder_buffer`
  and `taking_a_frame_zeroes_the_stale_tail_behind_the_next_one` (both fail with
  `drain`), and `tests/secret_copies.rs` adds
  `the_wire_codec_leaves_no_copy_of_the_token_in_freed_memory`, which runs
  encode -> push -> next_request under the freed-block allocator scan and needs
  0 hits (it reports 1 when the envelope wipe is removed).
- Docs: `DECISIONS.md` (Daemon and protocol) and `SECURITY.md` limit 6 now name
  what is wiped and the two residues that are not ours: kernel socket buffers,
  and JSON object keys.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, full
  `cargo test` all pass; `cargo audit` unavailable (skipped).
- **Next iteration must know:** the allocator scan looks for the *hex* of
  `WIRE_TOKEN_BYTES` (`r50c-wire-token-canary-000000001`) via a `OnceLock`
  needle set before the window opens; do not reuse that byte string. `R.50c`
  closes the R.50 split — R.51 (docs drift) is now the first open item.

## 2026-11-03 — Wipe the passmgr-owned copies of an injected value (TODO R.50b)

- `src/redact.rs`: `Redactor::push` now grows the overlap window through a new
  private `reserve_pending`, which allocates a bigger `Vec`, copies, wipes the
  old buffer and only then drops it. `Vec::extend_from_slice` used to `realloc`
  the window, freeing a block that still held up to `secret.len() - 1` bytes of
  the value. The window can never hold a complete occurrence, so the worst case
  was a 24-of-25-byte fragment.
- `src/runner.rs`: the reader thread wipes `buffer[..read]` right after the
  redactor has consumed it. Corrected the comment at `command.env`: std's own
  copies (the `OsString` in `Command`'s env map and the `NAME=value` string for
  `execve`) are freed unwiped after the spawn and cannot be owned or cleared
  through `Command`'s API.
- Decision: did **not** port the spawn to `posix_spawn` (the TODO's first
  option). It would replace `Command`/`Child`, the `pre_exec` `setpgid`, the
  pipe setup and the waitid/reap/process-group-kill sequence the run's stop
  paths rely on — far past one iteration, and a mistake there loses the
  group-kill guarantee. Took the TODO's documented alternative: `SECURITY.md`
  limit 6 and `DECISIONS.md` now name the residue, and the code comment no
  longer claims otherwise.
- Tests (`tests/secret_copies.rs`, its own integration binary with a
  pass-through `#[global_allocator]` that scans every freed block and
  `realloc`ated block for a canary, serialized behind a mutex):
  `the_redactor_leaves_no_copy_of_the_value_in_freed_memory` drives growth while
  the window holds the value's longest holdable fragment — 4 freed blocks
  before the fix, 0 after. `a_run_leaves_no_more_copies_than_the_spawn_itself`
  spawns `/bin/echo <canary>` through `runner::execute` and requires no more
  secret-bearing freed blocks than a bare `std::process::Command` with the same
  env and `pre_exec` hook leaves (3 vs 3); an extra passmgr copy fails it (I saw
  `4` from a copy in the test itself while writing it).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, full
  `cargo test` all pass; `cargo audit` unavailable (skipped).
- **Next iteration must know:** the reader's stack buffer wipe is *not*
  observable by the allocator scan (thread stacks are not heap), so it is
  covered by review only — do not delete it believing nothing tests it. The
  probe for the redactor test is `REDACT_CANARY[..24]`, not the whole canary:
  the window by design holds back `len - 1` bytes, so a full-match probe would
  never fire. R.50c (grant-token buffers in `src/protocol/codec.rs` and
  `src/client.rs`, and `FrameDecoder::drain`) is the next open item and the same
  fix-or-document trade-off applies, but these buffers cross the socket and
  `pmd` is long-lived, so prefer wiping.

## 2026-11-03 — Zeroize an oversized decrypted payload before refusing it (TODO R.50a)

- Split R.50 into three ordered items because it mixed three independent
  buffer-ownership fixes: **R.50a** oversized `decrypt_with_key` plaintext
  (done here), **R.50b** child-environment copies in `src/runner.rs`, **R.50c**
  grant-token buffers in `src/protocol/codec.rs`/`src/client.rs`. R.50b is now
  the first open item.
- `src/crypto.rs` `decrypt_with_key`: the decrypted `Vec` is wrapped in
  `Zeroizing` immediately after authentication, *before* the
  `MAX_PAYLOAD_BYTES` check. An oversized container is still refused with
  `MalformedVault`, but the plaintext is now wiped as it drops instead of
  being left in a freed allocation.
- Test (`crypto::tests::an_oversized_decrypted_plaintext_is_refused_and_zeroized`):
  a test-only `#[global_allocator]` forwards to `System` and compares the
  first 16 bytes of every freed block with a canary. The plaintext is built
  with the canary at offset 0 and `seal` is used directly (the only way past
  the writer's size cap); the caller's own copy is zeroized first. Verified
  the test fails on the old code with `left: 1, right: 0` and passes on HEAD.
  No production allocator or global state was added outside `#[cfg(test)]`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` all pass; `cargo audit` unavailable (skipped).
- **Next iteration must know:** the allocator watch lives in `mod tests` in
  `src/crypto.rs` and only counts the 16-byte canary `r50a-canary-0001`; any
  future test that reuses that prefix will get a false positive. R.50b is the
  harder one (env copies, reader stack buffer, `Redactor.pending`
  reallocations) and may itself need splitting; read its TODO text before
  starting.

