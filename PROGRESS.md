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

## 2026-11-03 — Backpressure a paused run reader instead of a write timeout (TODO R.49)

- `src/daemon/run.rs`: `serve_run` makes the run socket non-blocking right
  after the cancel check, builds the `runner::Stop` there, and every frame it
  sends goes through `write_client_frame`. That writer retries on `WouldBlock`
  and waits in `poll(POLLOUT)` in `runner::CANCEL_POLL` (100 ms) slices,
  checking `stop.requested()` (cancel or closed peer) before each. On
  `POLLERR|POLLHUP|POLLNVAL` it returns `BrokenPipe`; other errors propagate,
  so `runner::execute` aborts and reaps the child as before.
- Backpressure is real, not buffering: a stalled reader stops the relay, the
  bounded (8) frame channel fills, the pipe readers block, and the child's
  stdout pipe fills. No new queue, no unbounded memory.
- Control connections (`ping`, `lock`, `grant_*`) keep the 5 s read/write
  timeout; only the run worker's stream is exempt. Without the timeout,
  `lock`'s join no longer waits for a socket write (one poll slice).
- Decision: no write timeout on a run stream. A timeout cannot distinguish
  "slow reader" from "dead client" (`client_closed` does, exactly) and
  truncating a run claims the child finished; `DECISIONS.md`'s framing bullet
  records the exception. `runner::CANCEL_POLL` and `Stop::requested` are now
  `pub(crate)` so the writer and relay cannot drift.
- Tests: new `tests/run_backpressure.rs`. A 4 MiB child, reader silent 7 s:
  all 4,194,304 bytes plus `Exit(Code(0))` (old code: 106,460 bytes, no Exit).
  A stalled run client: FIONREAD proves the client queue stopped growing, then
  `lock` must answer within 2 s and no `Exit(Code(0))` follows (old: 5.14 s).
  Both proved failing on stashed `src/`, passing on HEAD.
- Gate: fmt, clippy `-D warnings`, full `cargo test` pass; audit not installed.
- **Next iteration must know:** future frame writes on a run socket must use
  `write_client_frame`; a plain `write_all` on the non-blocking socket can drop
  a frame on `WouldBlock`. A client that stalls but never disconnects now holds
  the child blocked for as long as it would run anyway; `lock`/SIGTERM still
  kill it. R.50 is next.

## 2026-11-03 — Refuse hidden characters in new service names and usernames, escape stored ones (TODO R.48)

- `src/store.rs`: `validate_service`/`validate_username` now refuse the whole
  table in `src/text.rs` (`is_hidden_or_reordering`: controls, bidi,
  zero-width/format, line separators, VS). The error names the classes and
  does not echo the value. `Credential::new`/`--rename`/`--username` go
  through it, so `pm add $'git\u{202e}moc.buh' alice` exits 2 before any
  password prompt or vault access.
- `Credential::from_decoded` is the reader's constructor and keeps the old
  control-only rule, because the payload is authenticated: a name in it was
  written by a passmgr build, and a vault written before this change may hold
  a bidi name. Refusing it on read would lock the human out of every
  credential. `encode` does not re-validate stored text, so such a vault can
  still be saved.
- Every human-facing line escapes a stored name: `list`, `get`, `show`, the
  add/edit success lines and the password prompt (`src/cli/commands.rs`), via
  `escape_hidden`. `--json` keeps the stored bytes (data channel, not a
  terminal); the grant approval summary already escaped (`ScopeEntry::describe`).
- `HIDDEN_FORBIDDEN_CLASSES` moved to `src/text.rs`; `grant::LABEL_FORBIDDEN_CLASSES`
  is now an alias, so the two validators cannot drift (TODO R.18 docs pin
  still passes).
- Tests: store unit tests reject U+202E/U+200B/U+FE0F/U+2028/NUL/BEL in both
  fields and in `Credential::new` (and assert the error does not echo the
  value), accept other scripts/accents/combining marks/emoji; a hand-built v4
  payload with a bidi service and a zero-width username decodes, re-encodes as
  v5 and round-trips unchanged; a v4 payload with C0/C1 is still malformed;
  `tests/cli_args_escape.rs` proves `add` exits 2 with no prompt/no vault and
  that `list`/`get`/`show` on a legacy v4 container print `\u{202e}`/`\u{200b}`
  with no raw hidden character.
- Fixed one existing test rather than weakening it: `cli::grant::tests::
  credential_names_are_escaped_in_the_summary` used `Credential::new` to build
  a bidi name, which is now a hard error. It now builds the `ScopePreview`
  literals directly; the rendering under test is unchanged, and the
  "such a name can exist" premise moved to the legacy-payload tests.
- Gate: fmt, clippy `-D warnings`, full `cargo test` all pass.
- **Next iteration must know:** TODO R.55's text (and the bullet at
  `TODO.md:1189`) still describes R.48 as open; fix it when doing R.55.
  `SECURITY.md`'s terminal-safety claim should say *stored* names are escaped
  and new ones are refused. MCP tool output (when built) must escape stored
  names too -- MCP is not a terminal, but a host may render it as one.

## 2026-11-03 — Review of f4c7796..c83c9b3 (4 findings: R.60–R.63)

- Findings by category: secrets/exposure 0, authorization 0, unsafe input 0,
  crypto 0, drift 0 standalone (R.61 also corrects an overclaim in the R.46
  doc comment and progress entry) — but 1 agent-facing exit-contract hole
  (R.60: a socket `BrokenPipe` exits 0, a false success for `run` and
  `grant revoke`) and 3 tests that do not prove what they claim (R.61 headroom
  test restates two constants, R.62 R.45 clock test has a 3-second startup
  budget, R.63 the documented-example guard counts prose). 0 unconfirmed.
- Scope: `git diff f4c7796..c83c9b3` in full, plus the surrounding code for
  every touched function, `PROMPT.md`, `DECISIONS.md`, `MCP.md`, `FORMAT.md`,
  `SECURITY.md`, `README.md`, `--help`, `TODO.md`/`TODO-done.md` (numbering
  continues at R.60), and the five new/changed tests run individually.
- Looked at and judged fine (do not redo): the R.44 watermark — checked before
  authorize, recorded only after the save succeeds, revocation exempt so the
  kill switch survives a rollback, marks kept for pruned grants, and no
  non-constant-time compare; `Grant::status` ordering means only revoked or
  expired grants are prunable (R.42), and the 7-day retention is applied at the
  same instant as the create re-check; R.46's `byte_len` growth accounting
  (8 + 8) matches `grant_byte_len` exactly today, and the daemon was already
  the writer of both post-creation fields; R.45's clock read really is after
  `open_with_key_for_update` on every retry; R.47's 141 diagnostic contains no
  secret, `ResponseError` has no free-form variant, and dropping the run socket
  makes the daemon SIGKILL the child's process group; R.43's `gh` example is a
  genuine `PROGRAM_RUNNERS` entry and all three documented examples carry
  `--allow-interpreter`; README/FORMAT/SECURITY/DECISIONS/`--help` agree with
  the code on payload sizes, prune retention and exit 141; `pm grant revoke`
  never writes the vault from the CLI, so every revocation raises the
  watermark; every refusal goes through `reject()`
  (`src/daemon.rs:810-813`), which can only send the fixed `ResponseError`
  enum, so no diagnostic string reaches an agent; `Ping` carries no
  credentials.
- Gate at review time: `cargo test --test docs` (21 passed), `--lib
  grant_growth_headroom`, `--test daemon_run
  a_run_is_denied_when_its_grant_expires_during_the_lock_wait` (3.94 s),
  `--test run a_closed_output_pipe_cancels_the_run_and_exits_nonzero` (0.76 s),
  `--test grant_cli grant_create_prunes_dead_grants_from_a_full_vault` (1.36 s)
  — all green.
- Fix in that order: R.60 (agent-visible false success), then R.61–R.63. No
  source files were changed by this review.

## 2026-11-03 — `run` reports a closed output pipe instead of success (TODO R.47)

- `src/cli/run.rs`: the relay callback now records a `BrokenPipe` in a
  `Cell<bool>` (`relay()`) instead of letting it fall through to the generic
  `main` mapping. On a closed stdout/stderr pipe, `run` writes one diagnostic
  to stderr and returns `EXIT_OUTPUT_CLOSED` (141). Only the relayed-output
  path uses the flag; a socket `BrokenPipe` keeps the old mapping.
- `src/error.rs`: new `EXIT_OUTPUT_CLOSED: u8 = 141` — the shell's SIGPIPE
  status (128 + 13). Why 141 and not the child's status: once relaying fails,
  the child's status is unknowable, and 0 would tell a `pipefail` pipeline
  that a possibly failed command succeeded. Dropping the connection makes the
  daemon kill the child (R.37), so the run is cancelled too.
- Docs: `src/cli/help.rs` run section and exit-code list, regenerated
  `tests/fixtures/help.txt` from the binary, `README.md` run text and exit
  table, `DECISIONS.md` (broken-pipe rule + exit-code contract).
- Test: `a_closed_output_pipe_cancels_the_run_and_exits_nonzero` in
  `tests/run.rs`. A real `passmgr run` gets bytes until the redactor emits,
  the test drops its end of the pipe, and the child (which waits on a flag
  file) prints again. Asserts 141, the stderr explanation, no canary, and —
  by polling `kill(pid, 0)` — that the daemon killed the child. Proved it
  fails on the old code (`ExitStatus(0)`), passes with it.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` pass (audit not installed).
- **Next iteration must know:** the redactor always holds back
  `secret.len() - 1` bytes (`src/redact.rs`), *independent of content*, as a
  timing-oracle defense. Any test that waits for relayed output before the
  child exits must pad the first write past that window (the new test prints
  a second padding line), or it deadlocks. Also: `run` deliberately does not
  pass through the child's exit code when the caller's pipe is gone.
  `tests/run.rs` is now 972 lines: split it before adding more tests.

## 2026-11-03 — Keep room for grant growth above the payload cap (TODO R.46)

- `src/store/payload.rs`: `byte_len` now returns `PayloadSize { encoded,
  content }`. The 10 MiB `MAX_PLAINTEXT_BYTES` check applies to `content`, the
  encoded size minus the `revoked_at`/`last_used` fields (8 bytes each) that
  appear only after a grant is created; `encoded` sizes the buffer and keeps
  the `debug_assert_eq!` exact. `decode` accepts `MAX_PAYLOAD_BYTES`.
- `src/crypto.rs`: new `MAX_PLAINTEXT_GROWTH_BYTES` (16 bytes x 1,024 grants
  = 16 KiB) and `MAX_PAYLOAD_BYTES`; `check_plaintext_len` and the decrypt
  bound use the latter. `src/store.rs` re-exports `GRANT_GROWTH_BYTES`.
- Why: a vault written at the content cap had no bytes left for a revocation,
  so `grant revoke --all` / `run` answered `internal` on the kill switch. I
  chose "exempt the bounded post-creation growth from the cap" over only
  reserving space for *new* grants: the reserve keeps future vaults from
  landing at the wall but still cannot revoke a vault an older build already
  wrote at the cap. This form makes both states work. `FORMAT.md` and a
  `DECISIONS.md` bullet document the content cap vs. the 16 KiB headroom.
- Tests: `a_revocation_fits_a_vault_written_at_the_payload_cap` in
  `src/daemon/tests.rs` fills credentials (measured with the real codec, not
  recomputed sizes) until `store::encode` emits exactly 10,485,760 bytes,
  encrypts with cheap KDF params, then requires `revoke_grants(...)` to return
  `Ok(1)` and the reopened vault to hold the revocation. Proved it fails on
  the old rule (temporary `size.encoded > MAX` check): it answered
  `Internal`. `grant_growth_headroom_covers_the_whole_grant_cap` in
  `src/store/tests.rs` is a compile-time assert tying 16 x `MAX_GRANTS` to
  the headroom. The new test takes ~6 s (debug AES-GCM over 10 MiB several
  times), hence its cheap KDF.
- Gate: fmt, clippy -D warnings, cargo test (all suites) pass.
- **Next iteration must know:** the cap is now "content", so error text for a
  too-large vault reports the content size, which can be a few bytes below the
  encoded size; do not "fix" that by reporting `encoded`. R.47 is next.

## 2026-11-03 — Authorize a run with the clock read after the lock (TODO R.45)

- `src/daemon/run.rs`: `record_use` no longer takes a `now`; it reads
  `unix_now()` immediately after `Vault::open_with_key_for_update` (and again
  on every `USE_RECORD_ATTEMPTS` retry) and uses that value for
  `check_grant_for_run`, `grant.authorizes` and `mark_used`. The clock read in
  `serve_run` before `record_use` is removed.
- Why: the vault write lock can block for 30 s per attempt (3 attempts on a
  failed save), so a time read before the wait authorized grants that had
  already expired. Expiry is now decided against the vault the use is recorded
  in. Added a DECISIONS bullet under "Daemon and protocol".
- Tests: new `a_run_is_denied_when_its_grant_expires_during_the_lock_wait` in
  `tests/daemon_run.rs` holds `vault.dat.lock` with `flock` before sending a
  run on a grant expiring in 3 s, waits until the daemon's `chmod` of the lock
  is observable (so the old code had read its clock), sleeps until one whole
  second past expiry, releases the lock and requires
  `RunFrame::Error(ResponseError::Denied)` and no secret bytes. A guard
  assertion fails the test if the daemon reached the lock after expiry, so it
  cannot pass vacuously. Proved it fails on the old shape (temporary
  `stale = unix_now()` before the open): it answered `Exit(Code(0))`.
- Fixture: `tests/support/mod.rs` gained `with_grant_expiring_in(seconds)` and
  a `grant_expires_at` field; `with_secret_and_uses` now delegates to a shared
  `build(secret, max_uses, expires_in)` with the old 3600 s default. The
  `wait_until_the_lock_is_open` helper moved from inside the R.38 symlink test
  to module scope in `tests/daemon_run.rs` so both tests use it.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` skipped (not installed).
- **Next iteration must know:** R.46 is next. `record_use`'s signature lost its
  `now` argument; the only clock read for a run now happens under the vault
  lock. The new test adds ~3-4 s to `daemon_run`. `revoke_grants` still reads
  `now` before its lock (it is used only for the write timestamp, not for an
  expiry decision), so it is untouched.

## 2026-11-03 — Refuse a rolled-back vault while pmd serves (TODO R.44)

- New `src/daemon/watermark.rs`: `GrantWatermarks` keeps, per grant id and
  only for this process, the furthest `uses` and whether a revocation was
  seen. `check` runs under the vault write lock before authorization and
  refuses a grant whose `uses` fell or whose revocation cleared; `record`
  only raises the mark and runs only after a save that succeeded.
- `record_use` answers `denied` on a regressed vault before marking or
  spawning. `revoke_grants` is deliberately exempt from the check (a rollback
  must not disable the kill switch) and records after its save.
- Tests: 7 unit tests in `watermark.rs`; two e2e tests in
  `tests/daemon_run.rs` (a spent `max_uses` and a cleared revocation both end
  in `Denied` after a snapshot is restored, and revoking the rolled-back vault
  still works); `tests/docs.rs` pins the new SECURITY limit.
- Decision: in-memory, not persisted — a marker file is rollbackable like the
  vault, so it would add an artifact without a boundary. The restart residual
  is SECURITY.md limit 7 ("Out of scope" is now 8); FORMAT.md notes the file
  is not rollback-evident, and DECISIONS.md records the choice.
- Gate: fmt, clippy `-D warnings` and the full test suite pass. `cargo audit`
  skipped (not installed).
- **Next iteration must know:** R.45 is next. `handle_connection` and
  `revoke_grants` now take `&GrantWatermarks`; `exchange_frame` in
  `src/daemon/tests.rs` creates a fresh one per call. The mark lives per
  daemon process, so a restarted `pmd` accepts a rolled-back fixture (not
  pinned by a test, on purpose). Restoring a legitimate backup needs
  `pm lock`/restart or runs answer `denied` until one.

## 2026-11-03 — Make every documented grant example runnable (TODO R.43)

- `README.md`'s quickstart under "Use a credential without reading it" allowed
  `/usr/bin/gh` without `--allow-interpreter`, so the first command a reader
  copied exited 5. Kept `gh` (the example is `gh auth status`) and added the
  flag plus a sentence explaining that `gh` can run another program and that
  `grant create` refuses it otherwise, linking to "Create a grant".
- New `tests/docs.rs` helpers `fenced_blocks`, `logical_lines` (joins shell
  `\` continuations) and `check_grant_examples`; the test
  `every_documented_grant_example_flags_a_program_runner` checks every fenced
  README block and `--help`'s Examples section, using the real
  `passmgr::grant::is_program_runner` on each `--command`. It also asserts both
  README grant examples and the `--help` one still exist, so deleting an
  example fails instead of making the check vacuous.
- Proved the test fails on the old quickstart (temporarily removed the flag,
  saw the expected assertion, restored) and passes at HEAD.
- No behavior change, so no DECISIONS entry. The README's later "Create a
  grant" example and `--help` were already correct since R.25.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` all pass. `cargo audit` skipped (not installed).
- **Next iteration must know:** the new test treats `--command=PATH` and
  `--command PATH` alike but does not parse quoted paths with spaces; no
  current example has one. R.44 is next.

## 2026-11-03 — Prune dead grants so a vault never fills up (TODO R.42)

- `pm grant create` now drops grants that are dead (revoked, or expired) and
  died at least 7 days before the write, in the same write that adds the new
  grant: new `src/grant/prune.rs` (`DEAD_GRANT_RETENTION_SECS`, pure
  `prune_dead`), `Vault::prune_dead_grants`, and `Vault::check_grant_writable`
  now takes `now` and prunes its candidate copy so the pre-approval check asks
  exactly what the write will do. Active and exhausted-but-unexpired grants
  are never dropped; the daemon's revoke/use writes still never prune.
- Chose prune-on-write over a `pm grant purge` subcommand: no new surface for
  an agent to reach, no extra approval, and the vault heals itself. Retention
  keeps `grant list`/`show` able to explain recent denials.
- Tests: pure prune table (kept/dropped at the window boundary, future
  deadlines, revoked/expired/exhausted/active); vault-level full-of-dead-grants
  creation round trip plus "keeps live and recently dead"; e2e pty
  `grant_create_prunes_dead_grants_from_a_full_vault` (proved failing without
  the CLI prune line). Fixture gained `with_dead_grants` and `seeded(count,
  created)`.
- Docs: FORMAT.md (the 1,024 limit counts dead rows; pruning changes no byte
  layout) and DECISIONS.md (the retention rule and why the daemon does not
  prune).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` all pass. `cargo audit` skipped (not installed).
- **Next iteration must know:** pruning only runs in `pm grant create`. A vault
  that is full of *recently* dead grants still refuses new ones (deliberate:
  the window is bounded by `DEAD_GRANT_RETENTION_SECS`), and `pm grant create`
  reports it as "too many grants". If a `pm grant purge` is ever wanted, it
  should require the master password at a TTY and go through the daemon like
  revoke. No other writer prunes, so `pm run` cannot silently drop history.

