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

