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

## 2026-11-03 — Review of a14dc54..f4c7796

- Findings by category: tests that don't prove what they claim 1 (R.57), drift
  2 (R.58, R.59), secret exposure 0, authorization 0, unsafe input 0, crypto
  misuse 0, maintainability 0. Nothing here is a broken build: at HEAD
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the full
  `cargo test` are green.
- R.57 was decided by experiment, not by reading. On a scratch copy of the
  tree with `src/cli/grant.rs:256` reverted to `Vault::open_with_key` +
  `lock_for_update()` (the pre-R.39 shape the test exists to catch),
  `cargo test --test grant_cli keeps_a_concurrent_vault_write` passed 3/3: the
  300 ms sleep puts the concurrent save *before* the CLI's read, so the
  compare-and-lock never sees a change. The two daemon-side R.39 tests do fail
  on the same revert (`src/daemon/tests.rs:558`, `tests/daemon_concurrency.rs:293`),
  which is why only the CLI half is filed.
- Looked at and judged fine — do not redo:
  - `src/redact.rs` R.36a: `marker_is_safe` rejects all four leak shapes
    (marker containing the secret, secret containing the marker, marker
    starting with a proper suffix of the secret, secret starting with a proper
    suffix of the marker); the absent-byte marker is safe because the secret
    holds none of its bytes, and the all-256-bytes fallback
    `vec![byte; secret.len() + 1]` with `byte != secret[0] && byte != secret[last]`
    is safe by construction. The test re-derives four real old leaks over the
    whole buffer and byte-at-a-time.
  - `src/runner.rs` R.37/R.38: `Stop`/`client_gone` short-circuits before the
    spawn; `leader_exited` (`waitid(P_PID, .., WEXITED|WNOHANG|WNOWAIT)`) plus
    "SIGKILL the group while the zombie still pins the pgid, then reap" is
    ordered correctly; `terminate`/`signal_group`/`abort` do not touch the
    secret; the `setsid` escape is documented in SECURITY.md and pinned by
    `tests/docs.rs`.
  - `src/daemon.rs` `revoke_grants` and `src/daemon/run.rs` `record_use` now
    lock before they read; both are covered by tests that genuinely fail when
    reverted (checked).
  - `src/crypto.rs` `encrypt_with_template`: re-decodes and authenticates the
    template before reusing its salt/params, keeps a fresh nonce; properties
    pinned by `src/vault/tests.rs` and `src/crypto.rs` tests (header bytes
    8..20 and salt 20..36 kept, nonce 36..48 fresh, daemon key still opens the
    rewrite, wrong password writes nothing).
  - `src/cli/grant.rs` `command_grant_create` (R.41): no TTY bypass, no
    client-side-only check, nothing written before the y/N, `--out` refused
    before the password via `check_available` with `O_EXCL`/`O_NOFOLLOW`/0600
    as the authority, unknown `--ref` refused before any socket contact, names
    escaped with `escape_hidden`, no credential value read.
  - Escaping classes: `validate_tag` (`src/store.rs:405-430`) allows only
    `[a-z0-9._-]` after a lowercase/digit first byte, so the unescaped tags in
    `describe_scope` (`src/cli/grant.rs:463-478`) are safe; `validate_field_name`
    (`src/grant/validate.rs:270-284`) allows only `[a-z0-9_-]{1,32}`, so
    `write_scope`'s unescaped `fields:` line (`src/cli/grant_summary.rs:129-132`)
    is safe too. `validate_service`/`validate_username` still only refuse
    `char::is_control` — that is already R.48.
  - Known and accepted: `escape_hidden` keeps literal backslashes, so a legacy
    stored name containing the text `\u{202e}` renders like a real RLO;
    validation rejects the real class for new values, and R.48 owns the legacy
    display. Left alone deliberately.
  - Layout/refactors: `src/runner/tests.rs` holds all 14 tests removed from
    `src/runner.rs` plus 4 new, `src/cli/grant/tests.rs` all 12 removed plus
    new ones — comparing assertion sets found no test lost in either split;
    `PROGRESS-archive.md` received exactly the oldest 292 lines of
    PROGRESS.md verbatim. No file in the range grew past the 1,000-line guard
    (`src/cli/grant.rs` 976, `src/runner.rs` 919, `src/daemon.rs` under it).
- New TODO items are R.57-R.59, appended at the end of the Phase R section;
  highest previous number was R.56.

## 2026-11-03 — Name the credential behind each grant ref (TODO R.41)

- `src/cli/grant.rs`: `preview_scope` resolves every ref and tag against the
  decrypted vault into `ScopeEntry { reference, service, username }`;
  `write_scope` prints `service (username) [pm://ref]` per ref and every
  credential each tag currently matches (`(no credential currently matches)`
  when empty). Every name goes through `grant::escape_hidden`; no value is
  read. A missing ref is `Error::EntryNotFound(ref)` (exit 3), raised before
  the summary, any socket contact and the token file.
- Ordering changed: the master password is prompted **before** the summary,
  because the names live only in the encrypted vault. The vault is dropped
  before the y/N; after yes the old path resumes (`load_session`, token file,
  challenge/prove, `grant_create`, vault write). An existing `--out` is still
  refused before the password through the new `TokenFile::check_available`
  (`symlink_metadata`; `O_EXCL` stays the authority). DECISIONS/README/MCP/
  help updated to the new order.
- Tests: unit `a_ref_is_shown_with_its_service_and_username`,
  `a_tag_is_shown_with_every_credential_it_matches`,
  `an_unknown_ref_is_refused_before_the_summary`,
  `credential_names_are_escaped_in_the_summary`, plus a dangling-symlink
  `--out` check; e2e `grant_create_shows_the_credential_behind_a_reference`
  (name before the confirmation, no secret, nothing written) and
  `grant_create_refuses_an_unknown_reference_before_any_socket_contact`
  (exit 3, no accept, no file, vault unchanged). Existing grant-create tests
  now feed `MASTER` first; the cancel test no longer asserts that the
  password was never asked.
- Layout: the change pushed `src/cli/grant.rs` past the 1,000-line guard, so
  the approval summary now lives in `src/cli/grant_summary.rs` (224 lines,
  `pub(super)` items) and the unit tests in `src/cli/grant/tests.rs`; the
  command module is back to 661 lines.
- Gate: fmt, clippy `-D warnings`, full `cargo test` pass (274 lib + 56 args
  + 21 cli + the rest).
- **Next iteration must know:** R.42 is next. `grant list`/`grant show` still
  print the old one-line `refs: pm://...` via `describe_scope`; reusing
  `preview_scope`/`write_scope` there is the follow-up, but leave the `--json`
  shape unchanged.

## 2026-11-03 — Keep the vault header on save (TODO R.40)

- `src/crypto.rs`: new `encrypt_with_template(plaintext, master_password,
  template)`. It decodes the template header, derives the key from that
  header's salt and KDF parameters, then delegates to `encrypt_with_key`,
  which authenticates the template and seals with the same header and a fresh
  nonce. A wrong password therefore returns `AuthenticationFailed` and writes
  nothing.
- `src/vault.rs::save`: an existing vault (`source.is_some()`) now saves
  through `encrypt_with_template`; only a brand-new file keeps
  `crypto::encrypt` with a random salt and the current defaults. This fixes
  both R.40 failures: `pm add`/`edit`/`delete` no longer invalidate a running
  `pmd`'s key, and KDF parameters a human raised are no longer reset to the
  defaults on the next write.
- Decision (also in `DECISIONS.md` and `FORMAT.md`): reusing the header is
  safe because every save has a fresh 96-bit nonce, and reuse is gated on
  authenticating the container it came from. Upgrading parameters stays a
  separate explicit action (TODO 8.2), never a side effect of a normal write.
  Chose "keep the header" over "refuse while `pmd` runs" because the latter
  would break `pm add` for every user with an unlocked daemon.
- Docs: `DECISIONS.md` (Crypto section, and the grant-write rationale that
  claimed `pm add` re-salts), `FORMAT.md` (saves keep the header), `README.md`
  (features and security design).
- Tests: `crypto::tests::reencrypting_with_the_password_keeps_the_header`,
  `a_non_default_header_survives_a_reencryption`,
  `encrypt_with_template_authenticates_before_reusing_the_header`;
  `vault::tests::saving_with_the_password_keeps_the_header_and_a_running_daemons_key`
  (a raised-parameter vault plus a key derived before the save still opens it)
  and `saving_with_a_wrong_password_changes_nothing`. The first and the
  vault one fail on the old code (params reset, salt changed, old key
  rejects); the wrong-password one fails because the old `save` happily
  re-encrypted under a password that never opened the vault.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` suite pass (`cargo audit` not installed, skipped).
- **Next iteration must know:** `Vault::save` now does a full decrypt of the
  source container before every save (authentication), so a save costs one
  extra AES-GCM pass over the file; irrelevant next to Argon2, which now runs
  once per save instead of once with the file's own parameters. A vault opened
  with `Vault::empty` (the file did not exist) still creates fresh
  defaults, so a concurrently-created file is caught by `lock_for_update`,
  not by the header. R.41 is next.

## 2026-11-03 — Open the vault under the lock for daemon writes (TODO R.39)

- `src/vault.rs`: new `Vault::open_with_key_for_update(path, key)` — takes the
  write lock *before* reading, the key-based counterpart of
  `open_for_update`. A writer that got in first is now seen instead of
  tripping `VaultChanged`.
- `src/daemon.rs::revoke_grants`, `src/daemon/run.rs::record_use` and
  `src/cli/grant.rs` (the save after `grant_approved`) all use it. The
  daemon's revocation no longer maps a lost race to `internal`, and an
  approved creation is added to the state read under the lock. `record_use`'s
  retry loop stays but is only for real I/O failures (8 → 3 attempts);
  `lock_for_update` keeps its compare-and-lock job for `add`/`edit`, which
  prompt a human while avoiding the lock.
- Docs: `DECISIONS.md` (which constructors may save; why compare-and-lock is
  only for prompted writers) and `MCP.md` (`grant_revoke` locks before it
  reads). No wire or format change.
- Tests: `tests/daemon_concurrency.rs::revocation_succeeds_while_runs_record_their_use`
  (20 trials, 8 concurrent runs per revoke; fails on the old code at trial 0
  with `Error(Internal)`), `src/daemon/tests.rs::revocation_does_not_lose_to_a_concurrent_vault_write`
  (a writer holds the lock and saves while the revocation is on its way;
  fails on old code with `Err(Internal)`), and
  `tests/grant_cli.rs::grant_create_keeps_a_concurrent_vault_write_and_still_succeeds`
  (PTY create blocked at the lock, a recorded use saved first; old code fails
  with "changed while it was open"). The last two also assert the concurrent
  write survives, so an "ignore the change" fix cannot pass.
- Gate: fmt, clippy, full `cargo test` green.
- **Next iteration must know:** `record_use` still re-runs the whole
  authorization on a failed save; with the lock-first open that is now only an
  I/O path, not a race path. A run that arrives while another writer holds the
  lock waits up to 30 s (`VaultBusy`) — unchanged and intended. R.40 (`save`
  re-salts) is untouched and still next.

## 2026-11-03 — Kill what is left of the group when a run completes (TODO R.38)

- `src/runner.rs`: the finished path no longer reaps with `Child::try_wait`.
  New `leader_exited(pid)` uses
  `waitid(P_PID, pid, WEXITED|WNOHANG|WNOWAIT)`, so the exited leader stays a
  zombie and its pid/pgid cannot be recycled. The path then sends `SIGKILL` to
  the group, reaps the leader with `child.wait()`, joins the readers and
  returns the exit status. Before this, a child that backgrounded a daemon and
  redirected its stdio left the value in that daemon's environment after the
  run, `lock` and `pmd`.
- `SIGKILL` with no `SIGTERM` grace on this path: both pipes are already at
  EOF, so a survivor is a straggler that would only keep the secret longer; a
  grace period would add 100 ms to every completed run. The cancel path keeps
  `SIGTERM` + grace + `SIGKILL`.
- Docs: `SECURITY.md` limit 1 now says the group is killed on cancel *and* on
  normal completion, and that a descendant which starts a new session
  (`setsid`) escapes the cleanup and can keep the value (accepted, with
  "start long-lived services outside a passmgr run"). `src/daemon.rs`'s "no
  copy of the injected secret outlives the key" is corrected;
  `DECISIONS.md` and `README.md` describe the normal-completion kill.
- Tests: `runner::tests::a_background_process_does_not_outlive_a_completed_run`
  runs `sh -c 'sleep 60 </dev/null >/dev/null 2>&1 &'`, asserts exit 0 and no
  output, then requires the grandchild pid to be gone within 2 s. It fails on
  the old code with "a background process outlived the completed run". New
  `tests/docs.rs::security_documents_post_run_survivors_and_the_setsid_escape`
  pins the limit-1 wording (kill, `setsid` gap, advice).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` suite pass (`cargo audit` not installed, skipped).
- **Next iteration must know:** R.39 is next (revoke races a concurrent run's
  vault write). A run that deliberately starts a long-lived helper (for
  example `ssh-agent`) is now killed when the run returns; that is the
  intended security trade, not a bug to relax. The `setsid` escape remains a
  known limit and a hostile child can use it.

## 2026-11-03 — Cancel a run when its client disconnects (TODO R.37)

- `runner::execute` now takes a `Stop` instead of the cancel flag: `cancel`
  (`pmd` shutdown) plus an optional `client_gone` predicate. It is checked
  before the spawn and at the top of both wait loops. Before this, `pmd` only
  noticed a dead client when a frame write failed, so the child kept the
  secret in its environment and the idle deadline stayed suspended.
- `daemon::run::client_closed(fd)` polls the accepted socket with a zero
  timeout and reports `POLLHUP|POLLERR|POLLNVAL`, so a silent child cannot
  delay it. A client that shuts down only its write half is still reading and
  keeps its run; only a full close cancels.
- `src/runner/tests.rs` is new: the tests moved out of `src/runner.rs`, which
  passed 1,000 lines with this change (same pattern as `src/daemon/tests.rs`;
  the layout guard now passes with no pending splits).
- Tests: `client_closed` (open, half-closed, dropped, unread bytes); a gone
  client in both runner loops (child killed within 2 s) and before the spawn
  (no child); an integration test that drops a run's client under
  `--idle-timeout 2` and sees child gone within 2 s, `pmd` within 6 s. All
  three fail without the fix.
- Also: `output_errors_and_cancellation_stop_the_child` printed one byte,
  which the redactor holds until EOF, so it waited out the child's 30 s sleep.
  It now prints more than the holdback window and the suite is 30 s faster.
- Gate: fmt, clippy and the full test suite pass.
- **Next iteration must know:** R.38 is next. On Linux a full close reports
  `POLLHUP` (with buffered bytes) and a half-close does not, so no zero-byte
  probe is needed. R.47's "child survives the CLI" half is fixed here; its
  exit status is still lost.

## 2026-11-03 — Pick a redaction marker that cannot spell the value (TODO R.36a)

- `src/redact.rs::choose_marker` only rejected a default marker that
  *contained* the secret. The marker is substituted for a value, so the raw
  text around the substitution can supply the rest: `redact(b"TED]X",
  b"TED]XX")` gave `[REDACTED]X`. Auditing for the item found two more shapes
  the old rule missed: the secret containing the marker (`xx[REDACTED]yy`)
  and a suffix of the secret being a prefix of the marker (`zz[REDACTED`).
- New `marker_is_safe(marker, secret)` rules out all four shapes: marker
  contains secret, secret contains marker, marker starts with a proper secret
  suffix, secret starts with a proper marker suffix. `choose_marker` keeps the
  readable `[REDACTED]` when it is safe and otherwise uses a run of a
  printable byte absent from the secret (10 bytes); when the secret uses all
  256 byte values it uses a run longer than the secret of a byte that is
  neither its first nor its last byte. Both fallbacks are provably safe
  (the absent byte cannot be part of the secret; the longer run cannot be
  contained and the end bytes rule out both boundary shapes).
- Tests: `the_marker_never_combines_with_surrounding_output` has one
  adversarial input per shape (including `TED]XX`), runs it whole-buffer and
  byte-at-a-time, and asserts the accumulated output never contains the
  secret. `a_secret_using_every_byte_value_still_gets_a_safe_marker` covers
  the degenerate branch. Mutation check: reinstating the old condition makes
  the new test fail with `marker leaked [84, 69, 68, 93, 88] in
  [91, 82, 69, 68, 65, 67, 84, 69, 68, 93, 88]` (`TED]X` in
  `[REDACTED]X`); the file was restored afterwards. Ordinary secrets still
  get `[REDACTED]`, asserted by `the_marker_never_contains_the_value`.
- `DECISIONS.md` records the marker rule. No README/SECURITY change: both
  already say "an exact, contiguous occurrence replaced by `[REDACTED]`" as
  the typical case and `tests/docs.rs` does not pin the literal marker.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` pass (`cargo audit` not installed, skipped).
- NEEDS HUMAN REVIEW: the safety argument assumes the child cannot make a
  marker and raw text combine in a way not covered by the four shapes; the
  two boundary shapes were enumerated by hand, not proved. The fallback
  marker is a visible run of one byte (e.g. `!!!!!!!!!!`), which no current
  test treats as a contract.
- **Next iteration must know:** the first unchecked item is now **R.37**
  (a run whose client disconnects keeps the child and the key alive).

## 2026-11-03 — Review of 2208a50..a14dc54

- Range: 10 commits (`03b7a31` argv escaping, `ce0a4b7` grant existence
  oracle, `1665846` docs, `d5e0762` A-then-B approval, `2d5c1ea` canonical
  exec, `bf6bcb6` daemon-enforcement tests, `a14dc54` fixed-window redaction,
  plus the previous review and the loop archive), 28 files, ~2.9k added lines.
  Reviewed every changed file except the `PROGRESS-archive.md` blob, opened the
  surrounding code where the diff was not decisive, and ran the targeted
  suites named below. No source, test or doc edit other than this review's
  `TODO.md`/`PROGRESS.md`.
- Findings: 2, both documentation. Secret exposure 0; authorization holes 0;
  unsafe input handling 0; crypto misuse 0; maintainability 0; drift 2
  (`R.55`, `R.56`) — `R.55` also closes the one missing-test gap (the new
  `SECURITY.md` property had no test).
- `R.55`: `SECURITY.md:50-56` says every argv-derived echo escapes hidden
  characters, but service names and usernames still print raw bidi/zero-width
  characters (open `R.48`); confirmed against the built binary, and no
  `tests/docs.rs` test pins the bullet.
- `R.56`: `src/redact.rs:96-97` still calls the held tail "a proper prefix of
  the secret"; since `R.36` it is arbitrary bytes bounded only by length, and
  the `consume` doc below it says so correctly.
- Judged fine (do not redo):
  - Escaping chain `src/text.rs` → validators/`Error::Display` → the
    `report_runtime_error` backstop is idempotent: escaped text contains no
    hidden characters, so the second pass is a no-op, and `escape_quoted` also
    escapes `'`/`\`. `Error::GrantNotFound` is the only interpolated value left
    unescaped at its own site, but the printer backstop covers it.
  - `R.31` oracle fix: `serve_run` runs `check_grant_for_run` (state, RUN
    capability, command) before `get_by_ref`, and a scope refusal maps to
    `NotFound`. The four-state test compares whole `RunFrame` vectors; the CLI
    counterpart asserts exits 5/5/5/3 plus the message text.
  - `R.34` canonical exec: the path is canonicalized once, checked and spawned
    from the same `Path`; `resolve_commands` (`src/cli/grant.rs`) canonicalizes
    `--command` at create, so the allowlist and the request agree; `$0` is the
    canonical path. The ctime-based lock-open signal in the swap test is sound
    (`open_with_key` takes no lock; the first lock-file touch is
    `lock_for_update`, after the allowlist check). 12/12 runs green.
  - `R.36` redactor: the length-based holdback is correct, the discarded prefix
    is zeroized, `Drop` zeroizes both buffers, `Debug` prints lengths only, and
    the held tail is emitted before `Message::Done` (a cancelled relay drops it
    on purpose). `tests/redaction_timing.rs` discriminates: under the old
    matching-prefix holdback the identical 35-byte prefix is relayed during the
    pause. Its 500 ms window is a lower bound on a leak, not a synchronization
    sleep.
  - `Vault::save_with_key` + `crypto::encrypt_with_key`: fresh random nonce on
    every write (no AES-GCM nonce reuse), the template is authenticated before
    sealing, and only the salt/KDF parameters are reused — which is exactly
    what keeps the daemon's held key valid, as the doc says.
  - Grant-token file reader (`src/grant/file.rs`): `O_NOFOLLOW`, `fstat` on the
    opened descriptor, `mode & 0o077 == 0`, uid check, size cap — the
    README/MCP "no group or world permission bits (0600 or 0400 in practice)"
    and "owned by you" wording is accurate and pinned by `tests/docs.rs`.
  - `denied_env_name`'s denylist lacks `GCONV_PATH`, `LOCPATH`,
    `PYTHONSTARTUP`, `PERL5OPT`, `NODE_OPTIONS` and `SSH_ASKPASS`, but it is
    not exploitable: the value injected into the chosen name is always the
    credential, never agent-chosen, so the agent controls the name and not the
    path or config it points at.
  - `concurrent_runs_cannot_exceed_max_uses` 40/40 and the symlink-swap test
    12/12 on this machine; no flake. Under extreme contention `record_use`'s
    8 retries return `Internal` (fail closed, before any child) instead of
    `Denied`; not reachable at 16 threads and not security-relevant.
  - MCP.md is still an unimplemented contract (`request_claim` and friends),
    and `SECURITY.md`'s "no audit record is written today" matches the code
    (no audit module).
- Gate: review only — no code change, so no full `cargo test` run. Targeted
  runs of the prebuilt test binaries: `daemon_run` 40×
  (`concurrent_runs_cannot_exceed_max_uses`) and 12×
  (`a_symlink_swapped_after_the_allowlist_check_cannot_change_the_program`),
  plus the in-range diff read in full and `tests/redaction_timing.rs` read
  line by line.
- **Next iteration must know:** the first unchecked item is still `R.36a`
  (marker can complete a secret), then `R.37`/`R.38` (secret outliving the run
  and the key), then this review's `R.55`/`R.56`.

## 2026-11-03 — Make redaction's holdback independent of the secret (TODO R.36)

- `src/redact.rs::consume` used to keep only a tail that was a proper prefix
  of the secret. Whether the relay stalled therefore depended on the secret,
  giving an agent that controls child output a byte-at-a-time prefix oracle.
  It now keeps the last `secret.len() - 1` bytes unconditionally (`at_end`
  flushes them) and drops/emits from the front, so `push` returns the same
  number of bytes for a correct and a wrong prefix of equal length. A complete
  match is still replaced immediately. Output order is preserved; tail output
  is delayed by up to `secret.len() - 1` bytes.
- Rejected the item's timer alternative: flushing a held partial prefix on a
  timer would let later bytes complete it into a visible secret. Fixed-length
  holdback is the only content-independent option that keeps the guarantee.
- Tests: `src/redact.rs::the_holdback_window_does_not_depend_on_content`
  (correct vs one-byte-perturbed prefix of the same length return equal byte
  counts, before and after the window) and
  `bytes_before_the_window_are_emitted_promptly`; existing tests updated to
  the fixed window. `tests/redaction_timing.rs` runs the real daemon: the
  child prints `RELAY-READY`, then the 36-byte prefix (or its perturbed twin),
  pauses 2 s, then a tail. It asserts only the sentinel is relayed before the
  pause, both cases emit nothing during a 500 ms quiet window, and the held
  bytes arrive in order afterwards. Reverting `consume` makes it fail with the
  perturbed 36-byte prefix relayed before the pause.
- Docs: `SECURITY.md` limit 3 and `DECISIONS.md` record the fixed window and
  the latency cost.
- Found but **not fixed** (new TODO R.36a): the default `[REDACTED]` marker
  can complete a secret that starts with one of its suffixes; with secret
  `TED]X`, `redact(b"TED]X", b"TED]XX")` contains `TED]X`. A small
  `choose_marker` change (fallback when a marker suffix is a secret prefix)
  closes it.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  full `cargo test` pass; `cargo audit` is not installed (skipped).
- **Next iteration must know:** the first unchecked item is now **R.36a**
  (the marker-completion leak found here), then R.37. `tests/redaction_timing.rs`
  adds ~5.5 s to the suite; its 500 ms quiet window is a lower bound on a
  leak, not a synchronization sleep, and it observes the sentinel first so it
  does not race daemon startup.

