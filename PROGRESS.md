## 2026-11-03 — Narrow the pre-spend claim and give the writer a capacity check (TODO R.22a)

- `Vault::check_grant_writable(&Grant)` (`src/vault.rs`) runs the writer's own
  `store::encode` over the candidate grant list and discards the bytes: nothing
  is written and the vault is unmodified. The pre-check and `save_with_key`
  therefore share one rule set (`MAX_GRANTS`, `MAX_PLAINTEXT_BYTES`, duplicate
  grant ids, grant validation), so they cannot drift.
- The daemon cannot make that check: it never opens the vault for
  `grant_create`. `GrantRequest::check_approvable`'s doc and the
  `Request::GrantCreate` comment in `src/daemon.rs` now claim only the
  expiry/30-day rule and name the CLI's pre-check. `MCP.md` and `DECISIONS.md`
  say who owns the vault-level check and that it runs before the proof; the
  advisory-vs-concurrent-writer caveat is in the method doc and DECISIONS.md
  (the write lock still refuses a lost update).
- R.22 is split: R.22a (this) is done; R.22b is `[!]` blocked on 3.4d, which
  must call the pre-check before `challenge`/`prove` and tick R.22b. 3.4d's
  text now carries that requirement plus the PTY test (seed at `MAX_GRANTS`,
  assert no challenge/prove frame, `Approvals::pending() == 0`).
- Tests: two unit tests in `src/vault/tests.rs` (a vault at `MAX_GRANTS`
  reports the writer's "too many grants" while the vault and the filesystem
  stay untouched; one slot left is accepted and a duplicate id is refused
  before the write -- the `MAX_PLAINTEXT_BYTES` branch shares the same
  `store::encode` call). `tests/docs.rs::
  docs_say_who_checks_vault_limits_before_the_proof` pins the MCP.md and
  DECISIONS.md sentences and fails if `src/grant/request.rs` or
  `src/daemon.rs` regains "no write could accept".
- No dependency change. Gate: `fmt --check`, `clippy --all-targets -D warnings`
  and the full `cargo test` green (230 lib tests); `cargo audit` not installed,
  skipped as the gate allows.
- **Next iteration must know:** the helper has no caller yet, on purpose. Do
  not teach `pmd` about vault limits (it must not learn vault state); 3.4d owns
  opening the vault and calling `check_grant_writable` before the proof.
## 2026-11-03 — Refuse hidden characters in grant command paths (TODO R.21)

- `src/grant/validate.rs`: `validate_commands` now rejects any command path
  holding a character the label table (`is_hidden_or_reordering`) refuses --
  C0/C1 controls, bidi, zero-width/format, line/paragraph separators and
  variation selectors -- so an agent-chosen path cannot forge the approval
  prompt or the `pm grant list|show` output (TODO 3.5/4.9).
- A rejection names the offending command, but `escape_hidden` renders every
  forbidden character (plus `'` and `\`) as its debug escape, so the error
  cannot move the cursor or erase the line. The label error still names only
  the class and never echoes the label.
- Create and decode both call this one function, so the check is on the write
  path and every older reader; stored grants need no migration and the format
  version is unchanged.
- Docs: `FORMAT.md` and `DECISIONS.md` state the command rule and why the same
  table applies; the class constant is unchanged, so `tests/docs.rs` still
  pins it.
- Tests: `tests/grant.rs::commands_must_not_hide_or_reorder_text` (four hidden
  forms refused through both `Grant::create` and `GrantRequest::new`, error
  escapes them and echoes no hidden character, visible `/usr/bin/gh` and
  `/usr/bin/grüße` still accepted); four new cases in
  `src/protocol/tests.rs::grant_create_rejects_payloads_the_vault_writer_would_refuse`;
  `src/daemon/tests.rs::a_grant_frame_with_a_forged_command_does_not_spend_the_approval`
  (hand-built wire frame answers `bad_request` and the proved approval is
  still spendable). `exchange` was split into `exchange` + `exchange_frame`
  so a test can send a frame it could not build through `Request`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` all green.
- **Next iteration must know:** R.22 is next -- vault-level limits still burn
  an approval after the master-password proof (only the expiry is checked in
  `check_approvable`). The daemon decode order and `Handled` path are
  unchanged. If a new error ever echoes a path, use `escape_hidden`.

## 2026-11-03 — Review of 388faab..4662526

Scope: `4662526` (`grant_create` request and daemon handler, TODO 3.4c),
`13944b8` (R.19 challenge ordering) and the four pure splits
`8c04c19`/`def4f60`/`ea9cc2d`/`a67ed6a`, reviewed against `388faab`. Read the
full diff, the new files (`src/grant/request.rs`, `src/grant/validate.rs`,
`src/grant/capabilities.rs`, `src/protocol/codec.rs`, `src/daemon/tests.rs`,
`tests/grant_create.rs`), the surrounding daemon/presence/vault paths and the
doc changes; re-ran the gate on the range head.

Findings: 4 — unsafe input / agent-visible text 1 (R.21), authorization plus an
overstated guarantee 1 (R.22), test gap 1 (R.23), doc drift 1 (R.24). Secret
exposure 0, crypto misuse 0, maintainability 0, panic/DoS 0.

Judged fine (do not redo):
- No secret-exposure path in the diff: the new request's `Debug` is redacted
  (`TokenHash` still has no `==`, the compile-fail doctest still guards it),
  the `grant_approved` answer is a fixed bare object pinned byte for byte, and
  no new `println!`/`eprintln!`/error string carries the token hash or a
  secret. The daemon never opens the vault on this path, so the e2e canary
  (`tests/support/mod.rs` `SECRET`) is genuinely injected by the fixture.
- Authorization: `grant_create` only works for a digest recorded by a verified
  HMAC proof, spends it once, and answers `denied` identically for "never
  approved", "already spent" and "different request". An agent that holds the
  session token can neither mint nor widen a grant, and `proven` alone
  authorizes nothing. Any session-token holder that knows the full request and
  its token hash can spend that approval, which is the documented same-user
  DoS limit (MCP.md, SECURITY.md), not escalation.
- Input handling: the frame body is capped at `MAX_MESSAGE_BYTES` = 64 KiB
  (`src/protocol/mod.rs:128`) before any allocation, every length is
  range-checked before slicing, `TokenHash::from_hex` cannot panic on
  non-ASCII input, `Scope::new`/`GrantRequest::new` re-normalize and re-cap
  refs/tags/fields/commands, and `validate_expiry` subtracts only after the
  `<= now` guard. The digest length prefixes cannot truncate because the caps
  hold before `digest()` is reachable.
- Crypto: no nonce, KDF or AEAD parameter changed; `RequestDigest` stays a
  SHA-256 (documented public, not a MAC), so the non-constant-time digest
  comparison in `Approvals::take` leaks nothing useful.
- R.19 fix is correct: `verify_and_consume` now uses `remove(index)` so the
  pool keeps issue order, and the new e2e test would have failed under
  `swap_remove`. `Challenges::issue` evicting index 0 is the documented policy
  (`src/presence.rs:292-309`); R.16's problem statement describes the bug it
  fixed, not current behaviour.
- The five splits are mechanical: no test function added, removed or weakened
  (only `pub`, import and rustfmt differences), `PENDING_SPLITS` is empty and
  the layout guard is green, largest file is `src/socket.rs` at 987 lines.
- Vault write path that 3.4d will use: `lock_for_update` compares the container
  byte for byte after taking the lock, so a stale writer gets `VaultChanged`
  instead of overwriting, and `save_with_key` reuses the source header so the
  daemon's key survives a grant write.
- Gate on `4662526`: `cargo fmt --check` and `cargo clippy --all-targets -- -D
  warnings` clean, `cargo test` green (227 lib tests plus every integration
  suite, 0 failures, doctests included). `cargo audit` is not installed here
  (DECISIONS.md:532); skipped as the gate allows.
- TODO R.15b is still correctly blocked on 3.4/4.9: 3.4c delivered only the
  daemon half, and the write path's obligation is unchanged. The only stale
  item is the wire shape in TODO.md item 3.4c (R.24).

## 2026-11-03 — Add the `grant_create` request and daemon handler (TODO 3.4c)

- New wire request/response: `Request::GrantCreate(GrantCreateRequest)` and
  `Response::GrantApproved` (bare `{"type":"grant_approved"}`, no token,
  hash, id or label). Fields are flat on the request object like `run`:
  `label, refs (pm://), tags, fields?, commands, capabilities (bit number),
  expires_at, max_uses?, token_hash (64 lowercase hex)`. Decoding rejects a
  token hash that is not 64 lowercase hex, a bad ref, unknown capability
  bits, an empty label and `max_uses: 0` at the frame boundary.
- `src/daemon.rs` re-normalizes the payload through `GrantRequest::new` (so
  the digest is over the canonical request), refuses an expiry that is past
  or more than 30 days out with `bad_request` **without** spending the
  approval, then calls `presence::Approvals::take` for the digest. Only a
  successful take answers `grant_approved`; the daemon never opens or writes
  the vault. The new `grant::validate_expiry` is shared with
  `Grant::create`, so the daemon and the future writer cannot drift.
- `TokenHash` gained lowercase `to_hex`/`from_hex` (no equality added; the
  compile-fail doctest still guards `==`). `Response::GrantApproved` added to
  `client.rs` and to the fixed-shape response test.
- Tests: daemon unit `grant_create_is_accepted_only_for_the_digest_the_human_proved`
  and `grant_create_refuses_an_expired_request_without_spending_the_approval`;
  protocol round-trip plus exact-JSON and rejection tests; end-to-end
  `tests/grant_create.rs::grant_create_spends_the_approval_once_without_writing_the_vault`
  (raw socket has no token-hash hex or secret, replay denied, vault bytes
  identical, daemon output clean). `Debug` for the request is redacted.
- Split to satisfy the layout guard (no allowlist entry): daemon unit tests
  moved verbatim to `src/daemon/tests.rs` (src/daemon.rs 824), `Capability`/
  `Capabilities` moved to `src/grant/capabilities.rs` and re-exported
  (src/grant.rs 931), and the new e2e test lives in `tests/grant_create.rs`
  (tests/daemon.rs 957). `PENDING_SPLITS` stays empty.
- Docs: MCP.md says the daemon only validates and spends the approval; the
  CLI holding the raw token assigns the id and writes. DECISIONS.md records
  the check-before-spend rule and the flat wire shape.
- Gate: `fmt --check`, `clippy --all-targets -D warnings`, full `cargo test`
  green (incl. doctests). `cargo audit` not installed; skipped.
- **Next iteration must know:** 3.4d is the CLI side; it must build the
  `GrantRequest` with a fresh 32-byte token, prove its digest, send
  `grant_create`, then write with `open_with_key` + `lock_for_update` +
  `save_with_key` and only then create `--out` with `O_EXCL`/0600.

## 2026-11-03 — Split the CLI tests and empty the layout allowlist (TODO R.20d)

- `tests/cli.rs` 1,463 -> 975 lines (21 tests). The reveal/agent section moved
  verbatim to `tests/cli_reveal.rs` (368 lines, 9 tests): the piped-stdin
  refusal, the agent-marker matrix, the `--agent` refusals over a PTY and over
  pipes, the metadata-command allowance, and the global `--agent` contract.
- Every helper moved to `tests/cli_support/mod.rs` (283): the `SERIAL` mutex
  and `serial()`, `run`/`run_with_env`/`base_command`, `vault_path`,
  `vault_password`, `add_example`, `EXAMPLE_SECRET`,
  `stdout`/`stderr`/`assert_success`/`get_reference`/
  `assert_canonical_reference`, `wait_for_prompt`, and the Linux-only
  `PtyOutput`/`run_on_pty`/`read_pty`. Both binaries include it with
  `mod cli_support;` + `use cli_support::*;`; helpers are `pub` (and
  `PtyOutput`'s fields) because a module's items are private to it, and the
  file has `#![allow(dead_code)]` like `tests/support/mod.rs` because each
  binary uses a different subset.
- `tests/layout.rs`: `PENDING_SPLITS` is now empty; the guard and its
  allowlist-shrinks test are unchanged (the second test simply iterates
  nothing). No new allowlist entries or `MAX_LINES` change.
- The move is mechanical: a per-function diff against `HEAD:tests/cli.rs`
  shows all 30 test bodies and every helper body identical apart from the
  `pub` prefixes and `PtyOutput` field visibility. Total CLI tests unchanged
  at 30 (21 + 9); no behavior change.
- Each binary has its own `SERIAL` static, so cargo may run `cli` and
  `cli_reveal` concurrently, each internally serial. Argon2 memory is still
  bounded per binary (64 MiB per unlock); the CLI binaries now peak at ~2x.
- Gate: `fmt --check`, `clippy --all-targets -D warnings`, full `cargo test`
  green (lib 223, cli 21, cli_reveal 9, daemon 20, docs 11, grant 23, layout 2,
  run 13, unlock 8, main 34, concurrency/shutdown plus doctests). `cargo audit`
  not installed; skipped per instructions.
- **Next iteration must know:** R.20 is complete and `TODO.md` Phase R has no
  unchecked items left; the next item is 3.4c (`grant_create` request and
  daemon handler, which also discharges the blocked R.15b). Phase R's only
  remaining entry is R.15b, which is `- [!]` blocked on 3.4/4.9.

## 2026-11-03 — Split the protocol frame codec from the request model (TODO R.20c)

- `src/protocol/mod.rs` 1,317 -> 444 lines: request/response types,
  `ProtocolError`, the request field validation (`validate_request`,
  `validate_absolute_path`, `valid_env_name`) and the `response` re-exports.
  The frame and body codec moved unchanged to `src/protocol/codec.rs` (304):
  `encode`, `decode`, `FrameDecoder`, `read_length`, `check_length`,
  `split_frame`, `encode_body`, `decode_body` and the JSON field helpers.
- The ~590-line inline test module moved to `src/protocol/tests.rs` (590), the
  `src/x.rs` + `src/x/` layout R.20a/R.20b used. `mod.rs` still re-exports
  `encode`/`decode`/`FrameDecoder`, so `client`, `daemon` and the CLI are
  unchanged; `split_frame` stays shared with `response.rs` through a private
  `use codec::split_frame;` (no new public surface).
- The move is mechanical: a normalized diff against `HEAD:src/protocol/mod.rs`
  shows the codec body byte-identical and the test body identical apart from
  the module wrapper, with only indentation, one `serde_json::Value` import
  and rustfmt re-wrapping different. `serde_json` is no longer imported by
  `mod.rs`; `tests.rs` imports `serde_json::Value` directly.
- `tests/layout.rs`: `PENDING_SPLITS` is now only `tests/cli.rs`; both guard
  tests pass.
- No behavior, wire-format or protocol-version change.
- Gate: `fmt --check`, `clippy --all-targets -D warnings`, full `cargo test`
  green (lib 223 of which protocol 40, cli 30, daemon 20, docs 11, grant 23,
  layout 2, run 13, unlock 8, main 34, plus concurrency/shutdown/single).
  `cargo audit` not installed; skipped per instructions.
- **Next iteration must know:** R.20d is the last split (`tests/cli.rs`,
  1,463): move the PTY/reveal/agent-marker tests and their helpers into
  `tests/cli_reveal.rs` with shared setup in e.g. `tests/cli_support/mod.rs`,
  then empty `PENDING_SPLITS` (do not delete the list or its second test).
  After that the next unchecked item is 3.4c (`grant_create` request and
  daemon handler, which also discharges R.15b).

## 2026-11-03 — Split the vault write lock from the vault lifecycle (TODO R.20b)

- `src/vault.rs` 1,271 -> 358 lines: only the `Vault` lifecycle, `read_container`
  and `insecure_permissions` remain. The write lock and atomic replacement
  moved to `src/vault/lock.rs` (199): `LOCK_SUFFIX`, `lock_path`,
  `acquire_write_lock`, `acquire_write_lock_with_timeout`, `write_container`,
  `with_path`, plus their two tests.
- The helpers are `pub(super)`; `src/vault.rs` re-exports `lock_path` and
  `LOCK_SUFFIX` with `pub use self::lock::{lock_path, LOCK_SUFFIX}`, so
  `passmgr::vault::lock_path` (used by `tests/cli.rs`) and every in-crate
  caller keep the same path. `mod lock;` is private, so no new public surface.
- The inline test module moved verbatim to `src/vault/tests.rs` (744), the same
  `src/x.rs` + `src/x/` layout R.20a used for `store`. The code move alone left
  `vault.rs` over 1,000 lines, so the tests had to move too. 22 of the 24 tests
  moved unchanged (only indentation and one import differ, verified by a
  normalized diff against `HEAD:src/vault.rs`); the two lock-only tests went to
  `src/vault/lock.rs` instead. Lib test count is unchanged at 223.
- `tests/layout.rs`: `src/vault.rs` removed from `PENDING_SPLITS` (now
  `src/protocol/mod.rs`, `tests/cli.rs`); both guard tests pass, including the
  one that fails if an allowlisted file is no longer oversized.
- No behavior, crypto or format change. `git diff` of moved code is a pure move.
- Gate: `fmt --check`, `clippy --all-targets -D warnings`, full `cargo test`
  green (lib 223, cli 30, daemon 20, docs 11, grant 23, layout 2, run 13,
  unlock 8, main 34, plus the concurrency/shutdown/single tests). `cargo audit`
  not installed; skipped per instructions.
- **Next iteration must know:** R.20c is next (`src/protocol/mod.rs`, 1,317).
  Move the frame/body codec to `src/protocol/codec.rs` and the inline tests to
  `src/protocol/tests.rs`, then drop the allowlist entry. Do not raise
  `MAX_LINES` or add allowlist entries; split in the same commit if a file
  grows past 1,000.

## 2026-11-03 — Split the store codec and add a layout guard (TODO R.20a)

- Split R.20 (four files over the ~1,000-line rule) into R.20a-R.20d, one file
  per iteration, and did R.20a. `src/store.rs` 1,868 -> 461 lines (model,
  validation, format constants only); the payload codec moved unchanged to
  `src/store/payload.rs` (659) and the inline test module to
  `src/store/tests.rs` (771), using the `src/grant.rs` + `src/grant/` layout
  rather than converting to `mod.rs`. `store.rs` still declares
  `encode`/`decode`/`Payload`, so no caller changed.
- New `tests/layout.rs` walks every `src/**/*.rs` and `tests/**/*.rs` and fails
  a file over 1,000 lines. `PENDING_SPLITS` names the three files R.20b-R.20d
  still have to split; a second test fails if a listed file is no longer
  oversized, so the list can only shrink. Verified the guard detects the three
  remaining offenders by temporarily emptying the allowlist.
- No behavior or format change; the split is mechanical. `store::tests` now
  imports the `crate::grant` types it used to get through `store.rs`'s glob
  (`Capabilities`, `Grant`, `GrantSpec`, `Scope`, `TokenHash`, and the
  `MAX_*`/`TOKEN_HASH_BYTES` constants).
- Tests: both `tests/layout.rs` tests (guarded by the temporary-allowlist
  probe above), and the whole existing suite, green.
- Gate: `fmt --check`, `clippy --all-targets -D warnings`, full `cargo test`
  (lib 223, cli 30, daemon 20, docs 11, grant 23, layout 2, run 13, unlock 8,
  main 34, concurrency/shutdown/other 1+6+1+1). `cargo audit` not installed;
  skipped per instructions.
- **Next iteration must know:** start R.20b (`src/vault.rs`, 1,271). Move the
  lock/atomic-write helpers to `src/vault/lock.rs`, keep `lock_path` and
  `lock_for_update`'s public path stable, and remove `src/vault.rs` from
  `PENDING_SPLITS`. Do not raise `MAX_LINES` or add to the allowlist; if a file
  grows past 1,000, split it in the same commit.

