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

## 2026-11-03 — Keep the challenge pool in issue order (TODO R.19)

- `src/presence.rs:348`: `Challenges::verify_and_consume` spent the nonce with
  `swap_remove`, so the last (newest) entry moved into the freed slot. When the
  spent nonce was the **oldest** (index 0) the newest landed there and the next
  `challenge` -- which evicts index 0 as "the oldest" -- destroyed it, so a
  flood could kill a nonce issued after the human started. Now uses
  order-preserving `remove(index)`; the pool caps at 16, so the memmove is
  irrelevant.
- Correction to the review text: consuming a *middle* nonce never promoted a
  newer one to index 0 (`swap_remove` only fills the freed slot with the last
  entry), so that case was already evicting the oldest survivor. The observable
  defect is the oldest-consume case, and the tests target it. Recorded in the
  TODO item.
- Docs: `MCP.md` and `DECISIONS.md` now also state that spending a nonce keeps
  the remaining ones in issue order, which makes "the oldest is evicted" true
  while two approvals overlap. `MAX_PENDING_CHALLENGES`' doc says the same.
- Tests (both fail with `swap_remove`, verified by re-running them against it):
  `consuming_the_oldest_nonce_keeps_the_oldest_survivor_evictable` and
  `consuming_a_middle_nonce_leaves_the_oldest_at_index_zero` (unit), and
  `spending_the_oldest_challenge_never_evicts_a_newer_one` (`tests/daemon.rs`,
  through the real socket: prove the oldest, refill, force one eviction, assert
  the next-oldest is denied and the two new nonces still prove).
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (lib 223; daemon 20).
  `cargo audit` not installed; skipped per instructions.
- **Next iteration must know:** the review's "consume a non-last nonce"
  reproduction was arithmetically wrong; if a future refactor adds another
  consumer of `pending`, it must keep order too (the doc comment says so).
  Next unchecked item is R.20 (split the four oversized files).
## 2026-11-03 — Review of a51e85f..388faab

Six commits (R.15a, R.16, R.17, R.18, 3.4a, 3.4b) reviewed against
`PROMPT.md`, `MCP.md`, `DECISIONS.md`, `FORMAT.md`, `SECURITY.md` and the
whole surrounding code. **2 findings**, both in `TODO.md` Phase R:

- Authorization/availability **1** (R.19): `Challenges::verify_and_consume`
  uses `swap_remove`, so after any non-last consume the next full pool
  evicts the newest nonce instead of the oldest, contrary to R.16 and every
  document that describes it. Confirmed with a standalone `Vec` probe. No
  privilege escalation; it lets a flood destroy a nonce with a proof in
  flight. Also a test gap (the new test never consumes) and drift in
  `MCP.md`, `DECISIONS.md` and the `daemon.rs` comment.
- Maintainability **1** (R.20): `src/store.rs` 1,868 and `src/vault.rs`
  1,271 lines (also `src/protocol/mod.rs` 1,317, `tests/cli.rs` 1,463);
  R.14 split `grant.rs` but this range still added +83 and +128 lines to the
  two largest ones.
- Secret exposure **0**, unsafe input handling **0**, crypto misuse **0**.

Judged fine -- do not redo:

- `crypto::encrypt_with_key`: key length and plaintext cap checked, template
  header decoded, template authenticated with `key` via `decrypt_with_key`
  before its salt/params are reused (the plaintext is dropped at once),
  fresh nonce, `ciphertext_len` recomputed, and `seal` rejects a length
  mismatch; container assembly is shared with `encrypt`.
- `Vault::save_with_key`: requires the write lock, refuses a read-only or
  containerless vault, reuses `write_container` (0600 temp, `persist`, dir
  fsync). Leaving `self.source` stale after a save is harmless (same salt,
  lock held) and fails closed as `VaultChanged`.
- `store::encode`: every grant goes through `Grant::check_stored` before it
  is written, so R.17 holds; the payload is already `Zeroizing<Vec<u8>>`
  (checked: no plaintext leak on drop); `encode_grant`'s `to_str().expect`
  is unreachable because `create` and `from_stored` both validate UTF-8.
- `grant::request`: every variable-length field is length-prefixed under a
  domain separator, with a pinned hex vector and tests for normalization,
  reordering, boundary shifting, every field, the token hash and `Debug`
  redaction. The 30-day lifetime and past-expiry rules are deliberately
  deferred to `create_grant` (clock-dependent), not missing.
- `daemon::prove`: the session token is checked before the body is used, the
  nonce is spent by the attempt, and the approval records only the digest
  that the MAC covered (tested in
  `a_verified_proof_records_exactly_the_digest_it_covered`). No secret,
  grant token or digest reaches stdout, stderr or the socket beyond what
  the protocol intends; `Proof`, `TokenHash` and `Grant` `Debug` impls stay
  redacted.
- R.18's label table: 32 code points pinned independently in
  `tests/grant.rs`, and `tests/docs.rs` pins `FORMAT.md`/`DECISIONS.md` to
  `grant::LABEL_FORBIDDEN_CLASSES`.
- Gate re-run here: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings` and `cargo test --lib` (221 passed) are green.

Still open from earlier: R.15b (blocked) is correctly unchecked; 3.4c/3.4d
remain the next work.

## 2026-11-03 — Re-encrypt with the unlocked key (TODO 3.4b)

- `src/crypto.rs`: new `encrypt_with_key(plaintext, key, template)`. It checks
  the key length and plaintext cap, decodes the template header, **authenticates
  the template with `key` before reusing its header** (the decrypted plaintext
  is dropped at once), then seals with a fresh random nonce and the template's
  salt, KDF params and format fields. Container assembly moved into a private
  `seal`, which `encrypt` now shares, so the two writers cannot drift.
- `src/vault.rs`: new `Vault::save_with_key(&self, key)`. It refuses a
  read-only vault (`ReadOnlyVault`) and, with `Error::Crypto`, a vault with no
  source container (`open_for_add` on a new file) because there is no header to
  reuse. Same lock requirement and atomic `write_container` as `save`.
- Why: `save(password)` takes a fresh salt, which would make a running `pmd`'s
  key stale after the first grant write. Keeping the salt is safe because the
  nonce is fresh; the decision text is in `DECISIONS.md`.
- Docs: `FORMAT.md` salt row and security bullet, `README.md` features and
  encryption bullets now say the salt is reused only by a key-preserving
  re-encryption.
- Tests: crypto — salt/params kept, nonce fresh, both password and key decrypt
  the result, wrong key -> `AuthenticationFailed`, non-container ->
  `NotAVault`, key length enforced. Vault —
  `saving_with_the_key_keeps_the_key_and_the_password_working` (also proves a
  grant survives and both openers see it), the read-only/containerless refusal
  writes nothing, and a wrong key leaves the file byte-identical.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (lib 221). `cargo
  audit` not installed; skipped.
- **Next iteration must know:** 3.4c is next (`grant_create` daemon request
  that spends the digest approval). `save_with_key` needs a locked vault whose
  `source` is the on-disk container, so 3.4d must do `open_with_key` ->
  `lock_for_update` -> `save_with_key` in that order. A containerless vault can
  never use `save_with_key`; `pm init`/`add` still use `save(password)`.

## 2026-11-03 — Canonical grant-create request and digest (TODO 3.4a)

- `TODO.md`: split 3.4 into 3.4a–3.4d (canonical request, key-preserving
  save, daemon approval request, CLI). This iteration did 3.4a only.
- New `src/grant/request.rs`: `GrantRequest::new(GrantSpec, TokenHash)`
  applies the clock-free rules of `Grant::create` (label, commands,
  capabilities, RUN needs a command, non-zero max-uses, expiry bound) and
  normalizes scope/commands; `digest()` returns the
  `presence::RequestDigest` of a length-prefixed, big-endian encoding with
  domain `passmgr-grant-create-v1`; `create_grant(now)` rebuilds the
  `GrantSpec` and calls `Grant::create`, so the written fields are exactly
  the digested ones. Exported as `passmgr::grant::GrantRequest`.
- Decided the digest covers the token hash (one approval cannot write a
  different token) but not the id or `created` (assigned at write time;
  neither widens access). Duplicated normalization in `new` cannot drift:
  `create_grant` re-runs `Grant::create`.
- Revised the write plan after finding a trap: `Vault::save(master_password)`
  takes a new salt, which would invalidate the running daemon's key. Grant
  writes will be done by the CLI with `encrypt_with_key` reusing the salt
  (3.4b); `pmd` will only spend the approval and has no grant-write request
  (3.4c). `DECISIONS.md` and TODO 3.4b–d updated; no 3.4a code changes.
- Tests: 7 unit tests in `request.rs` (normalization, every field changes the
  digest, length-prefix boundaries, pinned hex vector, invalid shapes,
  `create_grant` field fidelity, redacting `Debug`) plus a public-API round
  trip in `tests/grant.rs`.
- Gate: `fmt`, `clippy -D warnings` and full `cargo test` green (lib 216,
  grant 23, docs 11, plus the existing cli/daemon/run/unlock suites).
- **Next iteration must know:** start 3.4b. `crypto::encrypt_with_key` must
  authenticate the template **before** reusing its header, or a wrong key
  could replace the vault with an unopenable file. Do not call
  `Vault::save(master_password)` from the grant path. 3.4d needs a running
  daemon (`pm run` also does not auto-unlock).

## 2026-11-03 — One spelling for the forbidden label classes (TODO R.18)

- `src/grant/validate.rs`: kept the full rejection table (all variation
  selectors included) so a stored label renders exactly as the human
  approved. New `LABEL_FORBIDDEN_CLASSES` is the one spelling used by the
  rejection error: "control, bidi, zero-width/format, line-separator or
  variation-selector characters". The error still never echoes the label or
  the offending code point.
- Chose refusal over allowing VS15/VS16: a selector changes how the base
  character renders (heart as emoji vs text), so accepting one form weakens
  the verbatim-label rule; dropping only those ranges would also leave an
  invisible-mark exception. Recorded in `DECISIONS.md`; a human can drop the
  selector or pick another emoji.
- Docs: `FORMAT.md` and the `DECISIONS.md` grant bullet use the same list.
  `DECISIONS.md` said "an emoji without a zero-width joiner", false for
  `❤️`; it now says "without a variation selector or zero-width joiner".
- Tests: the label table gained U+FE0E, U+E0001 and U+E0020;
  `variation_selectors_are_refused_including_the_emoji_presentation`
  refuses "❤️ prod" and a bare VS15, accepts "❤ prod", and checks the
  error names the class without echoing the label. New
  `tests/docs.rs::docs_name_every_forbidden_label_character_class` pins both
  documents to the constant.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (209 lib, 22
  grant, 11 docs). `cargo audit` not installed; skipped.
- **Next iteration must know:** 3.4 (`pm grant create`) is next; it must
  refuse labels through `Grant::create`, not a duplicate CLI check.
  `LABEL_FORBIDDEN_CLASSES` lives in `src/grant/validate.rs`, re-exported
  from `passmgr::grant`.

## 2026-11-03 — The payload writer validates grants before writing (TODO R.17)

- `src/grant.rs`: `from_stored` is now `check_stored(&StoredGrant) -> Result<()>`
  plus a constructor, and the new `to_stored(&self) -> StoredGrant` builds
  exactly the fields the codec writes. `store::encode` derives the stored form,
  runs `check_stored` on it, and serializes **that** value instead of reading
  the `Grant` accessors again, so writer and reader cannot drift and a save can
  never emit a payload `decode` refuses. A failing grant is `InvalidInput`
  (exit 2); nothing is written.
- `mark_used`/`revoke` now return `Result<(), UpdateError>`. The new
  `UpdateError::TimestampOutOfRange` refuses `now > MAX_TIMESTAMP_UNIX` before
  touching the grant (`Denied` stays purely an authorization answer, which the
  daemon will render and audit in 3.6). `UpdateError::Denied` wraps the old
  refusal. `check_active` is unchanged; it is only reachable after the bound.
- Tests: `grant_mutations_refuse_timestamps_the_store_cannot_hold` (nothing is
  counted or revoked on refusal; `revoke(MAX_TIMESTAMP_UNIX)` is accepted, so
  the bound is inclusive), `every_grant_mutation_round_trips_through_the_payload`
  (create / used / revoked all `encode` then `decode` and compare equal), and
  the `src/grant.rs` unit test
  `the_payload_writer_refuses_a_grant_its_reader_would_reject` (corrupts
  `revoked_at` and the label through private fields, proves both `from_stored`
  and `encode` refuse; a valid grant still encodes).
- Docs: `FORMAT.md` grant-validation paragraph now says the same checks run
  before every write; `DECISIONS.md` records the codec symmetry and the
  `UpdateError` split.
- Size rule: the additions pushed `src/grant.rs` to 1,087 lines, so the label,
  command and field-name validators moved verbatim to `src/grant/validate.rs`
  (`grant.rs` is ~980 lines now). No behavior change;
  `pub use validate::validate_field_name` keeps `passmgr::grant::validate_field_name`
  working, and `mark_used`/`revoke` still use the same `MAX_*` constants.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` are green (209 lib tests). `cargo audit` is not
  installed; skipped.
- **Next iteration must know:** R.18 is next, then 3.4. There is still no
  production caller of `mark_used`/`revoke`, so 3.5/3.6 must map
  `UpdateError::Denied` to the protocol denial and treat
  `TimestampOutOfRange` as an internal error (it needs a broken clock).
  `StoredGrant` is now constructed by `Grant::to_stored` as well as by the
  decoder; keep the two field lists identical when a new grant field lands
  (`store` version bump), or the codec test will not catch the omission.
  R.18's label table now lives in `src/grant/validate.rs`, not `src/grant.rs`;
  its line numbers in TODO R.18 are stale.

## 2026-11-03 — A full challenge pool evicts instead of refusing (TODO R.16)

- `src/presence.rs`: `Challenges::issue` prunes expired nonces, then evicts
  the **oldest** pending nonce when `MAX_PENDING_CHALLENGES` is reached instead
  of returning `TooManyPending`; the variant is removed. `issue` can now fail
  only when the CSPRNG fails, which the daemon still answers `busy` to.
- Rationale: `challenge` needs only the session token that the agent holds by
  design, so a client hoarding 16 nonces could answer `busy` to the human's
  `pm grant approve` and block the only path that mints a grant. A single
  burst of 16 (an agent retry loop) can no longer block a human who asks
  afterwards.
- Rejected the TODO's alternative, a per-connection allowance: the client
  opens a new connection per request and every same-UID peer is
  indistinguishable, so an owner id would be either spoofable or meaningless.
  Oldest-first is the only rule that needs no identity.
- Residual limit, documented in `SECURITY.md` "Out of scope" and
  `DECISIONS.md`: a peer that keeps issuing challenges faster than a human
  round trip can still evict a fresh nonce (and it can already kill `pmd`).
  `MCP.md` now says a full pool always issues a new challenge.
- Tests: `a_full_challenge_pool_evicts_the_oldest_instead_of_refusing`
  (17th issue succeeds, exactly `issued[0]` is gone, `issued[1]` and the
  newest still verify) and
  `expired_challenges_are_pruned_before_a_fresh_one_is_evictable`; the daemon
  test `approval_still_works_after_an_agent_fills_the_challenge_pool` fills
  the pool over a real socket, proves with a fresh nonce (`Proven`) and gets
  `denied` for the evicted first nonce with an otherwise valid MAC.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (207 lib tests,
  19 daemon tests). `cargo audit` not installed; skipped.
- **Next iteration must know:** R.17 (store::encode can write what its decoder
  rejects) is next, then R.18. The daemon's `Challenge` handler still maps any
  error to `busy`; that is now only reachable on CSPRNG failure. `pm grant
  approve` (3.4/4.9) may still see a sustained flood evict its nonce: it
  should treat `denied` as "ask for a new challenge", not a hard failure.

## 2026-11-03 — Record the digest a presence proof approved (TODO R.15a)

- Split R.15: the daemon half is now fixed, the write half is R.15b, blocked
  on the first grant write (3.4/4.9).
- `src/presence.rs`: new `Approvals` store. `record(digest, now)` is called
  only after a proof verifies; `take(digest, now)` consumes exactly one
  matching digest and returns `NotApproved` for anything else without
  disturbing the waiting approval. Entries expire after the existing
  `CHALLENGE_LIFETIME` (60 s), are capped at `MAX_PENDING_APPROVALS` (16) and
  the **oldest** makes room, because only a key holder can add one (unlike
  the challenge pool R.16 has to protect). New `PresenceError::NotApproved`.
- `src/daemon.rs`: `run` owns the store beside `Challenges`; `handle_connection`
  records `prove.digest` before answering `proven`. So `Proven` now means "a
  human approved this exact digest", and nothing else can consume it.
- Docs: protocol `Prove`/`Response::Proven`, `client::prove`, `MCP.md`
  approval flow, and the `DECISIONS.md` presence list now say that `proven`
  authorizes nothing on its own and that the write must spend the approval
  once. `TODO.md` 3.4 gained that obligation and R.15b's test.
- Tests: `an_approval_is_bound_to_its_digest_and_spent_exactly_once` (A then
  B refused, A then A exactly once), `an_approval_expires_after_sixty_seconds`,
  `approvals_are_bounded_and_the_oldest_makes_room`, and the daemon-level
  `a_verified_proof_records_exactly_the_digest_it_covered` (real prove frame
  over a socket pair; inspects the store the daemon wrote). The old
  "cannot approve a different one" comment in `tests/daemon.rs` now says it
  is a MAC mismatch.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` are green (206 lib tests). `cargo audit` is not
  installed; skipped.
- **Next iteration must know:** R.16 (challenge-pool starvation) is next.
  The approval store is deliberately global to the daemon, not per
  connection, because the proof and the write arrive on different sockets;
  do not move it into `handle_connection`. R.15b must call
  `Approvals::take` *before* any vault write and only proceed on `Ok`.
  `src/daemon.rs` is now ~950 lines and `src/presence.rs` ~715, including
  tests: split before adding much more.

## 2026-11-03 — Review of 92448eda..a51e85fe

- Findings: 4 — authorization/approval binding 1 (R.15), availability of the
  approval path 1 (R.16), data integrity / format asymmetry 1 (R.17), doc and
  error-message drift 1 (R.18). Details in `TODO.md` under "Phase R". R.15
  and R.17 are latent (no write/caller yet) but shape 3.4-3.6; R.16 is live
  today for any process that can read the session file.
- Checked and judged sound, so the next reviewer need not redo it: R.11 list
  scope (`AccessRequest` enum; both variants go through `authorizes`,
  `matches_field(None)` only for an unrestricted grant, tests use in- and
  out-of-scope refs and tags); R.12 relay reaping (no `Child` in `relay`, test
  proves the leader stays `Z` across three poll slices and cancel reaps the
  group); R.13 `TokenHash` has no `PartialEq` outside the compile_fail
  doctest, `matches` is constant-time, `Debug` redacted; R.14 table is
  independent of the module table and the tests use their own codepoint list.
  Store v5: v4 credential bytes are unchanged, v1-v4 decode with no grants,
  unknown capability/flag bits and field modes are malformed, counts and
  lengths are capped, duplicate ids rejected, `Payload` `Debug` hides
  passwords and token hashes, and no stored field can fail to round-trip
  except the timestamp gap in R.17. Presence: pinned HMAC vector, nonce
  spent before the MAC check, every nonce/MAC failure answers `denied`, proof
  `Debug` redacted and zeroized, 60 s expiry / 16-cap tests, challenge and
  prove are session-token-gated, and no proof hex reaches `pmd`
  stdout/stderr (e2e canary).
- Adversarial input: `store::decode` survived 2.4 M random/structured
  payloads and 600 k mutations (bit flips, truncation, insertion) of a valid
  v5 payload holding a credential and a grant with refs, tags, field scope
  and commands; `protocol::decode`, `decode_response` and the presence hex
  parsers survived the same corpus. No panic and no unbounded allocation.
  `cargo test`, `cargo fmt --check` and `cargo clippy --all-targets -- -D
  warnings` are clean; `cargo audit` is not installed (unchanged from 3.3).
- Nits not filed: `Vault::is_empty` still tests only credentials (a
  grants-only vault reports empty; only tests call it), the trailing-byte
  error in `store::decode` says "after credential data" even for a grant
  tail, and the daemon-output canary in `tests/daemon.rs` checks only the
  first proof, not the one issued after the replay attempt.

