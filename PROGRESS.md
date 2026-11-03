## 2026-11-03 — Do not panic when `revoke --all` gets `not_found` (TODO R.27)

- `src/cli/grant.rs` (`command_grant_revoke`): the
  `Response::Error(ResponseError::NotFound)` arm now matches `options.id`
  instead of calling `.expect("not_found implies an id")`. `Some(id)` still
  gives `Error::GrantNotFound(id)` (exit 3); `None`, which only `--all`
  produces, gives `Error::Daemon("the unlock daemon refused the revocation
  (not_found)")` (exit 1). Any same-user process can replace the socket, so a
  hostile or buggy peer must never turn into a panic and a backtrace.
- No behavior change for a real daemon: `revoke_grants` (`src/daemon.rs`)
  answers `not_found` only for an id, so `--all` keeps its current success
  paths.
- Test: `tests/grant_manage_cli.rs::
  grant_revoke_all_reports_a_not_found_answer_without_panicking` binds a stub
  `UnixListener`, decodes the frame and asserts it is
  `GrantRevokeRequest::All`, answers the encoded `not_found` error, then
  requires exit 1, the clean message, no `panicked at`, no
  `not_found implies an id`, and an untouched vault. Verified it fails
  (exit 101, the panic text) against the previous code.
- Docs: `DECISIONS.md` records the `--all` + `not_found` mapping; TODO R.27 is
  checked off with a Done note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.28 (the "active" wording of `--all`) and
  R.29 (`--out` escaping) are the next Phase R items and touch the same file;
  neither was changed here. `tests/grant_manage_cli.rs` is now ~420 lines and
  has the stub-socket pattern this test needs if R.28/R.29 want one.

## 2026-11-03 — Show and confirm a grant before creating it (TODO R.26)

- `pm grant create` now builds the `GrantRequest` first and prints it to
  stderr before anything else: label, scope, canonical commands,
  capabilities, expiry and use limit, plus one warning per allowed program
  runner. The human must answer `y`/`yes`; anything else exits 2 with
  "cancelled; nothing was written". The confirmation sits before
  `load_session`, `TokenFile::create`, the master-password prompt and the
  daemon, so a `n` leaves no file, no socket traffic and no spent approval.
- `terminal::prompt_yes_no`/`is_yes` are the new prompt: only an explicit yes
  (case-insensitive, trimmed) approves; a blank line, another word or EOF is
  no.
- `grant::escape_hidden` (new, display form) escapes only hidden characters,
  so `Bob's token` keeps its apostrophe; the quoted error form that also
  escapes `\` and `'` is now the private `escape_quoted`. The summary and
  warning carry metadata only; no credential value exists at that point.
- The runner warning is bold red only when stderr is a TTY, so piped or
  captured output gains no escape sequences. A command path with a hidden
  character is still refused by `resolve_commands` before the summary, and
  the error names it as text (`\u{1b}`), never as bytes.
- Tests: two new PTY tests — cancelling keeps vault, token file and daemon
  untouched; a hidden-character command is refused before the summary — plus
  ordering/content assertions in the existing create and `--allow-interpreter`
  tests. Unit tests cover `is_yes`, warning colouring, summary contents and
  display escaping.
- `tests/grant_cli.rs` grew past 1,000 lines, so its fixture moved to
  `tests/grant_support/mod.rs` and the list/show/revoke tests to
  `tests/grant_manage_cli.rs`; no test content changed.
- Docs: README, `--help`/`tests/fixtures/help.txt`, the `MCP.md` runner bullet
  and `DECISIONS.md` now describe the summary and the confirmation order.
- Gate: `cargo fmt --check`, `clippy -D warnings` and the full `cargo test`
  pass. `cargo audit` is not installed; skipped as instructed.
- **Next iteration must know:** approving still only proves presence, not
  comprehension — the human must read the summary, and the digest binds the
  same request. The `--out` path is deliberately not in the summary; R.29
  still has to escape it in the success line and the overwrite error. Because
  the summary comes before `load_session`, approving with no daemon running
  shows "no passmgr daemon is running" (exit 1) after the yes; that ordering
  is what makes `n` provably socket-free.

## 2026-11-03 — Refuse program runners, not just interpreters (TODO R.25)

- `grant/validate.rs`: `INTERPRETERS`/`VERSIONED_INTERPRETERS` became
  `PROGRAM_RUNNERS`/`VERSIONED_PROGRAM_RUNNERS` and `is_interpreter` became
  `is_program_runner`. The table now covers what a grant's `argv[0]`-only
  binding makes dangerous: shells, launchers (`env`, `xargs`, `sudo`,
  `timeout`, `tmux`, `strace`, …), editors/pagers/man, tools with an exec
  option (`find`, `sed`, `tar`, `ssh`, `scp`, `nc`, …), alias/plugin CLIs
  (`git`, `gh`, `docker`, `podman`, `kubectl`, `helm`, `terraform`, `ansible`,
  …), build runners (`make`, `cargo`, `npm`, `go`, `mvn`, `bazel`, …) and DB
  clients (`psql`, `mysql`, `sqlite3`). `gh`/`git` are no longer treated as
  safe; matching is still file-name based with the same versioned-suffix rule.
- Chose the broad table over a per-command confirmation: a grant has nowhere
  to record per-command trust, and confirming every command would turn every
  grant into a wall of y/N prompts. The table is documented as best-effort,
  not a boundary — allowing any program is trusting it with the value.
- Docs: README's grant example now passes `--allow-interpreter` (with an
  explanation that `gh` itself is a runner), `--help` (and the byte-exact
  `tests/fixtures/help.txt`) describe the flag and the example the same way,
  `SECURITY.md` limit 2 is rewritten around `argv[0]`, `MCP.md` and
  `DECISIONS.md` name runners and the residual trust.
- Tests: unit table of every documented runner name plus lookalikes
  (`pythonista`, `shadow`, `envoy`, `tar.gz`); e2e with a fake executable
  named `gh` proving exit 5, no master-password prompt, no daemon session and
  no token file, and that `--allow-interpreter` stores the canonical path and
  prints neither token nor secret; docs contracts pin the prose and the
  README example.
- Gate: fmt, clippy -D warnings, full `cargo test` (including the Argon2 CLI
  suite) pass. `cargo audit` not installed, skipped as instructed.
- **Next iteration must know:** the refusal is CLI-only and the grant stores
  no "runner allowed" bit, so `grant show` cannot reveal that a human opted
  into a runner — worth a small follow-up if the approval UX (R.26) starts
  rendering one. `psql`/`mysql`/`sqlite3` are now runners, which matters for
  the Phase 7 presets. Versioned names are matched only for the versioned
  bases (`git-lfs`, `ssh-keygen`, `bash-completion` are plain exact names and
  not matched); that is the accepted best-effort gap.

## 2026-11-03 — Review of 4662526..4a16226

- 5 findings: 2 authorization (R.25, R.26; R.25 also exposes injected
  secrets), 2 unsafe input/output (R.27, R.29), 1 drift/test gap (R.28); 0
  direct secret-printing bugs, 0 crypto, 0 maintainability. Added R.25–R.29 to
  `TODO.md`.
- R.25 (high, authorization/secret exposure): the interpreter denylist omits
  `gh` and `git`. A grant for the README's `/usr/bin/gh` example can run
  `gh alias set --shell`, and `git -c alias...` runs a shell (both verified
  locally with `id -u` output `1000`), so an agent can read injected secrets.
  `src/grant.rs:953-954` currently pins the wrong expectation.
- R.26 (medium, authorization): `grant create` prompts for the master
  password without displaying the request. `MCP.md` and `DECISIONS.md` say the
  approval prompt shows command paths and a red interpreter warning. Presence
  is proved, but not informed consent.
- R.27 (low, unsafe input): `src/cli/grant.rs:369` panics on `not_found` for
  `revoke --all` because `options.id` is `None`.
- R.28 (low, drift/tests): `revoke --all` includes expired and exhausted
  grants despite the "active" wording in the help, decisions and test.
- R.29 (low, unsafe output): `--out` is echoed unescaped at
  `src/cli/grant.rs:226` and `:576`.
- Looked at and judged fine: `grant list`/`show` are metadata-only (no token,
  token hash or value; tests assert it); the token file is 0600 with
  `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, fsynced and unlinked on failure; the
  grant-create write happens only after `grant_approved`, uses
  `lock_for_update` + `save_with_key`, and `check_grant_writable` reuses
  `store::encode`; the presence proof binds the canonical digest;
  token/token-hash `Debug` is redacted and comparison is constant-time; no
  nonce/KDF change or other crypto misuse; no new unbounded read; files remain
  under 1,000 lines.
- Known/accepted, not counted: `run` is not yet grant-gated (TODO 3.6, stated
  in SECURITY.md and PROGRESS); `revoke` needs no proof because it only
  removes access (same-user DoS only); `revoke --all` is available to an agent
  by design.
- Gate: `cargo test --quiet` passes; no source, test or doc changes were made
  apart from `TODO.md` and this entry.

## 2026-11-03 — Add `pm grant list|show|revoke` (TODO 3.5)

- `pm grant list [--json]` / `grant show <id> [--json]`: local vault reads
  (master password, `--db` allowed) printing metadata only — id, label, scope,
  commands, capabilities, timestamps, uses, `status` = active|expired|
  exhausted|revoked. JSON is `{"grants":[...]}` or one grant object; no
  `token`, `token_hash` or secret key ever appears.
- `pm grant revoke <id>|--all [--json]`: daemon round-trip over the session
  token, no password, no TTY, allowed under `--agent`. New `grant_revoke`
  request (`id` xor `all: true`) and `grant_revoked {revoked:N}` response; the
  daemon's `revoke_grants` is its only vault write and reuses the hot key via
  `save_with_key`. Already-revoked id is a successful no-op, unknown id exit 3,
  `--all` counts only active grants. Refuses `--db`/`PASSMGR_DB` like `run`.
- `src/cli/args.rs` grew past 1,000 lines, so it became `src/cli/args/mod.rs`
  with the `grant` parsing in `src/cli/args/grant.rs` (mechanical move).
- Decided: revocation needs no proof (it only removes access) and is safe for
  agents to perform; see DECISIONS.md.
- Tests: protocol round-trip + strict rejections for `grant_revoke`/
  `grant_revoked`; args parsing (one target only, `--db` refusal); metadata
  has no token/hash; e2e list/show/revoke, agent revoke, `--all`, unknown id,
  no daemon, TTY-less revoke with a canary that must not leak.
- Gate green: fmt, clippy `-D warnings`, full `cargo test` (237 lib, 48 bin,
  145 integration, 2 doctests). `cargo audit` skipped as allowed.
- **Next iteration must know:** `run` does not yet consult grants (3.6), so
  "takes effect on the next request" is proven only by the persisted
  `revoked_at` and by `grant list`/`show`. PTY runs echo the typed password
  into stdout, so parse JSON from `run_with_env` piped runs instead.

## 2026-11-03 — Add `pm grant create` CLI (TODO 3.4d, closes R.22b)

- `src/cli/grant.rs` + `Command::Grant(GrantCommand::Create(..))`: resolve
  commands to canonical executables; refuse interpreters unless
  `--allow-interpreter`; TTY/no-agent gate (exit 5); require a daemon; create
  `--out` (`O_EXCL|O_NOFOLLOW`, 0600); prompt once, derive the key, build a
  `GrantRequest` with a fresh 32-byte token; open the vault and
  `check_grant_writable` **before** `challenge` (R.22b); prove, send
  `grant_create`, accept only `grant_approved`; re-lock, add, `save_with_key`
  (daemon key stays valid); commit the token file. Failures before commit
  unlink a file this run created.
- New `GrantToken` (`src/grant/token.rs`, split for the line limit): 32
  random bytes, `Zeroizing`, redacting `Debug`; hex only in `--out`, vault
  keeps SHA-256. `is_interpreter` (shells, runners, versioned
  python/perl/ruby/node/php/lua/pwsh/julia/Rscript) in `grant/validate.rs`.
- Docs: `--help`/golden file, README "Create a grant", SECURITY marker
  removed, DECISIONS policy; MCP.md unchanged.
- Tests: unit parsing/expiry/token-file/cleanup/Debug/interpreter; new
  `tests/grant_cli.rs` (5) proves the token is never printed and is 0600,
  stored scope/commands/hash, the daemon still injects after the write, an
  existing `--out` is refused before the prompt, interpreter/agent refusals,
  and a full vault against a stub socket (exit 2, no connection, no file).
- Gate green: fmt, clippy `-D warnings`, full `cargo test` (234 lib, 41 bin,
  123 integration/docs, 2 doctests); `cargo audit` skipped as allowed.
- **Next iteration must know:** 3.5 is next. `grant create` does not
  auto-unlock; an existing `--out` is detected after the session loads. No
  `--fields` flag yet (Scope fields `None`), deferred to Phase 6. A failure
  after `grant_approved` spends the approval; retry needs a fresh request.
  Grants are stored but not yet enforced (3.6).

## 2026-11-03 — One authoritative `grant_create` frame body (TODO R.24)

- TODO 3.4c's spec line showed the fields nested under a `request` key; they
  are flat like `run`. It now reads `{type:"grant_create", label, refs, tags,
  fields?, commands, capabilities, expires_at, max_uses?, token_hash}` and
  points at MCP.md for the exact body. (The old line was also missing its
  closing backtick, which is why the first scripted edit did not match.)
- `MCP.md` ("The daemon never writes a grant") now carries the exact frame
  body in one fenced `json` block, with every key present, `null` for unset
  `fields`/`max_uses`, the "at least one ref or tag" rule, and a note that
  `token` is the unlock session token and `token_hash` is a SHA-256, so no
  credential value is in the body. `src/protocol/mod.rs`'s illustrative sketch
  now says MCP.md holds the exact bytes.
- Decisions: the wire example lives in exactly one document and is pinned on
  both sides, so a doc edit cannot silently change the contract (DECISIONS.md,
  grant bullet). Ordering matters: the encoder's keys come out
  alphabetically (serde_json's `Map` is a `BTreeMap` here), so the doc body is
  the byte-for-byte encoder output.
- Tests: `src/protocol/tests.rs::mcp_documented_grant_create_body_is_the_wire_format`
  (literal decodes to `grant_create()`; re-encoding equals the literal byte
  for byte) and `tests/docs.rs::mcp_grant_create_example_has_the_encoder_keys`
  (extracts the fenced block, compares envelope + request key sets and the
  whole value to the encoder). Both were verified to fail on a nested example.
  The docs test's `fenced_json_after` helper returns `None` on a missing
  marker or block, so deleting the example fails instead of passing vacuously.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green (232 lib tests, docs 13); `cargo audit` not
  installed, skipped as the gate allows.
- **Next iteration must know:** 3.4d (the `pm grant create` CLI) is the next
  unchecked item and builds its encoder from MCP.md's example. The example
  uses the fixture token `0011…eeff` and the SHA-256 of `b"grant-token"`, so
  changing either literal means changing MCP.md, the `src/protocol/tests.rs`
  constant and the `tests/docs.rs` fixture together.

## 2026-11-03 — Prove the daemon's 30-day pre-spend refusal (TODO R.23)

- New daemon unit test
  `grant_create_refuses_a_request_longer_than_thirty_days_without_spending_the_approval`
  (`src/daemon/tests.rs`): after a successful `prove` for a request one hour
  past `MAX_GRANT_LIFETIME_SECS`, `grant_create` answers `bad_request`, the
  approval is still pending and `Approvals::take` for that digest succeeds;
  then a request exactly 30 days out is proved and answered `grant_approved`.
- Sent one hour over the cap, not one second: the daemon reads its own clock,
  so a tick between the test's `now` and the daemon's could otherwise turn a
  refusal into an acceptance. The exact one-second boundary is already covered
  deterministically by `Grant::create` (`tests/grant.rs:126`,
  `NOW + MAX_GRANT_LIFETIME_SECS + 1`), so nothing is left unproven.
- Verified the test fails without the behavior: deleting the 30-day branch in
  `grant::validate_expiry` made it answer `GrantApproved` instead of
  `BadRequest`.
- No production code or doc change; MCP.md and DECISIONS.md already state the
  rule. Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  and the full `cargo test` green (231 lib tests); `cargo audit` not installed,
  skipped as the gate allows.
- **Next iteration must know:** the next unchecked item is R.24 (fix the stale
  nested `grant_create` wire example in TODO 3.4c and add the flat key list to
  MCP.md), then 3.4d builds the CLI client from those docs.

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

