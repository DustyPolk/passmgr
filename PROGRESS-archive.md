# Progress archive (older entries, newest first)

## 2026-11-03 — Prove `pmd` enforces allowlist, capability and use limits (TODO R.35)

- Tests only, no production change. `tests/daemon_run.rs` gains
  `run_enforces_the_command_allowlist_and_the_run_capability`: a
  non-allowlisted script is `Denied` and leaves no marker; a symlink to it
  under an innocent name is `Denied` (the daemon canonicalizes first); a grant
  that allows `/bin/sh` but holds only the `list` capability is `Denied` and
  records no use.
- `concurrent_runs_cannot_exceed_max_uses`: 16 simultaneous `run`s against a
  `max_uses = 3` grant give exactly 3 `Exit(Code(0))`, 13 `Denied`, and 3 uses
  in the vault (`mark_used` re-checks under the write lock).
- Mutation check: replacing both `program` arguments in
  `src/daemon/run.rs::record_use` with `grant.commands()[0]` makes the first
  test fail with `Exit(Code(0))` from the unlisted program; the file was
  restored and `git diff src/daemon/run.rs` is empty.
- The expired/revoked/exhausted/out-of-scope cases from the item were already
  e2e in `a_denied_run_does_not_reveal_whether_a_reference_exists` (R.31), so
  they are not duplicated. No docs/decisions changed.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` pass (`cargo audit` not installed, skipped).
- **Next iteration must know:** the first unchecked item is now **R.36** (the
  redaction holdback timing oracle), which is a real code change in
  `src/redact.rs`. `tests/daemon_run.rs` is now ~730 lines; the layout guard
  still passes but the next addition there should consider splitting
  (R.54 already tracks the fixtures).

## 2026-11-03 — Exec the canonical authorized program, not the request path (TODO R.34)

- `src/runner.rs` `execute` now takes `program: &Path` separately from
  `args: &[String]`, runs `Command::new(program)` and lets it become
  `argv[0]`; the old `argv[0]`-is-the-program convention is gone from the
  API. `src/daemon/run.rs` passes the canonical path it checked, so a symlink
  swapped between the allowlist check and the spawn cannot redirect the exec,
  and a multi-call binary cannot be steered by a caller-chosen link name.
  `src/cli/run.rs::absolute` still sends the lexically absolute path; the
  single resolution happens in the daemon.
- Tests (`tests/daemon_run.rs`): (a) the lock-held swap from the item — the
  test flocks `<vault>.lock`, waits for the daemon's unconditional `chmod` to
  change the lock file's ctime (the daemon is non-dumpable, so `/proc/pid/fd`
  is not readable), then swaps the link; no loot file, `Exit(Code(0))` from
  `/bin/true`; (b) `sh`-link with `-c 'printf %s "$0"'` prints the canonical
  path. Both fail with the daemon mutated back to `request.command[0]`.
- Decisions: `#[allow(clippy::too_many_arguments)]` on `execute` — the inputs
  are orthogonal spawn parameters, and grouping them would obscure the
  `program`/`args` split this fix relies on. Recorded in DECISIONS.md with
  the multi-call rationale.
- Gate: fmt, clippy, full test suite pass.
- **Next iteration must know:** the exec still re-opens the path, so replacing
  the target *file* (not the link) in the canonicalize→exec window, or a
  writable-directory race, is not closed. The item's "consider" (open once,
  `fexecve`/`O_PATH`) is the follow-up; the daemon currently also relies on
  `Command::new` doing PATH lookup only when the path has no `/`, which the
  protocol rules out. Next unchecked item is R.35 (allowlist/scope proof).

## 2026-11-03 — Retire the stale R.15b block and prove A-then-B end to end (TODO R.33)

- `TODO.md` R.15b is now `[x]` (was `[!]`, "blocked on 3.4/4.9", both long
  done). Evidence recorded there: `src/daemon.rs`'s `GrantCreate` arm
  re-checks `check_approvable` and spends one approval with
  `approvals.take(&request.digest(), ...)`; the handler test
  `src/daemon/tests.rs::grant_create_is_accepted_only_for_the_digest_the_human_proved`
  already covered A-then-B and A-then-A. No code change was needed; only the
  checklist was lying.
- Added the missing socket-level case,
  `tests/grant_create.rs::grant_create_refuses_a_different_request_than_the_one_proven`:
  prove digest A over the real daemon socket, submit request B (same shape,
  different expiry) -> `denied` and a byte-identical vault; then A ->
  `grant_approved`, vault still byte-identical; then A again -> `denied`.
- Mutation check: with `Approvals::take` changed to ignore the digest
  (`.position(|_| true)`), the new test fails (`grant_approved` where
  `denied` was expected). The file was restored; `git diff src/presence.rs`
  is empty.
- Docs: none changed. `MCP.md`/`DECISIONS.md` already describe the one-shot
  digest-bound approval (R.32 aligned them).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` pass (`cargo audit` not installed, skipped).
- **Next iteration must know:** the first unchecked item is now **R.34** (the
  canonical-path check but raw-path exec, i.e. a symlink swap runs an
  unlisted program with the secret). The review asked for R.34 *and* R.35
  before any Phase 3/4 feature work; R.35 is the e2e allowlist/scope test
  that would catch a regression of R.34's fix. `tests/grant_create.rs` starts
  a second `pmd` per test with cheap KDF params, so it is a good template for
  daemon-socket e2e cases.
## 2026-11-03 — Align security and protocol docs with the implemented flow (TODO R.32)

- `SECURITY.md` "Current status" now says grant authorization for `run` is
  implemented (3.1–3.6), that the audit log is still open (TODO 3.8–3.9), and
  lists the real session-token requests: `ping`, `lock`, `challenge`, `prove`,
  `grant_create`, `grant_revoke`. The stale `status`/`revoke` names are gone
  from `SECURITY.md` and `DECISIONS.md` (`status` never existed; `revoke` is
  `grant_revoke`). The grants bullet no longer presents the audit log as
  current.
- `DECISIONS.md` now says `pm grant create` (TODO 3.4d) creates grants in the
  human's CLI and `pmd` still has no write request, replacing "The CLI still
  cannot create a grant".
- `MCP.md`: the claim bullet said the daemon hands the grant token over, but
  the daemon never sees a token. It now says the MCP server mints the token
  (the former claim secret), sends only its SHA-256 exactly like
  `pm grant create`, and `request_claim` can only confirm approval and return
  metadata. `DECISIONS.md`'s token-custody line matches.
- Token-file modes: README and `MCP.md` now say "no group or world permission
  bits (0600 or 0400 in practice)", matching `src/grant/file.rs`
  (`mode & 0o077 != 0` is refused, owner-only bits are free).
- Tests: `tests/docs.rs` gains a `markdown_section` helper and four contracts —
  the "Current status" section has no "not implemented yet"/session-token-only
  claim, names each session-token request and TODO 3.8; `DECISIONS.md` names
  the CLI as grant writer; `MCP.md` says the daemon never holds a token and
  `request_claim` never returns one; README and `MCP.md` agree on 0600/0400.
  Each fails on the previous text.
- Gate: `cargo fmt --check`, clippy `-D warnings`, full `cargo test` pass
  (`cargo audit` not installed, skipped).
- **Next iteration must know:** TODO 4.8 still calls the flow a
  "claim-secret exchange" and its "token is claimed once" test wording should
  be read as "the pending request/claim is consumed once, and no token is
  returned". Next unchecked item is R.33 (stale R.15b checklist entry).
## 2026-11-03 — Close the grant-token existence oracle (TODO R.31)

- `src/daemon/run.rs::record_use` now decides everything that does not need
  the credential before `Vault::get_by_ref`: grant state (revoked, expired,
  uses left), the `run` capability and the command allowlist, via the new
  `Grant::check_grant_for_run` in `src/grant.rs`. Previously the lookup came
  first, so a revoked/expired/exhausted token answered `Denied` for an
  existing ref and `NotFound` for an absent one — an existence oracle for
  every ref in the vault.
- An existing ref outside the grant's scope now maps `Denied::OutOfScope` to
  `RecordError::NotFound`, exactly like a missing ref, as `DECISIONS.md`
  already promised. Other denials stay `Denied`.
- `authorizes` was refactored onto the shared `check_capability` /
  `check_command` helpers without changing its order, so grant decisions keep
  one implementation. The unit tests moved to `src/grant/tests.rs` (declared
  with `mod tests;`) because `src/grant.rs` would have crossed the 1,000-line
  layout test; it is now 970 lines.
- Tests: unit test in `src/grant.rs` (dead state wins over a command mismatch;
  LIST-only grant is `NotCapable(Run)`); `tests/daemon_run.rs` loops revoked,
  expired, exhausted and out-of-scope grants and asserts existing and absent
  refs get the same frame, no child ran and no use was counted;
  `tests/run.rs` asserts the same CLI exit status (5 for dead grants, 3 for
  out-of-scope) and no canary leak. The daemon test fails against the old
  order (`NotFound` vs `Denied`).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` not installed, skipped).
- **Next iteration must know:** the vault rewrites in both new tests reuse
  the container header with `crypto::encrypt_with_key`; the daemon re-opens
  the vault per `run`, so this is also a useful pattern for future state
  tests. A grant that is already expired can only be built by calling
  `Grant::create` with a `now` in the past (it refuses `expires_at <= now`).
  Next unchecked item is R.32 (stale security/protocol docs).

## 2026-11-03 — Review of 49d9915..03b7a31 (human-requested, outside the loop)

- Full review of the overnight run (iterations 21–78) by five parallel
  reviewers split by area (run/daemon, grants/authz, vault/crypto,
  protocol/CLI, tests/docs). Every finding was reproduced with a scratch test,
  the built binary, or a mutation, and the key ones were re-checked by hand.
- 21 new items, R.34–R.54, most severe first: authorization 5 (R.34 symlink
  swap runs an unlisted program with the secret — high; R.39, R.41, R.44,
  R.45), secret exposure 3 (R.36 redaction timing oracle, R.37, R.38), weak
  tests 3 (R.35 no e2e test of allowlist/scope enforcement — high; R.52,
  R.53), crypto/zeroize 2 (R.40, R.50), capacity/unsafe input 3 (R.42, R.46,
  R.48), correctness 2 (R.47, R.49), drift 2 (R.43, R.51), maintainability 1
  (R.54).
- Corrected R.31 (its proposed fix leaves the oracle open through revoked,
  expired and exhausted grants) and R.33 (the A-then-B daemon test exists).
- **Do R.34 and R.35 before any Phase 3/4 feature work.** R.34 is the first
  finding that lets an agent hand a secret to a program the human did not
  allow; R.35's tests are what would have caught it.
- Looked at and judged fine (do not redo): token storage as SHA-256 with
  constant-time compare and redacted Debug; `max_uses` under concurrency (16
  parallel runs on `max_uses=3` gave exactly 3); presence challenge/prove
  (single-use nonces, digest-bound one-shot approvals, eviction order); the
  canonical request digest; nonces/AAD on every save including
  `encrypt_with_key`; payload decode bounds; v1–v4 migration; sidecar lock
  and atomic write; frame codec and run-frame decoding bounds; grant-token
  file reading (`O_NOFOLLOW`, owner/mode, size cap) and `--out` creation;
  the reveal gate; R.29/R.30 escaping; accept loop, worker cap, process-group
  setup and signal handling; the R.20 test moves and R.21–R.28 tests.
- Note: `cargo test` from a Claude Code shell fails two `agent::tests`
  (R.52); the loop's gate under pi is unaffected.

## 2026-11-03 — Escape untrusted argv in every CLI error (TODO R.30)

- New `src/text.rs` owns the hidden-character table and three renderers:
  `escape_hidden` (display text, keeps quotes), `escape_quoted` (inside
  `'...'`, also escapes quote/backslash) and `escape_path` (a `Path`, quoted).
  Moved table and helpers out of `src/grant/validate.rs`; `grant` re-exports
  `escape_hidden` so call sites did not move.
- Escaped at the source: `EntryId::parse_ref`, `validate_tag` (both echo
  branches), `validate_field_name`; every path-bearing `Error` variant
  (`VaultNotFound`, `ReadOnlyVault`, `VaultBusy`, `VaultChanged`) and every
  user-text variant (`DuplicateService`, `ServiceNotFound`, `EntryNotFound`,
  `InvalidInput`, `Refused`, `Daemon`, format/crypto details) now go through
  `src/text.rs`. `warn_insecure` and `grant show`'s command list use
  `escape_path`.
- Backstop: `src/cli/mod.rs` escapes the usage message and the rendered
  runtime error line. Escaping escaped text is a no-op, so a future message
  cannot forget without failing `tests/cli_args_escape.rs`.
- Tests: new `tests/cli_args_escape.rs` drives the real binary with an OSC 52
  payload in `--env` name and reference, `--ref`, `--expires`, `--length`, an
  unknown flag and `--db` (both the permissions warning and the open error),
  asserting no raw ESC/BEL in stdout or stderr and that both are named.
  Verified all three tests fail at HEAD f4bea69. Unit tests in
  `src/store/tests.rs` and `src/grant/validate.rs` cover the validators.
- Gate: `cargo fmt --check`, clippy `-D warnings`, full `cargo test` pass.
- **Next iteration must know:** `--tag` on `add`/`grant create` is validated
  after the password prompt, so no integration case was added for it; the
  validator unit test covers it. `escape_hidden` is the display default;
  quoted contexts must use `escape_quoted`. Remaining Phase R items R.31–R.33
  are untouched.

## 2026-11-03 — Review of 4a16226..2208a50

- 4 findings: 1 authorization (R.31), 1 unsafe input/output or terminal
  injection (R.30), 2 drift/test gap (R.32, R.33). No new secret-printing
  path, no crypto misuse, no maintainability issue. Added R.30–R.33 to
  `TODO.md` (Phase R, at the top of the item list).
- R.30 (high): R.29 fixed only `--out`; parse and validation errors still
  interpolate agent-supplied argv (`--env` name/reference, `--ref`, `--tag`,
  `--expires`, `--length`, unknown flags, `--db`). Confirmed against the built
  binary: `--env $'API_KEY=pm://\e]52;c;ZXZpbA==\a'` prints the raw ESC/BEL;
  OSC 52 and line-erase sequences reach the human's terminal before any grant
  or password check. `src/store.rs` validators echo the value too.
- R.31 (medium): `record_use` (`src/daemon/run.rs:160-171`) returns
  `not_found` for a missing ref but `denied` for an existing out-of-scope ref,
  violating `DECISIONS.md:254-256`/`:591` and giving a grant token an
  existence oracle (CLI exits 3 vs 5).
- R.32 (medium): `SECURITY.md:14-16` still says grant auth is "not
  implemented" and `run` is session-token gated; `:23` omits `grant_create`;
  `:63-68` presents the audit log as current (TODO 3.8 open);
  `DECISIONS.md:405-407` says the CLI cannot create grants; `README.md:182`
  says 0600 but 0400 is accepted; `MCP.md:280-283` says the daemon hands the
  token over.
- R.33 (low): TODO R.15b is still `[!]`/blocked on completed 3.4/4.9, but the
  daemon spends one approval by digest and tests cover replay and a different
  digest.
- Confirmed fine: `src/grant/file.rs` (regular file, own uid, no group/world
  bits, `O_NOFOLLOW`, 128-byte cap, no token echo), `TokenFile` (`create_new`
  + 0600 + `O_NOFOLLOW|O_CLOEXEC`, drop on failure), approval digest binding
  and one-shot spend, `serve_run`/`record_use` order (authorize, record use,
  then decrypt and spawn; 8 retries with `VaultChanged` re-read), redaction
  and chunk caps, no daemon/client logging of secrets, all files <1,000 lines,
  and test suites with no fixed sleeps and real canaries.
- Checked, not filed: raw grant token hex in the JSON frame `Vec<u8>` is not
  zeroized (same systemic pattern as the session token and proof; same-user
  memory is out of scope); `read_grant_token`'s comment says one trailing
  newline while `trim_end()` accepts all trailing whitespace (safe,
  doc-only); `record_use` takes `now` once for up to 8 lock retries (expiry
  judged at arrival; needs a same-user flock holder); no daemon-level expiry
  test (grant unit tests cover expiry).
- `cargo test --quiet` passes (all suites and doctests). Only `TODO.md` and
  this entry changed.

## 2026-11-03 — Daemon authorizes `run` by grant (TODO 3.6)

- Protocol v4: `RunRequest.grant` is required. A v3 daemon would ignore the
  new field and authorize with the session token alone, so the version bump is
  a hard downgrade guard, not cosmetic. `GrantToken::from_hex` accepts exactly
  64 lowercase hex characters and never echoes the input.
- `pmd`: `serve_run`/`read_request` moved to `src/daemon/run.rs`. The daemon
  canonicalizes `command[0]`, matches the token's SHA-256 against a grant,
  re-checks active/scope/capability/command, then records `uses` and
  `last_used` in the vault **before** copying the secret or spawning. The
  read/check/write step retries up to 8 times on a changed or busy vault; any
  final write failure is `internal`, so a use is never served unrecorded.
- CLI: `pm run [--grant-file FILE]` (fallback `PASSMGR_GRANT_FILE`). New
  `src/grant/file.rs` refuses symlinks, foreign owners, group/world-readable
  modes and files over 128 bytes, opens `O_NOFOLLOW`, and zeroizes the hex
  text. Missing or insecure token exits 5 before anything runs.
- Denial is one opaque `denied`, including a command that cannot be
  canonicalized, so the socket is not an allowlist oracle.
- Decision: record the use before spawning, so a crash cannot exceed
  `max_uses`; a spawn failure still consumes a use (conservative). `run` now
  needs two independent things: the session token and a grant token.
- Tests: protocol v4 round-trip, v3 rejection, missing/malformed grant; grant
  file mode/symlink/oversize/uppercase canary; daemon wrong grant, no grant in
  the frame, valid run, persisted use count and `last_used`, immediate
  revocation, use-limited grant; CLI missing grant, explicit flag, 0644 file;
  `grant_cli` proves the daemon's hot key still serves a run after the CLI
  rewrites the vault. Run tests moved to `tests/daemon_run.rs`.
- Docs: help + fixture, README run example, SECURITY, DECISIONS, MCP.md
  protocol example (`version` 4).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped.
- **Next iteration must know:** the next unchecked item is 3.7 (TTY-local
  `pm run`). There is still no audit record (3.8); use counting happens before
  spawn, so failed execs consume uses. `record_use` treats any vault-write
  failure as retryable and ends in `internal`.
- NEEDS HUMAN REVIEW: the canonicalize-then-exec window means a symlink can
  be swapped after the grant check. This is the existing best-effort
  command-allowlist limit (the child is spawned via the caller's path), not
  new; it is documented in SECURITY.md.


## 2026-11-03 — Escape argv-supplied `--out` paths before echoing them (TODO R.29)

- `src/cli/grant.rs`: new private `display_path(&Path) -> String` renders a path
  through `grant::escape_hidden` (after `to_string_lossy`, so a non-UTF-8 path
  still renders) instead of `Path::display`. Both places that echo `--out` use
  it: the success line, now factored into `grant_created_message(label, out)`
  so a unit test can reach it, and the existing-token-file error inside
  `TokenFile::create`. The label is escaped the same way (its validation
  already refuses hidden characters, so this only guards a future loosening).
- Chose a pure formatting helper over a PTY test because the escaping problem
  is in string construction, not terminal state; the path is the only argv
  value echoed outside the approval summary, which already escaped its text.
- Test: `a_token_path_with_hidden_characters_is_rendered_as_text` builds an
  OSC 52 payload (`\u{1b}]52;c;...`) and a BEL on the success line and an
  ESC/CR file name for the existing-file error, asserting the `\u{..}` text is
  present, no raw ESC/BEL/CR is, and the existing file is untouched. It fails
  (raw escape in the message) when `display_path` is swapped back to
  `path.display()`.
- Docs: `DECISIONS.md` says argv-supplied paths are escaped wherever they are
  echoed; TODO R.29 is checked off with a Done note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.29 was the last Phase R item, so the next
  `- [ ]` item is TODO 3.6 (daemon authorizes `run` by grant). `src/cli/
  grant.rs` is at 971 lines — the next addition there should move the
  summary/rendering helpers into `src/cli/grant/summary.rs` first. Any other
  argv path echoed to a human (e.g. future `--file`/`--out` flags) needs the
  same `display_path` treatment; there is no shared module for it yet.

## 2026-11-03 — `revoke --all` touches only active grants (TODO R.28)

- One predicate now decides "active": `GrantStatus` (`Active`, `Expired`,
  `Exhausted`, `Revoked`) and `Grant::status(now)` live in `src/grant.rs`.
  `Grant::is_active(now)` and the private `check_active` both go through it,
  so authorization, `grant list`/`show` and `revoke --all` cannot disagree.
  `GrantStatus::name()` owns the words "active"/"expired"/"exhausted"/
  "revoked"; the CLI's duplicate `grant_status` helper is gone.
- `revoke_grants` (`src/daemon.rs`) filters `grant.is_active(now)` instead of
  `!grant.is_revoked()`. `--all` therefore leaves expired and exhausted grants
  untouched and reports only the grants it actually revoked. Matching the docs
  was chosen over redefining "active" to mean "not revoked": a human needs the
  count to mean "grants that were in force".
- Docs: `DECISIONS.md` and the `grant_revoke` section of `MCP.md` now state
  that expired, exhausted and already-revoked grants are untouched and never
  counted; `src/cli/help.rs` already said "every active grant" and is now true.
- Test: `src/daemon/tests.rs::revoke_all_leaves_expired_and_exhausted_grants_alone`
  builds one active, one expired and one exhausted grant in a real vault with
  an explicit `now`, calls `revoke_grants(..., All, now)`, and asserts the
  count is 1, the active grant is `Revoked` with `revoked_at == Some(now)`, and
  the others keep their `Expired`/`Exhausted` status and `revoked_at == None`.
  It fails against the previous filter (count 3, all revoked).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.29 (`--out` escaping, `src/cli/grant.rs`) is
  the next Phase R item. `src/grant.rs` is at ~981 lines; adding another
  model concern should split its tests into `src/grant/tests.rs` first. The
  CLI's `grant list`/`show` output text is unchanged by this item.
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


## 2026-11-03 — Human-presence proof in the daemon (TODO 3.3)

- New `src/presence.rs`: `ChallengeNonce` (32 random bytes, hex on the wire),
  `RequestDigest` (public 32-byte commitment to the request being approved)
  and `Proof` (`HMAC-SHA256(key, "passmgr-approve-v1" || nonce || digest)`),
  plus a `Challenges` store with single-use, 60 s expiry and a 16-nonce cap.
- Protocol: additive `challenge` request (answer `challenge` with the nonce)
  and `prove` request (answer `proven` or the new `denied` error code). No
  secret crosses the socket: nonce and digest are public, the MAC is
  key-derived and single-use. `client::challenge` / `client::prove` are the
  client half; no CLI command uses them yet.
- Daemon: `challenges` lives in `run` and is passed to `handle_connection`
  together with the key. A nonce is spent **before** the MAC is checked, so
  one issue allows exactly one attempt; unknown, expired, spent and
  wrong-MAC all answer `denied` (not an oracle), and a denial does not
  refresh the idle timer.
- Decisions (also in `DECISIONS.md`): `hmac` 0.12 (shares `digest` 0.10 with
  `sha2`; 0.13 would duplicate the tree) and `verify_slice` for the
  constant-time tag check. `Proof` zeroizes and renders `Proof(<redacted>)`;
  its `PartialEq` *is* the constant-time `matches`. Protocol version stays 3
  because the request types are additive. `client::prove` takes a
  `ProveRequest`, so 3.4 only has to build the digest and prompt.
- Tests: pinned HMAC-SHA256 vector from Python's `hmac` (proves domain, field
  order and hash), binding to key/nonce/digest, hex strictness, single use,
  60 s expiry (59 s accepted, 60 s refused, expiry spends the nonce), unknown
  nonce, the 16-nonce cap and pruning, redacted `Debug`; protocol
  round-trip/exact frames/malformed prove fields; client round trip and
  denial; end-to-end daemon acceptance, replay refusal, wrong-key/wrong-
  digest/unknown-nonce/burned-nonce denials, token requirement, and the MAC
  absent from `pmd` stdout/stderr.
- Gate: fmt and clippy `-D warnings` clean; full `cargo test` green (202 lib
  tests, 18 daemon tests). `cargo audit` not installed; skipped.
- **Next iteration must know:** 3.4 must reuse `presence::Challenges` — add
  the proof to the grant-create request and verify it inside the same
  request that writes the grant, or a proof consumed by a separate `prove`
  can no longer authorize the write. `RequestDigest` has no canonical
  constructor for grant fields yet; define it in 3.4 together with the
  exact bytes both sides hash. Do not add a daemon request that *computes*
  a MAC; only the CLI may do that.
  `src/protocol/mod.rs` is now 1,313 lines (about half tests), over the
  ~1,000-line guide; splitting it is a Refill candidate, not part of 3.3.

## 2026-11-03 — Persist grants in store version 5 (TODO 3.2b)

- `src/store.rs`: store version 5 = the v4 credential records, byte for byte,
  followed by `u32 grant count` and one record per grant (id, token SHA-256,
  capability bits, flags, timestamps, uses, label, refs, tags, field scope,
  commands). `encode(credentials, grants)` / `decode -> Payload` now carry
  both lists; `decode` keeps versions 1-4 readable and gives them no grants.
- `src/grant.rs`: `StoredGrant` (public fields, payload-decoder only) and
  `Grant::from_stored`, which re-checks every `create` invariant plus
  `uses <= max_uses` and absurd timestamps. The vault reader therefore cannot
  accept a grant that `pm grant create` would refuse.
- `src/vault.rs`: `grants` field loaded/saved with the credentials;
  `grants()`, `grant()`, `grant_mut()`, `add_grant()` (duplicate id refused).
- Decisions: optional grant fields use a flags byte, because a magic `0`
  timestamp would make `None` and 1970 indistinguishable; unknown capability
  or flag bits are malformed, not ignored. The codec stays in `store.rs`
  (sole owner of the format) and `grant.rs` stays a pure model, joined by
  `StoredGrant`. A duplicate grant id on `add_grant` is `InvalidInput`, not a
  new variant: nothing yet needs to distinguish it, and the error text names
  the id (never the token).
- Tests: store round trip with every optional field (used, revoked,
  max_uses, field scope, tag scope); v4 -> v5 migration keeps ids/tags and
  adds no grants; v1-v4 all decode grantless; empty vault is
  `05 00 …` while `04 00 00 00 00` still opens; duplicate grant ids,
  truncated grant records, unknown capability/flag bits, unknown field mode,
  oversize label, and encode refusing a duplicate or >1024 grants are all
  refused as `MalformedVault`/`InvalidInput`; `Payload`'s derived `Debug`
  keeps the password and the token hash out of the output. Vault: grants
  survive
  save/reopen/revoke; duplicate id refused. `tests/grant.rs`:
  `from_stored` rebuilds metadata and rejects each tampered field.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (189 lib tests).
  `cargo audit` not installed; skipped.
- **Next iteration must know:** nothing can create a grant yet; 3.3 (human
  presence proof) is the next item. `src/store.rs` is now 1,806 lines (roughly
  half tests) and `src/vault.rs` 1,145: splitting the codec out of the tests
  is worthwhile but was out of scope here. `Scope::new` sorts/dedups, so the
  decoder rejects duplicate refs/tags/fields/commands *before* calling it;
  keep that order if you refactor.

## 2026-11-03 — Reject bidi and zero-width characters in grant labels (TODO R.14)

- `src/grant.rs`: `validate_label` now rejects Cc controls plus the Unicode
  **format** set (bidi embeddings/overrides/isolates U+061C, U+200E/F,
  U+202A-202E, U+2066-2069; zero-width U+200B-200D, U+2060-2064, U+FEFF, soft
  hyphen, tag characters, …), the line/paragraph separators (U+2028/2029) and
  the variation selectors. Implemented as the explicit table
  `is_hidden_or_reordering`; no new dependency (a general-category crate for
  one check would be a new tree to vet).
- Chose **reject** over strip: the label is stored verbatim and re-rendered by
  `pm grant list` and may come from an approved agent request (4.9), so a
  silently altered label would not match what a human approved. Cost: an
  emoji ZWJ sequence (U+200D) in a label is refused; plain emoji, combining
  accents, Arabic and CJK stay allowed. Error text names the class, never
  echoes the label.
- Tests in `tests/grant.rs`: `create_rejects_hidden_and_reordering_label_characters`
  loops 29 forbidden code points (a table written out in the test, so it is an
  oracle independent of the module's) through `Grant::create`, asserts refusal
  and that the error does not echo the label; it fails against the old
  `char::is_control` check (verified). `accepted_labels_hold_only_visible_characters`
  proves visible labels round-trip and neither the label nor its `Debug`
  rendering holds a forbidden code point.
- `DECISIONS.md`: the label limit now records the reject-not-strip rule.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green. `cargo audit` not installed; skipped.
- **Next iteration must know:** the TODO's "`pm grant list` rendering" test
  cannot exist yet (3.5 builds it); the guarantee currently holds by
  construction at `Grant::create`, and 3.5 must render `label()` verbatim, not
  re-sanitize. `validate_service`/`validate_username` (`src/store.rs:348-368`)
  still reject only Cc and can carry the same bidi bytes; they are
  human-typed today, so they were left alone, but a later item should decide
  on a shared guard (and what to do with existing vaults) before those names
  are rendered widely. Next item is 3.2b (persist grants, store version 5).

## 2026-11-03 — Make `TokenHash` comparisons constant-time by construction (TODO R.13)

- `src/grant.rs`: `TokenHash` now derives only `Clone, Copy`; `PartialEq` and
  `Eq` are gone, so `a == b` on a secret-derived digest no longer compiles and
  `TokenHash::matches` (the constant-time loop) is the only comparison. No
  caller used `==` (grep of `src/` and `tests/` confirmed before the change).
  `as_bytes` stays public for payload encoding, with a doc line saying never
  to compare those bytes with `==`.
- Docs on the type now state the rule and carry two doctests: a
  `compile_fail` one (`left == right` must not compile) and a companion one
  that compiles the same setup and uses `matches`, so the compile-fail test
  cannot pass merely because the snippet is broken somewhere else.
- Chose a `compile_fail` doctest over the TODO's `trybuild` option: no new
  dev-dependency (so there is none to justify), the real compiler is the
  oracle, and it runs under the existing `cargo test`. `trybuild` would have
  pulled a new tree in for one assertion; a source-guard text parse would
  prove only the source text, not the type's API.
- Verified the test is real: with `#[derive(Clone, Copy, PartialEq, Eq)]`
  temporarily restored, `cargo test --doc` fails with "Test compiled
  successfully, but it's marked `compile_fail`"; reverted, it passes.
- `DECISIONS.md`: the grant-token line now records the no-`PartialEq` rule and
  the doctest that pins it.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` (including the two doctests) green. `cargo audit` not
  installed; skipped.
- **Next iteration must know:** `TokenHash` cannot be compared, sorted or used
  as a map key; 3.2b/3.6 must look grants up with `matches`/`matches_token`
  (hash the presented token, then scan). `as_bytes` remains a way to compare
  bytes manually, so a later review may want it restricted to encoding. Next
  item is R.14 (bidi/zero-width grant labels).

## 2026-11-03 — Stop the relay from reaping the process-group leader (TODO R.12)

- `src/runner.rs`: `relay` no longer takes `&mut Child`, and its timeout arm no
  longer calls `try_wait`. It only observes the cancel flag and waits for both
  pipe readers. The leader therefore stays an unreaped zombie while a
  grandchild keeps the pipes open, so `child.id()` is still a valid, reserved
  pgid when `terminate` signals `-pgid`; `terminate`'s "deliberately not
  reaped" comment is now true. The `Finished` path (both pipes at EOF) still
  reaps via `try_wait`; nothing signals a group after that path.
- Chose removal over "cache the pid and never derive it after a reap": the
  review's other option would still leave two sources of truth for the group,
  and the relay never needed the child's status -- the readers' EOF is the
  only signal it acts on. Cost: none; the `Finished` loop already polls
  `try_wait` once output is done.
- Test in `src/runner.rs`:
  `a_finished_leader_is_not_reaped_while_a_grandchild_holds_the_pipes` runs
  `sh -c 'echo $$ >leader; sleep 30 & echo $! >grandchild'`, waits for the
  leader's `/proc` state to become `Z`, then sleeps three `CANCEL_POLL`
  slices and asserts it is still `Z` (not reaped). It then cancels, asserts
  `RunError::Cancelled`, and polls until both pids are gone. Verified it fails
  against the old `try_wait` in the relay (temporary patch: `left: None`) and
  passes with the fix. `process_state`/`process_is_gone` are shared helpers.
- `DECISIONS.md`: the process-group decision now records the no-reap rule.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green. `cargo audit` not installed; skipped.
- **Next iteration must know:** a run whose leader exits while a grandchild
  holds a pipe now waits indefinitely for the pipe (as before) unless
  cancelled; TODO 4.5's per-call timeout is what bounds it. Do not reintroduce
  any `try_wait`/`wait` in the relay path or in anything that can run before
  `terminate`. Next item is R.13 (drop `TokenHash`'s `PartialEq`/`Eq`).

## 2026-11-03 — Scope-check list requests by construction (TODO R.11)

- `src/grant.rs`: `AccessRequest` is now an enum, not a struct with public
  optional fields. `AccessRequest::List { target, field }` and
  `::Run { target, field, command }` both carry a `Target`, so a request that
  names no credential cannot be built. `Grant::authorizes` checks scope for
  **both** capabilities and checks the command only for `Run`;
  `AccessRequest::capability()`/`target()` replace the old public fields.
  `AccessRequest::list()` (target-less) is gone; enumeration must authorize
  each candidate entry (documented in `MCP.md` and `DECISIONS.md`).
- Removed `Denied::MissingTarget`/`MissingCommand`: the type now makes those
  caller bugs unrepresentable. `scope_allows` stays public as a pure helper,
  documented as never a substitute for `authorizes`.
- Chose the enum over keeping the struct and adding `target: Option`: the
  review's complaint was that a separate `scope_allows` call was forgettable;
  a constructible target-less request leaves the same trap. Cost: a slightly
  larger diff now, no callers existed yet.
- Tests in `tests/grant.rs` (16 total): new
  `list_requests_are_scope_checked_like_run_requests` (ref scope and tag
  scope for `List`, deny `OutOfScope`) and `list_requests_respect_field_scope`
  (allows the named field, denies another field and `None`); the old
  missing-target/command assertions were deleted because the values no longer
  compile. Both new tests fail with the previous "List => Ok(())" logic
  (verified with a temporary patch, then reverted).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green (all suites). `cargo audit` not installed; skipped.
- **Next iteration must know:** `AccessRequest` construction changed shape;
  anything written from the old struct literal must use `list`/`run` (no
  callers yet). A field-restricted grant currently cannot list/describe any
  entry (`field: None` is out of scope), so 4.4 must filter list output per
  entry and 6.5 must decide how to show allowed field *names*; that is
  deliberate and conservative until then. Next item is R.12 (relay reap).

## 2026-11-03 — Review of 533b68d..92448ed

- 4 findings, all in `TODO.md` Phase R: 1 authorization (R.11), 1 unsafe
  process control (R.12), 1 crypto/API (R.13), 1 input/UI (R.14). 0
  secret-exposure, 0 test-quality, 0 drift, 0 maintainability findings.
- R.11: `Grant::authorizes` returns `Ok(())` for a List request without
  checking its target/field (`src/grant.rs:635`); latent until 4.4, but the
  "single decision point" cannot enforce list/describe scope and no test
  covers it.
- R.12: the relay timeout branch reaps the group leader
  (`src/runner.rs:316-318`), so a later `terminate` can signal a recycled
  pgid; contradicts its own comment at `src/runner.rs:347-348`.
- R.13: `TokenHash` derives `PartialEq`/`Eq` (`src/grant.rs:127`) against the
  `SessionToken` convention (`src/token.rs:27-31`) and the constant-time
  claim in `DECISIONS.md:341`.
- R.14: `validate_label` rejects only Unicode Cc (`src/grant.rs:708`);
  U+202E and U+200B pass (verified), so grant labels can spoof `pm grant
  list`/`show`.
- Looked at and judged fine: R.6 process-group kill/reap and lock-ack
  ordering (`tests/daemon_shutdown.rs`); R.7 idle suspension (a same-user
  client can already keep the daemon alive with pings, documented as not a
  boundary, bounded by lock/signals and TODO 4.5); R.8 16-run cap and
  Busy-before-decrypt (`tests/daemon_concurrency.rs`); R.9 prompt-before-lock
  and byte-for-byte `VaultChanged` (`tests/cli.rs`); R.10 MCP.md honesty and
  docs tests; grant scope/check-order/limits and redacting `Debug`;
  README/SECURITY/help drift; no new secret-exposing print or serialize call
  in the range. Full `cargo test` green.

## 2026-11-02 — Grant model and authorization check (TODO 3.2a)

- New pure module `src/grant.rs` (no I/O, no clock): `GrantId` (16 random
  bytes, 32 hex), `TokenHash` (SHA-256 of the raw token, constant-time
  `matches`, `Debug` prints `<redacted>`, no `Display`), `Capabilities` bit
  field (`list`=1, `run`=2, unknown bits rejected), `Scope`,
  `AccessRequest`, `Denied`, `GrantSpec`, and `Grant` with `create`,
  `authorizes`, `scope_allows`, `allows_command`, `mark_used`, `revoke`.
- Split the original 3.2 into 3.2a (this: model + rules) and 3.2b (store v5
  persistence, `FORMAT.md`, vault plumbing). It packed a format bump, a model
  and two new crates into one iteration; the rules are the part everything
  else (3.6, 4.4, 4.9) depends on.
- Rules and why (all in `DECISIONS.md`): scope = listed ref **or** every
  listed tag (reuses the AND semantics of `list --tag`); a field-restricted
  grant refuses a request that names no field (conservative until 6.1);
  expiry is exclusive (`now >= expires_at`); check order is revoked, expired,
  used up, capability, scope, command; commands compare as exact `Path`s
  because the daemon canonicalizes first; a run grant needs >= 1 command,
  a list-only grant may have none; grant lifetime <= 30 days.
- Dependency: added `sha2` 0.10 (RustCrypto) only; it reuses the `digest`
  0.10 already in the tree via `blake2`/Argon2, so no duplicate major.
  `hmac` was moved to TODO 3.3 (its first use, the presence proof) so no
  unused crate lands now.
- Tests: 14 integration tests in `tests/grant.rs` (public API only) cover a
  FIPS SHA-256 vector, id round-trip/bad hex, capability bits, every
  `create` rejection, command sorting/dedup, scope ref/tag/field matching, the
  full denial table (expired, revoked, used up, not capable, out of scope,
  command not allowed, missing target/command), `mark_used`/`revoke`, the
  `Target::from(&Credential)` conversion, and that `Debug` contains neither
  the token hash nor the token.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green. `cargo audit` not installed; skipped.
- **Next iteration must know:** 3.2a has no persistence and no CLI, so
  nothing can create a grant yet. 3.2b must add a decoder-side constructor
  (`Grant::restore`) because `create` derives `created`/`uses`/`revoked_at`
  from "now" and validates a future expiry; a stored expired grant must
  still decode. `Scope` and `Grant` have no `PartialEq` (only `Scope` does);
  if 3.2b's round-trip test wants grant equality, compare field by field or
  add a deliberate `PartialEq`. `src/grant.rs` is 763 lines, `tests/grant.rs`
  465; keep both under the ~1,000 line rule.

## 2026-11-02 — Make MCP.md honest about redaction and command resolution (TODO R.10)

- Docs only: `MCP.md` now says redaction replaces an **exact, contiguous byte
  sequence** and that encoded/transformed copies (hex, base64, percent, case)
  are not redacted until TODO 4.6. "Tests that must exist" 1 and 3 no longer
  require the impossible: test 1 asserts exact bytes now and adds hex/base64
  from 4.6; the `base64` red-team bullet moved to that note.
- `MCP.md`'s `run_with_credentials` rules now say the MCP server only does the
  convenience resolution and that the **daemon** canonicalizes `command[0]`
  itself (symlinks), keeps it absolute, checks the canonical path against the
  grant allowlist and execs that path; an uncanonicalizable path is refused.
  This removes the contradiction where a "daemon-enforced" allowlist was
  checked against a path the untrusted MCP server chose.
- `DECISIONS.md`: recorded that daemon-side canonicalization/allowlist rule
  (marked planned for 3.6/4.5, since `src/protocol/mod.rs` today only requires
  an absolute `command[0]`) and extended the exact-bytes redaction decision to
  MCP.md. No behavior or dependency changed.
- Tests: `tests/docs.rs` gains `mcp_documents_the_exact_bytes_redaction_limit`
  and `mcp_says_the_daemon_checks_the_canonical_command_path`, plus an `MCP`
  include. Both fail against the previous MCP.md (verified with `git stash`),
  so the drift cannot silently return.
- Gate: fmt, clippy `-D warnings`, full `cargo test` pass. `cargo audit` is not
  installed.
- **Next iteration must know:** R.10 is the last Phase R item; TODO 3.2 (grant
  model) is next. When 3.6/4.5 implement command authorization, follow the new
  MCP.md wording (canonicalize in `pmd`, check the canonical path) and update
  the DECISIONS line from "planned" to current. When 4.6 lands, restore the
  hex/base64 assertions in MCP.md test 1 and the red-team list, and update the
  two contract tests together with README/`--help`/SECURITY.md.


## 2026-11-02 — Prompt before taking the vault write lock (TODO R.9)

- `src/vault.rs`: new `Vault::empty` and `Vault::lock_for_update`. The latter
  takes the same `<vault>.lock` flock but first compares the on-disk container
  bytes with those the vault was decrypted from (`Vault.source`), returning
  the new `Error::VaultChanged` (exit 1, nothing saved) on mismatch.
  `src/error.rs` gains that variant. `add`/`edit` now read + validate
  lock-free, prompt for the master password and new secret through a temp
  `Vault::open`, and only then lock and save (`src/cli/commands.rs`).
- Chose optimistic locking over "prompt first, then check": duplicate and
  not-found checks must stay before the credential prompt (existing tests),
  and feedback for a wrong master password should not wait for a lock. Cost:
  still two KDF runs per write (open + save), no lock held across a prompt, no
  lost update. DECISIONS.md/README.md/SECURITY.md updated.
- Tests: unit tests for the changed-bytes refusal, the lock actually
  excluding other writers, and an empty vault that never replaces a file that
  appeared meanwhile; CLI tests spawn `add`/`edit`, poll stderr until the
  secret prompt appears (10 s deadline, kill on timeout), then assert the
  lock file does not exist yet (`add`) and that a test-held flock makes
  `edit` sit at the prompt rather than exit `VaultBusy` (`edit`). Both fail on
  HEAD.
- Gate: fmt, clippy `-D warnings`, full `cargo test` pass.
- **Next iteration must know:** `VaultChanged` is a new exit-1 error; anything
  that prints errors for writers may need wording. `open_for_add` is now
  unused by the CLI (kept, used by vault tests) — `delete` still uses
  `unlock_for_update`. Next item is R.10 (MCP.md drift).

## 2026-11-02 — Bound concurrent runs and worker creation (TODO R.8)

- `src/daemon.rs`: new `pub const MAX_CONCURRENT_RUNS: usize = 16`. An
  authenticated `run` arriving while 16 workers exist is answered with the
  terminal error `busy` before `Vault::open_with_key`, so nothing is
  decrypted, no child starts and no reader thread is created; a refused run
  does not refresh `last_activity`. Workers are created with
  `thread::Builder::name("passmgr-run").spawn_scoped`, whose `io::Result` is
  handled; a `try_clone` of the socket answers `busy` on failure. Previously
  `scope.spawn` panicked on OS thread exhaustion, unwinding out of the scope
  and skipping the worker join, `session::remove_if_matches`, the socket
  unlink and the key wipe.
- `src/protocol/response.rs`: added `ResponseError::Busy` / wire code `busy`.
  An error code is additive, so `PROTOCOL_VERSION` stays 3: an old daemon
  never sends it and an old client treats an unknown code as a closed decode
  failure. `src/cli/run.rs` maps it to exit 1 with a "wait for one to finish"
  message.
- Chose 16 over serializing runs: `lock`/signals already cancel, and 16 keeps
  realistic parallel work (build + tests + tools) working while bounding
  children, reader threads and `/proc/<pid>/environ` exposure.
- Tests: new `tests/daemon_concurrency.rs` fills the cap with 16 children that
  record their pid and sleep, sends 64 more runs, and asserts each gets one
  `busy` terminal frame, that no refused child ran (marker file absent), that
  exactly 16 pids started, that `ping` and `lock` answer within 2 s, and that
  `lock` reaps every child. Verified it fails at HEAD with the cap check
  disabled (`left: RunFrame::Exit(Code(0))`); ran 5× for flake.
- Docs: README `run` section, SECURITY "Daemon hardening", DECISIONS daemon
  section (cap, busy, no version bump). TODO R.8 checked off.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green
  (173/34/28/16/1/6/8/13/8; CLI suite ~143 s). `cargo audit` not installed.
- **Next iteration must know:** R.9 (lock held across prompts) is next. The
  cap counts workers that have finished but not yet been joined (joined at the
  top of each accept-loop iteration), so a burst right after a run finishes
  can still see `busy` for at most one 200 ms poll; nothing depends on that
  slack. Slowloris and total connection count are still unbounded (9.4).

## 2026-11-02 — An in-flight run suspends the idle timeout (TODO R.7)

- `src/daemon.rs`: `Handled::Run` now sets `last_activity = Instant::now()`,
  and the idle check is `runs.is_empty() && last_activity.elapsed() >=
  idle_timeout`. A command longer than the remaining budget finishes; the
  timer restarts when the last run is joined (the join already refreshes it).
  `lock`/`SIGTERM`/`SIGINT` still cancel an in-flight run as before.
- Chose to suspend the deadline rather than merely refresh it on accept:
  refreshing alone would still kill a run at the *next* deadline. Until TODO
  4.5 adds a run timeout, an in-flight run is bounded only by `lock`/signals
  (and by the human's own command). A session token holder can keep the key
  alive with a long child, but that holder is already same-user and `lock`
  always works; `DECISIONS.md` records the trade-off.
- Tests: replaced the two idle tests that depended on killing an in-flight
  run. `tests/daemon_shutdown.rs` now has
  `a_run_in_flight_is_not_killed_by_the_idle_timeout` (idle 3 s, wait 2.5 s,
  a 5 s child prints `done`; asserts the output and terminal frame, that
  `pmd` is alive afterwards, then that it exits on the restarted timer) and
  `idle_timeout_removes_the_socket_and_session_file_and_refuses_a_reconnect`
  (no in-flight run). The grandchild tests now cover `lock` and `SIGTERM`
  only, per the R.6 note. Verified the new in-flight test fails at HEAD with
  `the idle timeout killed the run: []`.
- Docs: `DECISIONS.md` (idle semantics), `README.md`, `SECURITY.md`,
  `src/daemon.rs` module/`run` docs, `--help` text and
  `tests/fixtures/help.txt`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green (173/34/28/16/6/8/13/8; CLI suite ~143 s).
  `cargo audit` not installed; skipped.
- **Next iteration must know:** R.8 (concurrency cap) is next. Adding a run
  timeout (TODO 4.5) must interact with this rule: the timeout, not the idle
  deadline, should bound an in-flight run, and its cancellation must keep the
  existing "no terminal frame on cancel" behavior. `tests/daemon.rs`'s
  `idle_timeout_wipes_the_key_and_stops_the_daemon` and
  `successful_requests_refresh_the_idle_timeout` still hold.

## 2026-11-02 — Kill the whole process group on cancel; answer `lock` after the wipe (TODO R.6)

- `src/runner.rs`: the child now gets its own process group (`pre_exec` +
  `libc::setpgid(0, 0)`). `terminate` signals the group with `SIGTERM`, waits
  `TERM_GRACE` (100 ms) *without reaping* (the zombie leader pins the pgid),
  then `SIGKILL`, then kills/waits the leader directly (covers a cancel racing
  the spawn). The pipe readers take an `Arc<AtomicBool> stop` and `wait_readable`
  polls it in `CANCEL_POLL` (100 ms) slices before each blocking `read`, so a
  grandchild holding the pipes can no longer block `abort`/`join_all`. A small
  `OutputPipe` trait (`Read + AsRawFd`, blanket impl) keeps the reader type a
  single trait object; `dyn Read + AsRawFd + Send` is not a legal trait object.
- `src/daemon.rs`: `run` owns the `Handover` instead of borrowing key+token, so
  it can zeroize the key *before* answering `lock`. `Handled::Locked` now
  carries the stream; the loop breaks, cancels and joins the workers, drops the
  socket (unlink + instance lock), removes the session file, drops the
  handover, and only then writes `Response::Locked`. `serve_run` returns early
  if the cancel flag is set before decrypting and again before spawning, so no
  child can start after the wipe began.
- Tests: `src/runner.rs::cancellation_kills_a_grandchild_that_holds_the_pipes`
  (unit; zombie-aware `/proc/<pid>/stat` check) and three integration tests in
  the new `tests/daemon_shutdown.rs` mirroring the R.6 script
  `sh -c 'sleep 30 & echo $! > pidfile'` for `lock`, `SIGTERM` and a 2 s idle
  timeout. The `lock` test also asserts the socket and session file are already
  gone when the client receives `Locked`; the others assert both are gone and
  the grandchild is reaped. Verified all three fail at HEAD (stashed `src/`)
  with "pmd did not exit in time".
- `tests/daemon.rs` hit 1,109 lines, so its fixture/helpers moved to
  `tests/support/mod.rs` (256 lines, `#![allow(dead_code)]` per-binary subsets)
  and the six cancellation tests to `tests/daemon_shutdown.rs` (274); the main
  file is back to 625. Also de-flaked `client::tests::serve_frames`: it now
  stops on a failed frame write instead of panicking, since a client that stops
  at a terminal frame closing early is the behavior under test (seen once under
  parallel load).
- Docs: DECISIONS.md (group kill, polled readers, ack ordering, `serve_run`
  re-check), README.md (`run` cancellation paragraph), TODO R.6 note.
- Gate: fmt, clippy `-D warnings`, full `cargo test` green (173/34/28/22/8/13/8,
  re-run 3× for the lib suite; the CLI suite takes ~143 s). `cargo audit` not
  installed.
- **Next iteration must know:** R.7 (idle timeout vs in-flight runs) will
  change the semantics my new `idle_timeout_cancels_a_run_whose_grandchild_…`
  test relies on — when fixing R.7, keep an idle-cancel test that uses
  `--idle-timeout 2` with *no* in-flight run plus reconnect, and make the
  grandchild test drive cancellation through `lock`/`SIGTERM` only. A child
  that calls `setsid`/`setpgid` itself escapes the group kill (readers still
  stop; the orphan keeps the injected env) — that is the caller's own command
  and is already covered by the documented exfiltration limit.

## 2026-11-02 — Review of 3500f6d..533b68d

- Findings: 5 — containment/shutdown 1 (R.6), run policy 1 (R.7), resource
  bound 1 (R.8), lock scope 1 (R.9), doc drift 1 (R.10). Secret exposure 0,
  authorization 0, crypto 0, maintainability 0 (the >1000-line files predate
  this range).
- R.6 is reproduced at HEAD with a scratch script: a child that leaves a
  grandchild on its stdout/stderr makes `abort` join a reader that can never
  see EOF, so `lock` prints "has wiped its key and stopped" while `pmd` keeps
  the key, socket and session file and the child survives. The R.1 tests close
  the pipes first (`exec >&- 2>&-`), which is why they pass.
- R.7 reproduced too: a run accepted 0.4 s before a 4 s idle timeout is killed
  0.4 s in ("the unlock daemon closed the connection before the command
  finished").
- Looked at and judged fine: the sidecar flock (`src/vault.rs:247-297` — 0600
  via fchmod on the fd, `O_NOFOLLOW|O_CLOEXEC`, `is_file()`, `flock` retry,
  never unlinked, 30 s `VaultBusy`, `save` refuses a read-only vault); the new
  vault tests (exclusion, no lost update, no torn read, symlink refusal) are
  not vacuous; protocol v3 `cwd`/`command[0]` absolute-path validation;
  `run` refusing `--db`/`PASSMGR_DB` (no bypass through global-flag order or
  `--`); caller-cwd/caller-PATH resolution; the exact-bytes redaction test
  (asserts base64 is relayed verbatim, so it would fail if encodings came
  back); `denied_env_name` re-checked in `pmd`; no new secret-bearing
  `println!`/`{:?}`/serialize in the diff.

## 2026-11-02 — Serialize vault writers with a sidecar flock (TODO 3.1)

- `src/vault.rs`: `Vault` gained a private `write_lock: Option<File>`.
  `Vault::open_for_update` and `open_for_add` call
  `acquire_write_lock_with_timeout`, which opens `<vault>.lock` (0600,
  `O_NOFOLLOW|O_CLOEXEC`, `flock(LOCK_EX|LOCK_NB)` retried every 10 ms) and
  keeps the descriptor until the `Vault` is dropped. The lock is taken
  **before** the vault is read, so the whole read-modify-write is inside it.
  `save` returns the new `Error::ReadOnlyVault` when no lock is held; the
  lock file is never unlinked (unlinking a held lock lets a second writer lock
  a fresh inode). Timeout is 30 s -> new `Error::VaultBusy` (exit 1, nothing
  changed).
- `src/cli/commands.rs`: new `unlock_for_update` used by `edit` and `delete`;
  `add` already goes through `open_for_add`. `get`, `list`, `show` and the
  daemon keep using lock-free `Vault::open`/`open_with_key`: atomic
  temp+rename makes readers safe and must not serialize `run` workers.
- Chose per-constructor locking over a separate writer type: `save` checking
  `write_lock` is a cheap fail-closed backstop, and the change stays inside
  `vault.rs`. Chose a 30 s bound over blocking forever so an unattended
  command cannot hang on a stuck process.
- Tests (`src/vault.rs`): exclusion + 0600 mode + release on drop + 100 ms
  `VaultBusy`; two concurrent writers where the second is provably blocked
  and both changes land (verified this fails without the lock: `beta` is
  lost); a reader polling `Vault::open` while a writer saves 3 times never
  sees a torn file; a planted `<vault>.lock` symlink is refused and its target
  untouched; a read-only vault refuses `save`.
- Docs: `DECISIONS.md`, `README.md` (security bullets) and `SECURITY.md`
  describe the sidecar lock.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` pass (`cargo audit` not installed; skipped).
- **Next iteration must know:** a shadowed `Vault` binding keeps the lock
  until end of scope, so tests/callers that reopen the same vault must
  `drop` the old one first. `command_add`/`command_edit` hold the lock while
  prompting for a credential password, so a second writer can hit the 30 s
  timeout; that is the conservative choice until prompts move before the
  lock. `pmd` still does not write the vault; when grant rows move into the
  payload, a key-based `open_for_update_with_key` and daemon writes must use
  the same lock, and the daemon's cached key must be revisited after a CLI
  re-encryption.
- NEEDS HUMAN REVIEW: none.

## 2026-11-02 — Scope documentation contracts to the limit that carries them (TODO R.5)

- Test-only change in `tests/docs.rs`; no product code and no document text
  changed. New pure helper `markdown_limit(markdown, number)` returns the
  normalized body of one `### N.` subsection, and `security_limit(number)`
  panics when the section is missing, so deleting a limit fails its contract
  instead of making it vacuous.
- `security_documents_the_proc_environ_limit` no longer asks the whole file
  for `same user` (which matched the session-file sentence at
  `SECURITY.md:16`). It now requires three contiguous phrases from limit 1:
  the `/proc/<pid>/environ` sentence, "it does not apply to the child, which
  is a separate process", and the "does not defend against malware already
  running as you" consequence.
- Applied the same scoping to the R.3 contracts: the "follow encodings or
  transformations" and "It is not a sandbox." assertions now read limit 3
  only. The R.4 contract already compares exact phrases in README and
  `--help`.
- Tests: new `limit_contracts_reject_the_phrase_from_another_section` feeds a
  synthetic document whose intro contains the exact disclosure sentence but
  whose limit 1 does not; the limit-1 contract rejects it while limits 1 and 2
  still extract their own bodies. Also verified manually that rewording limit
  1's key sentence now makes `security_documents_the_proc_environ_limit`
  fail (restored before commit).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` pass (`cargo audit` not installed; skipped).
- **Next iteration must know:** Phase R is now empty; the next unchecked item
  is 3.1 (vault write lock). When a document's wording changes, update the
  contiguous phrase in `tests/docs.rs` in the same commit; the helper accepts
  only one-phrase bodies, not "the idea appears somewhere".
- NEEDS HUMAN REVIEW: none.

## 2026-11-02 — Refuse `--db`/`PASSMGR_DB` for `run` (TODO R.4)

- `src/cli/args.rs`: `parse_args` now reads `PASSMGR_DB` once, passes it to
  `finish_parsing`, and calls `refuse_run_vault_selection` for a `Run` command.
  An explicit `--db` or a non-empty `PASSMGR_DB` is a usage error (exit 2)
  before the program is resolved or the daemon is contacted. The message names
  the offending source and says `run` always uses the vault of the running
  unlock daemon. Other commands keep flag > env > default.
- Chose the refusal branch over "name/verify the vault in the request": the
  daemon is keyed by the runtime socket, the session file stores no vault
  path, and a protocol change belongs with grants (3.6). Refusal is the
  conservative option and costs no new concept.
- Docs: `src/cli/help.rs` (run paragraph + `--db` note), the regenerated
  `tests/fixtures/help.txt`, `README.md` (vault-selection list and the `run`
  section) and a `DECISIONS.md` bullet.
- Tests: `src/cli/args.rs` unit tests for the flag, the env variable and the
  non-`run` commands (the env case calls the pure helper instead of mutating
  the process environment). `tests/run.rs`
  `run_refuses_db_selection_before_connecting_or_running` starts a daemon with
  vault A and passes a second vault B, once by flag and once by env: exit 2,
  the message names `--db`/`PASSMGR_DB`, a child marker file is never created,
  the canary is absent, and the daemon still answers `ping`. `command_at` now
  clears `PASSMGR_DB` so tests do not inherit it. `tests/docs.rs`
  `docs_say_run_refuses_an_explicit_vault` runs the real `--help` and pins the
  claim in README and `--help`; `plain()` now also strips backticks.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass (`cargo audit` not installed; skipped).
- **Next iteration must know:** `lock` still accepts and ignores `--db` (it
  only talks to the socket); R.4 deliberately scoped to `run`. A shell that
  exports `PASSMGR_DB` for `unlock --db` must unset it for `run` — the error
  says so. R.5 is next: its current test matches `SECURITY.md:16`, not the
  accepted-limit sentence, so rewrite it against `/proc/<pid>/environ` + a
  specific phrase, and reuse this contract style.
- NEEDS HUMAN REVIEW: none. The refusal makes the previously silent
  ambiguity loud, which is the safer failure.

## 2026-11-02 — Stop promising encoded-secret redaction (TODO R.3)

- Docs only; no code changed. `README.md`, `src/cli/help.rs` and its golden
  `tests/fixtures/help.txt` now say an **exact, contiguous occurrence** of the
  injected secret is replaced with `[REDACTED]`, and that encoded or
  transformed copies (base64, hex, percent-encoding, case changes) are not;
  the README cites `SECURITY.md` limit 3 instead of promising "common
  encodings".
- Chose R.3's documentation branch, not "implement 4.6 first": 4.6 (hex,
  base64 std/url-safe with and without padding, percent-encoding, plus
  refusing <8-byte secrets for agent runs) is a multi-concept change and must
  not share an iteration with a review fix. The leak is now disclosed instead
  of falsely denied; `SECURITY.md` already described it correctly.
- `tests/docs.rs`: new `help_text()` helper runs the real `passmgr --help`;
  `docs_agree_that_redaction_does_not_follow_encodings` asserts README,
  `--help` and `SECURITY.md` limit 3 all state the exact-byte rule and that no
  document claims "common encodings". This is the contract style R.4 and R.5
  should reuse.
- `tests/run.rs`: `redaction_replaces_only_the_exact_secret_not_its_encodings`
  runs a child that prints the canary and its base64; the raw value is
  `[REDACTED]` and the encoded copy is relayed verbatim, pinning the
  documented limit. The base64 is computed in the test, so it needs no
  external binary on the child's fixed `PATH`.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` pass. `cargo audit` is not installed; skipped.
- **Next iteration must know:** the redactor is still exact-bytes only, so
  `run --env K=pm://… -- sh -c 'printf %s "$K" | base64'` still yields the
  value; that is limit 3 and the reason TODO 4.6 exists (and why an
  interpreter needs `--allow-interpreter`). When 4.6 lands, update README,
  `--help` + fixture, `SECURITY.md` limit 3, this docs contract and the
  `tests/run.rs` pin in one commit.
- NEEDS HUMAN REVIEW: none beyond the accepted limit itself.


## 2026-11-02 — Run children in the caller's cwd and resolve commands client-side (TODO R.2)

- `src/protocol/mod.rs`: protocol version 3. `RunRequest` gains a required
  absolute `cwd`; `run.command[0]` must be an absolute path, and both are
  validated on encode and decode (`validate_absolute_path`: non-empty, no NUL,
  at most `MAX_PATH_BYTES`, leading `/`). A version-2 daemon would ignore
  `cwd`, so the bump turns a silent wrong-directory run into an
  `unsupported_version` refusal.
- `src/runner.rs`: `execute` takes the caller's cwd and sets
  `Command::current_dir`, so relative arguments resolve where the caller meant.
- `src/cli/run.rs`: resolves `command[0]` before contacting the daemon — a
  bare name through the **caller's** `PATH` (empty entries skipped, regular
  executable files only), a name containing `/` against the caller's cwd, and
  an absolute path as given. Unresolvable bare names are a usage error (exit
  2) before the daemon is asked to run anything; an absolute nonexistent path
  still reaches the daemon and is reported as `spawn_failed` (exit 1), which
  keeps the existing refusal mapping. `cwd` is sent as the caller's absolute
  directory.
- Tests: runner unit test proves a relative argument resolves in the given cwd;
  protocol tests cover relative `command[0]`, relative/empty/NUL/overlong
  `cwd`, a missing `cwd`, and the new field set. E2E (`tests/run.rs`): a daemon
  started in A and a CLI in B, both with `rel.sh`, runs B's script; a bare
  name resolves through the CLI's `PATH`, not the daemon's; an unresolvable
  name is exit 2 and the daemon stays healthy. `tests/daemon.rs` fixtures now
  send `cwd: "/"` and absolute programs.
- Docs: `DECISIONS.md` (protocol v3 + run cwd/PATH policy), `README.md`,
  `src/cli/help.rs` and its golden fixture, `MCP.md` (the MCP server, not the
  daemon, resolves the program and sends `cwd`).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass. `cargo audit` is not installed; skipped.
- **Next iteration must know:** a child that itself execs a bare helper name
  still resolves that helper through the daemon's inherited `PATH` (the fixed
  allowlist), not the caller's — only `command[0]` is resolved client-side.
  That is consistent with `MCP.md` ("child's PATH") but surprising; if it
  matters, R.3/R.4 can document it or the daemon can be given the caller's
  `PATH` for the child later (do not widen the allowlist without a decision).
- NEEDS HUMAN REVIEW: the daemon trusts the caller-supplied absolute `cwd`
  and program path. That grants no new privilege (the token holder can already
  name any absolute program), but a grant-scoped allowlist in 3.6/4.x must
  match on this resolved absolute path, not on the agent's original text.

## 2026-11-02 — Serve runs concurrently and cancel them on lock/signal/idle (TODO R.1)

- `src/daemon.rs`: `run` is decoded and authenticated on the accept thread,
  but `serve_run` now runs on a `std::thread::scope` worker, so `ping`,
  `lock` and signal handling stay responsive while a child runs. The loop
  reaps finished workers (and counts them as activity) on every iteration.
  A shared `AtomicBool` cancel flag is set on `lock`, `SIGTERM`/`SIGINT` and
  the idle timeout; the scope joins every worker before the key is dropped.
- `src/runner.rs`: the `Relay::Finished` path no longer blocks in
  `child.wait()`; it polls `try_wait` (i.e. `waitpid(WNOHANG)`) every 100 ms
  and aborts when cancelled. The relay loop also checks the flag before each
  receive, so a child that keeps the channel full cannot delay cancellation.
  An interrupted run writes no terminal frame, so the client reports a
  `Daemon` error rather than a fake exit status.
- Tests (tests/daemon.rs): three e2e cases run a child that closes both
  pipes and sleeps 30 s — `lock` returns `Locked` in under 2 s and the child
  is reaped, `SIGTERM` stops `pmd` in under 2 s and reaps the child, and a
  `--idle-timeout 2` daemon exits and reaps the child while the run is live.
  Each polls with deadlines and asserts the socket is gone.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass.
- **Next iteration must know:** concurrent runs are now possible in the
  daemon; R.1 did not add a cap on simultaneous runs or connections (that is
  TODO 9.4's slowloris/idle-client work). Each worker re-opens the vault, so
  N parallel runs mean N Argon2-free key unlocks (key is already derived).
  A cancelled run is indistinguishable from a client disconnect to
  `serve_run`; neither writes a frame, which the CLI already maps to a
  `Daemon` error.

## 2026-11-02 — Review of 49d9915..3500f6d

- Reviewed the whole range (26 files, +6340/−2583): the new `src/runner.rs`,
  `src/cli/{run,args,mod}.rs`, `src/protocol/response.rs`, the streaming
  reader in `src/client.rs`, `serve_run` in `src/daemon.rs`, `SECURITY.md`
  and `tests/{run,docs}.rs`, plus `PROMPT.md`, `MCP.md`, `DECISIONS.md` and
  the archived TODO. `cargo test` passes on the range (16 daemon, 8 run,
  8 cli, 5 docs, 0 failures); `cargo audit` is still not installed. No source
  changes were made.
- Five findings, now `## Phase R` in `TODO.md`: authorization 1 (R.1),
  unsafe exec/path resolution 1 (R.2), documentation drift 2 (R.3, R.4),
  ineffective test 1 (R.5). No secret-exposure, crypto or maintainability
  finding. The session-token-only gate on `run` (TODO 3.6) and unaudited run
  frames (TODO 3.8) are the documented transition, not new findings.
- R.1 reproduced outside the suite: with a run child that closes both pipes
  and sleeps, `passmgr lock` timed out after 5 s and `pmd` was still alive
  2 s after SIGTERM (the daemon serves `run` inline on its accept thread, and
  the `Relay::Finished` path waits without polling the cancel flag). R.2
  reproduced with the daemon started in one directory and the CLI run from
  another: the daemon's copy of `./rel.sh` executed with the secret injected.
  Both scratch harnesses lived in `/tmp/pmreview` and are not committed.
- Looked at and judged fine (do not redo): the peer-uid check in
  `accept_peer`; constant-time token comparison and the session file's
  0600/`O_NOFOLLOW` handling; frame, chunk, argv and password bounds with
  no-panic parsers on arbitrary bytes; redacting `Debug` for `RunFrame`,
  `SessionToken` and `LockedKey`; the daemon-side loader/shell-hook denylist
  and its live-daemon test (`tests/daemon.rs:744`); redaction before the
  socket plus the raw-socket canary test; no new `println!`/`format!`/JSON
  path can carry a secret; no new file over ~1000 lines (`src/protocol/mod.rs`
  shrank from 1244 to 1080 when `response.rs` was split out). The CLI
  denylist test's `!marker.exists()` cannot fail (no daemon runs), but its
  exit-5 and stderr assertions still catch a CLI regression and the daemon
  test covers the actual spawn.
- Accepted and documented, not findings: `/proc/<pid>/environ` for the
  injected child, interpreter exfiltration, the partial-prefix output flush,
  `[REDACTED]` vs `MCP.md`'s `[REDACTED:<VAR>]` (Phase 4), and the `--db`
  note already in the previous entry. Do not expose `run` to MCP before R.1
  and 3.6 are fixed.

## 2026-11-02 — Document the accepted limits in `SECURITY.md` (TODO 2.7)

- New `SECURITY.md` (the file already referenced by `src/daemon.rs`,
  `src/redact.rs`, `src/runner.rs` and `src/token.rs` but never written):
  what passmgr protects, then seven accepted limits — (1) a same-user process
  can read an injected value from the running child's `/proc/<pid>/environ`
  (daemon hardening does not apply to the child), (2) an allowlisted
  interpreter or shell is equivalent to handing the agent the secret, (3)
  redaction is output-only and best-effort (no encodings, no other channels),
  (4) plaintext at a terminal/clipboard/rendered file leaves our control, (5)
  vault permission violations are warned about, not yet refused (8.10), (6)
  swap/hibernation and best-effort `mlock`, (7) out of scope: root,
  keyloggers, malicious same-user processes, compromised agent hosts.
- `SECURITY.md` also carries an honest **Current status** section: grants are
  not implemented yet and the session token is not an agent/human boundary
  (TODO 3.6 closes that). `README.md`'s security section now links to it, and
  `src/token.rs` no longer says "once TODO 2.7 lands".
- Decision (also in `DECISIONS.md`): `SECURITY.md` is the canonical limit
  list; a change that alters a limit updates it in the same commit.
- Tests: new `tests/docs.rs`, 5 compile-time doc contracts (`include_str!`,
  instant): `/proc/<pid>/environ` + "same user", interpreter exfiltration +
  `--allow-interpreter`, redaction is not a sandbox, the transitional
  session-token gap names TODO 3.6, and README links to SECURITY.md.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes.
  `cargo audit` is not installed; skipped, not installed.
- **Next iteration must know:** next unchecked item is **3.1** (vault write
  lock). When 3.6 lands, rewrite `SECURITY.md`'s "Current status" and update
  `tests/docs.rs::security_discloses_the_transitional_session_token_gap` in
  the same commit — that test exists to force the disclosure to be revisited,
  not to be deleted silently. TODO 9.7 later expands `SECURITY.md` into a full
  threat model; keep the README's crypto details there rather than duplicating
  them.
- **NEEDS HUMAN REVIEW:** the macOS sentence ("no `PR_SET_DUMPABLE` equivalent
  set by passmgr, so same-user ptrace/memory inspection of `pmd` is not closed
  here") is intentionally conservative and untested on this Linux machine; the
  exposure is admitted rather than claimed safe.

## 2026-11-02 — CLI `run` streams through the daemon (TODO 2.6d)

- New `src/cli/run.rs`: `command_run` validates the env name against the
  daemon's denylist (local refusal, exit 5, no socket), loads the session
  token, sends one `RunRequest`, and relays non-terminal frames to its own
  stdout/stderr (flushed per frame). Exits with the child's code; signal N
  renders as 128+N (the wire keeps them distinct). Terminal refusals map:
  `not_found` 3, `spawn_failed`/`bad_request`/`internal`/`unauthorized`/
  `unsupported` 1; no daemon -> 1 with "start one with 'passmgr unlock'".
- New `client::run(paths, token, &RunRequest, on_frame) -> RunOutcome`:
  streaming reader over `FrameDecoder` + `RunStream` ordering guard. No read
  timeout (silent children are legitimate); EOF before a terminal frame is a
  `Daemon` error. `decode_frame_body` restores the length prefix the decoder
  strips. Exposed `protocol::valid_env_name` so the CLI grammar cannot drift
  from the wire grammar (agreement test).
- `src/cli/args.rs`: `Command::Run(RunOptions)` via `parse_run`; exactly one
  `--env NAME=<ref>` (protocol injects one value), `--` required, argv after
  it is never re-parsed, limits (`MAX_ARGS`, `MAX_ARG_BYTES`, ref syntax)
  checked locally for a usage exit 2.
- Help text gained a `run` entry, example and note; `tests/fixtures/help.txt`
  regenerated deliberately; README documents `run`; DECISIONS gained the
  grammar/exit/stream-reader rules.
- Tests: 5 client unit tests (relay order, refusal, truncation, stop at first
  terminal, malformed frame), 3 parser tests, 2 code-mapping unit tests, a
  protocol grammar-agreement test, and 8 `tests/run.rs` e2e tests (injection +
  both-stream redaction, exit 7 passthrough, SIGTERM -> 143, agent mode with
  non-TTY stdio, no-daemon message, loader-name refusal with no spawn, usage
  exit 2, not-found 3 + spawn failure 1 with the daemon still healthy).
- Gate: fmt, clippy -D warnings, full test suite pass.
- **Next iteration must know:** `--db` is ignored by `run` (the daemon owns
  the vault it was started with); there is no multi-secret run yet; `run`
  frames are still unaudited until 3.8, and `run` is still session-token
  authorized until 3.6, so MCP must not expose it yet.

## 2026-11-02 — Daemon executes `run` with redacted output (TODO 2.6c)

- New `src/runner.rs` (cfg(unix)): `execute(argv, env_name, secret, inherited,
  cancel, emit)` spawns an argv (never a shell string) with stdin null, a
  fixed env allowlist, and exactly one injected variable. Two reader threads
  each own a `Redactor`; one output thread relays frames in order, checks the
  daemon's cancellation flag every 100 ms, splits redacted bytes at
  `MAX_CHUNK_BYTES`, and kills/reaps the child on output failure or cancel.
  `denied_env_name()` refuses loader/shell-hook names; `inherited_env()` keeps
  only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ`, `TMPDIR`,
  `TERM`.
- `src/daemon.rs`: `handle_connection` now takes the vault path and key.
  `Request::Run` resolves the ref with `EntryId::parse_ref`, opens the vault,
  copies only that password into a `Zeroizing<String>`, drops the vault
  (zeroizing the rest), then streams `RunFrame`s. Terminal outcomes:
  `Exit(code|signal)`, `Error(not_found)`, `Error(spawn_failed)`,
  `Error(bad_request)` for a denied env name, `Error(internal)` if the vault
  cannot be read. A failed run never kills the daemon.
- `ResponseError::Internal` added (`internal`) with round-trip coverage.
- Tests: 11 runner unit tests (allowlist, denylist, injection + redaction,
  no inherited test-process env, 10 KB secret split across 8 KiB reads,
  multi-frame 40 KB output, exit 7, SIGTERM, bad program, invalid env name,
  output failure/cancel kill the child) and 4 new daemon e2e tests
  (stdout+stderr redaction with canary absent from raw socket bytes and pmd
  output, not-found vs spawn-failed both non-fatal, every denied env name
  refused without spawning, 40 KB output split into bounded frames with a
  4096-byte secret redacted). The old "run is unsupported" assertion now
  expects `not_found`.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes
  (159 lib + 20 bin + 28 CLI + 16 daemon + 8 unlock). `cargo audit` not
  installed; skipped.
- **Next iteration must know:** TODO 2.6d owns `passmgr run` and the client
  stream reader (`src/client.rs` still reads exactly one response). Two
  deliberate edges for later: (1) a `lock` request cannot interrupt an
  in-flight `run` because the daemon serves one connection at a time; only
  SIGTERM/SIGINT (via the cancel flag) stops it — timeouts/process groups are
  TODO 4.5. (2) The redactor marker is `[REDACTED]`, while `MCP.md` promises
  `[REDACTED:<VAR>]`; Phase 4 must either extend the redactor or amend
  `MCP.md`. Run frames are not audited yet (3.8).
- **NEEDS HUMAN REVIEW:** until TODO 3.6, `run` is authorized by the session
  token alone, so any same-user process that can read the 0600 session file
  can use a stored secret. This ordering is inherent in `TODO.md` (2.6 before
  3.6) and is recorded in `DECISIONS.md`; do not expose an MCP tool for it
  before 3.6.

## 2026-11-02 — Protocol streaming `run` responses (TODO 2.6b)

- `src/protocol/response.rs` (new; moved out of `src/protocol.rs`, which is now
  `src/protocol/mod.rs`) adds `RunFrame` (`Stdout`/`Stderr`/`Exit`/`Error`),
  `RunExit` (`Code` or `Signal`), `RunStream` ordering state, and
  `encode_run_frame`/`decode_run_frame`. `Response`/`ResponseError` and the
  one-shot encoders moved with them; `crate::protocol::*` re-exports the same
  public API.
- Wire shape: `{"version":2,"response":{"type":"stdout","data":"<lowercase
  hex>"}}`; `exit` carries exactly one of `code` 0..=255 or `signal` 1..=127;
  `error` carries a stable code. Raw chunks are capped at `MAX_CHUNK_BYTES`
  (16 KiB) on encode *and* decode, and the cap is checked before hex decoding.
  `not_found` is added and deliberately also covers out-of-scope refs (no
  existence oracle); `spawn_failed` is the child-spawn error.
- Decisions: `RunFrame` is a distinct type from `Response` so one-shot and
  streaming responses cannot be confused; nothing follows a terminal frame
  (`RunStream`); signal deaths stay distinct from 128+N; protocol version
  stays 2 because only new response types were added, no request change. All
  recorded in `DECISIONS.md`.
- Tests (lib `protocol`, 34 pass): binary/UTF-8-invalid payload round-trips,
  chunk cap at/over the limit and hand-built oversized frames, malformed run
  frames (wrong types, non-hex/uppercase/odd hex, unknown codes, version 1,
  trailing bytes), one-shot/stream confusion, `RunStream` after-terminal
  rejection, stable error codes, and `Debug` never rendering child bytes.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes
  (148 lib + 20 bin + 28 CLI + 12 daemon + 8 unlock). `cargo audit` is not
  installed; skipped, not installed.
- **Next iteration must know:** 2.6c owns the daemon side: answer `Request::Run`
  by streaming `RunFrame`s through `encode_run_frame` (the daemon still
  returns `unsupported` today) and redact before encoding. `src/protocol/mod.rs`
  is 1045 lines (request/framing + its tests) and `response.rs` 776; split
  further only if it grows. Do not add a plaintext-bearing frame variant.

## 2026-11-02 — Split the CLI into `src/cli/` modules (TODO H.2)

- `src/main.rs` is now 7 lines (`mod cli;` + `fn main` -> `cli::main`).
  New modules: `src/cli/mod.rs` (entry, dispatch, `stdout_write`,
  `report_runtime_error`, the moved unit tests), `src/cli/args.rs` (all
  parsing, `Command`/option types, `DEFAULT_DB`), `src/cli/commands.rs`
  (local commands, prompts, JSON metadata, `unlock` helper, `warn_insecure`),
  `src/cli/unlock.rs` (`command_unlock`/`command_lock`, both cfgs) and
  `src/cli/help.rs` (`USAGE`, `HELP`). No behavior change.
- Visibility: items are `pub(crate)` and re-exported with globs from
  `cli/mod.rs`, so the moved test module still works with `use super::*`
  and every test body is unchanged. Struct fields are `pub(crate)`; enum
  variant fields inherit the enum's visibility (a field modifier there would
  not compile).
- `--help` byte-identity: captured `tests/fixtures/help.txt` from the
  **pre-split** binary (7933 bytes, md5 `8c185a1d9b9cdf012ededd6c00f331b6`)
  and added `help_output_matches_the_golden_file` in `tests/cli.rs`, which
  compares exact stdout. This is the before/after proof H.2 asked for; do not
  regenerate the fixture to "fix" a failure — a diff means behavior changed.
- Flaky test fix (test harness only, not shipped behavior): the full-suite
  run hit `write request: BrokenPipe` in
  `unauthorized_requests_do_not_refresh_the_idle_timeout`. The daemon can
  expire between `connect` and `write_all`, but `tests/daemon.rs::try_request`
  used `.expect("write request")`, so the probe loop's `_ => break` never ran.
  It now propagates the write error (`?`), the same class of fix as the
  iteration-21 read fix. The test's assertions are unchanged; ran it 5x
  alone and once in the full suite.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` passes (139 lib, 20 bin, 28 CLI, 12 daemon, 8 unlock;
  CLI is +1 for the golden help test). `cargo audit` is not installed;
  skipped, not installed.
- **Next iteration must know:** next is **2.6b** (protocol `stdout`/`stderr`/
  `exit` frames). Add new commands as `src/cli/<group>.rs` modules, not by
  growing `mod.rs`; keep each file under ~1,000 lines. `--help` is now a
  tested contract: update `tests/fixtures/help.txt` deliberately in the same
  commit when help text changes. `DECISIONS.md` has the layout decision.

## 2026-11-02 — Create `DECISIONS.md` (TODO H.1)

- New `DECISIONS.md` (~280 lines, 90 bullet entries): one-line standing
  decisions grouped as scope/naming, crypto, vault format and versions, CLI
  conventions, exit codes, daemon/protocol, grants/approval/MCP, dependencies
  and testing conventions.
  `TODO.md` H.1 is checked with a note that the file also covers dependencies
  and `MCP.md`. Cherry-picked from the rolled-back iteration-21 branch and
  re-verified; the only code change is the flaky-test harness fix below.
- Sourced from `PROGRESS.md`, `PROGRESS-archive.md`, `TODO-done.md`, `MCP.md`
  and a read of `src/error.rs`, `src/agent.rs`, `src/crypto.rs`,
  `src/protocol.rs`, `src/socket.rs`, `src/session.rs`, `src/store.rs`,
  `src/vault.rs` and `src/main.rs`, so each line is checked against the code,
  not only against older prose.
- Conventions chosen for the file: one decision per line; "Planned" marks a
  decision from `MCP.md` that the code does not implement yet; the exit-code
  section carries the full 0-6 mapping plus the `Crypto`-stays-1 rationale; an
  explicit "Open questions (not decided)" section keeps undecided behavior out
  of the decision list.
- Corrections made while extracting: the daemon has **no** `ok` response and
  no `not_found`/`spawn_failed` code yet (recorded as `pong`/`locked`/fixed
  error codes, with 2.6b planned); container version and store version are
  separate counters that both have a "version 1" with different meanings, so
  that is now stated in one place.
- Flaky-test fix: iteration 21's gate failed in
  `unauthorized_requests_do_not_refresh_the_idle_timeout` with
  `ConnectionReset` while reading a response, because the daemon can expire
  between accepting a connection and replying. That is expected, but the test
  helper `read_response` panicked instead of returning `Err`, so the loop's
  `_ => break` never ran. Added `try_read_response` (io::Result) and made
  `try_request` propagate the error; the test semantics are unchanged (it
  still requires repeated `unauthorized` replies and a prompt expiry).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` passes (139 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock).
  `cargo audit` is not installed on this machine; skipped, not installed.
- **Next iteration must know:** next is **H.2** (`src/main.rs` -> `src/cli/`,
  no behavior change, `--help` byte-identical). `DECISIONS.md` is the place to
  check a constraint before inventing one; if an iteration changes a decision,
  edit its line there *and* explain why in the new PROGRESS entry.
- **NEEDS HUMAN REVIEW:** `tests/daemon.rs` builds fixture vaults with
  `KdfParams::new(8 * 1024, 1, 1)` (the minimum bound) to keep the suite fast,
  which is arguably "weakening the KDF to speed up tests" even though the
  shipped default is untouched and the file does not test the KDF). Left as
  is; `DECISIONS.md` records the current practice. A human should rule on
  whether fixture-only cheap params are acceptable.
- Minor doc drift found, not fixed here: `--help` in `src/main.rs` states the
  tag rules twice, and README still says insecure vault modes are "warned
  about" while TODO 8.10 will make them a refusal. H.2 (help text is asserted
  byte-identical) must not "fix" the duplicate; do it in a later help/README
  item.


## 2026-11-02 — loop note: gate failed (iteration 21)

- Commits from this work iteration (TODO H.1) failed the gate and were rolled back.
- The work is kept on branch failed/iter-21-20261102-202146; you may cherry-pick from it and fix it.
- gate: `unauthorized_requests_do_not_refresh_the_idle_timeout --- FAILED`
- gate: `thread 'unauthorized_requests_do_not_refresh_the_idle_timeout' (414411) panicked at tests/daemon.rs:127:36:`
- gate: `test result: FAILED. 11 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.15s`
- gate: `error: test failed, to rerun pass `--test daemon``

## 2026-11-02 — Streaming output redactor (TODO 2.6a)

- New `src/redact.rs`, exported from `src/lib.rs`. No new dependency
  (`zeroize` was already present).
- `Redactor::push(&[u8]) -> Vec<u8>` streams child output. It scans a pending
  buffer and appends safe bytes to the output; on a complete occurrence it
  appends `[REDACTED]`. The longest suffix that is still a proper prefix of the
  value is held back (at most `secret.len() - 1` bytes) until the next push, so
  a value split across two reads is caught. `finish()` flushes a trailing
  partial prefix: a prefix is not the value, and holding it forever would
  truncate legitimate output.
- Matching is greedy left-to-right and operates on bytes, so binary output
  works (no UTF-8 assumption). Overlapping occurrences are consumed in order;
  the replacement marker cannot recreate the value at a boundary because it is
  itself scanned only as normal output.
- Marker: `[REDACTED]` unless that literal contains the value (e.g. the value
  is `[REDACTED]`, `REDACTED`, `D]`, `ACT`). In that case a run of a byte that
  does not occur in the value is used, so the marker cannot contain it and no
  occurrence can span the marker boundary. `finish()` is safe to call once;
  callers must not reuse a redactor afterwards.
- Secret lifetime: the value lives in a private `Vec`, is never exposed via
  `Debug`/`Display` (Debug prints only `secret_len`/`pending_len`), and the
  value plus the pending overlap are zeroized on drop. `discard_prefix` uses
  `copy_within`, then zeroizes the stale duplicate of the retained tail before
  truncating, so no fragment stays in the spare capacity.
- Documented limit (also for `SECURITY.md`, TODO 2.7): redaction protects the
  agent's context from accidental output. It is not a sandbox — the child has
  the value in its environment, so a hostile child can exfiltrate it through
  files, the network, or `/proc/<pid>/environ`. Only an exact contiguous
  occurrence is replaced.
- Tests (12 in `src/redact.rs`): whole/repeated occurrences, a split at every
  byte offset of the input, byte-at-a-time input, arbitrary chunk sizes,
  overlapping values (`aba`/`ababa`, `aa`/`aaaaa`), binary bytes with NUL and
  `0xff`, empty value passthrough, `finish` flushing a trailing prefix and
  releasing a disproved one, pending bound strictly below the value length,
  fallback marker for values that are substrings of `[REDACTED]`, and redacted
  `Debug` both fresh and half-consumed.
- Gate: `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes (139 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock);
  `cargo audit` is not installed on this machine.
- Next: 2.6b adds `stdout`/`stderr`/`exit` frames to the protocol; 2.6c wires
  `Redactor` into the daemon's `run` handler; 2.6d adds the CLI reader. Audit
  log assertions for `run` stay in 3.3.

## 2026-11-02 — Session token for the unlock daemon (TODO 2.5)

- New `src/token.rs` (`SessionToken`): 32 OS-random bytes from `getrandom`,
  rendered as 64 lowercase hex characters on the wire and in the session file.
  Bytes live in `Zeroizing`, `Debug` is `SessionToken(<redacted>)`, there is no
  `Display` and deliberately no `PartialEq` (`matches()` uses a branch-free-ish
  XOR loop), so accidental comparison or printing is hard.
- New `src/session.rs` (Unix): `store`, `load`, `remove`, `remove_if_matches`
  for `$XDG_RUNTIME_DIR/passmgr/session`. `store` goes through `ensure_dir`
  (0700, owner-only) and writes a `tempfile` in that directory with mode 0600,
  `fsync`s, renames and `fsync`s the directory. `load` is strict: regular file,
  owned by the current uid, mode **exactly** 0600, opened `O_NOFOLLOW`, bounded
  read (512 bytes); anything else is an error, never "repaired". This turns a
  planted symlink or loosened mode into a visible failure.
- Handover: `pmd` now reads `key(32) || token(32)` from the inherited stdin pipe
  (`daemon::read_handover`, exactly 64 bytes then EOF; wrong length or trailing
  data refuses to start). Neither value appears in argv or the environment.
- Protocol version 2: the envelope is
  `{"version":2,"token":"<64 hex>","request":{...}}`; the token is required on
  every request type and parsed *before* the request, so an unauthenticated
  peer cannot reach request parsing. Malformed/missing token → `bad_request`
  (no echo); well-formed but wrong token → new `unauthorized` response code.
  `protocol::decode` returns `AuthenticatedRequest` (redacted `Debug`).
- Daemon: `run(vault, runtime_dir, key, token, idle)` compares
  `authenticated.token().matches(token)` first and answers `unauthorized` with
  `Handled::Rejected`, which does **not** refresh the idle timer — a client
  with the wrong token cannot keep the key in memory. On any exit path
  (`lock`, signal, idle) the daemon removes the session file only if it still
  contains its own token (`remove_if_matches`), so it cannot delete a newer
  session's token after a fast re-unlock.
- Client/CLI: `client::request/ping` take a token, `lock` loads it from the
  session file and removes it after `Locked`. `unlock` clears a stale file,
  generates and stores the token *before* spawning `pmd`, passes it through the
  pipe, and removes the file again if the spawn fails. If the session file is
  missing, `lock` still probes the socket first so "no daemon is running" is
  reported precisely instead of blaming authentication.
- Wire compatibility: protocol version 1 frames are now rejected. This is
  local IPC between `passmgr` and its own `pmd`, both from this build, so no
  migration path is needed; the version field is what makes the mismatch
  explicit rather than a confusing parse error.
- Known limit (recorded in `src/token.rs`/`src/daemon.rs` docs): the token is
  **not** an agent/human boundary. Any same-user process can read a 0600 file,
  so it proves only what the socket's peer-uid check already proves. It stops
  an accidental or stale client and makes an unauthorized request explicit;
  scoped, revocable authorization arrives with grants (TODO 3.1).
- Tests (all passing): 10 new lib tests — token hex round-trip, strict
  lowercase-hex rejection, length check, redacted `Debug`; session store/load
  0600 with no leftover temp file, refusal of 0644/symlink/directory/missing,
  scoped removal, insecure runtime dir. Protocol: envelope now carries exactly
  `["request","token","version"]`; missing/wrong-type/non-64-lowercase-hex
  tokens rejected on ping/lock without echoing the token; decoded token matches
  what was encoded; `Debug` of `AuthenticatedRequest` hides it; exact-frame
  assertions updated to version 2. Daemon e2e: wrong token gets `unauthorized`
  and cannot `lock` the daemon; token absent from socket bytes, `/proc/cmdline`
  and daemon stdout/stderr; unauthorized pings every 200 ms for 4 s do not
  refresh a 2 s idle timeout; a malformed token frame is `bad_request`. CLI e2e:
  session file is 0600, its token appears in no output, a 0644 session file is
  refused (daemon untouched) and works again after `chmod 600`, and both `lock`
  and an idle timeout remove the session file.
- Gate: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes: 127 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock.
  `cargo audit` is not installed on this machine.

## 2026-11-02 — Idle timeout for the unlock daemon (TODO 2.4c)

- `src/daemon.rs`: new `DEFAULT_IDLE_TIMEOUT = 15 * 60` s, shared
  `parse_idle_timeout(&str)` (whole seconds, zero refused, no upper bound) and
  `run(vault, runtime_dir, key, idle_timeout)`. The accept loop checks
  `last_activity.elapsed() >= idle_timeout` at the top of every iteration
  (200 ms poll, so it stops within ~200 ms of the deadline unless a client is
  mid-request; a stalled request can delay it by at most the 5 s read
  timeout). Exiting drops `LockedKey` (zeroize + `munlock`) and then
  `DaemonSocket` (unlink + instance-lock release), and exits 0, exactly like
  `lock`/SIGTERM.
- Activity is defined as a **successfully decoded request after the peer
  check**, not raw bytes or connections. `handle_connection` now returns
  `Handled::{Served, Rejected, Locked}`: `Ping`/`Run` (well-formed) refresh the
  timer, a parse failure answers `bad_request` without refreshing, and `Lock`
  stops the daemon. This stops garbage traffic from keeping the key alive.
- Config surface: `pmd --idle-timeout SECS` (help updated) and
  `passmgr unlock --idle-timeout SECS` / `--idle-timeout=SECS`, parsed by the
  shared `parse_idle_timeout` and passed through `client::spawn_daemon(...)`
  as an extra argument. `None` means the default, applied in `command_unlock`.
  Unlock's stdout now reports the effective timeout as a `Duration` (`900s`).
  `Command::Unlock` carries `idle_timeout: Option<Duration>`; non-Unix builds
  keep a stub parser that accepts a bare `unlock` and refuses the flag.
- Security note recorded in the `daemon.rs` module docs: the idle timeout is a
  second line of defense, **not** an authorization boundary. Until the session
  token (2.5) and grants (3.1) land, any same-user process can send `ping` and
  keep the daemon alive. It still guarantees that an untouched session does
  not hold the key forever.
- Tests: 1 new lib test (`parse_idle_timeout` accepts positive whole seconds,
  default is 900 s, rejects `0`/empty/negative/fraction/unit/whitespace), 1 new
  CLI parse test (default `None`, both flag forms, zero/word/missing value
  rejected), 3 new `tests/daemon.rs` e2e tests (short timeout exits and removes
  the socket; pings every 250 ms for 4 s keep it alive past a 2 s timeout, then
  it expires; rejected frames every 200 ms for up to 4 s do not refresh, with
  an elapsed-time bound so a refresh bug fails), and 1 new `tests/unlock.rs` pty
  test proving `unlock --idle-timeout 1` reaches the daemon (prints `after 1s`,
  process disappears and socket is removed without `lock`).
- Gate: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes: 112 lib, 20 bin, 27 CLI, 9 daemon, 7 unlock. The
  CLI suite is Argon2-bound (~150 s). `cargo audit` is still not installed
  here (`no such command: audit`); run it where available.
- No new dependency, no crypto/vault-format change, no protocol change.
- Next: **2.5 session token file** — write a random token to
  `$XDG_RUNTIME_DIR/passmgr/session` (0600) at unlock, have requests carry it,
  reject mismatches. Keep the token out of argv, the environment and all
  output. Do not weaken the peer-uid check and do not add a plaintext request.

## 2026-11-02 — `pm unlock` / `pm lock` CLI (TODO 2.4b)

- New `src/client.rs` (`#[cfg(unix)]`): the client half of the daemon protocol
  — `ping`, `lock`, `spawn_daemon` and a generic `request`. Frame writes and
  reads are bounded (`MAX_MESSAGE_BYTES` + prefix + 1 byte via `take`), every
  connection has a 5 s timeout, and readiness polling is bounded at 10 s.
  `spawn_daemon` finds `pmd` next to the current executable, passes `--vault`
  and `--runtime-dir` (never the key), writes exactly the 32-byte key into
  `pmd`'s stdin and then closes it. Its stderr goes to an anonymous,
  immediately unlinked `tempfile` (0600): the daemon must not inherit the
  caller's stderr pipe, or `Command::output()` would block forever once the
  caller exits and later daemon writes would hit `EPIPE`. Startup failures
  report the exit status plus a bounded (8 KiB) excerpt of that log.
  After a successful ping the child is re-checked after one poll interval, so
  a pre-existing daemon answering the ping cannot mask our child dying on the
  instance lock.
- `pm unlock`: refuses in agent context with exit 5 **before** prompting (new
  `agent::check_human`, shared with `get --reveal`; the message is produced by
  `RevealRefusal::message_for(action)` so both call sites read naturally).
  Then: pre-check the socket (a live daemon means "run 'passmgr lock' first",
  exit 1), read the vault container, prompt once, derive + **authenticate**
  the key with `crypto::unlock_key`, drop the password and the container, then
  hand the key to `pmd`. A wrong password exits with the existing wrong
  password code and starts nothing. Prints the pid and a hint to stdout.
- `pm lock`: needs no TTY (it can only stop the daemon, never reveal
  anything), sends `lock`, and reports that the key was wiped. Without a
  daemon it exits 1 with the existing `SocketError::NotRunning` message.
- Both commands are Unix-only, with non-Unix stubs, matching `pmd`.
  `parse_command` rejects extra arguments; `--help` documents both.
- Fixed an intermittent, real single-instance race found while stress-running
  the new tests: `acquire_lock` could see `EWOULDBLOCK` for a few
  milliseconds after the previous holder's `DaemonSocket` was dropped on
  another thread (the final `fput` of a descriptor closed by a non-owning
  thread is deferred to that thread's task work). The instance lock now
  retries every 5 ms for up to 250 ms before reporting
  `SocketError::AlreadyRunning`. The lock is still exclusive — a live daemon
  holds it for its whole lifetime — so this only stops a just-exiting daemon
  from being reported as running, which would otherwise also hit `unlock`
  immediately after `lock`. Two tests pin it down: a live holder is still
  rejected, and a holder that releases within the grace window is acquired.
- Tests: 6 new lib tests in `src/client.rs` (round-trip, error passthrough,
  clear missing-daemon error, non-JSON/empty/oversized-prefix responses
  rejected without a panic, short key refused before spawning, startup
  failure reports status and log), 1 new `src/socket.rs` test, and
  `tests/unlock.rs` (6 e2e tests, Linux pty where a TTY is required): non-TTY
  refusal (exit 5, no prompt), agent-marker refusal on a pty, unlock → ping →
  lock round-trip with the secret absent from all output and from
  `pmd`'s argv and `/proc/<pid>/environ`, duplicate unlock refused without a
  prompt, wrong password exits 4 and starts no daemon, `lock` without a
  daemon. The e2e test writes the password to the pty before the child
  disables echo, so the pty echo can contain the password; that is a harness
  artifact, not a product leak (nothing else ever writes it).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` pass (111 lib, 19 bin, 27 CLI, 6 daemon, 6 unlock; the CLI
  suite is Argon2-bound, ~150 s). `cargo audit` is not installed here; run it
  where available.
- Decisions recorded: `Error::Daemon(String)` (exit 1) carries only daemon
  transport failures; unlock deliberately does **not** re-prompt when a
  daemon is already running (it tells the human to lock first) so a second
  unlock can never silently replace a running daemon's key.
- Next: 2.4c idle timeout, then 2.5 session token (the socket is currently
  authorized by peer uid only, so any same-user process may `ping`/`lock` —
  acceptable for now: no request returns plaintext and `lock` is a DoS at
  worst).

## 2026-11-02 — Unlock daemon core and `pmd` (TODO 2.4a)

- Split the original 2.4 into **2.4a** (this entry), **2.4b** (`pm unlock` /
  `pm lock` CLI) and **2.4c** (idle timeout), so each stays one iteration.
- New `src/daemon.rs` (`#[cfg(unix)]`, registered in `src/lib.rs`) and
  `src/bin/pmd.rs`. The daemon holds **only the derived 32-byte key**, never
  the decrypted vault: `Vault::open_with_key` decrypts on demand when `run`
  lands (2.6) and the plaintext is dropped immediately. Decided against
  keeping a decrypted `Vault` in memory for the daemon's whole lifetime.
- Key handover: `pmd` reads exactly `KEY_LEN` bytes from stdin (the inherited
  pipe from `unlock`, 2.4b) and then requires EOF; short, long or trailing data
  is refused. The key is never in argv or the environment. `LockedKey` keeps
  it in a stable `Zeroizing<Vec<u8>>`, `mlock`s it best-effort, and `munlock`s
  before zeroizing on drop. `Debug` prints only `mlock` state, no bytes.
- Hardening: `RLIMIT_CORE` 0 (fail closed) and Linux
  `prctl(PR_SET_DUMPABLE, 0)` (fail closed); `setsid()` best effort. On macOS
  there is no `prctl`, so core dumps are disabled but same-user `ptrace`
  exposure remains — TODO 2.7 must record that limit in `SECURITY.md`.
- Startup order: harden -> install SIGTERM/SIGINT handlers -> `setsid` ->
  verify the key against the vault -> bind the socket. A wrong key therefore
  never creates a socket or makes `pmd` look alive. The `DaemonSocket` is held
  for the whole loop (instance `flock` stays held) and dropped on lock/signal,
  removing the socket.
- Loop: non-blocking `accept_peer()` with a 200 ms sleep, so
  `SIGTERM`/`SIGINT` (handler only stores an `AtomicBool`) exits/wipes within
  ~200 ms. One request per connection, 5 s read/write timeout. `ping` ->
  `pong`; `lock` -> `locked` then wipe/exit; `run` -> `unsupported` (2.6);
  malformed, truncated, oversized, empty and unknown-type frames ->
  `bad_request`. `PeerRejected`/`PeerCheckFailed` are ignored and the owner
  keeps being served. No request can return a secret value.
- Protocol: added `Response { Pong, Locked, Error(ResponseError) }`,
  `ResponseError { BadRequest, Unsupported }` with stable codes
  `bad_request` / `unsupported`, `encode_response` / `decode_response`, and
  `ProtocolError::UnknownResponse`. The response schema is fixed and has no
  value field. Unknown response types/codes are rejected; echoed type names
  are truncated to 32 chars.
- Crypto reuse for the handover: split `decrypt` into
  `derive_vault_key(container, password, out)` and
  `decrypt_with_key(container, key)`, with `unlock_key(...)` deriving and
  authenticating in one step. `Vault::open_with_key` added. No parameter,
  format or ciphertext change: existing vaults still open unchanged.
- Tests: 11 new crypto/vault/protocol unit tests (key derive/decrypt split,
  wrong key, length checks, no key echo, response round-trip/fixed shape,
  unknown type/code, malformed frames, arbitrary bytes) and 5 `daemon.rs` unit
  tests (short/trailing key, length check, no bytes in `Debug`, no echo).
  New `tests/daemon.rs` (6 e2e tests, fast Argon2 params): ping/lock removes
  the socket and exits 0; SIGTERM and SIGINT exit cleanly and remove it;
  empty/oversized/truncated/unknown/`run` requests rejected without a crash
  and the daemon still serves; wrong key exits non-zero with no socket; a
  second daemon is refused while the first keeps serving; the generated
  secret appears in no response bytes, stdout/stderr, cmdline, or readable
  `/proc/<pid>/environ` (dumpable=0 usually makes the last unreadable).
- No new dependency (`libc` and `zeroize` already present). No network, store
  or audit-log change.
- Gate: `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` 156 passed (104 lib, 19 bin, 27 e2e CLI, 6 daemon e2e;
  CLI e2e is Argon2id-bound and serialized, ~148 s). `cargo audit` still not
  installed (`error: no such command: audit`).
- **Next iteration must know:** next is **2.4b** (`unlock`/`lock` CLI). Spawn
  `pmd` with the key on a pipe, wait for a `ping`/`pong` readiness check, and
  refuse `unlock` unless stdin and stdout are TTYs and no agent marker is set.
  Do not add any request that returns plaintext. Idle timeout is still absent
  (2.4c), so a daemon stays unlocked until `lock` or a signal. `mlock` failure
  is intentionally non-fatal and currently silent; if that matters, surface a
  warning without key material.

## 2026-11-02 — Peer credential check (TODO 2.3)

- `src/socket.rs` now verifies the connecting user before any request byte is
  read. New `PeerCredentials { uid, gid, pid: Option<i32> }` plus
  `peer_credentials(&UnixStream)` and `PeerCredentials::verify(expected_uid)`.
  Linux/Android read `getsockopt(SO_PEERCRED)` into `libc::ucred`; macOS/iOS
  call `libc::getpeereid` (no pid available, so `pid()` is `None` there). Both
  syscalls are validated: non-zero return is an error and Linux also requires
  the kernel to report exactly `size_of::<ucred>()` bytes. Any other Unix
  target returns `SocketError::PeerCheckUnsupported` and the daemon fails
  closed — no unchecked accept path exists on an unsupported platform.
- `DaemonSocket::accept_peer()` is the intended accept path. It calls
  `listener.accept()`, reads the peer credentials, compares the uid with
  `geteuid()`, and only then returns `(UnixStream, PeerCredentials)`. On
  mismatch the stream is dropped immediately (no reply, nothing read) and
  `SocketError::PeerRejected { expected, actual }` is returned. Documented in
  the module header that 2.4 must use `accept_peer()`, not `listener()`; the
  latter is kept public only for tests/explicitly validated callers.
- The check is **not** an authorization boundary on its own: any process
  running as the same user passes it. It separates users; the session token
  (2.5) and grants (3.1) separate agents from their owner. That limit is
  written in the module docs so it is not mistaken for more. PID is reported
  but never used for authorization (pids are reused).
- Error variants added: `PeerRejected`, `PeerCheckFailed(io::Error)`,
  `PeerCheckUnsupported`; all have `Display` text with uids only, and
  `source()` exposes the syscall error. `SocketError` remains module-local and
  is not wired into the CLI exit-code contract (2.4 decides the mapping).
- Tests: 3 new lib tests. `peer_credentials_report_the_current_user` (uid/gid
  match, Linux pid is our pid, macOS pid is `None`, free function and accept
  helper agree, a second connection still accepts);
  `accept_peer_rejects_a_foreign_uid_and_closes_the_connection` (client writes
  a request-shaped message, accept is forced to expect `uid+1`, gets
  `PeerRejected` with both uids, and the client reads EOF/reset with no
  reply); `verify_rejects_a_different_uid_with_a_clear_message` (unit-level
  forced-failure check plus message contents). No second user account needed.
- No new dependency (`libc` already present). No store, protocol, CLI or
  crypto change. The socket/lock/dir behavior from 2.2 is untouched.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 134 passed (88 lib + 19 bin + 27 e2e, ~150 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next is **2.4** (`pm unlock` / `pm lock`, idle
  timeout, SIGTERM/SIGINT wipe, `mlock`, `prctl(PR_SET_DUMPABLE, 0)`). Wire the
  accept loop to `DaemonSocket::accept_peer()` and keep the `DaemonSocket` (and
  therefore the `flock`) alive for the daemon's whole lifetime. There is still
  no request type that returns plaintext. Until 2.5 lands, authorize only the
  local session written at unlock; do not add a bypass. On Linux, remember
  that a rejected peer's socket is dropped without a response — do not turn
  `PeerRejected` into a wire error message.

## 2026-11-02 — Socket setup module (TODO 2.2)

- New `src/socket.rs` (registered in `src/lib.rs` as `#[cfg(unix)] pub mod
  socket;`). No daemon binary yet; this is the socket-placement layer that
  TODO 2.4 will bind. No CLI surface change.
- Paths: `RuntimePaths::resolve()` -> `$XDG_RUNTIME_DIR/passmgr` when that
  variable is set and non-empty, else `<temp_dir>/passmgr-<euid>` (macOS has
  no `XDG_RUNTIME_DIR`; `env::temp_dir()` is the per-user `$TMPDIR` there).
  The uid suffix keeps two users sharing a temp dir from colliding, and the
  directory checks below fail closed on anything pre-created by someone else.
  Files inside: `pmd.sock` and `pmd.lock`.
- `RuntimePaths::ensure_dir`: `create_dir` + `set_permissions(0700)` when it
  does not exist; when it does, `symlink_metadata` (never follows a symlink)
  must show a real directory, owned by `geteuid()`, mode exactly 0700.
  Otherwise `SocketError::InsecurePath` and no socket is created. Chose
  **refuse, not repair**, for an existing directory: a 0755 dir may already
  have been observed, so silently fixing it would hide a real exposure.
  Parents are never created (`create_dir`, not `create_dir_all`): a missing
  `XDG_RUNTIME_DIR` is a broken environment, not something to paper over.
- Single instance: `flock(LOCK_EX|LOCK_NB)` on `pmd.lock` (0600, created via
  `OpenOptionsExt::mode`, then `set_permissions` to narrow an old file).
  `EWOULDBLOCK` -> `AlreadyRunning`. The lock file is deliberately **not**
  unlinked on drop (unlinking while holding it lets a second daemon lock a
  fresh inode); the socket is unlinked on drop only if its inode still matches
  the one recorded at bind time.
- Ordering in `DaemonSocket::bind_at`: length-check the path (<= 104 bytes,
  the macOS `sun_path` limit, so a path that works on Linux also works there),
  validate/create the dir, take the lock, then probe the socket, then bind,
  then chmod 0600. Locking before probing means two simultaneous starts cannot
  both conclude "stale".
- Stale-socket rule: `symlink_metadata`; symlink or non-socket -> `NotASocket`
  and the file is left untouched; foreign uid -> refused; then a probe
  `UnixStream::connect`: success -> `AlreadyRunning` (never steal a live
  socket, even if the lock file was deleted), `ECONNREFUSED` -> unlink and
  rebind, `NotFound` -> race, fine. The probe connection is closed immediately;
  2.4's accept loop must tolerate a peer that connects and disconnects.
- The socket is chmodded 0600 *after* bind because bind applies the umask.
  Documented in the module: the 0700 directory already keeps other users out,
  so the window is not externally reachable; the chmod is defence in depth.
- `connect()` / `connect_at()` map `NotFound` and `ConnectionRefused` to
  `SocketError::NotRunning` so 2.6 can tell the user to run `pm unlock`.
  `SocketError` is a module-local enum (like `ProtocolError`) with `Display`
  and `std::error::Error`, not wired into the CLI exit-code contract yet; 2.4
  decides the mapping. No secret values exist anywhere in this module.
- Tests: 15 lib tests in `src/socket.rs` — XDG vs fallback resolution (empty
  XDG treated as unset), dir/socket/lock modes 0700/0600/0600 plus a real
  client-listener byte round-trip, reuse of an existing 0700 dir, second daemon
  rejected while the first keeps working, stale socket replaced, live socket
  without a lock not stolen (original listener still accepts), regular file at
  the socket path preserved, symlinked dir refused, 0750 dir refused with the
  mode named in the error, overlong path rejected before any I/O (no directory
  created), drop removes the socket but keeps the lock and releases it, connect
  with no daemon and with a stale socket both report `NotRunning`, `flock`
  conflict/release on the same path.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 131 passed (85 lib + 19 bin + 27 e2e, ~150 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`). No new dependency (`libc`, `tempfile`
  already present).
- **Next iteration must know:** next is **2.3** (peer credential check:
  `SO_PEERCRED` on Linux via `getsockopt`, `getpeereid` on macOS, before any
  read). Add it to `src/socket.rs` or a small `src/peer.rs`; the accepted
  stream from `DaemonSocket::listener()` is where to call it. Do not add a
  request type that returns plaintext. 2.4 will own signal handling, idle
  timeout and key zeroization; the `flock` guard must stay alive for the whole
  daemon lifetime (keep the `DaemonSocket` in scope).

## 2026-11-02 — Protocol framing module (TODO 2.1)

- New `src/protocol.rs` (registered in `src/lib.rs`): pure, no-I/O wire
  protocol for the future daemon. Frame = 4-byte big-endian length + JSON body.
  Envelope = `{"version":1,"request":{"type":...}}`. `encode(&Request)` and
  `decode(&[u8])` handle exactly one frame; `FrameDecoder` is the incremental
  read-loop state machine (`push`, `next_frame`, `next_request`, `buffered`).
- Request types: `ping`, `lock`, `run { env, ref, command }`. **There is no
  plaintext request type**, and `src/protocol.rs` documents why (any same-user
  process can reach the socket, so the daemon must never return a value). The
  test `requests_have_no_plaintext_field` pins the exact wire keys:
  `ping`/`lock` have only `type`; `run` has `type`, `env`, `ref`, `command`.
  `reveal`/`get`/`password`/`export` are rejected as unknown types.
- Limits: `MAX_MESSAGE_BYTES = 64 KiB` body cap, `MAX_BUFFERED_BYTES` = two
  max frames for the decoder, `MAX_ENV_NAME_BYTES = 128`,
  `MAX_REFERENCE_BYTES = 128`, `MAX_ARG_BYTES = 4096`, `MAX_ARGS = 256`.
  The declared length is validated **before** any slice/allocation is made
  from it (`check_length`), so a prefix of `u32::MAX` is rejected immediately;
  `FrameDecoder::push` rejects it as soon as the 4-byte prefix arrives, without
  waiting for the body. Zero-length bodies are `EmptyMessage`; a frame with
  bytes after it is `TrailingBytes` (one call decodes one frame).
- Decisions: unknown envelope **fields** are ignored (so 2.5 can add a session
  token and 3.x a grant without breaking peers); unknown envelope **versions**
  and unknown request **types** are hard errors. `run.ref` is validated with
  the canonical `store::EntryId::parse_ref` (reuse, no duplicated syntax); the
  daemon still must check existence and scope. `run.env` must be
  `[A-Za-z_][A-Za-z0-9_]*`. All validation runs on encode *and* decode, so a
  locally built request cannot bypass the contract. Errors carry lengths and a
  truncated (32-char) request type only — never field values (test
  `errors_do_not_echo_request_field_values`).
- `ProtocolError` is a separate enum with `Display` + `std::error::Error`; it
  deliberately does **not** reuse the CLI `Error`/exit-code contract, because
  these are daemon-internal failures. No new dependency (`serde_json` was
  already present). No store/crypto change.
- Tests: 16 new lib tests — round-trip of all three requests, exact framing
  bytes, truncated prefix/body, oversized declared length on `decode` and
  `FrameDecoder`, empty body, trailing bytes, oversized encode (20×4 KiB
  args), versions 0/2/99/u64::MAX, missing/mistyped envelope fields, unknown
  types incl. a 10 000-char type truncated in the error, wire-key pinning,
  all `run` field bounds, fragmented byte-at-a-time decoding, two frames in
  one push, buffer flood, and a deterministic xorshift smoke test over ~3 000
  random buffers (no panics).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 116 passed (70 lib + 19 bin + 27 e2e, ~149 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next is **2.2** (socket setup in
  `$XDG_RUNTIME_DIR/passmgr/`, dir 0700, socket 0600, stale-socket detection,
  single-instance lock). Use `FrameDecoder` for reads and `encode` for writes;
  do not add a request type that returns plaintext. `run.command` is an argv
  vector (no shell); 2.6 must spawn it directly.


## 2026-11-02 — Tags and timestamps in JSON (TODO 1.2b)

- TODO 1.2b: `list --json`, `show --json` entries now carry all six keys:
  `ref`, `service`, `username`, `tags`, `created`, `last_rotated`. The schema
  is unchanged elsewhere; `list` still prints exactly `{"entries":[...]}` and
  `show --json` the entry object. No password key exists by construction:
  `entry_metadata` only calls metadata getters.
- **Representation decision:** `tags` is always an array (sorted, deduped, as
  stored). `created` / `last_rotated` are RFC 3339 UTC strings
  (`2026-11-02T18:20:02Z`) and **`null` when the stored value is 0** (unknown,
  i.e. entries migrated from a pre-v4 payload). Chose strings over raw epoch
  integers because JSON here is the agent-facing surface: a UTC string is
  self-describing, has no timezone ambiguity, and fixed-width `...Z` strings
  sort chronologically, so an agent can use `>`. Storage still keeps raw
  `u64` seconds; this is presentation only.
- No new dependency. New module `src/timestamp.rs` exposes `format_utc(u64)
  -> String` and `to_json(u64) -> serde_json::Value`. `civil_from_days` is
  Howard Hinnant's exact proleptic-Gregorian algorithm, private, and total
  over the whole `u64` range (a value beyond the store bound would render a
  five-digit year instead of panicking; the store rejects those first). Values
  up to `store::MAX_TIMESTAMP_UNIX = 253402300799` all format with 4-digit
  years, up to `9999-12-31T23:59:59Z`.
- Tests: 13 known formatting vectors from `date -u` (epoch, day boundary,
  2000-02-29 leap century, 2024-02-29, 2100-01-01 non-leap century, y2038,
  max timestamp); leap-year contiguity test (each day strictly increasing,
  fixed 20-byte width, Feb 29 -> Mar 1); `to_json(0)` is `null` while
  `format_utc(0)` is the epoch. Two bin tests decode a hand-built store-v4
  payload (private `STORE_VERSION` is not exported, so the literal `4` is
  documented there) to prove zero timestamps render `null` and nonzero ones
  render exact strings, tags render sorted, and the password is absent from
  both the `Value` and its serialization. E2E
  `show_and_list_json_expose_metadata_only` now tags the entry during the
  rename edit, asserts the sorted `tags` array, asserts `created` is a
  20-byte `...Z` string, and asserts `created == last_rotated` after a
  metadata-only edit. `tags_are_stored_filtered_and_metadata_only` was
  updated from "JSON omits tags for now" to asserting the sorted tag arrays
  (same intent, new schema).
- Docs: README machine-readable section now shows a full entry example and
  documents `null`; Tags and Timestamps (security) bullets corrected.
- Gate: `cargo fmt --check` clean, clippy `--all-targets -D warnings` clean,
  `cargo test` 100 passed (54 lib + 19 bin + 27 e2e). `cargo audit` still not
  installed (`error: no such command: audit`); dependencies unchanged.
- **Next iteration must know:** Phase 1 is complete. Next is **2.1**
  (length-prefixed JSON protocol module, pure functions, max message size).
  The JSON schema for entry metadata should be treated as stable; if a field
  is ever added, agents already tolerate new keys, but never add `password`.
  `src/timestamp.rs` is the only place timestamp formatting lives.

## 2026-11-02 — Created/last-rotated timestamps (TODO 1.4, unblocks 1.2b)

- TODO 1.2b was the first unchecked item but was **blocked on 1.4**, so this
  iteration did 1.4 (the blocker). 1.2b is now unblocked and is next.
- Store **version 4**: each credential in the encrypted payload now carries
  `u64 created` and `u64 last_rotated` immediately after the 16-byte id. Both
  are Unix seconds UTC. Layout: `u8 version | u32 count | { id[16], created,
  last_rotated, service, username, password, tags }`. Container and crypto are
  unchanged (still container v2, same Argon2id/AES-GCM params).
- `created` is set by `Credential::new` together with `last_rotated` (adding a
  credential counts as its first rotation) and never changes afterwards.
  `Credential::set_password` is the only mutator that moves `last_rotated`; it
  reads the clock **before** validating/replacing, so a rejected password (e.g.
  empty) leaves both password and timestamp untouched. Public getters
  `created_unix()` / `last_rotated_unix()`.
- Migration: versions 1, 2 and 3 still decode. Pre-v4 entries get `created =
  last_rotated = 0`, documented as "unknown", rather than inventing a date at
  migration time; the next save writes version 4 and preserves the zeros. So a
  migrated entry has no known creation time; 1.2b must render `0` as
  unknown/absent, not 1970-01-01.
- Validation: timestamps above `store::MAX_TIMESTAMP_UNIX = 253_402_300_799`
  (9999-12-31T23:59:59Z) are `MalformedVault` (exit 6) on read and
  `InvalidInput` (exit 2) on write, so a hand-crafted payload cannot overflow
  future date rendering. `created > last_rotated` is **not** rejected: a clock
  that moves backwards is legitimate, and enforcing order would fail closed on
  real vaults for no security gain.
- Clock failure (system time before the Unix epoch or past the bound) returns
  `Error::Io` (exit 1) instead of adding an error variant; it is an environment
  failure, not user input.
- Precision is whole seconds. A rotation within the same second as the previous
  one leaves `last_rotated` numerically unchanged; tests therefore assert `>=`
  where the real clock is involved and use a crafted private field for the
  deterministic "rotation moves the timestamp" proof.
- Tests: store unit tests for the v4 round-trip (timestamps preserved), a new
  hand-built **v3** payload migrating with id/tags intact and timestamps 0,
  empty vault now `04 00 00 00 00`, v1/v2 migration timestamps 0, timestamp
  range rejection on both read and write, and a deterministic rotation test
  (created immutable, last_rotated moves, rejected password does not move it).
  Vault test `timestamps_survive_saves_and_rotation_keeps_created`; e2e
  `edit_rotates_the_password_without_printing_it` now captures `created`
  before the edit and asserts it is unchanged after rotating. No secret bytes
  are involved (timestamps are metadata).
- Docs: `FORMAT.md` payload v4, migration and timestamp rules; README security
  section gains a Timestamps bullet; `store.rs` module doc updated.
- Gate: `cargo fmt --check` clean, clippy `--all-targets -D warnings` clean,
  `cargo test` 95 passed (51 lib + 17 bin + 27 e2e, ~147 s). `cargo audit`
  still not installed (`error: no such command: audit`); no dependency changed.
- **Next iteration must know:** do **1.2b** (add `tags`, `created`,
  `last_rotated` to `entry_metadata` in `src/main.rs` and to text output if
  desired). Decide the JSON representation there: raw Unix seconds are the
  stored form; if ISO-8601 is wanted, either hand-roll days-from-civil or add a
  justified date dependency. Do not put `password` anywhere near that struct.

## 2026-11-02 — Tags on credentials (TODO 1.3)

- Implemented per-credential tags and store **version 3**. Payload gains
  `u32 tag count` plus `u32 length + UTF-8 bytes` per tag, sorted and
  duplicate-free. Versions 1 (no ids) and 2 (no tags) are still read and are
  rewritten as version 3 on save; the container stays v2 and the crypto
  parameters are unchanged.
- Tag rules (enforced on write **and** read, so a hand-crafted payload fails
  closed): 1-32 bytes, first byte ASCII lowercase letter or digit, remaining
  bytes `[a-z0-9._-]`, max 32 tags per credential. Invalid tags map to
  `InvalidInput`/exit 2 at the CLI, before any password prompt; malformed
  payload tags map to `MalformedVault`.
- CLI: `add --tag TAG` and `edit --tag TAG` (repeatable; `edit` replaces the
  whole set), `edit --clear-tags`, `list [--json] [--tag TAG]`. `list --tag` is
  an AND filter. Text output adds a `tags: a, b` line under each listing entry
  and a `Tags: a, b` line in `get`/`show`; both are omitted when untagged.
  Tags are metadata only and are deliberately **not** in JSON output yet:
  TODO 1.2b adds `tags`/`created`/`last_rotated` together in one schema change.
- `edit` now treats `--tag`/`--clear-tags` (without `--generate`) as
  metadata-only: it does not rotate the password and does not prompt for a new
  one. `--clear-tags` combined with `--tag` is a usage error.
- No new dependencies. `serde_json` was already present.
- Tests: store round-trip, v1→v3 and v2→v3 migration, tag validation (case,
  whitespace, control chars, non-ASCII, leading `-`/`_`/`.`, length, count),
  malformed payload duplicate/excess tags, vault filtering + persistence,
  CLI parser tests, and an e2e test covering add/list/filter/edit/clear,
  invalid-tag exit code 2, JSON omitting tags, and the secret never appearing
  on stdout/stderr.
- Gate: `cargo fmt --check` clean, clippy clean, `cargo test` 64 unit (47 lib + 17 bin) + 27 e2e
  passed (~141 s; e2e is Argon2id-bound and serialized). `cargo audit` is still
  not installed (`error: no such command: audit`), so that gate step remains
  skipped; no dependency changed this iteration.
- README (`Tags` section, `get`/`list`/`edit` examples) and `FORMAT.md`
  (payload v3, migration, tag validation) updated.
- **Next iteration must know:** 1.2b is still blocked on 1.4 but tags are now
  available to add to the JSON schema. Nothing about the daemon/grant work has
  started. `Vault::list_tagged` returns `&Credential` references; grant scope
  can reuse `Credential::has_all_tags`.

# Progress log

Newest entries first. Date, what was done, what the next iteration must know.

## 2026-11-02 — TODO 1.2a: `list --json` and `show <ref>`

- TODO 1.2 was split: this iteration did the JSON/reference half with the
  metadata that exists today. **1.2b** (adding `tags`, `created`,
  `last_rotated` to the JSON entry) stays unchecked until 1.3 and 1.4 land;
  adding keys later is backward compatible, so the schema is stable in the
  "agents must tolerate unknown keys" sense.
- New command `show [--json] <ref>`: accepts **only** a full `pm://<32 hex>`
  reference (parsed with `store::EntryId::parse_ref` *before* unlocking, so a
  bad reference is exit 2 and costs no password prompt). A well-formed but
  unknown reference returns the new `Error::EntryNotFound` (exit 3,
  "no credential found for reference '<ref>'"). Text output is `Ref`,
  `Service`, `Username` — no password line at all. A service name passed to
  `show` is a usage error (exit 2); references are the unambiguous handle.
- `list --json` prints exactly one JSON document, `{"entries":[{"ref":...,
  "service":...,"username":...}]}`, plus a newline, and nothing else on stdout
  (no "Stored Services:" header; the empty-vault "No credentials stored." prose
  goes to stderr only in text mode, so an empty vault is `{"entries":[]}`).
  `show --json` prints the entry object directly. The flag may appear before or
  after the positional argument.
- No-value guarantee is structural: `entry_metadata(&Credential)` in
  `src/main.rs` only ever reads `reference()`, `service()` and `username()`;
  `Credential::password()` is never called there. Do not "tidy" it into a
  serde-derived struct on `Credential`, which could add a password field by
  accident.
- **Dependency added:** `serde_json = "1"` (pulls `serde`, `serde_core`,
  `itoa`, `memchr`, `zmij`; no derive feature). Justification: correct JSON
  escaping of arbitrary UTF-8 metadata (quotes, backslashes, non-ASCII) is
  security-relevant output encoding; hand-rolling it risks malformed or
  ambiguous documents for agents to parse. It makes no network calls. No
  `serde` derive is enabled, so there is no `Serialize` impl on `Credential`.
- Library additions: `Vault::get_by_ref(&self, EntryId) -> Option<&Credential>`
  and `Error::EntryNotFound(String)` (mapped to `EXIT_NOT_FOUND`); unrelated
  error variants untouched. No store-format or crypto change.
- CLI parsing: `Command::List { json }` and `Command::Show { reference, json }`;
  `parse_list` rejects any argument other than `--json`; `parse_show` mirrors
  `parse_get` (supports `--`, rejects `--reveal` with exit 2).
- Docs: `--help` lists both commands and the JSON keys, README gains a
  "Machine-readable metadata" section.
- Tests: 2 new `src/main.rs` parser tests (`parses_list_and_show_json` and
  updated `Command::List` patterns), 1 new `src/vault.rs` test
  (`lookup_by_reference_is_stable_across_renames`), 1 new error-code case,
  3 new e2e tests in `tests/cli.rs`:
  `show_and_list_json_expose_metadata_only`,
  `json_output_escapes_metadata` (service `quote"back\slashé` round-trips),
  `show_rejects_bad_and_unknown_references` (exit 2 without prompting, exit 3
  for unknown, empty vault JSON, `--help` mentions both commands). All e2e
  assertions check the stored password is absent from stdout and stderr.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 84 passed (42 lib unit + 16 main unit + 26 e2e, ~125 s;
  e2e serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next unchecked item is **1.3 tags**
  (`--tag`, `list --tag`). Tags will also need a store-format bump (version 3)
  with a v2 migration reader, reusing the 1.1 pattern; keep `Credential::new`'s
  signature stable or add `with_tags`. Add tag filtering to `list` and a
  `--tag` field in `entry_metadata` only in 1.2b.

## 2026-11-02 — TODO 1.1: stable entry references (`pm://<id>`)

- `src/store.rs` store version 2: each credential now begins with a 16-byte
  random `EntryId` in the encrypted payload. `Credential::new` generates the id
  from `getrandom::fill` (no new dependency); decode checks uniqueness and
  rejects duplicate ids as `MalformedVault`.
- New public API in `src/store.rs`: `EntryId` (`generate`, `to_hex`, `to_ref`,
  `from_hex`, `parse_ref`, `Hash`/`Eq`, `Display`/`Debug`), `ENTRY_ID_BYTES`,
  `Credential::id()` and `Credential::reference()`. `Credential::with_id` is the
  private constructor used by the decoder; validation is unchanged.
- Reference syntax is `pm://` + exactly 32 hex chars, lower-cased on parse;
  upper-case input is accepted. **Decision:** no `pm://<service>#<prefix>` form
  and no id prefixes — a partial reference would be ambiguous, so the full id is
  required. Parse failures are `InvalidInput` (exit 2). The id is metadata, not
  a secret, so it is safe on stdout/stderr.
- Migration: `decode` accepts store version 1 (same layout without ids), gives
  each credential a fresh id in memory, and the next `save` writes version 2.
  No crypto or container change; the container format version stays 2 and the
  salt/nonce handling is untouched. Empty vault is now `02 00 00 00 00`;
  version 1 empty payloads are still accepted.
- CLI: `get` output gains a leading `Ref: pm://<id>` line (both metadata and
  `--reveal` modes, since the ref is not a secret); `list` lines are now
  `- <service> (<username>) [pm://<id>]`. `--help` and README document the
  reference. No new commands yet; `show <ref>` is TODO 1.2.
- `FORMAT.md`: payload section updated to version 2 with the id field, plus
  migration and duplicate-id rules.
- Tests: 6 new/updated unit tests in `src/store.rs` (v2 round-trip preserving
  ids, v1 payload migration with no data loss, unique/stable ids across
  encode/decode, hex/ref parsing incl. rejects, duplicate-id rejection,
  oversized-length now with an id) and 1 new `src/vault.rs` test
  (`entry_ids_are_stable_across_vault_saves`, including rename stability).
  1 new e2e test `entry_references_are_stable_and_leak_no_secrets`; exact-output
  e2e assertions updated for the new `Ref:`/`[pm://...]` formats (still assert
  `EXAMPLE_SECRET` is absent).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 79 passed (41 lib unit + 15 main unit + 23 e2e, ~97 s;
  e2e serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** TODO 1.2 (`list --json` + `show <ref>`). Resolve
  references with `passmgr::store::EntryId::parse_ref` and compare against
  `Credential::id()`; there is deliberately no `Vault::get_by_ref` yet, add one
  if it keeps 1.2 clean. Old vaults (store v1) are migrated on the first save,
  so ids are stable from that point on but a v1 vault gets new ids once.

## 2026-11-02 — TODO 0.6: `rm` alias and `edit`

- `rm <service>` is a pure alias for `delete`: `parse_command` routes both
  through `parse_single_argument(&command, rest).map(Command::Delete)`, so
  messages and exit code 3 for an unknown service are identical.
- New `edit <service> [--username U] [--rename NAME] [--generate]
  [--strong|--simple|--pin] [--length N]`. `--rename` was added beyond the
  TODO wording so a service can actually be renamed (the item's test list
  required it).
- Rotation rule is a pure function, `edit_rotates_password(&EditOptions)`:
  a bare `edit` or `--generate` rotates; `--username` and/or `--rename`
  without `--generate` is a metadata-only edit and does **not** prompt for a
  password. Rotating prompts for the new value twice through the existing
  no-echo `terminal::prompt_password` (`prompt_credential_password`), then
  saves. `--generate` stores a fresh value and prints only the entry name, so
  no secret reaches stdout/stderr.
- Ordering: non-secret inputs are validated before `unlock`; the service is
  looked up before any replacement-password prompt, so an unknown service
  exits 3 without consuming a password prompt. Renaming onto an existing
  service fails with `DuplicateService` (exit 1); renaming to the same name is
  a no-op. Renaming happens before the username/password update, and all
  follow-up mutations use the new name.
- New library API: `store::validate_service`, `store::validate_username`
  (`validate_identity` now composes them), `Credential::set_service`,
  `set_username`, `set_password` (each validates and leaves the value
  untouched on error), `Vault::get_mut` and `Vault::rename`.
- Docs: `--help`, README (new "Edit a credential" section, `rm` alias) updated.
  No store-format or crypto changes.
- Tests: one new setter unit test in `src/store.rs` and one new vault test
  (`renaming_and_editing_credentials`), 3 new parsing/decision tests in
  `src/main.rs` (`parses_edit_metadata_and_generation_options`,
  `edit_rejects_bad_arguments`, `rm_is_an_alias_for_delete`), and 5 new e2e
  tests in `tests/cli.rs` (rotate with no secret bytes, rename+username with
  the old name returning 3, generated replacement not printed, unknown service
  exits 3 before the password prompt, `rm` parity).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 73 passed (36 lib unit + 15 main unit + 22 e2e, ~77 s;
  e2e is serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** Phase 0 is complete; next is TODO 1.1 (stable
  entry ids + store version 2 migration). There is no `run`/daemon yet, so
  `edit` still opens the vault directly with a TTY prompt.

## 2026-11-02 — TODO 0.5: stable exit codes

- `src/error.rs` now owns the CLI exit-code contract: public `EXIT_OK` (0),
  `EXIT_FAILURE` (1), `EXIT_USAGE` (2), `EXIT_NOT_FOUND` (3),
  `EXIT_AUTH_FAILED` (4), `EXIT_REFUSED` (5), `EXIT_MALFORMED_VAULT` (6), plus
  `Error::exit_code()`. Re-exported from `src/lib.rs`.
- Mapping: `VaultNotFound`/`ServiceNotFound` → 3; `AuthenticationFailed` → 4;
  `Refused` → 5; `NotAVault`/`LegacyVault`/`UnsupportedVersion`/
  `UnsupportedFormat`/`MalformedVault` → 6; `InvalidInput` → 2 (invalid input at
  a prompt is treated as usage, e.g. empty master password); `Io`/`Crypto`/
  `DuplicateService` → 1 (generic failure).
- Decision: `Crypto` stays at 1, not 6. It also covers RNG and cipher-setup
  failures during save, which are not a malformed vault file. Vault corruption
  at read time surfaces as `MalformedVault` (6) or `AuthenticationFailed` (4).
- `src/main.rs`: `main()` no longer hardcodes 1/5; it prints via
  `report_runtime_error` and exits with `error.exit_code()`. BrokenPipe still
  exits 0. `CliError::Usage` uses `EXIT_USAGE`. The removed
  `CliError::Runtime(Error::Refused(..))` arm produced identical output because
  `Error::Refused` Display is the message and `report_runtime_error` adds no
  hint for it.
- `--help` and README now document all six codes (README table replaced).
- Tests: new `error.rs` unit test asserts every variant's code and the numeric
  constants; new e2e `exit_codes_are_stable` covers unknown service (3), wrong
  password (4), truncated vault (6 + "malformed vault"), non-vault file (6),
  empty master password (2), unknown option (2), and greps `--help` for each
  documented code. Existing e2e expectations updated: wrong password 1→4,
  missing vault 1→3, legacy vault 1→6.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 63 passed (34 lib unit + 12 main unit + 17 e2e, ~51 s).
  `cargo audit` still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.6 (`rm` alias + `edit`) is next. Use the
  `EXIT_*` constants for any new exit path; do not hardcode numbers. `rm` is a
  pure alias, so route it to `Command::Delete`. `edit` will need the vault
  password re-prompted twice for a rotation and should return 3 for an unknown
  service.

## 2026-11-02 — TODO 0.4: global `--agent` flag

- `src/agent.rs` now models the signal source explicitly: new
  `pub enum AgentSource { Env(&'static str), Flag }` and
  `RevealRefusal::AgentContext(AgentSource)`. `reveal_refusal` takes
  `Option<AgentSource>` (was `Option<&'static str>`), and the message renders
  either "`NAME` is set" or "the --agent flag was passed".
- New `agent::agent_source(agent_flag: bool)` resolves env marker first, then
  the flag; `agent::check_reveal(agent_flag: bool)` now takes the flag. The flag
  can only *add* refusal — `agent_source(false)` is `None` and every existing
  terminal/marker decision is unchanged.
- `src/main.rs`: `Parsed { db_path, agent, command }`; `--agent` is parsed in
  the global-option loop beside `--db` and is a bare boolean (repeating it is
  harmless). `command_get(service, reveal, agent_mode, path)` passes it to
  `check_reveal`, still **before** `unlock`, so a refused reveal never prompts
  or opens the vault. `USAGE`, `HELP` and README updated, including
  "global options must come before the command".
- Decision: `--agent` is global-prefix only (`passmgr --agent get ...`).
  `passmgr get --agent ...` is a usage error (exit 2) rather than silently
  ignored — one placement rule, no ambiguity with `--`. Documented in help and
  asserted by a test.
- Tests: 3 new unit tests in `src/agent.rs` (flag refuses with two terminals;
  flag cannot weaken the check; env marker reported before the flag) plus an
  extended message test. 2 new unit tests in `src/main.rs` (parsing before the
  command, including repeats and `--help`; bare-flag/placement errors). 4 new
  e2e tests in `tests/cli.rs`: `--agent` blocks reveal on a full pty, blocks it
  over pipes (exit 5, stderr names `--agent`, no secret bytes), metadata
  `get`/`list` still work under `--agent`, and `--agent` is documented/rejected
  after the command.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 61 passed (33 lib unit + 12 main unit + 16 e2e, ~47 s).
  `cargo audit` still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.5 (stable exit codes) is next;
  `Error::Refused` maps to 5, everything else still exits 1. `--agent` currently
  affects only reveal; TODO 4.x will extend it to JSON/help behavior.

## 2026-11-02 — TODO 0.3: `add --generate` no longer prints the password

- `src/main.rs::command_add` no longer prints `Generated password: <value>`.
  The generated value is still stored; stdout is now empty for `add --generate`
  and stderr prints `Credential '<service>' added successfully with a generated
  password.` (entry name only). The non-generate path still prints
  `Credential added successfully.` so existing assertions hold.
- The generated value is only obtainable through the TTY-gated
  `get --reveal` (or in-process `Vault::open`). No new bypass.
- `tests/cli.rs::generated_add_then_get_returns_same_password` now reads the
  stored value in-process via `vault_password`, asserts stdout is exactly empty,
  asserts neither stream contains the generated bytes, asserts the confirmation
  names the entry, and re-checks the stored value is unchanged.
- README (`add` section) and `--help` updated: `--generate` stores but never
  prints; read back with `get --reveal`.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 52 passed (30 lib unit + 10 main unit + 12 e2e, ~34 s).
  `cargo audit` is still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.4 is next (`--agent` global flag wired
  into `agent::check_reveal`). Note for review: the standalone `generate`
  command (`src/main.rs::command_generate`) still prints a freshly generated
  password to stdout. It exposes no stored secret and is a human-facing
  generator, so it is out of scope for 0.3, but decide in a later item whether
  agent mode should refuse or redact it too.

## 2026-11-02 — TODO 0.2: `--reveal` gated on a TTY and agent context

- New `src/agent.rs`: `AGENT_MARKERS` (`PASSMGR_AGENT`, `CLAUDECODE`,
  `CURSOR_AGENT`, `CODEX_SANDBOX`), `agent_marker()`, `is_agent_context()`,
  pure decision fn `reveal_refusal(stdin_tty, stdout_tty, marker)` returning
  `RevealRefusal` (`AgentContext(marker)` / `StdinNotTerminal` /
  `StdoutNotTerminal`), and `check_reveal()` which wires in `IsTerminal` + env.
- `command_get` calls `check_reveal()` **before** `unlock`, so a refused reveal
  never opens the vault or prompts for the master password. No bypass flag.
- `Error::Refused(String)` added (`src/error.rs`, Display prints the message
  verbatim) and `main()` maps it to exit code 5. This is the first piece of TODO
  0.5; other errors still exit 1.
- Design choice: an agent marker counts when **present**, even with an empty
  value (conservative). Precedence in the refusal reason: marker → stdin →
  stdout.
- `src/lib.rs` exposes `pub mod agent`.
- Tests: 5 new unit tests in `src/agent.rs` (all markers, unrelated vars,
  all four terminal combinations, marker precedence, message text). `tests/cli.rs`
  now strips agent markers from the test environment (`base_command`), asserts
  piped `get --reveal` → exit 5 with no secret, loops all four markers, and adds
  Linux-only pty tests via `posix_openpt`/`ptsname` (`run_on_pty`, `read_pty`,
  handles EIO after child exit): stdout-piped refusal, success on a real pty, and
  `PASSMGR_AGENT=1` refused even on a pty. Piped reveal success assertions were
  replaced with an in-process `passmgr::Vault::open` read (`vault_password`).
- README and `--help` updated: exit 5 meaning, both-terminals rule, marker list,
  "no bypass".
- Gate: `cargo fmt --check` clean, clippy `-D warnings` clean, `cargo test`
  52 passed (30 lib unit + 10 main unit + 12 e2e, ~35 s). `cargo audit` still not
  installed on this machine (only unverified gate step).
- **Next iteration must know:** TODO 0.4's `--agent` flag must feed into
  `agent::check_reveal` so it *adds* refusal; `agent.rs` already holds the
  decision. TODO 0.3 (`add --generate` printing the secret) is untouched.
  Piped `--reveal` in docs/tests is now expected to fail with 5. The pty tests
  are `#[cfg(target_os = "linux")]`; macOS relies on the unit tests for the
  decision logic.

## 2026-11-02 — TODO 0.1: `get` is metadata-only, `--reveal` added

- `passmgr get <service>` now prints `Password: <redacted>` and never the stored
  value. Plaintext requires `get --reveal <service>`; `--reveal` is parsed before
  or after the service name. This is the only plaintext path from `get`.
- `src/main.rs`: `Command::Get` became `Command::Get { service, reveal }`, added
  `parse_get` (mirrors `parse_add` arg handling: `--`, `-h/--help`, rejects
  unknown flags and more than one positional). Unit tests
  `get_reveals_only_with_the_flag` / `get_rejects_bad_arguments` assert the
  default is not-reveal.
- `tests/cli.rs`: `EXAMPLE_SECRET` fixture replaced plain `secret`; new assertions
  prove plain `get` contains no secret bytes on stdout or stderr, and that
  `--reveal` still returns the value. Tests still use the piped CLI for
  `--reveal` — TODO 0.2 must change that to an in-process read once the TTY gate
  lands (a piped `--reveal` will then be refused).
- Gate: `cargo fmt --check` clean, clippy clean, `cargo test` 17 passed (10 unit
  + 7 e2e). `cargo audit` still not installed (see previous entry).
- **Next iteration must know:** `add --generate` still prints
  `Generated password: <value>` to stdout — that is TODO 0.3, untouched here.
  `--reveal` currently has **no TTY/agent check** (TODO 0.2); do not ship before
  0.2.
- README updated in the same commit (the `get` section and the flag semantics).

## 2026-11-02 — Bootstrap plan (no feature work)

- Repo state: existing Rust CLI (commit `f93b765` "rust rewrite") with Argon2id +
  AES-256-GCM, atomic saves, 0600 vault, password generator, `add`/`get`/`delete`/
  `list`/`generate`. Legacy C implementation archived in `legacy-c/`. No
  `PROGRESS.md`/`TODO.md` existed, so this iteration only wrote them (per the
  iteration protocol).
- Gate baseline at start of this iteration: `cargo fmt --check` clean,
  `cargo clippy --all-targets -- -D warnings` clean, `cargo test` 15 passed
  (8 unit + 7 e2e in `tests/cli.rs`, ~20 s — e2e cost is Argon2id at default
  params, acceptable). `cargo audit` is **not installed** on this machine; the
  gate step is skipped until it is, verify manually with `cargo tree` if needed.
- Wrote `TODO.md`: 5 phases, 24 items, ordered. Phase 0 fixes existing invariant
  violations before any new feature.
- Decisions recorded:
  - **Crypto approach stays the custom container** (Argon2id + AES-256-GCM,
    `FORMAT.md` v2), not `age`. Already implemented and documented; do not mix
    the two. No crypto parameter changes without a migration note.
  - Store format is versioned separately from the container; adding entry ids,
    tags and timestamps (TODO 1.1/1.3/1.4) requires store version 2 **with a
    version 1 reader**, no crypto change.
- **Known invariant violations in current code** (must be fixed in Phase 0, listed
  so they are not forgotten):
  - `src/main.rs::command_get` prints `Password: <plaintext>` to stdout with no
    TTY check and no `--reveal` flag.
  - `src/main.rs::command_add` prints `Generated password: <plaintext>` on
    `--generate`.
- README documents `get` as printing the password; it must be updated in the same
  commit as TODO 0.1/0.2.
- No `NEEDS HUMAN REVIEW` items yet.
