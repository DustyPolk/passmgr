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

