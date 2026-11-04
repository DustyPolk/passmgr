## 2026-11-04 — `pm audit` listing and `pm audit verify` (TODO 3.9)

- `src/audit/read.rs` (new; `audit.rs` re-exports it): strict `Record` parser
  for the writer's schema, `verify` walking `prev` from the all-zero genesis,
  `load`/`select` for listings. The first impossible link is named
  (`line N: prev does not match line N-1`), and a file not ending in `\n` is
  refused.
- `pm audit [--json] [--grant ID] [--since 30s|15m|1h|7d] [--limit N]` lists
  oldest first, newest N (default 50) of the filtered set, header
  `Audit records (showing N of M):`, `{"records":[...]}` for `--json`.
  `pm audit verify` prints `Audit log verified: N records.` and exits 6 on a
  broken chain. Neither needs a password: records hold no secret or token.
- `Error::Audit` (exit 1) is an unreadable/loose log; `Error::AuditBroken`
  (exit 6) a broken chain. Reads take a shared `flock` (a concurrent append
  cannot look like tampering) and refuse over 64 MiB. `timestamp::parse_utc`
  parses exactly the 20-byte format `format_utc` writes.
- Tests: 8 units in `src/audit/read.rs` (edited/deleted/reordered/torn, schema
  matrix, loose path, filter/tail) and 12 in `tests/audit_cli.rs` (listing,
  JSON shape, filters, edited→exit 6 naming lines 3 and 2, deleted→line 2,
  reordered→line 1, torn tail, empty log, 0644 refused, no prompt, `$HOME`
  fallback). `tests/docs.rs` pins the new tail limit.
- Docs: SECURITY limit 8 (Out of scope → 9), README, HELP (+ golden file),
  DECISIONS, MCP, TODO. Gate: fmt, clippy `-D warnings`, full `cargo test`
  green; `cargo audit` skipped (not installed).
- **Next iteration must know:** `--since` is an age, not a date. A denial whose
  token matched an expired/out-of-scope grant still has `grant: null` (3.8
  note), so `--grant` misses it; returning the matched id from `record_use` is
  a follow-up. Verify cannot see a changed/deleted final record or the file's
  deletion (SECURITY limit 8).

## 2026-11-04 — Hash-chained audit log for daemon and local runs (TODO 3.8)

- New `src/audit.rs`: `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback
  `~/.local/state`), one JSON line with `v`, `ts`, `source`, `event`,
  `outcome`, `grant`, `ref`, `command`, `args`, `exit`/`signal`, `prev`.
  `prev` = SHA-256 of the previous line without its newline; first is 64 zeros.
- Appends hold an exclusive `flock`, read only the last line, refuse a torn or
  oversized (>32 KiB) last line, write `O_APPEND`, and `fsync`. The file is
  0600 in a 0700 `passmgr` dir; `O_NOFOLLOW`, regular-file, owner and exact-mode
  checks refuse a loose path instead of repairing it.
- `src/daemon/run.rs` preflights the log before parsing and records every path
  (bad request, denied, not found, internal, cancelled, spawn/output failure,
  allowed); `record_use` now returns the authorizing `GrantId` for the record.
  An unrecordable run is refused with `internal` before decrypting or spawning.
- `src/cli/run.rs` audits the grant-less local path too (`source: local`, no
  grant) with the same outcomes and fail-closed preflight (exit 5 before the
  password prompt when the log is unusable).
- Tests: `src/audit.rs` units (path rules, one-line JSON, control-char bounds,
  chain + 0600/0700, loose file/dir refusal, torn/oversized last line) and new
  `tests/audit.rs` (real daemon: allowed/denied records free of the secret and
  both tokens, two-record chain, unrecordable log refuses the run, modes).
  `tests/run_local.rs` asserts the local record. Tests set `XDG_STATE_HOME` per
  fixture/binary so they never touch the real log. SECURITY, README, MCP,
  DECISIONS and `tests/docs.rs` updated.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, full
  `cargo test` green; `cargo audit` skipped (not installed).
- **Next iteration must know:** denied records carry `grant: null` even when a
  token matched an expired/out-of-scope grant (`record_use` returns only the
  error); TODO 3.9's `--grant` filter should accept that or a follow-up should
  return the matched id. `args` are capped at 16 × 128 chars (truncated).
- NEEDS HUMAN REVIEW: the record is appended after the child ends, so a crash
  mid-run can lose the line even though the secret was injected. The preflight
  only proves writability. A pre-run "started" record would double every use;
  left for a human decision.

## 2026-11-04 — `run` for humans without a grant (TODO 3.7)

- `src/cli/run.rs`: `command_run(options, agent_mode, db_path)` now has two
  paths. A grant token (`--grant-file` or `PASSMGR_GRANT_FILE`) keeps the old
  daemon path unchanged. With neither, the CLI first applies
  `agent::check_human` (stdin **and** stdout TTYs, no marker/`--agent`), parses
  the reference, prompts for the master password and opens `--db`/the default
  vault, drops the decrypted vault before spawning, and calls the same
  `runner::execute` + streaming redactor used by `pmd`. The grant path never
  falls back to local injection when the daemon is missing.
- `src/cli/args/mod.rs`: the `--db`/`PASSMGR_DB` usage error now applies only
  when a grant selects the daemon; a grant-less local run accepts the vault
  flag like other commands. `src/cli/mod.rs` passes agent mode and the parsed
  vault path into `command_run`.
- Chose the reveal gate (both streams TTY) rather than stdin-only: a local run
  hands a secret to a command chosen at the terminal, so a piped stdout is
  refused even though relayed output is redacted. Documented in help, README,
  DECISIONS and SECURITY.
- Tests: new `tests/run_local.rs` (7 tests, PTY-driven) proves injection plus
  redaction of both streams and exit-status pass-through; refusal for every
  agent marker, for `--agent`, for non-TTY stdin **and** stdout; unknown ref =
  exit 3; and a grant token always selects the daemon path. `tests/run.rs`
  tests that assumed no-grant meant "daemon without a token" now pass a grant
  or assert the local refusal. `tests/cli_support` also clears
  `PASSMGR_DB`/`PASSMGR_GRANT_FILE` for hermetic runs.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` suite green; `cargo audit` skipped (not installed).
- NEEDS HUMAN REVIEW: a grant-less local `run` is not audited yet because the
  hash-chained audit log is still TODO 3.8. The TODO now explicitly requires
  3.8 to cover local runs; until then only the vault's `last_used` field
  records the use.
- **Next iteration must know:** a grant token in the environment selects the
  daemon path at parse time too, so `--db` is refused even if the daemon is
  down; there is deliberately no local fallback. `tests/run.rs` is now 985
  lines: put new run e2e coverage in `tests/run_local.rs` or split it first.

## 2026-11-04 — Measure grant growth headroom from the codec (TODO R.61)

- `src/store/payload.rs`: deleted the public `GRANT_GROWTH_BYTES` (production
  never read it; only the test and the `src/store.rs` re-export did) and its
  re-export. The private `grant_growth_bytes` is now `pub(super)` and stays the
  single accounting `encode` subtracts from the encoded size. No behavior
  change: `content` and `MAX_PAYLOAD_BYTES` are unchanged.
- `src/store/tests.rs`: rewrote `grant_growth_headroom_covers_the_whole_grant_cap`
  to measure the growth instead of restating a constant. The fixture sets
  every optional field (max_uses, a listed field scope, two tags, two refs,
  two commands), then encodes the one-grant payload before `mark_used`, after
  it and after `revoke`; the delta is the measured growth. Asserts:
  `measured == grant_growth_bytes(&grant)` (encoder drift fails),
  the attributed content size is identical before and after the transitions,
  and `measured * MAX_GRANTS <= MAX_PLAINTEXT_GROWTH_BYTES`.
- Mutation-checked: removing the `last_used` term from `grant_growth_bytes`
  fails it (16 vs 8). The exact-cap daemon test
  (`a_revocation_fits_a_vault_written_at_the_payload_cap`) still covers the
  end-to-end save.
- `DECISIONS.md`: the payload-limit bullet now names the private helper and the
  measured test instead of a public constant.
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** Phase R is now empty of `- [ ]` items; the next
  unchecked item is **3.7** (`pm run` for humans — local path without a
  grant). This matters for the test suite: `tests/run.rs` is near the 1,000
  line limit, so split before adding e2e coverage there.

## 2026-11-04 — Never let a failed request write look like success (TODO R.60)

- `src/client.rs`: the new private `send_request` is the only request-frame
  write, used by `request()` and `run()`; every `write_all`/`flush` failure
  becomes `Error::Daemon` ("the unlock daemon went away before it received the
  request"). Before, the `io::Error` became `Error::Io`, and `main` maps a bare
  `BrokenPipe` to exit 0 — so a `pmd` that exited after accepting (lock, idle
  timeout, crash) made `run` and `grant revoke --all` report success for a
  request it never received. `read_response` does the same for the answer
  (empty read, reset, any other error), because the stub socket race can lose
  on either side: the first full-suite run after the cherry-pick failed with
  `I/O error: Connection reset by peer` from the read, which still exited 1 but
  did not name the daemon; after a connect, a lost daemon is a daemon error on
  every transport path.
- `main`'s arm is unchanged; its comment now says it covers only this
  process's own stdout/stderr writes. `src/cli/run.rs`'s `relay` comment no
  longer claims a socket `BrokenPipe` takes the generic mapping.
- Tests: `client::tests::a_failed_request_write_is_a_daemon_error_not_a_broken_pipe`
  and `a_closed_connection_without_an_answer_is_a_daemon_error` (dropped
  `UnixStream` peer, deterministic EPIPE/EOF, assert the variant, the nonzero
  exit code and that the message names the daemon);
  `tests/daemon_gone.rs` (new file) and
  `tests/grant_manage_cli.rs::grant_revoke_all_fails_when_the_daemon_goes_away_before_the_request`
  use an accept-then-close stub and require exit 1 with stderr naming the
  daemon. Mutation-checked: they fail with the old `?` (exit 0 vs 1).
- `DECISIONS.md` "Exit codes" records the rule: the `BrokenPipe` -> 0 arm is
  only for this process's own output.
- Earlier attempt (iteration 116, branch `failed/iter-116-20261103-234729`)
  failed the gate on a test-harness flake, not on this change:
  `tests/cli_support/mod.rs` wrote the scripted stdin and `.expect`ed it,
  so a child that refuses before prompting (`--agent`, non-TTY reveal) could
  exit first and turn the setup write into an EPIPE panic. The piped-stdin
  writes in `tests/cli_support/mod.rs` (both helpers) and `tests/unlock.rs`'s
  piped `run` now tolerate exactly `BrokenPipe` (any other error still fails)
  and the outcome is still asserted from the child's output.
- Gate: fmt, clippy, full `cargo test` green; `cargo audit` skipped.
- **Next iteration must know:** next unchecked item is R.61 (`GRANT_GROWTH_BYTES`
  is restated rather than measured). `tests/run.rs` is back to 972 lines, so a
  new e2e there needs a split first; R.60's socket tests live in
  `tests/daemon_gone.rs`.

## 2026-11-04 — loop note: gate failed (iteration 116)

- Commits from this work iteration (TODO R.60) failed the gate and were rolled back.
- The work is kept on branch failed/iter-116-20261103-234729; you may cherry-pick from it and fix it.
- gate: `agent_flag_blocks_reveal_over_pipes --- FAILED`
- gate: `thread 'agent_flag_blocks_reveal_over_pipes' (1476829) panicked at tests/cli_support/mod.rs:58:14:`
- gate: `test result: FAILED. 8 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.06s`
- gate: `error: test failed, to rerun pass `--test cli_reveal``

## 2026-11-04 — Attempt a run's use save exactly once (TODO R.58)

- `src/daemon/run.rs`: deleted `USE_RECORD_ATTEMPTS` and the retry loop.
  `record_use` now delegates to a private
  `record_use_with_save(..., save: impl FnMut(&Vault) -> crate::Result<()>)`
  and answers `RecordError::Internal` after a single failed `save_with_key`;
  the child never runs.
- Chose delete over document: since R.39 every attempt reads under the write
  lock, so a retry cannot merge a lost update, and a save that failed *after*
  its rename landed already holds the increment — a retry charges a second
  use of a `max_uses` grant. `DECISIONS.md` records the one-attempt rule and
  drops "re-reads it on every retry"; R.39's "(retry loop gone)" is now true.
- Test: `src/daemon/run.rs::tests::a_failed_use_save_is_attempted_exactly_once`
  injects a failing save through the seam and asserts one attempt,
  `Internal`, and `uses() == 0` after reopening the vault. Mutation-checked:
  with a 3-attempt loop patched in it fails (attempts 3 vs 1).
- Gate: fmt, clippy, full `cargo test` green (first full run hit a
  non-reproducing `tests/cli_support/mod.rs:58` stdin BrokenPipe in
  `tags_are_stored_filtered_and_metadata_only`; that test passed alone and
  the second full run was green). `cargo audit` skipped.
- **Next iteration must know:** next unchecked item is R.60 (a socket
  `BrokenPipe` mapped to exit 0 in `src/cli/mod.rs:47`).
  `record_use_with_save` is production code with a test seam; keep `save` as
  `FnMut` so a future test can count attempts.

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

