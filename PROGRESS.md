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

