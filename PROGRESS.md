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

