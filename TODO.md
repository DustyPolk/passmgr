# TODO

Ordered, small, testable tasks. One unchecked item per iteration; split items that
are too big rather than doing partial work.

Rules that apply to every item:
- The agent-facing surface returns references and metadata, never secret values.
- Every security-relevant behavior needs a test that proves it (e.g. the secret is
  absent from stdout, stderr and logs).
- No new network-capable dependency. Justify any new dependency in `PROGRESS.md`.

## Phase R — review findings (fix first)

- [x] **R.15a `prove` answered "approved" without recording what was
      approved.**
      Split from R.15. `src/daemon.rs` now stores the verified digest as a
      one-shot approval (`presence::Approvals`) before answering `proven`, so
      the daemon learns exactly which request a human approved, not merely
      that some key holder MAC'd 32 bytes. The store is in memory, expires
      after 60 s, is capped at 16 (the oldest makes room, because only a key
      holder can add one), and `take` consumes exactly one matching digest.
      Done: `Approvals::{record,take}` in `src/presence.rs`, wired into
      `handle_connection`; the misleading "cannot approve a different one"
      comment in `tests/daemon.rs` now says it is a MAC mismatch; `MCP.md`,
      `DECISIONS.md` and the protocol/client docs describe the approval.
- [!] **R.15b The write must spend the approval exactly once.** Blocked on
      TODO 3.4/4.9, which own the first grant write. Test: complete `prove`
      for digest A, submit a create whose canonical digest is B, and assert it
      is refused and writes nothing; then assert A-then-A succeeds exactly
      once. The daemon half of the binding is already proved by
      `a_verified_proof_records_exactly_the_digest_it_covered`, so this item
      is the write path's obligation, not a new mechanism.

- [x] **R.16 Any session-token holder can occupy all 16 challenge slots and
      block human approval.**
      `MAX_PENDING_CHALLENGES` (`src/presence.rs:56`) is global; `issue`
      (`src/presence.rs:282-292`) prunes only when called and otherwise
      refuses at the cap; `Request::Challenge` (`src/daemon.rs:593-605`)
      needs only the session token, which the MCP agent holds by design
      (`SECURITY.md`: any same-user process can read the 0600 session file).
      Failure (confirmed by the code; same-user DoS is partly accepted, but
      this one silently blocks the only path that mints a grant): the agent
      sends 16 `challenge` requests, then the human's `pm grant approve`
      gets `busy` ("too many outstanding challenges") and cannot approve;
      repeat every 59 s to sustain it. No unauthorized access results, but
      the approval flow is the boundary and must not be starvable by the
      party it constrains. Fix: evict the oldest pending nonce (or reserve a
      small per-connection allowance) instead of failing the human, and
      record the choice in `DECISIONS.md`. Test: fill the pool, then assert
      a new `challenge` still succeeds, the evicted nonce is refused and the
      newest works; add a daemon test where approval succeeds after 16
      agent-issued challenges.
      Done: `Challenges::issue` prunes expired nonces and then evicts the
      **oldest** when the pool is full, so it no longer fails; the
      `PresenceError::TooManyPending` variant is gone (only a CSPRNG failure
      answers `busy` now). No per-connection allowance: every request is a
      fresh connection and the peer UID is identical for agent and human, so
      such a rule would be spoofable. A sustained flood can still evict a
      fresh nonce; recorded as same-user DoS in `SECURITY.md`. Tests: the
      pool eviction unit test, the prune-before-evict test, and the daemon
      test where a proof succeeds after 16 agent-issued challenges while the
      evicted first nonce is denied.

- [x] **R.17 `store::encode` can write a payload its own decoder rejects, so
      one bad timestamp bricks the vault.**
      `Grant::from_stored` (`src/grant.rs:616-641`) rejects `revoked_at` /
      `last_used` above `MAX_TIMESTAMP_UNIX`, but `Grant::mark_used`
      (`src/grant.rs:798-803`) and `Grant::revoke` (`src/grant.rs:805-810`)
      accept any `u64`, and `store::encode` (`src/store.rs:547-600`) checks
      only credential timestamps (`validate_timestamps`, `src/store.rs:683`)
      and grant-id uniqueness, never the grant invariants. Verified in a
      scratch crate: `grant.revoke(u64::MAX - 1)` -> `encode` succeeds (191
      bytes) -> `decode` fails with `malformed vault: revoked_at timestamp
      18446744073709551614 exceeds the maximum of 253402300799 Unix
      seconds`. Failure (latent: no caller today, 3.5/3.6 add some):
      `Vault::save` replaces the good vault with the unreadable payload and
      every later open fails `MalformedVault`; all credentials are lost.
      `now_unix()` (`src/store.rs:215`) guards its own callers, so this needs
      a caller that passes a raw value, but the writer must never emit what
      its reader refuses. Fix: bound `now` in `mark_used`/`revoke` (same
      `MAX_TIMESTAMP_UNIX` check, error return) and re-validate grants in
      `encode` before producing bytes. Test: `mark_used(MAX_TIMESTAMP_UNIX +
      1)` and `revoke(MAX_TIMESTAMP_UNIX + 1)` must error, and a round-trip
      property test over every public `Grant` constructor must hold (`encode`
      then `decode` succeeds).
      Done: `Grant::mark_used` and `Grant::revoke` now return
      `Result<(), UpdateError>`, where the new `UpdateError::TimestampOutOfRange`
      refuses `now > MAX_TIMESTAMP_UNIX` and changes nothing (`UpdateError` is
      separate from `Denied`, which stays an authorization answer).
      `Grant::from_stored` was split into `check_stored(&StoredGrant)` plus a
      `to_stored()` builder; `store::encode` derives the stored form, runs the
      decoder's check on it, and serializes **that** value, so writer and
      reader cannot drift. Tests: the mutation bound (including the inclusive
      maximum), a round trip over create/used/revoked, and a `src/grant.rs`
      unit test that corrupts a private field and proves `encode` refuses it.

- [x] **R.18 The label rejection table is broader than every document and
      error message that describes it.**
      `is_hidden_or_reordering` (`src/grant.rs:880-909`) rejects variation
      selectors U+FE00-FE0F, so `Grant::create` refuses a normal emoji
      presentation label such as "❤️ prod" (U+2764 U+FE0F) with "a grant
      label must not contain control, bidi or zero-width characters"
      (`src/grant.rs:855-857`). But `FORMAT.md:149` lists only "control, bidi
      or zero-width", and `DECISIONS.md:358-359` says "an emoji without a
      zero-width joiner ... is allowed"; only `DECISIONS.md:354-355`
      mentions variation selectors, and the error names none of the extra
      classes (VS, U+2028/U+2029, tag characters). `tests/grant.rs:236-266`
      never uses U+FE0F, so the table cannot catch the regression.
      Failure: a human approving a grant for "❤️ prod" is refused with a
      message that names the wrong character class; 3.5 will pin whichever
      behavior ships. Fix: decide explicitly — either allow VS15/VS16 (they
      select a visible presentation, they do not hide text) and drop those
      ranges, or keep rejecting them and say so in `FORMAT.md`,
      `DECISIONS.md` and the error message. Test: add "❤️ prod" and a
      genuine VS1-14 case to the accept/reject table with the chosen
      outcome, and add a `tests/docs.rs` contract so the documents cannot
      drift from the table again.
      Done: kept the whole class refused (a stored label must render exactly
      as approved) and made the class explicit. New
      `grant::LABEL_FORBIDDEN_CLASSES` is the single spelling used by the
      rejection error, `FORMAT.md` and `DECISIONS.md`; `DECISIONS.md` also
      records why VS15/VS16 are refused. Tests: the table now includes
      U+FE0E, U+E0001 and U+E0020; a dedicated test refuses "❤️ prod" and a
      bare VS15 label while accepting the selector-free heart, and asserts
      the error names the class without echoing the label; `tests/docs.rs`
      pins both documents to the constant.

- [x] **R.19 Consuming a non-last challenge reorders the pool, so the next
      full pool evicts the newest nonce, not the oldest.**
      `Challenges::verify_and_consume` takes the nonce with
      `self.pending.swap_remove(index)` (`src/presence.rs:340`), which moves
      the last (newest) entry into the freed slot. The comment that promises
      "`pending` is in issue order, so index 0 is the oldest"
      (`src/presence.rs:312`) and the eviction itself
      (`self.pending.remove(0)`, `src/presence.rs:316`) then evict the wrong
      entry. Every description of the R.16 fix says oldest-first:
      `src/presence.rs:60`, the `Prove` arm comment in `src/daemon.rs:605`,
      `MCP.md:208` ("dropping the oldest") and `DECISIONS.md:421` ("the
      **oldest** nonce is evicted").
      Failure: whenever a non-last nonce is consumed -- a human proving
      while an agent floods `challenge`, or two concurrent approval flows --
      the newest nonce jumps to index 0; one further `challenge` from any
      session-token holder then evicts it. That is precisely the case
      oldest-first was chosen to avoid, so the flood can destroy a nonce
      with a proof in flight and the human must re-run the whole TTY
      approval. Reproduced with a standalone `Vec` probe: after consuming
      index 1 of [2,4,6,8] the vec is [2,8,6] and the next `issue` evicts
      8, the newest. No capability is widened (a proof still needs the
      key), so this is an approval-path availability bug plus drift in a
      checked-off item and three documents.
      Fix: consume with order-preserving `self.pending.remove(index)` (the
      pool holds 16 entries, so the memmove is irrelevant), or evict the
      entry with the smallest `issued` stamp; then make the MCP.md and
      DECISIONS.md wording true.
      Test: fill the pool, consume a non-last nonce, issue one more, and
      assert through `daemon::prove` that the oldest survivor was evicted
      and the newest still verifies. The existing
      `a_full_challenge_pool_evicts_the_oldest_instead_of_refusing`
      (`src/presence.rs:645`) only covers a pool with no consumption.
      Done: `verify_and_consume` now uses order-preserving
      `self.pending.remove(index)` (`src/presence.rs:348`), with a doc comment
      saying why. Correction to the finding: consuming a *middle* nonce never
      put a newer one at index 0 -- `swap_remove` only moves the last entry
      into the freed slot -- so that case already evicted the oldest survivor.
      The observable breakage is spending the **oldest** nonce, which made the
      newest take its place and the next `challenge` evict it. Tests cover
      both: `consuming_the_oldest_nonce_keeps_the_oldest_survivor_evictable`
      and `consuming_a_middle_nonce_leaves_the_oldest_at_index_zero` (unit),
      plus the end-to-end
      `spending_the_oldest_challenge_never_evicts_a_newer_one` in
      `tests/daemon.rs`; the first and third fail with `swap_remove` (checked
      by running them against it). `MCP.md`, `DECISIONS.md` and the
      `MAX_PENDING_CHALLENGES` doc now say that spending keeps issue order.

- [x] **R.20a Split `src/store.rs` and add the layout guard.**
      Split from R.20 (four files are over the ~1,000-line rule; each file is
      one iteration). `src/store.rs` (1,868 lines) now holds the credential
      model and validation only (461 lines); the payload codec moved to
      `src/store/payload.rs` (659) and its tests to `src/store/tests.rs` (771),
      with `store.rs` re-exporting `encode`/`decode`/`Payload` so every caller
      is unchanged. New `tests/layout.rs` walks `src/**/*.rs` and `tests/**/*.rs`
      and fails any file over 1,000 lines; `PENDING_SPLITS` names the three
      files the remaining sub-items still have to split, and a second test
      fails if a listed file is no longer oversized (the list only shrinks).
      Test: the layout guard fails (`src/vault.rs` 1,271, `src/protocol/mod.rs`
      1,317, `tests/cli.rs` 1,463) when `PENDING_SPLITS` is emptied, passes
      with the post-split tree, and the lib suite (223) is unchanged.
- [x] **R.20b Split `src/vault.rs` (1,271 lines) by concern.**
      Move the write-lock and atomic-write machinery (`acquire_write_lock`,
      `acquire_write_lock_with_timeout`, `write_container`, `with_path`) into
      `src/vault/lock.rs` (or a similarly named module), leaving the vault
      lifecycle in `src/vault.rs`. Keep the public items (`lock_for_update`,
      `lock_path`, errors) where callers expect them. Remove `src/vault.rs`
      from `PENDING_SPLITS` in `tests/layout.rs`.
      Test: the layout guard passes without that entry and the existing lock /
      atomic-write unit tests plus `tests/unlock.rs` still pass; the split is
      behavior-preserving.
      Done: `src/vault.rs` is now 358 lines (lifecycle, `read_container`,
      `insecure_permissions`); the lock and atomic-write helpers moved to
      `src/vault/lock.rs` (199) as `pub(super)`, with `pub use self::lock::{
      lock_path, LOCK_SUFFIX }` so every caller's path is unchanged and
      `tests/cli.rs` still uses `passmgr::vault::lock_path`. The inline test
      module also moved, mechanically, to `src/vault/tests.rs` (744) -- the
      same `src/x.rs` + `src/x/` layout R.20a used -- because the code move
      alone left `vault.rs` over 1,000. Only the two lock-only tests
      (`write_lock_is_exclusive_private_and_released_on_drop`,
      `write_lock_refuses_a_symlink`) moved into `lock.rs`'s own test module;
      the other 22 are unchanged apart from indentation and one import.
- [x] **R.20c Split `src/protocol/mod.rs` (1,317 lines).**
      Move the frame and body codec (`encode`, `decode`, `FrameDecoder`,
      `read_length`, `check_length`, `encode_body`, `decode_body`) into
      `src/protocol/codec.rs`, keep the request types and validation in
      `mod.rs`, and move the ~590-line test module to `src/protocol/tests.rs`
      (as R.20a did for `store`). Remove `src/protocol/mod.rs` from
      `PENDING_SPLITS`.
      Test: the layout guard passes without that entry; the protocol unit
      tests and `tests/daemon.rs` still pass unchanged.
      Done: `src/protocol/mod.rs` is 444 lines (request/response types,
      `ProtocolError`, field validation, `valid_env_name`); `codec.rs` is 304
      (`encode`, `decode`, `FrameDecoder`, `read_length`, `check_length`,
      `split_frame`, the body codec and its JSON helpers); `tests.rs` is 590.
      `mod.rs` re-exports `encode`/`decode`/`FrameDecoder`, and the private
      `use codec::split_frame;` keeps `response.rs`'s `super::split_frame`
      working without widening it. The moved code is byte-identical to
      `HEAD:src/protocol/mod.rs` apart from the module wrapper; only
      indentation, the two relocated imports and rustfmt's re-wrapping
      differ. Lib test count unchanged at 223 (40 in `protocol::tests`).
- [x] **R.20d Split `tests/cli.rs` (1,463 lines).**
      Move the PTY/reveal/agent-marker tests and their helpers (`run_on_pty`,
      `read_pty`, the serial guard where needed) into a second test binary
      (e.g. `tests/cli_reveal.rs`), keeping the shared helpers in one place
      (e.g. `tests/cli_support/mod.rs`) so both binaries use the same vault
      setup. Remove `tests/cli.rs` from `PENDING_SPLITS`.
      Test: the layout guard passes without that entry and every moved test
      keeps its behavior (same assertions, same canaries); total test count is
      unchanged.
      Done: `tests/cli_reveal.rs` (368 lines, 9 tests: the reveal refusals,
      the PTY success path, and the `--agent` tests); `tests/cli.rs` is 975
      lines with the remaining 21 tests. `tests/cli_support/mod.rs` (283) holds
      every helper, now `pub`, including `SERIAL`/`serial`, `run_on_pty` and
      `read_pty`. `PENDING_SPLITS` is empty; its second guard test still runs.
      All 30 test bodies are byte-identical to `HEAD` apart from the `pub`
      prefixes (verified by a per-function diff), total CLI tests unchanged at
      30, and the rest of the suite is unchanged. Each binary has its own
      `SERIAL` mutex, so the two binaries can run concurrently; both still run
      their own tests one at a time.

- [x] **R.21 A grant's command allowlist accepts terminal control, bidi and
      zero-width characters, so an agent-chosen path can forge the line a
      human reads when approving it.**
      `validate_commands` (`src/grant/validate.rs:105-118`) rejects only a
      relative path, an empty string, an embedded NUL and an over-long path.
      The label validator two functions above
      (`src/grant/validate.rs:33`, table at `src/grant/validate.rs:67`)
      rejects every C0/C1 control, bidi override, zero-width/format character,
      line separator and variation selector, precisely because a label "may
      come from an approved agent request" (TODO R.18). A command path now has
      the same provenance and no filter: `grant_create` carries attacker-chosen
      paths over the socket (`src/daemon.rs:643-673` re-normalizes them through
      `Scope`/`GrantRequest`, which sorts and dedups but filters no
      character class), `canonicalize` preserves whatever bytes
      the file name holds, TODO 3.5 makes `pm grant list|show` print the
      allowlist, and TODO 4.9 shows an agent's request to the human before they
      approve it.
      Failure: an agent asks for a grant whose command is
      `/usr/bin/gh\x1b[2K\r/usr/bin/true`; `pm grant show` (or the approval
      prompt) renders only `/usr/bin/gh` because the escape erases the rest of
      the line, so the human approves a binary they were never shown and every
      later render lies the same way. `\n` in a path splits one allowlist
      entry across two visual lines, and U+202E or U+200B hides the real tail
      of a path behind the displayed one.
      Fix: apply the same character-class rejection in `validate_commands`
      (share the predicate with `validate_label`; it is private today), so no
      path carrying a hidden or reordering character can be stored, approved,
      sent over the wire, or printed. Stored grants need no migration: the
      check belongs on the create path.
      Test: `GrantRequest::new`/`GrantSpec` with `/usr/bin/gh\x1b[2K\r`,
      `/usr/bin/gh\ntrue`, `/tmp/\u{202e}bin` and `/tmp/a\u{200b}b` is refused
      with an error that names the offending command, while `/usr/bin/gh` and a
      non-ASCII but visible path such as `/usr/bin/grüße` are still accepted;
      extend `grant_create_rejects_payloads_the_vault_writer_would_refuse` so a
      frame carrying the escaped path is `bad_request` and leaves no approval
      spent.
      Done: `validate_commands` shares the private `is_hidden_or_reordering`
      table; the error names the command with every hidden character escaped
      (`escape_hidden`, which also escapes a quote and a backslash). Both
      `Grant::create` and
      `GrantRequest::new` use it, so create and decode agree and stored grants
      need no migration.

- [x] **R.22a "Never spent on a request no write could accept" was false for
      vault-level limits.**
      `GrantRequest::check_approvable` (`src/grant/request.rs:146-152`) checks
      only the expiry, but its doc comment and the daemon comment at
      `src/daemon.rs:650-660` claimed that no write could then refuse the
      request. The write also fails on vault limits: `store::encode` refuses
      more than `MAX_GRANTS` (1024) grants or more than `MAX_PLAINTEXT_BYTES`,
      and `Vault::save_with_key` only discovers that after the approval is
      gone. The daemon must not learn vault state, so the claim was narrowed
      to the expiry rule and the vault-level check moved to the writer.
      Done: new `Vault::check_grant_writable(&Grant)` (`src/vault.rs`) runs the
      writer's own `store::encode` over the candidate grant list and writes
      nothing, so the pre-check cannot drift from the write path. The
      `check_approvable` and daemon comments now say the daemon checks the
      expiry rule only and name the CLI's pre-check; `MCP.md` and
      `DECISIONS.md` say who owns the vault-level check and when it runs, and
      `tests/docs.rs::docs_say_who_checks_vault_limits_before_the_proof` pins
      those sentences and forbids the old absolute claim in both comments.
      Tests: `check_grant_writable_refuses_a_full_vault_without_writing` (a
      vault at `MAX_GRANTS` reports the writer's "too many grants", the vault
      is unmodified and the file is never created) and
      `check_grant_writable_accepts_a_grant_that_still_fits` (one slot left is
      accepted; a duplicate id is refused before the write). The
      `MAX_PLAINTEXT_BYTES` branch shares the same `store::encode` call.
- [x] **R.22b `pm grant create` must refuse a full vault before the proof.**
      Blocked on TODO 3.4d, which owns the CLI and its vault access. 3.4d must
      open the vault with the derived key and call
      `Vault::check_grant_writable` on the grant it is about to propose
      **before** it sends `challenge`/`prove`, so a vault at `MAX_GRANTS`
      fails with "too many grants" and spends no approval. Test: seed a vault
      at `MAX_GRANTS`, run `pm grant create` on a PTY, assert the
      "too many grants" error, assert no `challenge`/`prove` frame reached a
      stub socket, and assert `Approvals::pending() == 0`. Do not add
      `MAX_GRANTS` to `check_approvable`; tick this item when 3.4d lands.

- [x] **R.23 Nothing tests the 30-day branch of the pre-spend check, so the
      30-day refusal could be dropped without a failure.**
      MCP.md:224-226 and DECISIONS.md promise that `grant_create` refuses a
      request whose expiry is past **or more than 30 days out** without
      spending the approval. `GrantRequest::new` does not check the clock (it
      only caps `expires_at` at `MAX_TIMESTAMP_UNIX`,
      `src/grant/request.rs:90-92`), so the 30-day rule reaches the daemon only
      through `check_approvable` -> `grant::validate_expiry`
      (`src/grant.rs:535-551`). The single daemon test,
      `grant_create_refuses_an_expired_request_without_spending_the_approval`
      (`src/daemon/tests.rs:261`), only sends `now - 1`; the past-expiry and
      over-`MAX_TIMESTAMP` cases are covered elsewhere (the latter already
      fails in `GrantRequest::new`).
      Failure: a refactor replaces `check_approvable` with `expires_at <= now`
      (or deletes the 30-day rule as "duplicated in `Grant::create`") because
      the suite stays green; a human's approval is then spent on a 90-day
      request that the writer rejects, which is exactly the failure 3.4c says
      it prevents.
      Test: send `grant_request(now + 30 * 86_400 + 1)` after a successful
      `prove`, assert `bad_request`, assert `Approvals::pending() == 1`, then
      assert an `Approvals::take` for that exact digest still succeeds; keep
      the existing `now - 1` case and add `now + 30 * 86_400` (accepted) as the
      boundary.
      Done: `grant_create_refuses_a_request_longer_than_thirty_days_without_spending_the_approval`
      (`src/daemon/tests.rs`) proves the daemon's 30-day refusal, the unspent
      approval and the exact-30-day acceptance. It sends one hour over the cap
      rather than one second, because the daemon reads its own clock; the
      exact one-second boundary is already covered deterministically by
      `Grant::create` in `tests/grant.rs` (`NOW + MAX_GRANT_LIFETIME_SECS + 1`).
      Verified the new test fails (`GrantApproved` instead of `BadRequest`)
      with `validate_expiry`'s 30-day branch removed.

- [x] **R.24 TODO 3.4c still documents the `grant_create` request nested under
      a `request` key, so the only concrete wire shape in the docs is wrong.**
      Its protocol line (`TODO.md`, item 3.4c, the "Protocol request"
      paragraph under `### Phase 3`) shows
      `{type:"grant_create", request:{label, refs, tags, fields?, commands,
      capabilities, expires_at, max_uses?, token_hash}}`; the implementation and
      the same item's Done note ("fields are flat on the request object like
      `run`, not nested under a `request` key") put those fields flat, and
      `src/protocol/tests.rs` pins the flat shape. MCP.md:219-226 describes the
      fields in prose but never names the keys, so a reader who needs the shape
      has only the wrong spec line. 3.4d (the next iteration) builds the client
      from this file.
      Failure: the 3.4d client is written from the spec line, the daemon decodes
      the nested form as `label: null` and answers `bad_request`, and the
      resulting debugging session "fixes" the encoder instead of the doc.
      Fix: correct that spec paragraph (TODO.md, item 3.4c) to the flat shape
      and add the exact key
      list (one fenced JSON example) to MCP.md's "The daemon never writes a
      grant" paragraph so the wire shape has one authoritative home.
      Test: pin that MCP.md example in `src/protocol/tests.rs` as a literal,
      assert `decode` yields the expected `GrantCreateRequest` and that
      re-encoding reproduces the literal byte for byte (a nested example fails
      this), and have `tests/docs.rs` assert the key set in the example equals
      the encoder's key set.
      Done: TODO 3.4c's spec line is now the flat shape and names MCP.md as
      the home of the exact body (the old line also had an unterminated code
      span). `MCP.md` ("The daemon never writes a grant") carries the full
      frame body with every key, the `null` rule for `fields`/`max_uses`, and
      a note that no credential value is in it; `src/protocol/mod.rs`'s
      sketch now points there. Tests: `src/protocol/tests.rs::
      mcp_documented_grant_create_body_is_the_wire_format` pins the literal,
      decodes it to `grant_create()` and re-encodes to the same bytes;
      `tests/docs.rs::mcp_grant_create_example_has_the_encoder_keys` extracts
      the fenced block from MCP.md and compares envelope and request key sets
      plus the whole value to the encoder (a nested example fails, verified).

- [ ] **R.25 The interpreter gate is an incomplete name list, and the
      documented `gh` example is itself a program runner.**
      `is_interpreter` (`src/grant/validate.rs:130-192`) refuses only the fixed
      names in `INTERPRETERS`/`VERSIONED_INTERPRETERS`; `gh` and `git` are
      absent, and `src/grant.rs:937-962` explicitly asserts that `/usr/bin/gh`
      and `/usr/bin/git` are **not** interpreters. But a grant binds only
      argv[0] (`Grant::allows_command`), so any allowed program that can run
      another command is a shell. `README.md:220` uses
      `--command /usr/bin/gh` as the example.
      Failure: a human approves that example, and the agent runs
      `gh alias set --shell pwn 'id -u > /tmp/proof'; gh pwn` (verified: the
      proof file contains `1000`) or
      `git -c alias.pwn='!id -u > /tmp/proof' pwn` (also verified). Either can
      read the injected secret from the environment and send it out. The
      gate's stated purpose (`MCP.md:265-268`, `DECISIONS.md:529-536`) is
      defeated, and the unit test locks the bypass in.
      Fix: add `gh`, `git` and the other known runners (`find`, `sed`, `tar`,
      `ssh`, `go`, `docker`, `podman`, `kubectl`, …) to the table, or require
      an explicit per-command trust confirmation for every command because
      argv is unconstrained; update the README example and the test so it no
      longer calls git/gh safe.
      Test: a unit table over every documented runner name, plus an e2e test
      where `passmgr grant create --command /usr/bin/gh` exits 5 with the
      interpreter refusal before the password prompt and creates no token
      file, and the same command with `--allow-interpreter` succeeds.

- [ ] **R.26 `pm grant create` prompts for the master password without ever
      showing the request the human is approving.**
      `command_grant_create` checks the TTY, creates the token file and calls
      `prompt_master(false)` at `src/cli/grant.rs:153`; the `GrantRequest` is
      built at `src/cli/grant.rs:163-176`, and its label, refs/tags, commands,
      expiry and max uses are never printed. `MCP.md:265-268` promises
      "Approval shows a red warning" for interpreters, and
      `DECISIONS.md:362-363` says the approval prompt renders command paths,
      but no grant-create prompt does; `--allow-interpreter` silently skips
      the refusal at `src/cli/grant.rs:129-136`.
      Failure: an agent supplies the argv for a terminal command (the normal
      threat model), the human sees only "Enter Master Password", and the
      digest they prove covers e.g. a 30-day, 100-use, all-refs grant for
      `--command /usr/bin/gh`. Presence is proved, but not informed consent.
      There is no test that any summary is shown.
      Fix: build the request first and print a sanitized summary (label,
      refs/tags, commands, expiry, max uses and the red interpreter warning)
      before the prompt, then require an explicit y/N; on `n` exit 2 before
      creating the token file or contacting the daemon.
      Test: a PTY `grant create` with sentinel values asserts every value and
      the warning appear before the "Master Password" prompt, that a command
      containing a hidden character is refused before any summary, and that
      answering `n` sends no `challenge`/`prove` and leaves no token file.

- [ ] **R.27 `grant revoke --all` panics if the daemon answers `not_found`.**
      In the `Response::Error(ResponseError::NotFound)` arm,
      `src/cli/grant.rs:369` does
      `Err(Error::GrantNotFound(options.id.expect("not_found implies an id")))`.
      `--all` leaves `options.id` as `None`, so any daemon, or a same-user
      process that replaced the socket, answering `{"type":"error",
      "code":"not_found"}` makes the CLI panic instead of reporting a clean
      error. The current daemon returns `not_found` only for an id
      (`src/daemon.rs:738-740`), so this is a robustness/DoS bug, not a secret
      leak.
      Failure: `passmgr grant revoke --all` exits 101 with a panic and a
      backtrace; a script cannot distinguish that from a crash, and the arm is
      untested.
      Fix: match on `options.id`; `Some(id)` -> `GrantNotFound(id)`, `None` ->
      a `Daemon`/protocol error such as "the daemon refused the revoke".
      Test: a stub `UnixListener` reads the `grant_revoke` frame and writes a
      `not_found` error; assert a nonzero exit, a normal message, and no
      `panicked at` or `not_found implies an id` in stderr.

- [ ] **R.28 `grant revoke --all` revokes expired and exhausted grants while
      the help, decisions and test say "active".**
      `revoke_grants` (`src/daemon.rs:743-748`) filters only
      `!grant.is_revoked()`, so expired and exhausted grants are included and
      counted; `grant_status` treats "active" as neither revoked, expired nor
      exhausted. `src/cli/help.rs:125` says "every active grant",
      `DECISIONS.md:414` says "`--all` targets only active grants", and
      `tests/grant_cli.rs:713` seeds only three active grants.
      Failure: with one active, one expired and one exhausted grant,
      `grant revoke --all` prints "Revoked 3 grant(s)" and flips the expired
      and exhausted rows to `revoked`; a human cannot tell which grants were
      actually in force. A future refactor that adds a status filter has no
      failing test.
      Fix: filter with the same predicate as `grant_status` (a new
      `is_active(now)`), or change the docs to "every grant that is not
      already revoked" and count all changed; keep one predicate.
      Test: a `revoke_grants` unit test with an explicit `now` and one active,
      one expired and one exhausted grant, asserting the chosen contract,
      the count, and each grant's `revoked_at`/status.

- [ ] **R.29 `--out` paths are echoed with raw control characters.**
      The success line at `src/cli/grant.rs:226` interpolates
      `options.out.display()`, and the existing-file error at
      `src/cli/grant.rs:576` interpolates `path.display()`; unlike command
      paths, neither is passed through `escape_hidden`/`escape_debug`. The path
      is argv and can be agent-suggested.
      Failure: `passmgr grant create ... --out $'\e]52;c;...'` writes a raw
      OSC 52 escape to the human's terminal on success or when the file
      already exists, letting the suggested path manipulate the terminal or
      clipboard after the human trusted the command. (Confirmed by code
      inspection; no scratch e2e was run because the happy path needs a daemon
      and a written grant.)
      Fix: escape the path for display with the same helper used for commands
      in both messages.
      Test: a formatting unit test, or a PTY existing-file case, asserts the
      message contains `\u{1b}` as text and no raw ESC/OSC sequence.

## Phase 3 — grants and audit log

The design for grants, approval and audit lives in `MCP.md` ("Grants and the
approval flow", "Audit"). Follow it.

- [x] **3.1 Vault write lock.** The CLI and `pmd` will both write the vault.
      Add an exclusive `flock` on `<vault>.lock` held across every
      read-modify-write. Test: two concurrent writers both land (no lost
      update), and a reader never sees a torn file.
      Done: `Vault::open_for_update`/`open_for_add` take the sidecar lock
      before reading and hold it until drop; `save` refuses a read-only
      `Vault`. `add`/`edit`/`delete` use it; reads stay lock-free.
- [x] **3.2a Grant model and authorization check.** New pure module
      `src/grant.rs` with the fields per `MCP.md`: id, SHA-256 token hash,
      label, scope (refs, tags, optional field names), command allowlist,
      capabilities (`list`, `run`), expires_at, max_uses, uses, created,
      revoked_at, last_used. Validation for every field, and
      `Grant::authorizes(&AccessRequest, now) -> Result<(), Denied>` as the
      single decision point, plus `scope_allows` for list filtering,
      `mark_used` and `revoke`. Add `sha2` (RustCrypto) for the token hash;
      `hmac` moves to 3.3 where the presence proof first uses it. No store
      change yet. Table-driven tests: expired, revoked, used up, missing
      capability, ref out of scope, tag match, field scope, command not
      allowed, a known SHA-256 vector, and a redacting `Debug`.
      Done: model + pure check in `src/grant.rs`, tests in `tests/grant.rs`;
      `hmac` deferred to 3.3 so no unused dependency lands. Grants are not
      persisted yet.
- [x] **3.2b Persist grants in store version 5.** Add the grant list after
      the credentials in the payload, encode/decode with the same length
      caps, v5 keeps credentials byte-identical to v4 and earlier versions
      migrate to an empty grant list. `Vault` gains grant accessors used by
      `save`. Update `FORMAT.md` and `DECISIONS.md`. Tests: v4 -> v5
      migration, every older version decodes with no grants, a round trip,
      duplicate grant ids and a truncated grant record are `MalformedVault`.
      Note: optional fields are behind a flags byte (not a magic `0`
      timestamp), and `Vault::add_grant` reports a duplicate id as
      `InvalidInput` rather than a new error variant.
- [x] **3.3 Human-presence proof.** Add `hmac` (RustCrypto) here, its first
      use. Daemon `challenge` request returns a nonce. The CLI answers with
      `HMAC-SHA256(key, "passmgr-approve-v1" || nonce || digest)`. The daemon
      verifies in constant time, and a nonce is single-use with a 60 s
      expiry. Tests: correct proof accepted, wrong key/reused
      nonce/expired nonce/altered digest rejected. Done: `src/presence.rs`,
      `challenge`/`prove` requests, `client::challenge`/`client::prove`; the
      nonce is spent by any attempt and all failures answer `denied`. The
      master-password prompt and the request digest arrive with 3.4.
**3.4 `pm grant create`** needs four steps (it was too large for one
iteration: TTY proof, canonical request, daemon write, token file). Ordered:
- [x] **3.4a Canonical grant-create request and digest.** New pure module
      `src/grant/request.rs`: `GrantRequest::new(GrantSpec, TokenHash)`
      normalizes every field exactly as `Grant::create` will (label, scope,
      commands, capabilities, expiry shape, max-uses), and `digest()` returns
      the `presence::RequestDigest` of a length-prefixed encoding
      (`b"passmgr-grant-create-v1"`, then label, refs, tags, optional fields,
      commands, capability bits, expiry, optional max-uses, token hash) with a
      domain separator and big-endian lengths. `create_grant(now)` builds the
      `Grant` from the normalized fields. The digest covers only what the
      request writes; id and `created` are assigned at write time and cannot
      widen access. Tests: reordered/duplicated refs, tags, fields and
      commands give the same digest; changing any field or the token hash
      changes it; length-prefix boundaries cannot be shifted (`ab`+`c` vs
      `a`+`bc`); the canonical form has a pinned hex vector; a RUN request
      without commands, empty capabilities, `max_uses == 0`, a too-large
      expiry and a non-UTF-8 command are refused; `create_grant` writes
      exactly the requested fields; `Debug` redacts the token hash. Done:
      `src/grant/request.rs`; 7 unit tests plus a public-API test in
      `tests/grant.rs`; `GrantRequest` is re-exported from `passmgr::grant`.
- [x] **3.4b Re-encrypt with the unlocked key (no re-salt).**
      `Vault::save(master_password)` takes a fresh salt, which would make the
      running daemon's derived key stale after any grant write. Add
      `crypto::encrypt_with_key(plaintext, key, template_container)`: it first
      authenticates the template with `key` (so a wrong key can never produce
      an unopenable vault), then reuses the template header's salt and KDF
      params with a fresh random nonce and the same AAD. Add
      `Vault::save_with_key(&self, key)` (refuses a read-only vault; requires
      the source container; writes atomically). Tests: the result decrypts
      with the original password, keeps salt/params, uses a new nonce;
      a wrong key returns `AuthenticationFailed` and writes nothing;
      `save_with_key` refuses a read-only vault; a grant survives a reopen;
      the daemon's key still decrypts the saved container.
      Done: `crypto::encrypt_with_key` authenticates the template with the key
      before reusing its header, then seals with a fresh nonce and the same
      salt/params (container assembly is a shared private `seal`, so `encrypt`
      and `encrypt_with_key` cannot drift). `Vault::save_with_key` refuses a
      read-only vault and, with `Error::Crypto`, a vault that has no source
      container to copy the header from. Docs updated in `FORMAT.md` and
      `README.md`.
- [x] **3.4c `grant_create` request and daemon handler (TODO R.15b).**
      Protocol request `{type:"grant_create", label, refs, tags, fields?,
      commands, capabilities, expires_at, max_uses?, token_hash}` — flat on
      the request object like `run`, no nested `request` key; `MCP.md` ("The
      daemon never writes a grant") holds the exact frame body — and response
      `{type:"grant_approved"}` (no token, hash or grant id in
      any response; the CLI assigns the id when it writes). The daemon
      decodes and re-normalizes through `GrantRequest::new`, computes the
      digest, and calls `presence::Approvals::take` for it. The daemon does
      not open or write the vault: no request type in `pmd` can create a
      grant, so an agent that reaches the socket cannot mint one even if an
      approval were forged. A digest mismatch, an unspent approval, an
      expired/out-of-range expiry or >30 d lifetime answers
      `denied`/`bad_request` and writes nothing. Tests: `prove(A)` then
      `grant_create(B)` is refused; `prove(A)` then `grant_create(A)`
      succeeds exactly once and a replay is refused; the vault is byte-identical
      after both; response JSON has no secret material.
      Done: fields are flat on the request object like `run`, not nested under
      a `request` key. `GrantRequest::check_approvable` reuses the new
      `grant::validate_expiry`, so a request no write could accept is
      `bad_request` and leaves the approval unspent. A hash that is not 64
      lowercase hex, a bad ref, unknown capability bits, an empty label and
      `max_uses: 0` are refused at the boundary.
- [x] **3.4d `pm grant create` CLI** (TTY + master password via the proof,
      refused in agent context with exit 5). Flags: `--label`, `--ref`/`--tag`
      (repeatable), `--command PATH` (repeatable; resolved to a canonical
      path at creation), `--expires 1h|30m|7d` (required, max 30 d),
      `--max-uses N`, `--allow-interpreter`, `--out FILE`. The CLI builds a
      `GrantRequest` with a fresh 32-byte token, derives the key once from the
      password, proves its digest, sends `grant_create`, and only after
      success opens the vault with that same key (`open_with_key` +
      `lock_for_update` + `save_with_key`) and writes the grant; it then
      writes the raw token to `--out` with `O_EXCL` and mode 0600, never to
      stdout. Before it asks for the proof it must call
      `Vault::check_grant_writable` on the grant it proposes, so a vault at
      `MAX_GRANTS` fails with "too many grants" and spends no approval (closes
      R.22b; tick that item too). Requires a running daemon (`pm unlock`
      first); it does not auto-unlock in this item. Refuse interpreter
      commands (a shared pure list in `grant/validate.rs`) without
      `--allow-interpreter`. Tests: the token is absent from stdout/stderr,
      the file mode is 0600, an existing `--out` is refused without
      overwriting, interpreter commands are refused without the flag,
      agent/TTY refusal exits 5, a full vault sends no `challenge`/`prove`
      (R.22b), and the daemon is still usable after the write (its key was
      not invalidated).
      Done: `--expires` also accepts minutes (`30m`); interpreter refusal and
      the TTY/agent gate happen before the password prompt; a newly created
      `--out` is unlinked when a later step fails; `check_grant_writable` runs
      after key derivation (needed to open the vault) but before `challenge`.
- [x] **3.5 `pm grant list|show|revoke` (+ `--json`).** list/show print
      metadata only, never tokens or hashes. revoke needs no password and takes
      effect on the next request. `revoke --all` exists. Tests for each.
      Done: revoke goes over the daemon session token (`grant_revoke` /
      `grant_revoked`) and is the daemon's only vault write; it refuses
      `--db`/`PASSMGR_DB` like `run`. list/show read the vault locally with the
      master password. Enforcement of `revoked_at` by `run` is still 3.6.
- [ ] **3.6 Daemon authorizes by grant.** `run` and every new
      credential-touching request require a grant token. The unlock session
      token (2.5) only authorizes `ping`, `lock`, `status` and `revoke`.
      Record this in `DECISIONS.md`: holding the session file is not enough
      to use secrets. Tests: session token refused for `run`, valid grant
      accepted, uses counted, last_used updated.
- [ ] **3.7 `pm run` for humans.** With `--grant-file FILE` it goes through
      the daemon. Without it, at a TTY, it prompts for the master password and
      runs locally (same redaction code). In agent context without a grant it
      exits 5. Tests for all three paths.
- [ ] **3.8 Audit log.** `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback
      `~/.local/state`), 0600, append-only with `O_APPEND`, one JSON object
      per line, hash-chained (`prev`). Written by the daemon for every
      authorized or denied credential request. Tests: one record per run, the
      secret and the token are absent from the file, the chain links.
- [ ] **3.9 `pm audit [--json] [--grant ID] [--since DUR] [--limit N]` and
      `pm audit verify`.** verify reports the first broken link with exit 6.
      Tests: tampering with, deleting or reordering a line is detected.

## Phase 4 — MCP server (`pm mcp serve`)

Implement `MCP.md`. Do not use an MCP SDK: write a small, synchronous
JSON-RPC layer with `serde_json` (decided; see `DECISIONS.md` after H.1). It
keeps the dependency tree small and stdout hygiene under our control.

- [ ] **4.1 JSON-RPC 2.0 line codec** (`src/mcp/jsonrpc.rs`, pure). Parse and
      serialize requests, notifications, responses and errors. 1 MiB line cap
      with resync to the next newline; batches rejected; ids may be a string
      or a number. Tests: every error code in `MCP.md`, oversize lines,
      invalid UTF-8, missing `jsonrpc`.
- [ ] **4.2 Era handling** (`src/mcp/era.rs`). Legacy `initialize`/
      `notifications/initialized`/`ping`, modern `_meta` validation, `-32022`
      with the supported list, `server/discover`, `resultType` and
      `serverInfo` on modern results. Table-driven tests for both eras and
      for era switching.
- [ ] **4.3 `pm mcp serve` loop + `tools/list`.** A stdio loop where stdout
      carries only JSON and logs go to stderr. Tool definitions have
      hand-written JSON Schemas (`additionalProperties: false`), `title`,
      LLM-oriented `description`, `annotations`, and `outputSchema`. The
      `instructions` text is per `MCP.md`. Tests: an e2e session over pipes in
      both eras, and every stdout line parses.
- [ ] **4.4 Daemon `list`/`describe` requests** with grant-scoped results
      (out of scope = not found). Then the MCP tools `list_credentials` and
      `describe_credential`. Tests: scope filtering, tag/query filter, no
      grant → isError, and no value appears anywhere in the response.
- [ ] **4.5 `run_with_credentials`: env injection via the daemon** (reuse
      2.6). Command resolution plus the allowlist check, the env-name
      denylist, a from-scratch child env, timeout with process-group kill,
      per-stream output caps with truncation flags. Tests: the child sees the
      var; printenv is redacted; timeout kills grandchildren; output capped.
- [ ] **4.6 Encoded-value redaction.** Extend the streaming redactor with
      hex (lower/upper), base64 std/url-safe (with and without padding) and
      percent-encoding of each secret. Count redactions. Refuse secrets
      shorter than 8 bytes for agent runs. Property-style tests with random
      secrets and random chunk boundaries (deterministic seed).
- [ ] **4.7 `access_status` tool.**
- [ ] **4.8 Access requests.** Daemon `request_create` (pending requests held
      in daemon memory, max 3 per client connection id, expire after 1 h),
      the `request_access` tool, and the claim-secret exchange. Tests: a
      forged claim fails, the token is claimed once, and the token never
      appears in tool output.
- [ ] **4.9 `pm grant pending` and `pm grant approve|deny <id>`.**
      approve shows the full request with agent text sanitized and labelled
      untrusted, lets the human narrow the scope, duration and commands,
      requires y/N plus the presence proof, and refuses in agent context.
      Tests: control/bidi characters stripped, a non-TTY approve gives exit 5.
- [ ] **4.10 Best-effort desktop notification** when a request arrives
      (`notify-send` / `osascript`, found on PATH and spawned with argv only).
      Its absence never fails the request. Test with a fake binary on PATH.
- [ ] **4.11 Audit for MCP calls** (client name from `clientInfo`, tool,
      outcome) per `MCP.md`.
- [ ] **4.12 Session-wide canary test** per `MCP.md` "Tests that must
      exist" #1 and #2.
- [ ] **4.13 Red-team test suite** (`tests/mcp_redteam.rs`), one test per
      bullet in `MCP.md` #3. If any of them fails, the bug it found comes
      first.
- [ ] **4.14 `pm mcp config --client claude-code|cursor|codex|gemini|generic`**
      prints the config snippet (or the `claude mcp add …` command) for that
      client. It **prints only** and never edits another tool's config files.
      Snippets reference `PASSMGR_GRANT_FILE` optionally. Test: the snippet is
      valid JSON/TOML for each client.
- [ ] **4.15 `notifications/cancelled`** kills the in-flight child. Test with
      a `sleep` child.

## Phase 5 — more injection methods

- [ ] **5.1 `stdin_ref` / `pm run --stdin <ref>`.** The daemon writes the
      secret to the child's stdin and closes it. Tests: the child reads it,
      and the value is redacted if echoed.
- [ ] **5.2 `files` / `pm run --file VAR=<ref>`.** 0600 temp file per
      `MCP.md` (`O_EXCL|O_NOFOLLOW`, 0700 dir), path in VAR, unlinked on
      exit, timeout and daemon shutdown. Tests: mode 0600, the file is gone
      after the run, a pre-placed symlink is not followed.
- [ ] **5.3 `pm run --env-file FILE`.** Lines of `VAR=pm://…` (refs only; a
      literal value is a hard error that names the line number, never the
      value). Comments and blank lines are allowed. `pm env check FILE`
      validates without running. Tests for each rule.
- [ ] **5.4 `pm import-env .env [--tag T] [--prefix P]`** (human, TTY).
      Moves each literal value into the vault as a new credential, writes
      `.env.pm` with refs (0644, safe to commit), and never prints values.
      The original file is left untouched; the command prints a reminder to
      delete it. Tests: values land in the vault, the `.env.pm` content
      matches, no value appears in stdout/stderr.
- [ ] **5.5 `pm render TEMPLATE --out FILE`** (human first). `{{pm://id}}`
      / `{{pm://id/field}}` placeholders; output 0600, written atomically,
      refuses a symlinked output or an existing file without `--force`.
      Unknown placeholder = error naming the placeholder. Record in
      `SECURITY.md` that a rendered file is readable by anything running as
      the user.

## Phase 6 — richer credentials

- [ ] **6.1 Multi-field entries (next store version).** Named secret fields
      (`password`, `token`, `api_key`, custom `[a-z0-9_-]{1,32}`), field refs
      `pm://<id>/<field>` (a bare ref = the `password` field), and `url` and
      `notes` metadata (notes are non-secret; a secret note is a field).
      Migration maps the old password to the `password` field. Update
      `FORMAT.md`. Tests: migration, field refs in `run`, field names (not
      values) in JSON.
- [ ] **6.2 CLI for fields:** `add/edit --field NAME` (prompted twice, hidden),
      `--field-generate NAME`, `--url`, `--notes`, and `edit --rm-field`.
      Tests.
- [ ] **6.3 TOTP fields.** Store base32 seeds (RFC 6238, SHA-1/SHA-256,
      6/8 digits, 30 s). `pm://id/totp` injects the **current code** at run
      time. The seed is never injectable. Test vectors from RFC 6238.
- [ ] **6.4 Grant scope by field.** A grant can allow `pm://id/token` but not
      `pm://id/password`. Tests.
- [ ] **6.5 Expose fields, url and totp-capability in `list_credentials` /
      `describe_credential`** (names and booleans only).

## Phase 7 — agent-safe provisioning

- [ ] **7.1 `create` grant capability + `create_generated_credential` MCP
      tool.** The daemon generates a random value (length 16..128, charset
      options), stores it under a new entry (with tags; it must fall inside
      the grant's tag scope) and returns **only** the ref. The agent can then
      inject it (for example, set a DB password via `psql`) without ever
      seeing it. Tests: the value never appears in the response or the audit
      log, and an out-of-scope tag is refused.
- [ ] **7.2 `rotate_credential` MCP tool** (capability `rotate`).
      Generates a new value for a field, then runs a grant-allowed
      `apply_command` with **both** old and new values injected (`OLD_*`,
      `NEW_*`). Commits the new value only if it exits 0; otherwise keeps the
      old value. Tests: success path, failure path keeps the old value.
- [ ] **7.3 Per-call human confirmation mode.** Grant flag `--confirm-each`:
      every run waits (up to 120 s) for `pm grant confirm <request>` at a TTY,
      using the presence proof. Tests with a short timeout.
- [ ] **7.4 Grant templates.** `pm grant create --preset gh|aws|psql|ssh`
      fills sensible command allowlists. Data-driven, no special cases in
      code.

## Phase 8 — human experience

- [ ] **8.1 `pm passwd`.** Change the master password: re-derive and
      re-encrypt atomically, and keep the old file until the new one is
      fsynced. A running daemon must be locked first (refuse otherwise).
      Tests: the old password fails and the new one works afterwards; a crash
      mid-way (simulated) leaves a usable vault.
- [ ] **8.2 KDF parameter upgrade.** If the stored Argon2 params are below
      the current defaults, offer an upgrade on the next human unlock
      (`--upgrade-kdf` non-interactively). Tests.
- [ ] **8.3 `pm status [--json]`.** Daemon state, idle-timeout remaining,
      vault path, store version, grant count, last audit record time. No
      secrets. Agents may call it.
- [ ] **8.4 `pm doctor`.** Checks file modes (vault, runtime dir, socket,
      audit log, grant files), stale socket, daemon dumpability, core-dump
      limit, swap presence (warn), `PASSMGR_GRANT_FILE` mode, and the clock.
      Each problem has a one-line fix hint. Exit 0/1. Tests per check where
      feasible.
- [ ] **8.5 Config file** `$XDG_CONFIG_HOME/passmgr/config.json` (idle
      timeout, default grant expiry, audit path, notification on/off).
      Unknown keys are an error. Precedence: flag > env > config > default.
      Tests.
- [ ] **8.6 Encrypted backup/restore.** `pm backup DIR` copies the vault
      atomically with a timestamped name and 0600 mode; `pm restore FILE`
      verifies that the file decrypts with the master password before
      replacing (and keeps the old vault as `.bak`). Tests.
- [ ] **8.7 Import from Bitwarden JSON (unencrypted export) and generic CSV**
      (human, TTY). Map fields, tag the imported entries `imported`, print
      counts only. Tests with generated fixture files.
- [ ] **8.8 Clipboard for humans.** `get --copy` (TTY-only, same gate as
      reveal) pipes to `wl-copy`/`xclip`/`pbcopy` via stdin (never argv).
      It clears after 30 s only if the clipboard still holds our value (check
      by hash). Tests with fake clipboard binaries on PATH.
- [ ] **8.9 Shell completions** (`pm completions bash|zsh|fish`), generated
      from the same command table as `--help`. Test: every command appears.
- [ ] **8.10 Vault permission refusal** (was 5.1). A group- or
      world-readable vault is **refused**, not warned about, with a fix hint
      (`chmod 600`). Tests: refusal on 0640/0604, ok on 0600.

## Phase 9 — hardening

- [ ] **9.1 Corrupt/truncated/wrong-password tests for every parser** (vault
      container, store payload of each version, grant records, audit lines,
      config, env-file, MCP lines). Each must give a clean error and exit
      code, never a panic.
- [ ] **9.2 Property tests** (add `proptest` as a dev-dependency only) for
      protocol framing, the JSON-RPC codec, the redactor (secret never
      survives any chunking), and store round-trips. `cargo fuzz` is not
      usable here (no nightly), so record that.
- [ ] **9.3 Daemon memory hygiene.** `MADV_DONTDUMP` on key and plaintext
      buffers, `mlock` all plaintext buffers, zeroize env buffers after
      spawn, `RLIMIT_CORE=0` verified by test, no plaintext in `Debug` output
      (test with `format!("{:?}")` on every secret-bearing type).
- [ ] **9.4 Socket and request fuzz-style tests.** Random bytes, a slow
      client (slowloris) and many concurrent connections must not crash the
      daemon or starve `lock`. Add a per-connection read deadline and a
      connection cap.
- [ ] **9.5 Landlock (Linux, best-effort) for `pmd`.** Restrict filesystem
      access to the vault, runtime dir, state dir, and exec of allowlisted
      binaries, if it can be done without breaking `run`. If not feasible,
      document why in `SECURITY.md` and check this off.
- [ ] **9.6 `cargo deny`-style dependency policy in `deny.toml`** (licenses,
      no git sources, no network-capable crates such as `reqwest`, `hyper`,
      `ureq`). Add a test that greps `Cargo.lock` for the banned names, so
      it runs in the gate without extra tools.
- [ ] **9.7 Threat model in `SECURITY.md`** (was 5.3). Cover the socket, grants,
      presence proof, `/proc/<pid>/environ`, interpreters in allowlists,
      encoded exfiltration, swap/core dumps, rendered files, the TTY-only
      reveal rule, and what is explicitly out of scope (root, a malicious
      same-user process, a compromised agent host).
- [ ] **9.8 macOS compile hygiene.** Every `cfg(target_os)` branch has a
      counterpart or a clean `compile_error!`/stub. Unit tests for the
      platform-independent parts. (Skip actual macOS runs; no target here.)

## Phase 10 — docs and release

- [ ] **10.1 `AGENTS.md`.** How an agent should use passmgr (MCP first, CLI
      second), ref syntax, exit codes, the full tool list with examples, and
      what will be refused and why. Test: every MCP tool and every CLI
      command is mentioned.
- [ ] **10.2 `--help` rewrite for an LLM reader.** In agent context, help
      omits reveal/copy entirely. Tests.
- [ ] **10.3 README rewrite.** A 60-second quickstart (init → add → unlock →
      `pm mcp config --client claude-code` → approve a request), a security
      model summary, and comparisons. Keep it accurate against `--help`.
- [ ] **10.4 `examples/`** with worked, tested-by-script recipes: GitHub CLI
      token, AWS keys via env, Postgres password via env-file, SSH key via a
      `files` injection. Each has a shell test that runs with fake binaries.
- [ ] **10.5 `CHANGELOG.md` and version 0.2.0.** CI workflow file
      `.github/workflows/ci.yml` running the gate (file only; the tool
      itself stays offline).
