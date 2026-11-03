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
- [x] **R.15b The write must spend the approval exactly once.** Test:
      complete `prove` for digest A, submit a create whose canonical digest is
      B, and assert it is refused and writes nothing; then assert A-then-A
      succeeds exactly once. The daemon half of the binding is already proved
      by `a_verified_proof_records_exactly_the_digest_it_covered`, so this
      item is the write path's obligation, not a new mechanism.
      Done (R.33): 3.4/3.6 shipped. `src/daemon.rs`'s `GrantCreate` arm
      re-checks `check_approvable` and spends exactly one approval with
      `approvals.take(&request.digest(), ...)`; the A-then-B and A-then-A
      cases now exist both through the handler
      (`src/daemon/tests.rs::grant_create_is_accepted_only_for_the_digest_the_human_proved`)
      and over the real socket
      (`tests/grant_create.rs::grant_create_refuses_a_different_request_than_the_one_proven`).
      The vault is byte-identical after every refusal and success.

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

- [x] **R.25 The interpreter gate is an incomplete name list, and the
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
      Done: took the first fix (broaden the table), not a per-command
      confirmation, because `Grant` has no place to record a per-command trust
      decision and confirming every command would make every grant prompt
      noisy. The table is now `PROGRAM_RUNNERS` in `src/grant/validate.rs` and
      `is_interpreter` is `is_program_runner`: shells, launchers (`env`,
      `xargs`, `sudo`, `timeout`, `tmux`, …), editors/pagers, tools with an
      exec option (`find`, `sed`, `tar`, `ssh`, `nc`), alias/plugin CLIs
      (`git`, `gh`, `docker`, `podman`, `kubectl`, `terraform`, …), build
      runners (`make`, `cargo`, `npm`, `go`, …) and DB clients (`psql`,
      `sqlite3`) are refused. Over-refusal stays preferred; the docs now say
      the list is best-effort and that allowing any program is a trust
      decision, since a grant binds only `argv[0]`. The flag keeps its name.
      `README.md`, `--help`/`tests/fixtures/help.txt`, `SECURITY.md` limit 2,
      `MCP.md` and `DECISIONS.md` are updated; the README/help example now
      passes `--allow-interpreter` and explains that `gh` is a runner. Tests:
      `src/grant/validate.rs::program_runners_are_recognised_by_file_name`
      covers the
      documented names and lookalike false positives;
      `tests/grant_cli.rs::grant_create_refuses_a_program_runner_without_the_flag`
      uses a fake executable named `gh` (exit 5, no prompt, no daemon, no
      token file, no grant) and `…_accepts_a_program_runner_when_the_human_allows_it`
      proves the override stores the canonical path;
      `tests/docs.rs::security_documents_program_runner_exfiltration` and
      `documented_grant_example_flags_a_program_runner` pin the prose.

- [x] **R.26 `pm grant create` prompts for the master password without ever
      showing the request the human is approving.** (done: the summary and an
      explicit y/N now come before the token file, the password and any daemon
      contact; the summary is stderr-only metadata and stays plain when not a
      TTY.)
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

- [x] **R.27 `grant revoke --all` panics if the daemon answers `not_found`.**
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
      Done: the arm matches `options.id`: `Some(id)` stays `GrantNotFound`
      (exit 3), `None` (which `--all` and only `--all` produces) becomes
      `Error::Daemon("the unlock daemon refused the revocation (not_found)")`
      and exits 1. The new test fails against the old `expect` (exit 101 and
      `not_found implies an id`).

- [x] **R.28 `grant revoke --all` revokes expired and exhausted grants while
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
      Done: code now matches the docs. `GrantStatus` and `Grant::status(now)`
      live in `src/grant.rs`; `Grant::is_active(now)` and the private
      `check_active` both use that one classifier, and `grant list`/`show`
      print `GrantStatus::name()`. `revoke_grants` filters with
      `grant.is_active(now)`, so expired and exhausted grants are untouched
      and never counted. The unit test in `src/daemon/tests.rs` fails against
      the old `!is_revoked()` filter (it would report 3 and revoke all 3).

- [x] **R.29 `--out` paths are echoed with raw control characters.**
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
      Done: new `display_path` (`src/cli/grant.rs`) escapes a path through
      `escape_hidden` (`to_string_lossy` first, so a non-UTF-8 path still
      renders), and the success line moved into `grant_created_message` so it
      is unit-testable. Both messages use it; the label is escaped the same
      way (validation already refuses hidden characters, so this is
      defense-in-depth). The unit test covers an OSC 52 payload on the success
      line and an ESC/CR file name on the existing-file error, and fails
      against the plain `display()`.

- [x] **R.30 Argument and validator errors echo agent-supplied argv raw, so a
      suggested value can drive the human's terminal.**
      R.29 escaped only `--out`; the rest of the argument/validation errors
      still interpolate the raw value: `src/cli/args/mod.rs:141` (unknown
      global option), `:241` (unknown command), `:311` (`run`'s unexpected
      argument), `:320` (`--env` name), `:336` (`--env` reference), `:417`,
      `:462`, `:490`, `:524`, `:591`, `:694`, `:766`, `:773`, `:786`
      (`parse_length`), and `src/cli/args/grant.rs:86,186,232,257,289`
      (unknown subcommand/flag). `src/cli/grant.rs:58,63,70,76` interpolate
      `--expires` text. Validators echo too: `EntryId::parse_ref`
      (`src/store.rs:140-150`), `validate_tag` (`src/store.rs:403-428`,
      including the bad character) and `validate_field_name`
      (`src/grant/validate.rs:362-373`).
      `Error::VaultNotFound`/`ReadOnlyVault`/the lock and changed errors
      (`src/error.rs:95` and `:126-138`) print `path.display()`, so `--db`
      is in the same class.
      Failure (confirmed against the built binary): `passmgr run --env
      $'API_KEY=pm://\e]52;c;ZXZpbA==\a' -- /bin/true` prints
      `passmgr: --env reference 'pm://^[]52;c;ZXZpbA==^G' ...` — the raw ESC
      and BEL reach stderr, before any grant or password is checked. OSC 52
      (`\e]52;c;...`) overwrites the human's clipboard; `\e[2K\r` can erase
      and rewrite the line so the visible error is a lie. The same was
      confirmed for `--env` names, `--ref`, `--tag`, `--expires`
      (`invalid --expires '^[]52;c;...'`) and an unknown argument. This
      contradicts `DECISIONS.md`'s rule that agent-supplied text shown to a
      human is sanitized.
      Fix: escape untrusted argv at every display site. Put the helper in a
      low module (a new `src/text.rs`, or reuse `escape_hidden` by moving it)
      because `src/store.rs` cannot depend on `grant`; alternatively sanitize
      once in the top-level error printer so no future message can forget.
      Test: a table-driven CLI test (the real binary, as `tests/run.rs` does)
      passing `\x1b]52;c;ZXZpbA==\x07` in `--env` name, `--env` reference,
      `--ref`, `--tag`, `--expires`, `--length`, an unknown flag, and `--db`;
      assert stderr contains no raw `\x1b`/`\x07` and does show the visible
      `\u{1b}`/`\u{7}` form. Add unit cases to `validate_tag`,
      `EntryId::parse_ref` and `validate_field_name`. All must fail against
      the current code.
      Done 2026-11-03: helpers moved to `src/text.rs` (`escape_hidden`,
      `escape_quoted`, `escape_path`); validators, `Error::Display`,
      `warn_insecure` and `grant show` escape at the source, and the CLI
      printer escapes both the usage message and the runtime error line as a
      backstop. `tests/cli_args_escape.rs` covers every flag above except
      `--tag` (validated after the password prompt; unit-tested instead).

- [x] **R.31 A valid grant token is an existence oracle for out-of-scope
      references, contradicting `DECISIONS.md`.**
      `src/daemon/run.rs:160-171` (`record_use`) looks the credential up
      first: a missing ref returns `RecordError::NotFound` (`:162-163`),
      while an existing ref outside the grant reaches `authorizes` (`:168`)
      and returns `RecordError::Denied` (`:170-171`). `DECISIONS.md:254-256`
      and `:591` promise "an out-of-scope ref answers exactly like a
      nonexistent one (no existence oracle)", and the CLI maps the two to
      different exits (`src/cli/run.rs:241-243` vs `:265-271`).
      Failure: with a grant for `pm://A`, `pm run --env
      X=pm://B ...` (B exists but out of scope) exits 5 with "the unlock
      daemon refused the run", while `pm://C` (nonexistent) exits 3 with
      "no credential found for reference 'pm://C'". The agent learns that B
      exists even though the grant forbids using it.
      **Corrected by the 2026-11-03 human-requested review:** the fix
      above is not enough. `record_use` finds the grant by token hash
      whatever its status (`matches_token`, `src/grant.rs:830`), then looks
      the credential up (`NotFound`), and only then calls `authorizes`
      (`Denied`). So a revoked, expired or exhausted grant's token is also an
      existence oracle, and for every ref in the vault (reproduced: revoked
      grant, existing ref -> `Error(Denied)`, absent ref ->
      `Error(NotFound)`). Answering `not_found` only for scope denials leaves
      that open.
      Fix: check the grant's state (active, not expired, uses left, RUN
      capability, command allowed) before the credential lookup, and make an
      out-of-scope ref answer exactly like a nonexistent one; or change
      `DECISIONS.md` and the CLI mapping if the oracle is accepted. Keep one
      contract.
      Test: in `tests/daemon_run.rs`, for each denied grant state (revoked,
      expired, exhausted, out of scope), an existing ref and a nonexistent
      ref get the same `RunFrame::Error` and the same CLI exit status. It
      must fail against the current order.
      Done: `Grant::check_grant_for_run` (state, RUN bit, command allowlist)
      now runs before `get_by_ref`, and an existing out-of-scope ref maps to
      `NotFound`. A dead grant answers `Denied` for every ref, so its token is
      no longer an oracle either.

- [x] **R.32 Security and protocol docs still describe the pre-3.6 state.**
      `SECURITY.md:14-16` says grant authorization is "not implemented yet"
      and that `run` is authorized by the session token, contradicting
      `:21-23` and the code; `:23` omits `grant_create` from the operations
      the session token authorizes; `:63-68` presents the hash-chained audit
      log as part of "Grants" although TODO 3.8 is still open (`run` writes
      no audit record). `DECISIONS.md:405-407` says "The CLI still cannot
      create a grant". `README.md:182` says the token file "must be in a 0600
      file", but `src/grant/file.rs` accepts 0400 as well. `MCP.md:280-283`
      says "The daemon hands the grant token over **once**", but 3.4c made
      the CLI generate and write the token (the daemon only stores its hash),
      so an MCP implementer would build a claim exchange that cannot work.
      Failure: a reviewer trusts `SECURITY.md` and treats `run` as
      session-token gated (the hole 3.6 just closed) or expects `pm audit` to
      exist; an MCP implementation follows `MCP.md` and asks the daemon for a
      token it never had.
      Fix: update the four docs to the implemented flow (grant required;
      `grant_create` in the session-token list; audit still TODO 3.8; CLI
      writes the token; 0600/0400 documented as the code behaves), or open
      explicit TODOs where the doc is the intended future contract.
      Test: extend `tests/docs.rs` to assert `SECURITY.md` contains neither
      "not implemented yet" nor the session-token-only claim, that its
      session-token list contains `grant_create`, that `DECISIONS.md` says
      the CLI creates the grant, and that `MCP.md`'s token-ownership sentence
      matches the daemon-stores-only-the-hash contract.
      Done: the four documents now describe the implemented flow. `MCP.md`
      says the MCP server mints the token (the claim secret) and
      `request_claim` can only confirm approval, never return a token. Also
      corrected the same stale session-token list in `DECISIONS.md`
      (`status`/`revoke` are not request types) and the 0600-only token-file
      claim in `MCP.md`.

- [x] **R.33 TODO R.15b is stale: the property it guards is implemented and
      tested.**
      `TODO.md:28-34` keeps `[!]` and "Blocked on TODO 3.4/4.9", but 3.4 and
      3.6 are `[x]`. `src/daemon.rs`'s GrantCreate arm re-checks
      `check_approvable` and then spends exactly one approval with
      `approvals.take(&request.digest(), ...)`; `tests/grant_create.rs:27`
      proves the identical request is refused the second time and the vault
      is untouched; `src/presence.rs:767` proves a different digest does not
      consume the approval. An A-then-B `grant_create` test already exists
      over a real socket pair through the daemon's connection handler
      (`src/daemon/tests.rs:242`, via `exchange_frame`); only a CLI-level e2e
      is missing.
      Failure: the next iteration sees an open blocked item, assumes the
      write path is still unprotected, and either reimplements it or treats
      the approval as replayable in a new caller.
      Fix: check R.15b off with the evidence above and, if wanted, add the
      A-then-B `grant_create` case to `tests/grant_create.rs`.
      Test: none beyond the existing tests; the checklist must stop saying
      blocked.
      Done: R.15b is `[x]` with the evidence. Added
      `tests/grant_create.rs::grant_create_refuses_a_different_request_than_the_one_proven`:
      prove A over the real socket, submit B (different expiry, so a
      different digest) -> `Denied` and a byte-identical vault; then A ->
      `grant_approved`, still byte-identical; then A again -> `Denied`. It
      fails against a mutated `Approvals::take` that ignores the digest
      (`GrantApproved` instead of `Denied`).

- [x] **R.34 `pmd` checks the canonical program path but execs the raw
      request path, so a symlink swap runs an unlisted program with the
      secret.**
      Done: `runner::execute` now takes the executable separately and spawns
      exactly the canonical path the daemon authorized, with that path as
      `argv[0]`. Residual: a swap of the target *file* between
      canonicalize and `execve` is still open (`fexecve`/`O_PATH` would
      close it); see PROGRESS.md. Tests: lock-held link swap and `$0`.
      `src/daemon/run.rs:81` canonicalizes `command[0]` and uses the result
      only for the grant check (`record_use`, `:92`); `:114-115` then hands
      the original `request.command` to `runner::execute`, and
      `src/runner.rs:177` calls `Command::new(argv[0])` on the client's
      path. The comment at `:79-80` and `MCP.md:151-158`/`DECISIONS.md:535-538`
      say the canonical path is executed; it is not. `src/cli/run.rs:207-213`
      deliberately keeps the symlinked path.
      Failure (reproduced three ways): grant allows `/bin/true`; the agent
      makes `dir/tool -> /bin/true`, holds `flock` on `<vault>.lock` (a
      same-user file) so `record_use` waits after the check passed, repoints
      `dir/tool` at a script that writes `$API_KEY` to a file, releases the
      lock: `Exit(Code(0))` and the file holds the secret. A plain rename
      loop wins the race on the first attempt too. Second effect without any
      race: argv[0] is the agent's chosen name, so a multi-call binary
      (busybox, rustup's `cargo`/`rustfmt` links) runs whichever applet the
      link is named after while matching the same canonical allowlist entry.
      Fix: execute exactly the canonical path that was authorized, and set
      argv[0] to that canonical path (not the caller's name, which
      re-opens the multi-call problem); record the choice in
      `DECISIONS.md`. Consider opening the binary once and `fexecve`-ing the
      checked fd so a swap of the target file itself is also closed.
      Test: in `tests/daemon_run.rs`, (a) the lock-held swap above must leave
      no loot file and answer `Denied` or run `/bin/true`; (b) a symlink to an
      allowlisted `/bin/sh` run with `-c 'echo "$0"'` must print the
      canonical path, not the link name.

- [ ] **R.35 No test proves `pmd` enforces the grant's command allowlist,
      scope or capability on `run`.**
      Every daemon and CLI `run` test sends an allowlisted command
      (`tests/support/mod.rs:96`, `tests/run.rs` `Daemon`), every fixture
      vault holds exactly one in-scope credential, and no test sends a grant
      without RUN, an expired grant, or concurrent runs against `max_uses`.
      `tests/grant.rs` covers only the pure `Grant::authorizes`.
      Failure (mutation-tested): changing `src/daemon/run.rs:165-171` to
      authorize `grant.commands()[0]` instead of the requested program keeps
      the whole suite green, so a refactor could let a grant for
      `/usr/bin/printenv` run `/bin/sh` with the secret unnoticed. TODO 3.6's
      done note and `DECISIONS.md:276-279` describe guarantees nothing guards.
      Test: e2e cases in `tests/daemon_run.rs`, each of which must fail
      against the mutation above: a non-allowlisted command (`/usr/bin/env`)
      answers `Denied` and creates no marker file; a symlink to a
      non-allowlisted program under an innocent name answers `Denied`; a
      grant without RUN answers `Denied`; an expired grant answers `Denied`;
      16 parallel runs on `max_uses=3` give exactly 3 exits; a second,
      existing, out-of-scope credential gets the R.31 answer.

- [ ] **R.36 Redaction holdback timing reveals the secret one byte at a
      time.**
      `src/redact.rs:111-114` holds output back only when the buffered tail
      is a proper prefix of the secret; any other tail is emitted at once.
      Whether output is delayed therefore depends on the secret.
      Failure (reproduced e2e): an agent that controls bytes a granted
      program relays (a FIFO, `tail -f`, a local server fetched by curl or a
      cloud CLI with `--endpoint-url`) sends `known+c`, pauses, then more
      output. Wrong guesses arrive in <100 ms; a correct prefix is held for
      the whole pause. The scratch test recovered `s3cret` byte by byte. This
      is a channel passmgr creates; `SECURITY.md` limit 3 does not cover it.
      Fix: make the holdback independent of the secret, e.g. always hold the
      last `secret_len - 1` bytes until more output or EOF (bounded latency),
      or flush the held bytes on a fixed timer regardless of content. If a
      residual channel remains, document it in `SECURITY.md` limit 3.
      Test: a `Redactor` unit test pushes a correct prefix and a wrong prefix
      of the same length; `push` must return the same number of bytes for
      both. Plus an e2e latency test like the scratch one.

- [ ] **R.37 A run whose client disconnects keeps running and holds the key
      past the idle timeout.**
      `src/runner.rs:291-323` (`relay`) and the `Finished` wait loop
      (`:240-252`) never check the client socket; a dead client is noticed
      only when a frame write fails. `src/daemon.rs:462` suspends the idle
      timeout while any run is registered.
      Failure (reproduced): `--idle-timeout 2`, child `exec sleep 20`, client
      socket dropped; 6 s later `pmd` and the child are alive, the child's
      environment holds the secret, and `ping` answers. Agent hosts kill
      timed-out tool calls routinely, so each leaves a live child with the
      secret, a used run slot, and an unlocked key until `lock`.
      Fix: poll the client stream for HUP/RDHUP/EOF in both loops and cancel
      the run (process-group kill) when the client is gone.
      Test: start that run, drop the client, assert the child is gone within
      2 s and `pmd` exits within ~4 s under `--idle-timeout 2`.

- [ ] **R.38 A detached grandchild keeps the secret after the run ends,
      after `lock`, and after `pmd` exits.**
      `src/runner.rs:234-245`: after a normal finish (both pipes at EOF,
      leader reaped) the process group is never signalled.
      `src/daemon.rs:56-58` claims "no copy of the injected secret outlives
      the key"; `SECURITY.md` limit 1 only discusses exposure "while the child
      is running". A grandchild that calls `setsid` escapes even the
      cancel-path group kill; that is noted only in a `runner.rs` comment.
      Failure (reproduced): `sh -c 'sleep 60 </dev/null >/dev/null 2>&1 &'`
      exits 0; after `lock` answers `Locked` and `pmd` exits, the `sleep` is
      alive with the secret in `/proc/<pid>/environ`. Real tools do this
      (gradle daemon, ssh ControlPersist, credential-cache daemons).
      Fix: signal the group on normal completion too without reusing a
      reaped pgid (`waitid(WNOWAIT)`, `kill(-pgid)`, then reap), and document
      the `setsid` escape and post-run survivors in `SECURITY.md`; correct
      the `daemon.rs` comment.
      Test: the scenario above leaves no live grandchild after the run
      returns; a `tests/docs.rs` contract for the documented `setsid` limit.

- [ ] **R.39 `grant revoke` (and `grant create`) fails with `internal`
      whenever a concurrent `run` writes the vault.**
      `src/daemon.rs` `revoke_grants` (~`:723-768`) opens the vault without
      the lock, then `lock_for_update()` maps `VaultChanged` to
      `ResponseError::Internal` with no retry, while `record_use` retries 8
      times (`src/daemon/run.rs:33,152`). Every run writes the vault to
      record its use. `src/cli/grant.rs` (~`:192` vs `:234`) has the same
      race: the vault is read before `challenge`, the approval is spent, and
      a run's write in between makes the create fail after the human
      approved.
      Failure (reproduced twice): 4-8 threads looping runs while revoke is
      sent; revoke failed 1-2 times before succeeding, answering
      "the unlock daemon refused the revocation (internal)". The kill switch
      is flaky exactly when an agent is busy using the grant.
      Fix: take the write lock before reading (a key-based
      `open_for_update`) in `revoke_grants`, and in `record_use`; in
      `grant create`, re-open under the lock and add the grant to the fresh
      vault instead of byte-comparing the stale one.
      Test: concurrent runs plus one `grant_revoke`; the first revoke must
      return `Ok(1)` and the grant must be revoked on disk, in each of ~20
      trials. Same shape for `grant create` against concurrent runs.

- [ ] **R.40 `Vault::save(master)` re-salts and resets the KDF parameters,
      stranding a running `pmd` and silently downgrading stronger
      parameters.**
      `src/vault.rs:176` calls `crypto::encrypt(&plaintext, master_password,
      KdfParams::default())`, so every `add`/`edit`/`delete`
      (`src/cli/commands.rs:61,188,203`) writes a new salt and default
      parameters. None of those commands checks for a running daemon;
      `DECISIONS.md:510` assumes none is running.
      Failure (reproduced): (a) with `pmd` unlocked, `pm add` makes the
      daemon's key useless; every `run` and `grant revoke` then answers
      `internal` until `lock`+`unlock`, so revocation silently stops working.
      (b) a vault written with (128 MiB, t=4, p=2) is rewritten with
      (64 MiB, t=3, p=1) on the next add, undoing the upgrade `FORMAT.md`
      stores the parameters for (and the future TODO 8.2).
      Fix: keep the existing salt and parameters on save (derive with the
      header's parameters), or refuse `add`/`edit`/`delete` while a daemon is
      unlocked as 8.1 does for `passwd`; update `DECISIONS.md:510`.
      Test: a vault with non-default parameters keeps them after `save`; after
      add/edit/delete, the key from the pre-existing file still opens the
      vault (or the commands exit with a clear refusal while `pmd` runs).

- [ ] **R.41 The grant approval prompt shows refs only as opaque
      `pm://<hex>` ids, and refs are never checked against the vault.**
      `src/cli/grant.rs:167` prints the approval summary via
      `describe_scope` (~`:517`), which prints `id.to_ref()` only. The CLI has
      already decrypted the vault (`open_with_key`, ~`:190`) but neither shows
      the service/username behind each ref (or what each tag matches) nor
      refuses a nonexistent ref. `MCP.md` says the human sees the whole
      request first.
      Failure: an agent suggests `pm grant create --label "github ci token"
      --ref pm://<bank-password-id> --command /usr/bin/curl ...`; the human
      sees a friendly agent-written label and an unreadable id and approves
      the wrong credential.
      Fix: print service and username (escaped) for every ref and the matched
      entries for every tag before the confirmation; refuse an unknown ref
      before `challenge`.
      Test: in `tests/grant_cli.rs`, a ref's service name appears in the
      transcript before the confirmation prompt; a nonexistent ref exits
      with a usage/not-found error before any socket contact.

- [ ] **R.42 Grants are never removed, so a vault stops accepting new grants
      after 1,024 creates in its lifetime.**
      `src/store/payload.rs:118-123` refuses `grants.len() > MAX_GRANTS`
      counting revoked and expired grants; `src/vault.rs:277-302` has no
      remove/prune, and no TODO item plans one. Grants live at most 30 days.
      Failure: at ~3 short grants a day a vault hits the cap within a year;
      from then on every `pm grant create` fails in `check_grant_writable`
      ("too many grants") with no CLI recovery. The existing full-vault test
      uses only active grants, hiding this.
      Fix: prune grants that are expired or revoked (and past a short
      retention window, so `grant list` can still show recent history) when
      writing, or add `pm grant purge`; never prune an active grant. Record
      the retention rule in `DECISIONS.md` and `FORMAT.md`.
      Test: a vault with `MAX_GRANTS` expired/revoked grants accepts a new
      grant; active grants are never removed.

- [ ] **R.43 The README's main `run` example is refused with exit 5.**
      `README.md:170-173` creates a grant with `--command /usr/bin/gh` and no
      `--allow-interpreter`, but R.25 made `gh` a program runner
      (`src/grant/validate.rs:146`). R.25 fixed only the example under
      "### Create a grant"; `tests/docs.rs:158` checks only that block.
      Failure (reproduced): the first quickstart a user or agent copies exits
      5 with "refusing to allow a shell, interpreter or program runner" and
      writes no token file.
      Fix: use a non-runner in the quickstart or add `--allow-interpreter`
      with a sentence on why.
      Test: a docs test that checks every fenced block containing
      `grant create` in `README.md` and `--help`: any `--command` whose
      basename `is_program_runner` must carry `--allow-interpreter`.

- [ ] **R.44 Copying an older `vault.dat` back undoes revocation and resets
      `max_uses`.**
      `pmd` re-reads the vault file on every request
      (`src/daemon/run.rs:153-154`, `revoke_grants` in `src/daemon.rs`) and
      remembers no grant state; `save_with_key` keeps the salt, so any older
      copy (backup, leftover temp file, a copy the agent made) still opens
      with the daemon's key. `SECURITY.md:76-78` promises revocation and use
      limits with no rollback caveat.
      Failure (reproduced): snapshot the vault, use a `max_uses=1` grant
      (`Exit(0)`), second run `Denied`, write the snapshot back, run again:
      `Exit(Code(0))`. The same works for `revoked_at`.
      Fix: either `pmd` keeps a monotonic in-memory high-water mark per grant
      id for its lifetime (uses never decrease, `revoked_at` never clears) and
      refuses a vault that regresses, or `SECURITY.md` and `FORMAT.md`
      document rollback as an accepted same-user limit (limit 1/7). Record
      which in `DECISIONS.md`.
      Test: the sequence above ends in `Denied` (mitigated), or a
      `tests/docs.rs` contract pins the documented limit.

- [ ] **R.45 Grant expiry is checked with a `now` read before the vault-lock
      wait.**
      `src/daemon/run.rs:87` reads the clock once; `record_use`
      (`:152-187`) then authorizes and `mark_used(now)` after
      `lock_for_update`, which can block up to 30 s per attempt, 8 attempts.
      Failure (reproduced): a grant expiring in 3 s; the agent holds
      `flock` on `vault.dat.lock`, sends a run, releases after 8 s: the run
      is authorized ~5 s after expiry. Up to 16 runs can be queued this way,
      with an overrun of minutes.
      Fix: read the clock again after the lock is acquired and authorize
      with that.
      Test: the scenario above answers `Denied`.

- [ ] **R.46 At the payload size limit a revocation cannot be saved.**
      Revoking or recording a use adds 8 bytes to a grant record
      (`src/store/payload.rs:93-101`); `check_grant_writable`
      (`src/vault.rs:319-323`) admits a grant right up to
      `MAX_PLAINTEXT_BYTES`. The daemon maps the save error to `internal`.
      Failure (reproduced): a 10,485,756-byte payload plus `revoke` fails to
      encode; `grant revoke` always answers `internal`. `run` fails closed,
      but the kill switch fails too.
      Fix: reserve the growth (e.g. 16 bytes per grant) in the pre-check and
      `byte_len`, or exempt revocation growth from the cap.
      Test: in that state `revoke_grants` succeeds.

- [ ] **R.47 `passmgr run` exits 0 when its stdout pipe closes, hiding the
      child's status.**
      `src/cli/mod.rs:46-48` maps any `Error::Io(BrokenPipe)` to `EXIT_OK`;
      the stdout relay in `src/cli/run.rs:122-127` returns exactly that. Help
      (`src/cli/help.rs:76-77`) and `README.md:199` say `run` exits with the
      child's status. The child also keeps running after the CLI exits (see
      R.37).
      Failure (reproduced): `set -o pipefail; passmgr run ... -- deploy |
      head -1` reports success when `deploy` exits 7.
      Fix: for `run`, a broken stdout pipe exits non-zero (141, or the
      child's status if it is known) and cancels the run.
      Test: CLI e2e with a child that prints, sleeps and exits 7 while the
      reader is dropped: status is non-zero, never 0.

- [ ] **R.48 Service names and usernames accept bidi and zero-width
      characters and are printed raw.**
      `src/store.rs:377-394` (`validate_service`, `validate_username`) refuse
      only `char::is_control`, not the shared hidden/reordering table in
      `src/text.rs`. The values are printed unescaped in the add prompt
      (`src/cli/commands.rs:322`), success lines (`:66,193,195`), `list`
      (`:229-235`), `get` (`:96-103`) and `show` (`:278-284`).
      Failure (reproduced with the binary): `pm add $'git‮moc.buh' alice`
      prompts and lists as "github.com", and the unclosed RLO also reverses
      the rest of the `list` line, including the `pm://` ref the human copies
      into a grant. Contradicts the PROMPT rule to sanitize bidi characters.
      Fix: reject hidden/reordering characters in both validators; escape
      stored legacy values on display.
      Test: validators reject U+202E, U+200B and U+FE0F; `add` with a bidi
      service exits 2 before any prompt; `list` escapes a legacy stored value.

- [ ] **R.49 A client that stops reading for 5 s gets its run killed without
      a terminal frame, and `lock` waits behind the stalled write.**
      `src/daemon.rs:470` sets a 5 s write timeout on the stream handed to
      the run worker; `relay` (`src/runner.rs:304`) cannot see `cancel` while
      blocked in `emit`.
      Failure (reproduced): a 4 MB child with the client paused 7 s delivers
      ~106 KB then EOF, no `Exit` frame (`passmgr run ... | less` with nobody
      paging, Ctrl-S, a slow MCP host). With a stalled run client, `lock`
      answered after 4.55 s, near the CLI's 5 s `REQUEST_TIMEOUT`, so `lock`
      can report failure although it succeeded.
      Fix: apply backpressure to the child (stop reading its pipes) instead
      of timing out the client; make the blocked write observe `cancel`
      (poll with a short timeout and retry).
      Test: pausing the reader for 7 s still yields all bytes plus
      `Exit(Code(0))`; with a stalled run client, `lock` answers within 2 s.

- [ ] **R.50 The secret and grant tokens are left in freed memory without
      being zeroized.**
      (a) `src/runner.rs:184-187` says the process keeps the value only in
      `secret` and the redactors, but `Command::env` stores an `OsString`
      copy, `spawn` clones it into its env map and builds a `NAME=value`
      CString; a global-allocator scan found 3 freed blocks containing the
      secret after one run of `/usr/bin/true`. The reader's stack buffer
      (`:400`) and `Redactor.pending` reallocations (`src/redact.rs:74`) hold
      more copies. (b) Grant-token hex is copied into plain `String`/`Vec`
      buffers on both sides: `src/protocol/codec.rs:192,228,41-44`,
      `src/client.rs:147-148`, the `FrameDecoder` buffer (`codec.rs:93,125`,
      `drain` does not wipe), the `serde_json::Value` (`:232`) and the owned
      `grant` string (`:276`). `pmd` is long-lived and these are not locked.
      (c) `src/crypto.rs:377-392` returns early on an oversized plaintext
      without wrapping the decrypted `Vec` in `Zeroizing`.
      Fix: (c) wrap in `Zeroizing` before the length check. (a)/(b) build the
      child envp in zeroizing buffers (e.g. `posix_spawn`), make `encode`
      return `Zeroizing<Vec<u8>>` and wipe the decoder buffer on drain/drop;
      or, where that is impractical, correct the comment and list the
      residual copies in `SECURITY.md` limit 6. Split if too big.
      Test: the allocator-scan test as its own integration binary reports 0
      (or documents the accepted residue); a `FrameDecoder` unit test sees a
      zeroed buffer after `next_frame`; an oversized-plaintext test returns
      `MalformedVault`.

- [ ] **R.51 More docs drift beyond R.32.**
      `DECISIONS.md:420-421` says the daemon's only vault write is
      `revoked_at` (since 3.6 `record_use` writes `uses`/`last_used` on every
      run); `FORMAT.md:217-220` describes key-reuse re-encryption as a CLI
      exception, but `pmd` does it on every run and revoke.
      `SECURITY.md:23` and `DECISIONS.md:276` say the session token
      authorizes `ping`, `lock`, `status` and `revoke`: no `status` request
      exists and the wire name is `grant_revoke`.
      `src/client.rs:27-35` still says grants are "TODO 3.1";
      `src/protocol/mod.rs:14-16` omits `grant_revoke` and `:69-70` omits
      `denied`/`busy`/`internal`/`unauthorized`; `src/protocol/response.rs:69-70`
      describes a `Busy` case R.16 removed.
      `src/cli/help.rs:188` says every command but generate/help/version
      needs the master password (`lock`, `run`, `grant revoke` do not);
      `help.rs:146-147` says only `run` refuses `--db` (so does
      `grant revoke`); `help.rs:81-84` and `README.md:183` say `run` exits 5
      without an in-scope grant (a nonexistent ref exits 3).
      `README.md:522-534` exit-code table: code 3 omits unknown reference and
      unknown grant id; code 5 lists only reveal, though run denial, a
      missing/insecure grant file, `grant create` in agent context, the
      program-runner refusal and a refused env name also exit 5.
      `tests/docs.rs:189` searches the whole of `SECURITY.md`, so it passes
      while `:14-16` says the opposite (the R.5 failure mode).
      Fix: correct each; fold into R.32 if done together.
      Test: `tests/docs.rs` derives the session-token request list from the
      `Request` wire names (minus `run`) and scopes the check to its section;
      the README exit-code table is checked against `Error::exit_code`; the
      protocol module doc lists every `Request` variant.

- [ ] **R.52 Unit tests depend on the caller's agent environment markers.**
      `agent::tests::the_agent_flag_refuses_even_with_two_terminals` and
      `the_agent_flag_cannot_weaken_the_check` fail when `CLAUDECODE=1` or
      `AI_AGENT` is set (any Claude Code shell), and pass otherwise. The
      loop's gate is unaffected only because pi does not set them.
      Failure: a human or another agent runs `cargo test` from Claude Code
      and sees two failures unrelated to their change.
      Fix: make the detection take its environment as a parameter in tests,
      or clear the markers in the test setup.
      Test: `CLAUDECODE=1 AI_AGENT=1 cargo test --lib agent` passes.

- [ ] **R.53 `a_run_in_flight_is_not_killed_by_the_idle_timeout` has a 0.5 s
      timing margin.**
      `tests/daemon_shutdown.rs:142-149` (added in R.7) starts `pmd` with
      `--idle-timeout 3`, sleeps a fixed 2.5 s, then must connect before the
      next idle poll. A 0.5 s stall makes the connect fail, which says
      nothing about the property. Not reproduced under CPU contention, but
      this machine has already rolled back an iteration for a timing flake.
      Fix: start the run first, then assert the daemon outlives
      `idle + margin` while it is in flight; or use a larger timeout and
      margin. No fixed sleeps for synchronization.
      Test: the rewritten test passes with the suite pinned to 2 busy cores.

- [ ] **R.54 Seven files sit just under the 1,000-line guard, and three test
      fixtures duplicate vault+grant setup.**
      `src/socket.rs` 987, `src/grant.rs` 985, `src/cli/grant.rs` 972,
      `tests/cli.rs` 972, `src/runner.rs` 918, `src/protocol/response.rs`
      912, `src/client.rs` 905. TODO 4.9 lands in `src/cli/grant.rs` and will
      have to split it mid-item, as R.26 did. `tests/support/mod.rs`
      `Fixture`, `tests/run.rs` `Daemon` and `tests/grant_support/mod.rs`
      `Fixture` each build their own vault, grant and grant file with their
      own constants.
      Fix: split the files by concern before the next feature touches them
      (start with `src/cli/grant.rs` and `src/grant.rs`); one shared
      vault+grant builder used by all three fixtures.
      Test: `tests/layout.rs` stays green with every file under ~800 lines;
      test counts unchanged.

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
- [x] **3.6 Daemon authorizes by grant.** `run` and every new
      credential-touching request require a grant token. The unlock session
      token (2.5) only authorizes `ping`, `lock`, `status` and `revoke`.
      Record this in `DECISIONS.md`: holding the session file is not enough
      to use secrets. Tests: session token refused for `run`, valid grant
      accepted, uses counted, last_used updated.
      Done: protocol v4 makes `run.grant` mandatory; `pmd` canonicalizes
      `command[0]`, matches the token hash against an active grant, re-checks
      scope/capability/command, and records the use in the vault before it
      copies the secret or spawns. `pm run` reads `--grant-file` or
      `PASSMGR_GRANT_FILE` (regular, own uid, 0600/0400, `O_NOFOLLOW`).
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
