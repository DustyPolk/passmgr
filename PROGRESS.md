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

