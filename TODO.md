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
- [ ] **3.4b Re-encrypt with the unlocked key (no re-salt).**
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
- [ ] **3.4c `grant_create` request and daemon handler (TODO R.15b).**
      Protocol request `{type:"grant_create", request:{label, refs, tags,
      fields?, commands, capabilities, expires_at, max_uses?, token_hash}}
      and response `{type:"grant_approved"}` (no token, hash or grant id in
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
- [ ] **3.4d `pm grant create` CLI** (TTY + master password via the proof,
      refused in agent context with exit 5). Flags: `--label`, `--ref`/`--tag`
      (repeatable), `--command PATH` (repeatable; resolved to a canonical
      path at creation), `--expires 1h|30m|7d` (required, max 30 d),
      `--max-uses N`, `--allow-interpreter`, `--out FILE`. The CLI builds a
      `GrantRequest` with a fresh 32-byte token, derives the key once from the
      password, proves its digest, sends `grant_create`, and only after
      success opens the vault with that same key (`open_with_key` +
      `lock_for_update` + `save_with_key`) and writes the grant; it then
      writes the raw token to `--out` with `O_EXCL` and mode 0600, never to
      stdout. Requires a running daemon (`pm unlock` first); it does not
      auto-unlock in this item. Refuse interpreter commands (a shared pure
      list in `grant/validate.rs`) without `--allow-interpreter`. Tests: the
      token is absent from stdout/stderr, the file mode is 0600, an existing
      `--out` is refused without overwriting, interpreter commands are
      refused without the flag, agent/TTY refusal exits 5, and the daemon is
      still usable after the write (its key was not invalidated).
- [ ] **3.5 `pm grant list|show|revoke` (+ `--json`).** list/show print
      metadata only, never tokens or hashes. revoke needs no password and takes
      effect on the next request. `revoke --all` exists. Tests for each.
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
