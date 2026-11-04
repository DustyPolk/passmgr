# TODO

Ordered, small, testable tasks. One unchecked item per iteration; split items that
are too big rather than doing partial work.

Rules that apply to every item:
- The agent-facing surface returns references and metadata, never secret values.
- Every security-relevant behavior needs a test that proves it (e.g. the secret is
  absent from stdout, stderr and logs).
- No new network-capable dependency. Justify any new dependency in `PROGRESS.md`.

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
      `grant_revoked`) and is one of the daemon's two vault writes (`run`
      records a use); it refuses
      `--db`/`PASSMGR_DB` like `run`. list/show read the vault locally with the
      master password. Enforcement of `revoked_at` by `run` is still 3.6.
- [x] **3.6 Daemon authorizes by grant.** `run` and every new
      credential-touching request require a grant token. The unlock session
      token (2.5) only authorizes `ping`, `lock`, `challenge`, `prove`,
      `grant_create` and `grant_revoke`; `run` additionally needs a grant
      token.
      Record this in `DECISIONS.md`: holding the session file is not enough
      to use secrets. Tests: session token refused for `run`, valid grant
      accepted, uses counted, last_used updated.
      Done: protocol v4 makes `run.grant` mandatory; `pmd` canonicalizes
      `command[0]`, matches the token hash against an active grant, re-checks
      scope/capability/command, and records the use in the vault before it
      copies the secret or spawns. `pm run` reads `--grant-file` or
      `PASSMGR_GRANT_FILE` (regular, own uid, 0600/0400, `O_NOFOLLOW`).
- [x] **3.7 `pm run` for humans.** With `--grant-file FILE` it goes through
      the daemon. Without it, at a TTY, it prompts for the master password and
      runs locally (same redaction code). In agent context without a grant it
      exits 5. Tests for all three paths.
      Note: the local path reuses the reveal gate, so stdin **and** stdout must
      be TTYs; a grant token (flag or env) always selects the daemon path and
      is never a fallback to local injection. Local runs are audited by 3.8.
- [x] **3.8 Audit log.** `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback
      `~/.local/state`), 0600, append-only with `O_APPEND`, one JSON object
      per line, hash-chained (`prev`). Written by the daemon for every
      authorized or denied credential request, and by the CLI for a grant-less
      local `run` (added by 3.7). Tests: one record per run, the
      secret and the token are absent from the file, the chain links.
      Note: `src/audit.rs` writes `v`, `ts`, `source`, `event`, `outcome`,
      `grant`, `ref`, `command`, `args`, `exit`/`signal` and `prev`; appends
      are serialized with `flock` and `fsync`ed, and an unrecordable run is
      refused before decrypting (fail closed). MCP fields stay with 4.11.
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

## Phase L — low-severity review findings

Review findings judged low severity (see `REVIEW.md`): memory-residue
defense against a same-user attacker, test hygiene and flakiness, comment
and doc wording, and file layout. They wait until the feature phases above
are done. Work them in order like any other item.

- [ ] **R.67 The reader-thread stack wipe is not covered by any test, so it
      can be deleted silently.** `src/runner.rs:528` holds the raw child output
      (which contains the injected value) in a stack array and
      `src/runner.rs:542` wipes it; the allocator scan in
      `tests/secret_copies.rs::a_run_leaves_no_more_copies_than_the_spawn_itself`
      (`tests/secret_copies.rs:254`) only sees heap blocks, so removing the
      wipe keeps the whole suite green. The test also compares against a
      baseline with `hits <= baseline` (measured: both 3), so it has no margin
      to catch a newly lost wipe of its own canary.
      Fix: own the read buffer on the heap (`Box<[u8; READ_CHUNK]>` or
      `Zeroizing<Vec<u8>>`) so `push`/`drain` and the wipe are observable, and
      replace `<= baseline` with a differential assertion on the raw-output
      canary: the measured release count must be lower when the wipe is
      present than when it is removed (pin the count if it is deterministic).
      Test: delete the wipe locally and confirm the new assertion fails; keep
      the current baseline comparison only as a sanity check.

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

- [ ] **R.56 `Redactor::finish`'s doc states the invariant the fixed window
      deliberately dropped.**
      `src/redact.rs:94-97` says "A held-back suffix is by construction only a
      proper prefix of the secret, so emitting it does not reveal the value."
      Since R.36 the holdback is content-independent: for secret `abcdef`,
      `push(b"xyz")` holds `xyz`, which is not a prefix, and `finish` returns
      it. `consume`'s own doc (`src/redact.rs:109-117`) gives the real reason
      ("shorter than the secret by construction"), so the file contradicts
      itself; the "never contains a complete occurrence" contract holds only
      because of the length bound.
      Failure: the next change that trusts `:96` — e.g. holding only bytes that
      are a prefix, to restore the sentence — reintroduces the
      content-dependent holdback R.36 exists to remove, and an agent that
      controls child output learns the secret's prefix byte-by-byte from the
      relay timing; alternatively a reviewer auditing "only a proper prefix can
      leave the redactor" concludes the code is broken and adds an assertion
      that panics on real output.
      Fix: say the held suffix is "at most `secret.len() - 1` bytes, so it
      cannot contain a complete occurrence; its content is arbitrary".
      Test: a `src/redact.rs` unit test `the_held_tail_is_arbitrary_bytes`:
      `redact("abcdef", b"xyz") == b"xyz"`, mid-stream `push(b"xyz")` returns
      nothing, and `push(b"abcdef")` returns only the marker. A prefix-only
      holdback fails the first two.

- [ ] **R.57 The grant-create race test can pass without the race happening, so
      R.39's CLI half is untested.** `tests/grant_cli.rs:717`
      (`grant_create_keeps_a_concurrent_vault_write_and_still_succeeds`) orders
      its concurrent save with `std::thread::sleep(Duration::from_millis(300))`
      (`tests/grant_cli.rs:777`) and never observes that the CLI is at the
      lock; the comment above the sleep (`tests/grant_cli.rs:774-776`) admits
      "If it is still earlier, it reads the new state and the race simply did
      not happen".
      Verified by experiment: with `src/cli/grant.rs:256` reverted to
      `Vault::open_with_key` + `lock_for_update()` (the pre-R.39 read-then-lock
      shape, i.e. exactly the bug the test is named for) the test passed 3/3 on
      a scratch copy. The CLI's reads simply landed after the 300 ms save, so
      `lock_for_update`'s byte compare saw no change. The daemon-side tests do
      fail on that revert (`src/daemon/tests.rs:558` `Internal` vs `Ok(1)`,
      `tests/daemon_concurrency.rs:293` `RunFrame::Error(Internal)`), so only
      the CLI half is unproven.
      Failure: a later refactor that reintroduces read-then-lock in
      `command_grant_create` (or reverts R.39 for `grant create`) keeps the
      suite green while a human's approval is spent and then refused with
      `VaultChanged`; no test fails, and the token file is already gone.
      Fix: order the save from the daemon side instead of by sleeping. Use the
      stub-socket pattern already in this file
      (`grant_create_refuses_an_unknown_reference_before_any_socket_contact`,
      `tests/grant_cli.rs:217`, stub bound at `tests/grant_cli.rs:223`): accept,
      read `challenge`, answer a challenge,
      read `prove`, then run `grant_mut(seeded).mark_used(now)` +
      `save_with_key` and `drop(writer)` in the test, and only then answer
      `grant_approved`. The CLI's pre-approval read is provably before
      `challenge`, and the save is provably before the CLI's post-approval
      read, so read-then-lock fails deterministically.
      Test: that rewritten test must fail on the reverted `src/cli/grant.rs` and
      pass on HEAD, keeping the current assertions (exit ok, two grants, seeded
      `uses() == 1`, token file written).

- [ ] **R.59 DECISIONS says no plaintext is held while the human reads the
      summary, but the vault key is.** `DECISIONS.md:625-626`: "the vault is
      dropped before the y/N so plaintext is not held while the human reads".
      True of the decrypted credentials, false of the key that decrypts them:
      `key` (`src/cli/grant.rs:179`) is live across `print_approval_prompt`
      (`src/cli/grant.rs:202`) and `prompt_yes_no` (`src/cli/grant.rs:203`)
      because `Proof::compute` (`src/cli/grant.rs:218`) and
      `open_with_key_for_update` (`src/cli/grant.rs:256`) need it; only the
      master password (`:180`) and the container (`:181`) are dropped.
      Failure: a reader (or the next `SECURITY.md` edit) takes the sentence to
      mean a memory disclosure while the prompt is on screen is harmless, when
      a core dump at `:203` yields the 32-byte key that decrypts the whole
      vault offline — the property `PROMPT.md`'s zeroize rule is about.
      Fix: state what is actually held — "the decrypted vault is dropped before
      the y/N; the derived key stays live until the grant is written and is
      zeroized on drop".
      Test: a `tests/docs.rs`-style assertion (that file already pins DECISIONS
      sentences) that the grant-create bullet names the held key and does not
      claim the window holds no plaintext-capable material.

- [ ] **R.62 The R.45 clock test gives the whole startup three seconds, so a
      slow machine fails the test instead of testing the daemon.**
      `tests/daemon_run.rs:672-712`: `Fixture::with_grant_expiring_in(3)`
      (`:677`) stamps `expires_at = now + 3` inside `Fixture::build`
      (`tests/support/mod.rs:105`), and those same three seconds must also
      cover `fixture.start()` (spawn `pmd`, ping until `pong`), the `run`
      request, the daemon's `open_with_key_for_update` and
      `wait_until_the_lock_is_open`. `:712` then asserts
      `observed < fixture.grant_expires_at`, "the daemon read the clock after
      the grant expired; the test proves nothing" — a loaded machine turns a
      slow start into a hard failure of the test that guards R.45, and the
      obvious repair (raise the number) re-arms the same race.
      Failure: `cargo test` on a busy box (16 test threads, each building an
      8 MiB-KDF fixture) takes over 3 s between `build()` and the lock chmod;
      the suite goes red with a message that blames the daemon.
      Fix: stop racing startup. Build the grant with a long expiry, and once
      `wait_until_the_lock_is_open` has observed the daemon blocked *before* it
      reads the vault, rewrite that grant's `expires_at` to `observed + 1`, then
      sleep to `observed + 2`, release the lock and expect `Denied`. The rewrite
      must keep the container header (salt/KDF) so the daemon's live key still
      opens it, as `rewrite_vault` already does (`tests/daemon_run.rs:290-299`);
      that needs the fixture to keep its credential and grant (or a
      `Fixture::set_grant_expiry` helper).
      Test: the same test, with the expiry derived from the clock the test
      observed and no dependency on how fast `pmd` starts.

- [ ] **R.63 The "every documented grant example" guard counts prose as an
      example, so it survives deleting the examples it protects.**
      `tests/docs.rs:607-638` counts *every* line containing the substring
      "grant create", including prose: `README.md:182` ("…so `grant create`
      refuses it otherwise.") and `README.md:257` ("…`grant create` prompts…").
      `tests/docs.rs:643-660` then requires only `README.md >= 2` and
      `--help >= 1` such lines. The parser also matches `--command` tokens
      literally, so a quoted path (`--command '/usr/bin/git'`) reaches
      `is_program_runner` with the quotes attached and is not recognised as a
      runner.
      Failure: someone rewrites the quickstart without `/usr/bin/gh` (or drops
      both real examples); the prose lines keep the count at 2 and
      `every_documented_grant_example_flags_a_program_runner` still passes while
      the invariant it exists for (R.43: a copied example must not exit 5) is
      unenforced. A quoted example is skipped for the same reason.
      Fix: recognise command-shaped lines only (a line whose first tokens are
      `passmgr`/`pm` `grant` `create`, not a backticked mention), and strip one
      layer of matching quotes before `is_program_runner`.
      Test: unit-test `check_grant_examples` directly — prose only must return
      0; a quoted runner example without `--allow-interpreter` must fail
      (`#[should_panic]`); the real README/`--help` must still be accepted.

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
