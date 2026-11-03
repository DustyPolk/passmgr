# TODO

Ordered, small, testable tasks. One unchecked item per iteration; split items that
are too big rather than doing partial work.

Rules that apply to every item:
- The agent-facing surface returns references and metadata, never secret values.
- Every security-relevant behavior needs a test that proves it (e.g. the secret is
  absent from stdout, stderr and logs).
- No new network-capable dependency. Justify any new dependency in `PROGRESS.md`.

## Phase R — review findings (fix first)

From the review of `533b68d..92448ed` (2026-11-03). Fix these before
continuing Phase 3; each names the test that must prove the fix.

- [x] **R.11 A list request can carry an out-of-scope target and still be
      authorized.** `Grant::authorizes` (`src/grant.rs:635`) returns `Ok(())`
      for `Capability::List` without reading `request.target` or
      `request.field`; `AccessRequest`'s fields are public
      (`src/grant.rs:389-393`) and `AccessRequest::list()` (`src/grant.rs:397`)
      leaves both `None`. So the "single decision point" (TODO 3.2a) cannot
      enforce scope for `list`/`describe`: 4.4 must remember a separate
      `scope_allows` call, and nothing forces it. `tests/grant.rs:346` only
      asserts `Ok(())` for `list()`; there is no test with a target. Failure
      (latent: no caller until 4.4): `describe_credential` builds
      `AccessRequest { capability: List, target: Some(out_of_scope), .. }`,
      gets `Ok(())`, and returns metadata for a credential outside the grant
      (and, once 6.1 exposes fields, its value). Fix: give list/describe a
      target and enforce `scope_allows` in `authorizes` (keep `list()` only
      for the enumeration path, if the caller is then forced to filter).
      Test: a list-only grant scoped to ref A must deny a List request with
      `target = B` (`OutOfScope`) and allow `target = A`; a field-restricted
      grant must deny `field: None` and a different field.
      Done: `AccessRequest` is now an enum; `List`/`Run` both carry the
      `Target`, `authorizes` scope-checks both, and `list()` (target-less) is
      gone. `Denied::MissingTarget`/`MissingCommand` removed with it.
- [x] **R.12 A run's relay reaps the process-group leader, so `terminate` can
      signal a recycled group.** `src/runner.rs:316-318` calls
      `let _ = child.try_wait();` on every relay timeout, which reaps the
      leader as soon as it exits while a grandchild still holds a pipe.
      `terminate` (`src/runner.rs:349-357`) then signals `-child.id()`, but
      its comment (`src/runner.rs:347-348`) promises the leader is
      "deliberately not reaped ... so the group signal can never hit an
      unrelated group". Once the group is empty and the pid is reused, a
      later `lock`/SIGTERM/SIGINT sends SIGTERM then SIGKILL to an unrelated
      same-uid process group; the window is unbounded until cancel. Failure:
      a run whose leader exits immediately while a grandchild keeps
      stdout/stderr open (e.g. `sh -c 'echo $$ >pid; (sleep 600) &'`) leaves
      a reaped pid behind; minutes later `passmgr lock` can kill the user's
      editor if it took that pid. Fix: remove the `try_wait` from `relay`
      (the `Finished` loop at `src/runner.rs:241-260` already reaps), or
      never derive the pgid after a reap. Test: run that command; after more
      than `CANCEL_POLL`, assert `/proc/<pid>/stat` still shows state `Z`
      (not reaped), then cancel and assert both processes are gone. This test
      fails today.
      Done: `relay` no longer takes the `Child`, so it cannot reap; the
      timeout arm only checks the cancel flag. Test
      `a_finished_leader_is_not_reaped_while_a_grandchild_holds_the_pipes`
      proves the zombie survives three poll slices and is reaped only by the
      cancel path.
- [x] **R.13 `TokenHash` exposes a non-constant-time `==`.** `src/grant.rs:127`
      derives `PartialEq, Eq` on `TokenHash`, while `SessionToken` documents
      the opposite convention ("deliberately no `PartialEq` implementation
      that could be used by accident", `src/token.rs:27-31`) and
      `DECISIONS.md:341` states `TokenHash::matches` is constant-time. No
      caller uses `==` today, so this is latent, but the next store lookup
      (3.2b/3.6) can compare hashes with an early-exit comparison and turn a
      secret-derived digest into a timing oracle. Fix: drop `PartialEq`/`Eq`
      (keep `matches` the only comparison), as `SessionToken` does. Test: a
      compile-fail UI case (trybuild) proving `TokenHash == TokenHash` does
      not compile; if a new dev-dependency is refused, a source-guard test
      that parses the `TokenHash` derive list and fails if `PartialEq`/`Eq`
      returns.
      Done: the derive is `Clone, Copy` only; `matches` is the sole
      comparison. A `compile_fail` doctest in `src/grant.rs` proves `==` does
      not compile, and its companion doctest proves `matches` does. Chose a
      doctest over `trybuild`/a source guard: no new dependency and the
      compiler, not a text parse, is the oracle.
- [x] **R.14 Grant labels accept bidi and zero-width characters.**
      `validate_label` (`src/grant.rs:699-713`) rejects only
      `char::is_control` (`src/grant.rs:708`), which is Unicode Cc. Verified:
      U+202E RIGHT-TO-LEFT OVERRIDE and U+200B ZERO WIDTH SPACE both pass.
      The label is stored unchanged and is rendered by the future
      `pm grant list`/`show` (`MCP.md`), and 4.9 may take it from an approved
      agent request (unconfirmed: label provenance until 4.9), so
      agent-supplied text can reach a human terminal without the bidi
      stripping `PROMPT.md` requires. Failure: a label containing `\u{202E}`
      reorders the rest of the line, e.g. making the scope or expiry read
      backwards or hiding text; `\u{200B}` hides a character. Fix: reject (or
      strip) the Unicode bidi-control and zero-width/format sets in
      `validate_label` before storing. Test: `Grant::create` with
      `label: "prod\u{202E}nimda"`, `"a\u{200B}b"` and `"a\u{2066}b"` must
      be rejected (or sanitized to the visible characters), and a rendering
      test asserts `pm grant list` output contains none of those code points.
      Done: `validate_label` rejects Cc plus the Unicode format (`Cf`),
      line/paragraph separator and variation-selector sets via
      `is_hidden_or_reordering`; the whole label is refused (not stripped) so
      it always matches what a human approved. Tested with a test-local
      table of 29 code points (independent of the module's table); the
      `pm grant list` half waits for 3.5, so the rendering test proves the
      accepted label and its `Debug` rendering hold no such code point.

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
- [ ] **3.2b Persist grants in store version 5.** Add the grant list after
      the credentials in the payload, encode/decode with the same length
      caps, v5 keeps credentials byte-identical to v4 and earlier versions
      migrate to an empty grant list. `Vault` gains grant accessors used by
      `save`. Update `FORMAT.md` and `DECISIONS.md`. Tests: v4 -> v5
      migration, every older version decodes with no grants, a round trip,
      duplicate grant ids and a truncated grant record are `MalformedVault`.
- [ ] **3.3 Human-presence proof.** Add `hmac` (RustCrypto) here, its first
      use. Daemon `challenge` request returns a nonce. The CLI answers with
      `HMAC-SHA256(key, "passmgr-approve-v1" || nonce || digest)`. The daemon
      verifies in constant time, and a nonce is single-use with a 60 s
      expiry. Tests: correct proof accepted, wrong key/reused
      nonce/expired nonce/altered digest rejected.
- [ ] **3.4 `pm grant create`** (TTY + master password via the proof, refused
      in agent context with exit 5). Flags: `--label`, `--ref`/`--tag`
      (repeatable), `--command PATH` (repeatable; resolved to a canonical
      path at creation), `--expires 1h|30m|7d` (required, max 30 d),
      `--max-uses N`, `--allow-interpreter`. The token is written **only** to
      `--out FILE` (created 0600 with `O_EXCL`), never to stdout. Tests: the
      token is absent from stdout/stderr, the file mode is 0600, interpreter
      commands are refused without the flag.
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
