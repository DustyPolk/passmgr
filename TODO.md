# TODO

Ordered, small, testable tasks. One unchecked item per iteration; split items that
are too big rather than doing partial work.

Rules that apply to every item:
- The agent-facing surface returns references and metadata, never secret values.
- Every security-relevant behavior needs a test that proves it (e.g. the secret is
  absent from stdout, stderr and logs).
- No new network-capable dependency. Justify any new dependency in `PROGRESS.md`.

## Phase R — review findings (fix first)

Findings from the security review of `3500f6d..533b68d` (details in
`PROGRESS.md`). R.6 is a regression of the R.1 fix: it breaks the containment
guarantee `lock`, SIGTERM and the idle timeout are supposed to provide. These
come before Phase 3.

- [x] **R.6 Shutdown hangs forever when a grandchild holds the child's
      stdout/stderr; `lock` reports a wipe that never happens.**
      `src/runner.rs:296` (`abort`) kills and waits for the direct child, drops
      the receiver and calls `join_all(readers)` (`src/runner.rs:305`), which
      joins reader threads blocked in `read()` on the child's pipes. The
      `Relay::Cancelled` branch (`src/runner.rs:236`, cancel set at
      `src/runner.rs:269`) and the output-error path both go through `abort`.
      A grandchild inherits the pipe write ends, so `read()` never returns EOF
      and the join never returns. `src/daemon.rs:445-446` then blocks in the
      scope join, so `session::remove_if_matches` (`src/daemon.rs:453`), the
      socket unlink and the key drop never run, while `passmgr lock` has
      already printed "The unlock daemon has wiped its key and stopped."
      Reproduced at HEAD: `run --env K=pm://… -- /bin/sh -c 'sleep 300 &'`,
      then `lock` -> exit 0, message printed, `pmd` still alive, `pmd.sock`
      and the session file still present, `sleep 300` still running. The same
      hang happens on SIGTERM and on the idle timeout, so `pmd` can outlive
      the key-wipe promise indefinitely. Also `serve_run` (`src/daemon.rs:530`)
      never checks `cancel` before `Vault::open_with_key`/`execute`, so a run
      accepted just before `lock` can still decrypt and spawn a child after
      the acknowledgement. Fix: kill the whole process group (SIGTERM then
      SIGKILL) so pipe holders die; do not join a reader that can never see
      EOF (close the pipe fds, or detach the readers with a bounded join);
      acknowledge `lock` only after the join and the key drop; check `cancel`
      at the top of `serve_run`. Test: child `sh -c 'sleep 30 &'` (grandchild
      holds both pipes) -> `lock` returns, `pmd` exits within ~2 s, socket and
      session file are gone, grandchild is reaped; repeat for SIGTERM and a
      2 s idle timeout. The existing `tests/daemon.rs` cancellation tests
      `exec >&- 2>&-` first, which is why they miss this.
      Done differently: the readers poll a cancel flag (100 ms slices) before
      each blocking read instead of closing fds, the child gets its own process
      group via `setpgid`, and `lock`'s answer is written by `run` after the
      join, the unlink and the key drop (see PROGRESS.md 2026-11-02 R.6).
- [x] **R.7 An in-flight `run` is not activity, so it is killed at the idle
      deadline.**
      `src/daemon.rs:421` pushes a worker for `Handled::Run` without touching
      `last_activity`; only `Handled::Served` (`src/daemon.rs:416`) and a
      *finished* run refresh it, and the idle check (`src/daemon.rs:403`) runs
      every 200 ms. A run accepted 0.4 s before the 15 min deadline is killed
      0.4 s in: reproduced with `unlock --idle-timeout 4`, sleep 3.6 s, then
      `run -- sh -c 'sleep 3; printf done'` -> the daemon closes the
      connection and the child never prints `done`. Any job longer than the
      remaining idle budget (a build, a test suite) dies mid-work, and
      `tests/daemon.rs::idle_timeout_cancels_a_run_whose_child_keeps_running`
      cements the behavior. Fix: refresh `last_activity` when a run is
      accepted and do not enforce the idle timeout while runs are in flight
      (bound them with the 4.5 timeout instead); update the DECISIONS.md
      sentence "a run that is still going does not keep the key alive past
      the idle timeout" and the R.1 test. Test: idle timeout 3 s, wait 2.5 s,
      run a 5 s child that prints `done`; assert `done` is relayed and the
      daemon exits only after it finishes.
      Done: `Handled::Run` refreshes `last_activity` and the idle check is
      gated on `runs.is_empty()`. The two idle-cancel tests that relied on
      killing an in-flight run were replaced: `tests/daemon_shutdown.rs` now
      has `a_run_in_flight_is_not_killed_by_the_idle_timeout` and an idle
      no-run test that also proves the socket, session file and reconnect are
      gone. Until TODO 4.5 lands, an in-flight run is bounded only by
      `lock`/signals; see PROGRESS.md.
- [ ] **R.8 No bound on concurrent runs, worker threads or children.**
      `src/daemon.rs:421` spawns one worker per accepted `Run` (plus two
      reader threads and one child with the secret in its env) with no cap.
      A client can open many connections and start unbounded children,
      multiplying the `/proc/<pid>/environ` exposure window and exhausting
      pids/memory; if `scope.spawn` fails it panics out of the scope, skipping
      `session::remove_if_matches` (`src/daemon.rs:453`) and leaving a stale
      session file and socket. Before R.1 runs were serialized, so this is a
      regression. Test: 64 concurrent runs with a short idle timeout; the
      daemon must still answer `ping`/`lock`, and runs past a documented cap
      must be refused with a stable error.
- [ ] **R.9 The vault write lock is held across interactive prompts.**
      `src/cli/commands.rs:34` (`open_for_add`) takes the lock before
      `prompt_credential_password` (`src/cli/commands.rs:42`); `edit` takes it
      in `unlock_for_update` (`src/cli/commands.rs:271-274`) before the
      credential prompt at `src/cli/commands.rs:155`. With
      `WRITE_LOCK_TIMEOUT` 30 s (`src/vault.rs:23`) a human who leaves
      `passmgr edit svc --generate` open blocks a scripted `passmgr add` for
      30 s, which then exits 1 with `VaultBusy` ("another passmgr process is
      updating … try again") although no update is in progress; `open_for_add`
      also creates `<vault>.lock` even if the user aborts. DECISIONS.md
      claims a healthy lock is released in milliseconds. Fix: prompt for all
      secrets before acquiring the lock. Test: hold the lock in one thread,
      prompt-block a second writer, and assert it does not fail with
      `VaultBusy` (or assert `add` prompts before `<vault>.lock` exists).
- [ ] **R.10 MCP.md still promises encoded-secret redaction and contradicts
      itself on who resolves `command[0]`.**
      `MCP.md:151-153` says redaction covers "best-effort encodings (lower/upper
      hex, standard and URL-safe base64 … percent-encoding)"; the daemon
      redacts exact bytes only (DECISIONS.md defers encodings to 4.6), and
      `MCP.md:233`/`:236` repeat the promise. The paragraph at `MCP.md:147-150`
      is headed "Rules, enforced by the **daemon**" but says "the daemon …
      never resolves either itself; the MCP server does the resolving" — the
      daemon cannot enforce a command allowlist on a path the untrusted MCP
      server chose, and `src/protocol/mod.rs` only checks that `command[0]`
      starts with `/`. `tests/docs.rs` pins README/`--help`/SECURITY.md but
      not MCP.md. Fix: state the current exact-bytes limit in MCP.md (or mark
      encoding redaction as 4.6), record in DECISIONS.md that the daemon
      canonicalizes and checks `command[0]` itself, and add the MCP.md
      contract test.

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
- [ ] **3.2 Grant model in the vault (next store version).** Fields per
      `MCP.md`: id, SHA-256 token hash, label, scope (refs, tags, optional
      field names), command allowlist, capabilities, expires_at, max_uses,
      uses, created, revoked_at, last_used. Migration from the previous store
      version gives an empty grant list. Pure scope-check function
      `Grant::authorizes(&Request, now) -> Result<(), Denied>` with
      table-driven tests: expired, revoked, used up, ref out of scope, tag
      match, command not allowed. Add `sha2` and `hmac` (RustCrypto) and
      justify them in `PROGRESS.md`.
- [ ] **3.3 Human-presence proof.** Daemon `challenge` request returns a
      nonce. The CLI answers with
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
