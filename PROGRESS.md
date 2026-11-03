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

## 2026-11-02 — Run children in the caller's cwd and resolve commands client-side (TODO R.2)

- `src/protocol/mod.rs`: protocol version 3. `RunRequest` gains a required
  absolute `cwd`; `run.command[0]` must be an absolute path, and both are
  validated on encode and decode (`validate_absolute_path`: non-empty, no NUL,
  at most `MAX_PATH_BYTES`, leading `/`). A version-2 daemon would ignore
  `cwd`, so the bump turns a silent wrong-directory run into an
  `unsupported_version` refusal.
- `src/runner.rs`: `execute` takes the caller's cwd and sets
  `Command::current_dir`, so relative arguments resolve where the caller meant.
- `src/cli/run.rs`: resolves `command[0]` before contacting the daemon — a
  bare name through the **caller's** `PATH` (empty entries skipped, regular
  executable files only), a name containing `/` against the caller's cwd, and
  an absolute path as given. Unresolvable bare names are a usage error (exit
  2) before the daemon is asked to run anything; an absolute nonexistent path
  still reaches the daemon and is reported as `spawn_failed` (exit 1), which
  keeps the existing refusal mapping. `cwd` is sent as the caller's absolute
  directory.
- Tests: runner unit test proves a relative argument resolves in the given cwd;
  protocol tests cover relative `command[0]`, relative/empty/NUL/overlong
  `cwd`, a missing `cwd`, and the new field set. E2E (`tests/run.rs`): a daemon
  started in A and a CLI in B, both with `rel.sh`, runs B's script; a bare
  name resolves through the CLI's `PATH`, not the daemon's; an unresolvable
  name is exit 2 and the daemon stays healthy. `tests/daemon.rs` fixtures now
  send `cwd: "/"` and absolute programs.
- Docs: `DECISIONS.md` (protocol v3 + run cwd/PATH policy), `README.md`,
  `src/cli/help.rs` and its golden fixture, `MCP.md` (the MCP server, not the
  daemon, resolves the program and sends `cwd`).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass. `cargo audit` is not installed; skipped.
- **Next iteration must know:** a child that itself execs a bare helper name
  still resolves that helper through the daemon's inherited `PATH` (the fixed
  allowlist), not the caller's — only `command[0]` is resolved client-side.
  That is consistent with `MCP.md` ("child's PATH") but surprising; if it
  matters, R.3/R.4 can document it or the daemon can be given the caller's
  `PATH` for the child later (do not widen the allowlist without a decision).
- NEEDS HUMAN REVIEW: the daemon trusts the caller-supplied absolute `cwd`
  and program path. That grants no new privilege (the token holder can already
  name any absolute program), but a grant-scoped allowlist in 3.6/4.x must
  match on this resolved absolute path, not on the agent's original text.

## 2026-11-02 — Serve runs concurrently and cancel them on lock/signal/idle (TODO R.1)

- `src/daemon.rs`: `run` is decoded and authenticated on the accept thread,
  but `serve_run` now runs on a `std::thread::scope` worker, so `ping`,
  `lock` and signal handling stay responsive while a child runs. The loop
  reaps finished workers (and counts them as activity) on every iteration.
  A shared `AtomicBool` cancel flag is set on `lock`, `SIGTERM`/`SIGINT` and
  the idle timeout; the scope joins every worker before the key is dropped.
- `src/runner.rs`: the `Relay::Finished` path no longer blocks in
  `child.wait()`; it polls `try_wait` (i.e. `waitpid(WNOHANG)`) every 100 ms
  and aborts when cancelled. The relay loop also checks the flag before each
  receive, so a child that keeps the channel full cannot delay cancellation.
  An interrupted run writes no terminal frame, so the client reports a
  `Daemon` error rather than a fake exit status.
- Tests (tests/daemon.rs): three e2e cases run a child that closes both
  pipes and sleeps 30 s — `lock` returns `Locked` in under 2 s and the child
  is reaped, `SIGTERM` stops `pmd` in under 2 s and reaps the child, and a
  `--idle-timeout 2` daemon exits and reaps the child while the run is live.
  Each polls with deadlines and asserts the socket is gone.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` all pass.
- **Next iteration must know:** concurrent runs are now possible in the
  daemon; R.1 did not add a cap on simultaneous runs or connections (that is
  TODO 9.4's slowloris/idle-client work). Each worker re-opens the vault, so
  N parallel runs mean N Argon2-free key unlocks (key is already derived).
  A cancelled run is indistinguishable from a client disconnect to
  `serve_run`; neither writes a frame, which the CLI already maps to a
  `Daemon` error.

## 2026-11-02 — Review of 49d9915..3500f6d

- Reviewed the whole range (26 files, +6340/−2583): the new `src/runner.rs`,
  `src/cli/{run,args,mod}.rs`, `src/protocol/response.rs`, the streaming
  reader in `src/client.rs`, `serve_run` in `src/daemon.rs`, `SECURITY.md`
  and `tests/{run,docs}.rs`, plus `PROMPT.md`, `MCP.md`, `DECISIONS.md` and
  the archived TODO. `cargo test` passes on the range (16 daemon, 8 run,
  8 cli, 5 docs, 0 failures); `cargo audit` is still not installed. No source
  changes were made.
- Five findings, now `## Phase R` in `TODO.md`: authorization 1 (R.1),
  unsafe exec/path resolution 1 (R.2), documentation drift 2 (R.3, R.4),
  ineffective test 1 (R.5). No secret-exposure, crypto or maintainability
  finding. The session-token-only gate on `run` (TODO 3.6) and unaudited run
  frames (TODO 3.8) are the documented transition, not new findings.
- R.1 reproduced outside the suite: with a run child that closes both pipes
  and sleeps, `passmgr lock` timed out after 5 s and `pmd` was still alive
  2 s after SIGTERM (the daemon serves `run` inline on its accept thread, and
  the `Relay::Finished` path waits without polling the cancel flag). R.2
  reproduced with the daemon started in one directory and the CLI run from
  another: the daemon's copy of `./rel.sh` executed with the secret injected.
  Both scratch harnesses lived in `/tmp/pmreview` and are not committed.
- Looked at and judged fine (do not redo): the peer-uid check in
  `accept_peer`; constant-time token comparison and the session file's
  0600/`O_NOFOLLOW` handling; frame, chunk, argv and password bounds with
  no-panic parsers on arbitrary bytes; redacting `Debug` for `RunFrame`,
  `SessionToken` and `LockedKey`; the daemon-side loader/shell-hook denylist
  and its live-daemon test (`tests/daemon.rs:744`); redaction before the
  socket plus the raw-socket canary test; no new `println!`/`format!`/JSON
  path can carry a secret; no new file over ~1000 lines (`src/protocol/mod.rs`
  shrank from 1244 to 1080 when `response.rs` was split out). The CLI
  denylist test's `!marker.exists()` cannot fail (no daemon runs), but its
  exit-5 and stderr assertions still catch a CLI regression and the daemon
  test covers the actual spawn.
- Accepted and documented, not findings: `/proc/<pid>/environ` for the
  injected child, interpreter exfiltration, the partial-prefix output flush,
  `[REDACTED]` vs `MCP.md`'s `[REDACTED:<VAR>]` (Phase 4), and the `--db`
  note already in the previous entry. Do not expose `run` to MCP before R.1
  and 3.6 are fixed.

## 2026-11-02 — Document the accepted limits in `SECURITY.md` (TODO 2.7)

- New `SECURITY.md` (the file already referenced by `src/daemon.rs`,
  `src/redact.rs`, `src/runner.rs` and `src/token.rs` but never written):
  what passmgr protects, then seven accepted limits — (1) a same-user process
  can read an injected value from the running child's `/proc/<pid>/environ`
  (daemon hardening does not apply to the child), (2) an allowlisted
  interpreter or shell is equivalent to handing the agent the secret, (3)
  redaction is output-only and best-effort (no encodings, no other channels),
  (4) plaintext at a terminal/clipboard/rendered file leaves our control, (5)
  vault permission violations are warned about, not yet refused (8.10), (6)
  swap/hibernation and best-effort `mlock`, (7) out of scope: root,
  keyloggers, malicious same-user processes, compromised agent hosts.
- `SECURITY.md` also carries an honest **Current status** section: grants are
  not implemented yet and the session token is not an agent/human boundary
  (TODO 3.6 closes that). `README.md`'s security section now links to it, and
  `src/token.rs` no longer says "once TODO 2.7 lands".
- Decision (also in `DECISIONS.md`): `SECURITY.md` is the canonical limit
  list; a change that alters a limit updates it in the same commit.
- Tests: new `tests/docs.rs`, 5 compile-time doc contracts (`include_str!`,
  instant): `/proc/<pid>/environ` + "same user", interpreter exfiltration +
  `--allow-interpreter`, redaction is not a sandbox, the transitional
  session-token gap names TODO 3.6, and README links to SECURITY.md.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes.
  `cargo audit` is not installed; skipped, not installed.
- **Next iteration must know:** next unchecked item is **3.1** (vault write
  lock). When 3.6 lands, rewrite `SECURITY.md`'s "Current status" and update
  `tests/docs.rs::security_discloses_the_transitional_session_token_gap` in
  the same commit — that test exists to force the disclosure to be revisited,
  not to be deleted silently. TODO 9.7 later expands `SECURITY.md` into a full
  threat model; keep the README's crypto details there rather than duplicating
  them.
- **NEEDS HUMAN REVIEW:** the macOS sentence ("no `PR_SET_DUMPABLE` equivalent
  set by passmgr, so same-user ptrace/memory inspection of `pmd` is not closed
  here") is intentionally conservative and untested on this Linux machine; the
  exposure is admitted rather than claimed safe.

## 2026-11-02 — CLI `run` streams through the daemon (TODO 2.6d)

- New `src/cli/run.rs`: `command_run` validates the env name against the
  daemon's denylist (local refusal, exit 5, no socket), loads the session
  token, sends one `RunRequest`, and relays non-terminal frames to its own
  stdout/stderr (flushed per frame). Exits with the child's code; signal N
  renders as 128+N (the wire keeps them distinct). Terminal refusals map:
  `not_found` 3, `spawn_failed`/`bad_request`/`internal`/`unauthorized`/
  `unsupported` 1; no daemon -> 1 with "start one with 'passmgr unlock'".
- New `client::run(paths, token, &RunRequest, on_frame) -> RunOutcome`:
  streaming reader over `FrameDecoder` + `RunStream` ordering guard. No read
  timeout (silent children are legitimate); EOF before a terminal frame is a
  `Daemon` error. `decode_frame_body` restores the length prefix the decoder
  strips. Exposed `protocol::valid_env_name` so the CLI grammar cannot drift
  from the wire grammar (agreement test).
- `src/cli/args.rs`: `Command::Run(RunOptions)` via `parse_run`; exactly one
  `--env NAME=<ref>` (protocol injects one value), `--` required, argv after
  it is never re-parsed, limits (`MAX_ARGS`, `MAX_ARG_BYTES`, ref syntax)
  checked locally for a usage exit 2.
- Help text gained a `run` entry, example and note; `tests/fixtures/help.txt`
  regenerated deliberately; README documents `run`; DECISIONS gained the
  grammar/exit/stream-reader rules.
- Tests: 5 client unit tests (relay order, refusal, truncation, stop at first
  terminal, malformed frame), 3 parser tests, 2 code-mapping unit tests, a
  protocol grammar-agreement test, and 8 `tests/run.rs` e2e tests (injection +
  both-stream redaction, exit 7 passthrough, SIGTERM -> 143, agent mode with
  non-TTY stdio, no-daemon message, loader-name refusal with no spawn, usage
  exit 2, not-found 3 + spawn failure 1 with the daemon still healthy).
- Gate: fmt, clippy -D warnings, full test suite pass.
- **Next iteration must know:** `--db` is ignored by `run` (the daemon owns
  the vault it was started with); there is no multi-secret run yet; `run`
  frames are still unaudited until 3.8, and `run` is still session-token
  authorized until 3.6, so MCP must not expose it yet.

## 2026-11-02 — Daemon executes `run` with redacted output (TODO 2.6c)

- New `src/runner.rs` (cfg(unix)): `execute(argv, env_name, secret, inherited,
  cancel, emit)` spawns an argv (never a shell string) with stdin null, a
  fixed env allowlist, and exactly one injected variable. Two reader threads
  each own a `Redactor`; one output thread relays frames in order, checks the
  daemon's cancellation flag every 100 ms, splits redacted bytes at
  `MAX_CHUNK_BYTES`, and kills/reaps the child on output failure or cancel.
  `denied_env_name()` refuses loader/shell-hook names; `inherited_env()` keeps
  only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ`, `TMPDIR`,
  `TERM`.
- `src/daemon.rs`: `handle_connection` now takes the vault path and key.
  `Request::Run` resolves the ref with `EntryId::parse_ref`, opens the vault,
  copies only that password into a `Zeroizing<String>`, drops the vault
  (zeroizing the rest), then streams `RunFrame`s. Terminal outcomes:
  `Exit(code|signal)`, `Error(not_found)`, `Error(spawn_failed)`,
  `Error(bad_request)` for a denied env name, `Error(internal)` if the vault
  cannot be read. A failed run never kills the daemon.
- `ResponseError::Internal` added (`internal`) with round-trip coverage.
- Tests: 11 runner unit tests (allowlist, denylist, injection + redaction,
  no inherited test-process env, 10 KB secret split across 8 KiB reads,
  multi-frame 40 KB output, exit 7, SIGTERM, bad program, invalid env name,
  output failure/cancel kill the child) and 4 new daemon e2e tests
  (stdout+stderr redaction with canary absent from raw socket bytes and pmd
  output, not-found vs spawn-failed both non-fatal, every denied env name
  refused without spawning, 40 KB output split into bounded frames with a
  4096-byte secret redacted). The old "run is unsupported" assertion now
  expects `not_found`.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes
  (159 lib + 20 bin + 28 CLI + 16 daemon + 8 unlock). `cargo audit` not
  installed; skipped.
- **Next iteration must know:** TODO 2.6d owns `passmgr run` and the client
  stream reader (`src/client.rs` still reads exactly one response). Two
  deliberate edges for later: (1) a `lock` request cannot interrupt an
  in-flight `run` because the daemon serves one connection at a time; only
  SIGTERM/SIGINT (via the cancel flag) stops it — timeouts/process groups are
  TODO 4.5. (2) The redactor marker is `[REDACTED]`, while `MCP.md` promises
  `[REDACTED:<VAR>]`; Phase 4 must either extend the redactor or amend
  `MCP.md`. Run frames are not audited yet (3.8).
- **NEEDS HUMAN REVIEW:** until TODO 3.6, `run` is authorized by the session
  token alone, so any same-user process that can read the 0600 session file
  can use a stored secret. This ordering is inherent in `TODO.md` (2.6 before
  3.6) and is recorded in `DECISIONS.md`; do not expose an MCP tool for it
  before 3.6.

## 2026-11-02 — Protocol streaming `run` responses (TODO 2.6b)

- `src/protocol/response.rs` (new; moved out of `src/protocol.rs`, which is now
  `src/protocol/mod.rs`) adds `RunFrame` (`Stdout`/`Stderr`/`Exit`/`Error`),
  `RunExit` (`Code` or `Signal`), `RunStream` ordering state, and
  `encode_run_frame`/`decode_run_frame`. `Response`/`ResponseError` and the
  one-shot encoders moved with them; `crate::protocol::*` re-exports the same
  public API.
- Wire shape: `{"version":2,"response":{"type":"stdout","data":"<lowercase
  hex>"}}`; `exit` carries exactly one of `code` 0..=255 or `signal` 1..=127;
  `error` carries a stable code. Raw chunks are capped at `MAX_CHUNK_BYTES`
  (16 KiB) on encode *and* decode, and the cap is checked before hex decoding.
  `not_found` is added and deliberately also covers out-of-scope refs (no
  existence oracle); `spawn_failed` is the child-spawn error.
- Decisions: `RunFrame` is a distinct type from `Response` so one-shot and
  streaming responses cannot be confused; nothing follows a terminal frame
  (`RunStream`); signal deaths stay distinct from 128+N; protocol version
  stays 2 because only new response types were added, no request change. All
  recorded in `DECISIONS.md`.
- Tests (lib `protocol`, 34 pass): binary/UTF-8-invalid payload round-trips,
  chunk cap at/over the limit and hand-built oversized frames, malformed run
  frames (wrong types, non-hex/uppercase/odd hex, unknown codes, version 1,
  trailing bytes), one-shot/stream confusion, `RunStream` after-terminal
  rejection, stable error codes, and `Debug` never rendering child bytes.
- Gate: fmt clean, clippy `-D warnings` clean, full `cargo test` passes
  (148 lib + 20 bin + 28 CLI + 12 daemon + 8 unlock). `cargo audit` is not
  installed; skipped, not installed.
- **Next iteration must know:** 2.6c owns the daemon side: answer `Request::Run`
  by streaming `RunFrame`s through `encode_run_frame` (the daemon still
  returns `unsupported` today) and redact before encoding. `src/protocol/mod.rs`
  is 1045 lines (request/framing + its tests) and `response.rs` 776; split
  further only if it grows. Do not add a plaintext-bearing frame variant.

## 2026-11-02 — Split the CLI into `src/cli/` modules (TODO H.2)

- `src/main.rs` is now 7 lines (`mod cli;` + `fn main` -> `cli::main`).
  New modules: `src/cli/mod.rs` (entry, dispatch, `stdout_write`,
  `report_runtime_error`, the moved unit tests), `src/cli/args.rs` (all
  parsing, `Command`/option types, `DEFAULT_DB`), `src/cli/commands.rs`
  (local commands, prompts, JSON metadata, `unlock` helper, `warn_insecure`),
  `src/cli/unlock.rs` (`command_unlock`/`command_lock`, both cfgs) and
  `src/cli/help.rs` (`USAGE`, `HELP`). No behavior change.
- Visibility: items are `pub(crate)` and re-exported with globs from
  `cli/mod.rs`, so the moved test module still works with `use super::*`
  and every test body is unchanged. Struct fields are `pub(crate)`; enum
  variant fields inherit the enum's visibility (a field modifier there would
  not compile).
- `--help` byte-identity: captured `tests/fixtures/help.txt` from the
  **pre-split** binary (7933 bytes, md5 `8c185a1d9b9cdf012ededd6c00f331b6`)
  and added `help_output_matches_the_golden_file` in `tests/cli.rs`, which
  compares exact stdout. This is the before/after proof H.2 asked for; do not
  regenerate the fixture to "fix" a failure — a diff means behavior changed.
- Flaky test fix (test harness only, not shipped behavior): the full-suite
  run hit `write request: BrokenPipe` in
  `unauthorized_requests_do_not_refresh_the_idle_timeout`. The daemon can
  expire between `connect` and `write_all`, but `tests/daemon.rs::try_request`
  used `.expect("write request")`, so the probe loop's `_ => break` never ran.
  It now propagates the write error (`?`), the same class of fix as the
  iteration-21 read fix. The test's assertions are unchanged; ran it 5x
  alone and once in the full suite.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` passes (139 lib, 20 bin, 28 CLI, 12 daemon, 8 unlock;
  CLI is +1 for the golden help test). `cargo audit` is not installed;
  skipped, not installed.
- **Next iteration must know:** next is **2.6b** (protocol `stdout`/`stderr`/
  `exit` frames). Add new commands as `src/cli/<group>.rs` modules, not by
  growing `mod.rs`; keep each file under ~1,000 lines. `--help` is now a
  tested contract: update `tests/fixtures/help.txt` deliberately in the same
  commit when help text changes. `DECISIONS.md` has the layout decision.

## 2026-11-02 — Create `DECISIONS.md` (TODO H.1)

- New `DECISIONS.md` (~280 lines, 90 bullet entries): one-line standing
  decisions grouped as scope/naming, crypto, vault format and versions, CLI
  conventions, exit codes, daemon/protocol, grants/approval/MCP, dependencies
  and testing conventions.
  `TODO.md` H.1 is checked with a note that the file also covers dependencies
  and `MCP.md`. Cherry-picked from the rolled-back iteration-21 branch and
  re-verified; the only code change is the flaky-test harness fix below.
- Sourced from `PROGRESS.md`, `PROGRESS-archive.md`, `TODO-done.md`, `MCP.md`
  and a read of `src/error.rs`, `src/agent.rs`, `src/crypto.rs`,
  `src/protocol.rs`, `src/socket.rs`, `src/session.rs`, `src/store.rs`,
  `src/vault.rs` and `src/main.rs`, so each line is checked against the code,
  not only against older prose.
- Conventions chosen for the file: one decision per line; "Planned" marks a
  decision from `MCP.md` that the code does not implement yet; the exit-code
  section carries the full 0-6 mapping plus the `Crypto`-stays-1 rationale; an
  explicit "Open questions (not decided)" section keeps undecided behavior out
  of the decision list.
- Corrections made while extracting: the daemon has **no** `ok` response and
  no `not_found`/`spawn_failed` code yet (recorded as `pong`/`locked`/fixed
  error codes, with 2.6b planned); container version and store version are
  separate counters that both have a "version 1" with different meanings, so
  that is now stated in one place.
- Flaky-test fix: iteration 21's gate failed in
  `unauthorized_requests_do_not_refresh_the_idle_timeout` with
  `ConnectionReset` while reading a response, because the daemon can expire
  between accepting a connection and replying. That is expected, but the test
  helper `read_response` panicked instead of returning `Err`, so the loop's
  `_ => break` never ran. Added `try_read_response` (io::Result) and made
  `try_request` propagate the error; the test semantics are unchanged (it
  still requires repeated `unauthorized` replies and a prompt expiry).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` passes (139 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock).
  `cargo audit` is not installed on this machine; skipped, not installed.
- **Next iteration must know:** next is **H.2** (`src/main.rs` -> `src/cli/`,
  no behavior change, `--help` byte-identical). `DECISIONS.md` is the place to
  check a constraint before inventing one; if an iteration changes a decision,
  edit its line there *and* explain why in the new PROGRESS entry.
- **NEEDS HUMAN REVIEW:** `tests/daemon.rs` builds fixture vaults with
  `KdfParams::new(8 * 1024, 1, 1)` (the minimum bound) to keep the suite fast,
  which is arguably "weakening the KDF to speed up tests" even though the
  shipped default is untouched and the file does not test the KDF). Left as
  is; `DECISIONS.md` records the current practice. A human should rule on
  whether fixture-only cheap params are acceptable.
- Minor doc drift found, not fixed here: `--help` in `src/main.rs` states the
  tag rules twice, and README still says insecure vault modes are "warned
  about" while TODO 8.10 will make them a refusal. H.2 (help text is asserted
  byte-identical) must not "fix" the duplicate; do it in a later help/README
  item.

