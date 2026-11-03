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

## 2026-11-02 — loop note: gate failed (iteration 21)

- Commits from this work iteration (TODO H.1) failed the gate and were rolled back.
- The work is kept on branch failed/iter-21-20261102-202146; you may cherry-pick from it and fix it.
- gate: `unauthorized_requests_do_not_refresh_the_idle_timeout --- FAILED`
- gate: `thread 'unauthorized_requests_do_not_refresh_the_idle_timeout' (414411) panicked at tests/daemon.rs:127:36:`
- gate: `test result: FAILED. 11 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.15s`
- gate: `error: test failed, to rerun pass `--test daemon``

## 2026-11-02 — Streaming output redactor (TODO 2.6a)

- New `src/redact.rs`, exported from `src/lib.rs`. No new dependency
  (`zeroize` was already present).
- `Redactor::push(&[u8]) -> Vec<u8>` streams child output. It scans a pending
  buffer and appends safe bytes to the output; on a complete occurrence it
  appends `[REDACTED]`. The longest suffix that is still a proper prefix of the
  value is held back (at most `secret.len() - 1` bytes) until the next push, so
  a value split across two reads is caught. `finish()` flushes a trailing
  partial prefix: a prefix is not the value, and holding it forever would
  truncate legitimate output.
- Matching is greedy left-to-right and operates on bytes, so binary output
  works (no UTF-8 assumption). Overlapping occurrences are consumed in order;
  the replacement marker cannot recreate the value at a boundary because it is
  itself scanned only as normal output.
- Marker: `[REDACTED]` unless that literal contains the value (e.g. the value
  is `[REDACTED]`, `REDACTED`, `D]`, `ACT`). In that case a run of a byte that
  does not occur in the value is used, so the marker cannot contain it and no
  occurrence can span the marker boundary. `finish()` is safe to call once;
  callers must not reuse a redactor afterwards.
- Secret lifetime: the value lives in a private `Vec`, is never exposed via
  `Debug`/`Display` (Debug prints only `secret_len`/`pending_len`), and the
  value plus the pending overlap are zeroized on drop. `discard_prefix` uses
  `copy_within`, then zeroizes the stale duplicate of the retained tail before
  truncating, so no fragment stays in the spare capacity.
- Documented limit (also for `SECURITY.md`, TODO 2.7): redaction protects the
  agent's context from accidental output. It is not a sandbox — the child has
  the value in its environment, so a hostile child can exfiltrate it through
  files, the network, or `/proc/<pid>/environ`. Only an exact contiguous
  occurrence is replaced.
- Tests (12 in `src/redact.rs`): whole/repeated occurrences, a split at every
  byte offset of the input, byte-at-a-time input, arbitrary chunk sizes,
  overlapping values (`aba`/`ababa`, `aa`/`aaaaa`), binary bytes with NUL and
  `0xff`, empty value passthrough, `finish` flushing a trailing prefix and
  releasing a disproved one, pending bound strictly below the value length,
  fallback marker for values that are substrings of `[REDACTED]`, and redacted
  `Debug` both fresh and half-consumed.
- Gate: `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes (139 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock);
  `cargo audit` is not installed on this machine.
- Next: 2.6b adds `stdout`/`stderr`/`exit` frames to the protocol; 2.6c wires
  `Redactor` into the daemon's `run` handler; 2.6d adds the CLI reader. Audit
  log assertions for `run` stay in 3.3.

## 2026-11-02 — Session token for the unlock daemon (TODO 2.5)

- New `src/token.rs` (`SessionToken`): 32 OS-random bytes from `getrandom`,
  rendered as 64 lowercase hex characters on the wire and in the session file.
  Bytes live in `Zeroizing`, `Debug` is `SessionToken(<redacted>)`, there is no
  `Display` and deliberately no `PartialEq` (`matches()` uses a branch-free-ish
  XOR loop), so accidental comparison or printing is hard.
- New `src/session.rs` (Unix): `store`, `load`, `remove`, `remove_if_matches`
  for `$XDG_RUNTIME_DIR/passmgr/session`. `store` goes through `ensure_dir`
  (0700, owner-only) and writes a `tempfile` in that directory with mode 0600,
  `fsync`s, renames and `fsync`s the directory. `load` is strict: regular file,
  owned by the current uid, mode **exactly** 0600, opened `O_NOFOLLOW`, bounded
  read (512 bytes); anything else is an error, never "repaired". This turns a
  planted symlink or loosened mode into a visible failure.
- Handover: `pmd` now reads `key(32) || token(32)` from the inherited stdin pipe
  (`daemon::read_handover`, exactly 64 bytes then EOF; wrong length or trailing
  data refuses to start). Neither value appears in argv or the environment.
- Protocol version 2: the envelope is
  `{"version":2,"token":"<64 hex>","request":{...}}`; the token is required on
  every request type and parsed *before* the request, so an unauthenticated
  peer cannot reach request parsing. Malformed/missing token → `bad_request`
  (no echo); well-formed but wrong token → new `unauthorized` response code.
  `protocol::decode` returns `AuthenticatedRequest` (redacted `Debug`).
- Daemon: `run(vault, runtime_dir, key, token, idle)` compares
  `authenticated.token().matches(token)` first and answers `unauthorized` with
  `Handled::Rejected`, which does **not** refresh the idle timer — a client
  with the wrong token cannot keep the key in memory. On any exit path
  (`lock`, signal, idle) the daemon removes the session file only if it still
  contains its own token (`remove_if_matches`), so it cannot delete a newer
  session's token after a fast re-unlock.
- Client/CLI: `client::request/ping` take a token, `lock` loads it from the
  session file and removes it after `Locked`. `unlock` clears a stale file,
  generates and stores the token *before* spawning `pmd`, passes it through the
  pipe, and removes the file again if the spawn fails. If the session file is
  missing, `lock` still probes the socket first so "no daemon is running" is
  reported precisely instead of blaming authentication.
- Wire compatibility: protocol version 1 frames are now rejected. This is
  local IPC between `passmgr` and its own `pmd`, both from this build, so no
  migration path is needed; the version field is what makes the mismatch
  explicit rather than a confusing parse error.
- Known limit (recorded in `src/token.rs`/`src/daemon.rs` docs): the token is
  **not** an agent/human boundary. Any same-user process can read a 0600 file,
  so it proves only what the socket's peer-uid check already proves. It stops
  an accidental or stale client and makes an unauthorized request explicit;
  scoped, revocable authorization arrives with grants (TODO 3.1).
- Tests (all passing): 10 new lib tests — token hex round-trip, strict
  lowercase-hex rejection, length check, redacted `Debug`; session store/load
  0600 with no leftover temp file, refusal of 0644/symlink/directory/missing,
  scoped removal, insecure runtime dir. Protocol: envelope now carries exactly
  `["request","token","version"]`; missing/wrong-type/non-64-lowercase-hex
  tokens rejected on ping/lock without echoing the token; decoded token matches
  what was encoded; `Debug` of `AuthenticatedRequest` hides it; exact-frame
  assertions updated to version 2. Daemon e2e: wrong token gets `unauthorized`
  and cannot `lock` the daemon; token absent from socket bytes, `/proc/cmdline`
  and daemon stdout/stderr; unauthorized pings every 200 ms for 4 s do not
  refresh a 2 s idle timeout; a malformed token frame is `bad_request`. CLI e2e:
  session file is 0600, its token appears in no output, a 0644 session file is
  refused (daemon untouched) and works again after `chmod 600`, and both `lock`
  and an idle timeout remove the session file.
- Gate: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes: 127 lib, 20 bin, 27 CLI, 12 daemon, 8 unlock.
  `cargo audit` is not installed on this machine.

## 2026-11-02 — Idle timeout for the unlock daemon (TODO 2.4c)

- `src/daemon.rs`: new `DEFAULT_IDLE_TIMEOUT = 15 * 60` s, shared
  `parse_idle_timeout(&str)` (whole seconds, zero refused, no upper bound) and
  `run(vault, runtime_dir, key, idle_timeout)`. The accept loop checks
  `last_activity.elapsed() >= idle_timeout` at the top of every iteration
  (200 ms poll, so it stops within ~200 ms of the deadline unless a client is
  mid-request; a stalled request can delay it by at most the 5 s read
  timeout). Exiting drops `LockedKey` (zeroize + `munlock`) and then
  `DaemonSocket` (unlink + instance-lock release), and exits 0, exactly like
  `lock`/SIGTERM.
- Activity is defined as a **successfully decoded request after the peer
  check**, not raw bytes or connections. `handle_connection` now returns
  `Handled::{Served, Rejected, Locked}`: `Ping`/`Run` (well-formed) refresh the
  timer, a parse failure answers `bad_request` without refreshing, and `Lock`
  stops the daemon. This stops garbage traffic from keeping the key alive.
- Config surface: `pmd --idle-timeout SECS` (help updated) and
  `passmgr unlock --idle-timeout SECS` / `--idle-timeout=SECS`, parsed by the
  shared `parse_idle_timeout` and passed through `client::spawn_daemon(...)`
  as an extra argument. `None` means the default, applied in `command_unlock`.
  Unlock's stdout now reports the effective timeout as a `Duration` (`900s`).
  `Command::Unlock` carries `idle_timeout: Option<Duration>`; non-Unix builds
  keep a stub parser that accepts a bare `unlock` and refuses the flag.
- Security note recorded in the `daemon.rs` module docs: the idle timeout is a
  second line of defense, **not** an authorization boundary. Until the session
  token (2.5) and grants (3.1) land, any same-user process can send `ping` and
  keep the daemon alive. It still guarantees that an untouched session does
  not hold the key forever.
- Tests: 1 new lib test (`parse_idle_timeout` accepts positive whole seconds,
  default is 900 s, rejects `0`/empty/negative/fraction/unit/whitespace), 1 new
  CLI parse test (default `None`, both flag forms, zero/word/missing value
  rejected), 3 new `tests/daemon.rs` e2e tests (short timeout exits and removes
  the socket; pings every 250 ms for 4 s keep it alive past a 2 s timeout, then
  it expires; rejected frames every 200 ms for up to 4 s do not refresh, with
  an elapsed-time bound so a refresh bug fails), and 1 new `tests/unlock.rs` pty
  test proving `unlock --idle-timeout 1` reaches the daemon (prints `after 1s`,
  process disappears and socket is removed without `lock`).
- Gate: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` passes: 112 lib, 20 bin, 27 CLI, 9 daemon, 7 unlock. The
  CLI suite is Argon2-bound (~150 s). `cargo audit` is still not installed
  here (`no such command: audit`); run it where available.
- No new dependency, no crypto/vault-format change, no protocol change.
- Next: **2.5 session token file** — write a random token to
  `$XDG_RUNTIME_DIR/passmgr/session` (0600) at unlock, have requests carry it,
  reject mismatches. Keep the token out of argv, the environment and all
  output. Do not weaken the peer-uid check and do not add a plaintext request.

## 2026-11-02 — `pm unlock` / `pm lock` CLI (TODO 2.4b)

- New `src/client.rs` (`#[cfg(unix)]`): the client half of the daemon protocol
  — `ping`, `lock`, `spawn_daemon` and a generic `request`. Frame writes and
  reads are bounded (`MAX_MESSAGE_BYTES` + prefix + 1 byte via `take`), every
  connection has a 5 s timeout, and readiness polling is bounded at 10 s.
  `spawn_daemon` finds `pmd` next to the current executable, passes `--vault`
  and `--runtime-dir` (never the key), writes exactly the 32-byte key into
  `pmd`'s stdin and then closes it. Its stderr goes to an anonymous,
  immediately unlinked `tempfile` (0600): the daemon must not inherit the
  caller's stderr pipe, or `Command::output()` would block forever once the
  caller exits and later daemon writes would hit `EPIPE`. Startup failures
  report the exit status plus a bounded (8 KiB) excerpt of that log.
  After a successful ping the child is re-checked after one poll interval, so
  a pre-existing daemon answering the ping cannot mask our child dying on the
  instance lock.
- `pm unlock`: refuses in agent context with exit 5 **before** prompting (new
  `agent::check_human`, shared with `get --reveal`; the message is produced by
  `RevealRefusal::message_for(action)` so both call sites read naturally).
  Then: pre-check the socket (a live daemon means "run 'passmgr lock' first",
  exit 1), read the vault container, prompt once, derive + **authenticate**
  the key with `crypto::unlock_key`, drop the password and the container, then
  hand the key to `pmd`. A wrong password exits with the existing wrong
  password code and starts nothing. Prints the pid and a hint to stdout.
- `pm lock`: needs no TTY (it can only stop the daemon, never reveal
  anything), sends `lock`, and reports that the key was wiped. Without a
  daemon it exits 1 with the existing `SocketError::NotRunning` message.
- Both commands are Unix-only, with non-Unix stubs, matching `pmd`.
  `parse_command` rejects extra arguments; `--help` documents both.
- Fixed an intermittent, real single-instance race found while stress-running
  the new tests: `acquire_lock` could see `EWOULDBLOCK` for a few
  milliseconds after the previous holder's `DaemonSocket` was dropped on
  another thread (the final `fput` of a descriptor closed by a non-owning
  thread is deferred to that thread's task work). The instance lock now
  retries every 5 ms for up to 250 ms before reporting
  `SocketError::AlreadyRunning`. The lock is still exclusive — a live daemon
  holds it for its whole lifetime — so this only stops a just-exiting daemon
  from being reported as running, which would otherwise also hit `unlock`
  immediately after `lock`. Two tests pin it down: a live holder is still
  rejected, and a holder that releases within the grace window is acquired.
- Tests: 6 new lib tests in `src/client.rs` (round-trip, error passthrough,
  clear missing-daemon error, non-JSON/empty/oversized-prefix responses
  rejected without a panic, short key refused before spawning, startup
  failure reports status and log), 1 new `src/socket.rs` test, and
  `tests/unlock.rs` (6 e2e tests, Linux pty where a TTY is required): non-TTY
  refusal (exit 5, no prompt), agent-marker refusal on a pty, unlock → ping →
  lock round-trip with the secret absent from all output and from
  `pmd`'s argv and `/proc/<pid>/environ`, duplicate unlock refused without a
  prompt, wrong password exits 4 and starts no daemon, `lock` without a
  daemon. The e2e test writes the password to the pty before the child
  disables echo, so the pty echo can contain the password; that is a harness
  artifact, not a product leak (nothing else ever writes it).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` pass (111 lib, 19 bin, 27 CLI, 6 daemon, 6 unlock; the CLI
  suite is Argon2-bound, ~150 s). `cargo audit` is not installed here; run it
  where available.
- Decisions recorded: `Error::Daemon(String)` (exit 1) carries only daemon
  transport failures; unlock deliberately does **not** re-prompt when a
  daemon is already running (it tells the human to lock first) so a second
  unlock can never silently replace a running daemon's key.
- Next: 2.4c idle timeout, then 2.5 session token (the socket is currently
  authorized by peer uid only, so any same-user process may `ping`/`lock` —
  acceptable for now: no request returns plaintext and `lock` is a DoS at
  worst).

## 2026-11-02 — Unlock daemon core and `pmd` (TODO 2.4a)

- Split the original 2.4 into **2.4a** (this entry), **2.4b** (`pm unlock` /
  `pm lock` CLI) and **2.4c** (idle timeout), so each stays one iteration.
- New `src/daemon.rs` (`#[cfg(unix)]`, registered in `src/lib.rs`) and
  `src/bin/pmd.rs`. The daemon holds **only the derived 32-byte key**, never
  the decrypted vault: `Vault::open_with_key` decrypts on demand when `run`
  lands (2.6) and the plaintext is dropped immediately. Decided against
  keeping a decrypted `Vault` in memory for the daemon's whole lifetime.
- Key handover: `pmd` reads exactly `KEY_LEN` bytes from stdin (the inherited
  pipe from `unlock`, 2.4b) and then requires EOF; short, long or trailing data
  is refused. The key is never in argv or the environment. `LockedKey` keeps
  it in a stable `Zeroizing<Vec<u8>>`, `mlock`s it best-effort, and `munlock`s
  before zeroizing on drop. `Debug` prints only `mlock` state, no bytes.
- Hardening: `RLIMIT_CORE` 0 (fail closed) and Linux
  `prctl(PR_SET_DUMPABLE, 0)` (fail closed); `setsid()` best effort. On macOS
  there is no `prctl`, so core dumps are disabled but same-user `ptrace`
  exposure remains — TODO 2.7 must record that limit in `SECURITY.md`.
- Startup order: harden -> install SIGTERM/SIGINT handlers -> `setsid` ->
  verify the key against the vault -> bind the socket. A wrong key therefore
  never creates a socket or makes `pmd` look alive. The `DaemonSocket` is held
  for the whole loop (instance `flock` stays held) and dropped on lock/signal,
  removing the socket.
- Loop: non-blocking `accept_peer()` with a 200 ms sleep, so
  `SIGTERM`/`SIGINT` (handler only stores an `AtomicBool`) exits/wipes within
  ~200 ms. One request per connection, 5 s read/write timeout. `ping` ->
  `pong`; `lock` -> `locked` then wipe/exit; `run` -> `unsupported` (2.6);
  malformed, truncated, oversized, empty and unknown-type frames ->
  `bad_request`. `PeerRejected`/`PeerCheckFailed` are ignored and the owner
  keeps being served. No request can return a secret value.
- Protocol: added `Response { Pong, Locked, Error(ResponseError) }`,
  `ResponseError { BadRequest, Unsupported }` with stable codes
  `bad_request` / `unsupported`, `encode_response` / `decode_response`, and
  `ProtocolError::UnknownResponse`. The response schema is fixed and has no
  value field. Unknown response types/codes are rejected; echoed type names
  are truncated to 32 chars.
- Crypto reuse for the handover: split `decrypt` into
  `derive_vault_key(container, password, out)` and
  `decrypt_with_key(container, key)`, with `unlock_key(...)` deriving and
  authenticating in one step. `Vault::open_with_key` added. No parameter,
  format or ciphertext change: existing vaults still open unchanged.
- Tests: 11 new crypto/vault/protocol unit tests (key derive/decrypt split,
  wrong key, length checks, no key echo, response round-trip/fixed shape,
  unknown type/code, malformed frames, arbitrary bytes) and 5 `daemon.rs` unit
  tests (short/trailing key, length check, no bytes in `Debug`, no echo).
  New `tests/daemon.rs` (6 e2e tests, fast Argon2 params): ping/lock removes
  the socket and exits 0; SIGTERM and SIGINT exit cleanly and remove it;
  empty/oversized/truncated/unknown/`run` requests rejected without a crash
  and the daemon still serves; wrong key exits non-zero with no socket; a
  second daemon is refused while the first keeps serving; the generated
  secret appears in no response bytes, stdout/stderr, cmdline, or readable
  `/proc/<pid>/environ` (dumpable=0 usually makes the last unreadable).
- No new dependency (`libc` and `zeroize` already present). No network, store
  or audit-log change.
- Gate: `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings`
  clean; `cargo test` 156 passed (104 lib, 19 bin, 27 e2e CLI, 6 daemon e2e;
  CLI e2e is Argon2id-bound and serialized, ~148 s). `cargo audit` still not
  installed (`error: no such command: audit`).
- **Next iteration must know:** next is **2.4b** (`unlock`/`lock` CLI). Spawn
  `pmd` with the key on a pipe, wait for a `ping`/`pong` readiness check, and
  refuse `unlock` unless stdin and stdout are TTYs and no agent marker is set.
  Do not add any request that returns plaintext. Idle timeout is still absent
  (2.4c), so a daemon stays unlocked until `lock` or a signal. `mlock` failure
  is intentionally non-fatal and currently silent; if that matters, surface a
  warning without key material.

## 2026-11-02 — Peer credential check (TODO 2.3)

- `src/socket.rs` now verifies the connecting user before any request byte is
  read. New `PeerCredentials { uid, gid, pid: Option<i32> }` plus
  `peer_credentials(&UnixStream)` and `PeerCredentials::verify(expected_uid)`.
  Linux/Android read `getsockopt(SO_PEERCRED)` into `libc::ucred`; macOS/iOS
  call `libc::getpeereid` (no pid available, so `pid()` is `None` there). Both
  syscalls are validated: non-zero return is an error and Linux also requires
  the kernel to report exactly `size_of::<ucred>()` bytes. Any other Unix
  target returns `SocketError::PeerCheckUnsupported` and the daemon fails
  closed — no unchecked accept path exists on an unsupported platform.
- `DaemonSocket::accept_peer()` is the intended accept path. It calls
  `listener.accept()`, reads the peer credentials, compares the uid with
  `geteuid()`, and only then returns `(UnixStream, PeerCredentials)`. On
  mismatch the stream is dropped immediately (no reply, nothing read) and
  `SocketError::PeerRejected { expected, actual }` is returned. Documented in
  the module header that 2.4 must use `accept_peer()`, not `listener()`; the
  latter is kept public only for tests/explicitly validated callers.
- The check is **not** an authorization boundary on its own: any process
  running as the same user passes it. It separates users; the session token
  (2.5) and grants (3.1) separate agents from their owner. That limit is
  written in the module docs so it is not mistaken for more. PID is reported
  but never used for authorization (pids are reused).
- Error variants added: `PeerRejected`, `PeerCheckFailed(io::Error)`,
  `PeerCheckUnsupported`; all have `Display` text with uids only, and
  `source()` exposes the syscall error. `SocketError` remains module-local and
  is not wired into the CLI exit-code contract (2.4 decides the mapping).
- Tests: 3 new lib tests. `peer_credentials_report_the_current_user` (uid/gid
  match, Linux pid is our pid, macOS pid is `None`, free function and accept
  helper agree, a second connection still accepts);
  `accept_peer_rejects_a_foreign_uid_and_closes_the_connection` (client writes
  a request-shaped message, accept is forced to expect `uid+1`, gets
  `PeerRejected` with both uids, and the client reads EOF/reset with no
  reply); `verify_rejects_a_different_uid_with_a_clear_message` (unit-level
  forced-failure check plus message contents). No second user account needed.
- No new dependency (`libc` already present). No store, protocol, CLI or
  crypto change. The socket/lock/dir behavior from 2.2 is untouched.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 134 passed (88 lib + 19 bin + 27 e2e, ~150 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next is **2.4** (`pm unlock` / `pm lock`, idle
  timeout, SIGTERM/SIGINT wipe, `mlock`, `prctl(PR_SET_DUMPABLE, 0)`). Wire the
  accept loop to `DaemonSocket::accept_peer()` and keep the `DaemonSocket` (and
  therefore the `flock`) alive for the daemon's whole lifetime. There is still
  no request type that returns plaintext. Until 2.5 lands, authorize only the
  local session written at unlock; do not add a bypass. On Linux, remember
  that a rejected peer's socket is dropped without a response — do not turn
  `PeerRejected` into a wire error message.

## 2026-11-02 — Socket setup module (TODO 2.2)

- New `src/socket.rs` (registered in `src/lib.rs` as `#[cfg(unix)] pub mod
  socket;`). No daemon binary yet; this is the socket-placement layer that
  TODO 2.4 will bind. No CLI surface change.
- Paths: `RuntimePaths::resolve()` -> `$XDG_RUNTIME_DIR/passmgr` when that
  variable is set and non-empty, else `<temp_dir>/passmgr-<euid>` (macOS has
  no `XDG_RUNTIME_DIR`; `env::temp_dir()` is the per-user `$TMPDIR` there).
  The uid suffix keeps two users sharing a temp dir from colliding, and the
  directory checks below fail closed on anything pre-created by someone else.
  Files inside: `pmd.sock` and `pmd.lock`.
- `RuntimePaths::ensure_dir`: `create_dir` + `set_permissions(0700)` when it
  does not exist; when it does, `symlink_metadata` (never follows a symlink)
  must show a real directory, owned by `geteuid()`, mode exactly 0700.
  Otherwise `SocketError::InsecurePath` and no socket is created. Chose
  **refuse, not repair**, for an existing directory: a 0755 dir may already
  have been observed, so silently fixing it would hide a real exposure.
  Parents are never created (`create_dir`, not `create_dir_all`): a missing
  `XDG_RUNTIME_DIR` is a broken environment, not something to paper over.
- Single instance: `flock(LOCK_EX|LOCK_NB)` on `pmd.lock` (0600, created via
  `OpenOptionsExt::mode`, then `set_permissions` to narrow an old file).
  `EWOULDBLOCK` -> `AlreadyRunning`. The lock file is deliberately **not**
  unlinked on drop (unlinking while holding it lets a second daemon lock a
  fresh inode); the socket is unlinked on drop only if its inode still matches
  the one recorded at bind time.
- Ordering in `DaemonSocket::bind_at`: length-check the path (<= 104 bytes,
  the macOS `sun_path` limit, so a path that works on Linux also works there),
  validate/create the dir, take the lock, then probe the socket, then bind,
  then chmod 0600. Locking before probing means two simultaneous starts cannot
  both conclude "stale".
- Stale-socket rule: `symlink_metadata`; symlink or non-socket -> `NotASocket`
  and the file is left untouched; foreign uid -> refused; then a probe
  `UnixStream::connect`: success -> `AlreadyRunning` (never steal a live
  socket, even if the lock file was deleted), `ECONNREFUSED` -> unlink and
  rebind, `NotFound` -> race, fine. The probe connection is closed immediately;
  2.4's accept loop must tolerate a peer that connects and disconnects.
- The socket is chmodded 0600 *after* bind because bind applies the umask.
  Documented in the module: the 0700 directory already keeps other users out,
  so the window is not externally reachable; the chmod is defence in depth.
- `connect()` / `connect_at()` map `NotFound` and `ConnectionRefused` to
  `SocketError::NotRunning` so 2.6 can tell the user to run `pm unlock`.
  `SocketError` is a module-local enum (like `ProtocolError`) with `Display`
  and `std::error::Error`, not wired into the CLI exit-code contract yet; 2.4
  decides the mapping. No secret values exist anywhere in this module.
- Tests: 15 lib tests in `src/socket.rs` — XDG vs fallback resolution (empty
  XDG treated as unset), dir/socket/lock modes 0700/0600/0600 plus a real
  client-listener byte round-trip, reuse of an existing 0700 dir, second daemon
  rejected while the first keeps working, stale socket replaced, live socket
  without a lock not stolen (original listener still accepts), regular file at
  the socket path preserved, symlinked dir refused, 0750 dir refused with the
  mode named in the error, overlong path rejected before any I/O (no directory
  created), drop removes the socket but keeps the lock and releases it, connect
  with no daemon and with a stale socket both report `NotRunning`, `flock`
  conflict/release on the same path.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 131 passed (85 lib + 19 bin + 27 e2e, ~150 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`). No new dependency (`libc`, `tempfile`
  already present).
- **Next iteration must know:** next is **2.3** (peer credential check:
  `SO_PEERCRED` on Linux via `getsockopt`, `getpeereid` on macOS, before any
  read). Add it to `src/socket.rs` or a small `src/peer.rs`; the accepted
  stream from `DaemonSocket::listener()` is where to call it. Do not add a
  request type that returns plaintext. 2.4 will own signal handling, idle
  timeout and key zeroization; the `flock` guard must stay alive for the whole
  daemon lifetime (keep the `DaemonSocket` in scope).

## 2026-11-02 — Protocol framing module (TODO 2.1)

- New `src/protocol.rs` (registered in `src/lib.rs`): pure, no-I/O wire
  protocol for the future daemon. Frame = 4-byte big-endian length + JSON body.
  Envelope = `{"version":1,"request":{"type":...}}`. `encode(&Request)` and
  `decode(&[u8])` handle exactly one frame; `FrameDecoder` is the incremental
  read-loop state machine (`push`, `next_frame`, `next_request`, `buffered`).
- Request types: `ping`, `lock`, `run { env, ref, command }`. **There is no
  plaintext request type**, and `src/protocol.rs` documents why (any same-user
  process can reach the socket, so the daemon must never return a value). The
  test `requests_have_no_plaintext_field` pins the exact wire keys:
  `ping`/`lock` have only `type`; `run` has `type`, `env`, `ref`, `command`.
  `reveal`/`get`/`password`/`export` are rejected as unknown types.
- Limits: `MAX_MESSAGE_BYTES = 64 KiB` body cap, `MAX_BUFFERED_BYTES` = two
  max frames for the decoder, `MAX_ENV_NAME_BYTES = 128`,
  `MAX_REFERENCE_BYTES = 128`, `MAX_ARG_BYTES = 4096`, `MAX_ARGS = 256`.
  The declared length is validated **before** any slice/allocation is made
  from it (`check_length`), so a prefix of `u32::MAX` is rejected immediately;
  `FrameDecoder::push` rejects it as soon as the 4-byte prefix arrives, without
  waiting for the body. Zero-length bodies are `EmptyMessage`; a frame with
  bytes after it is `TrailingBytes` (one call decodes one frame).
- Decisions: unknown envelope **fields** are ignored (so 2.5 can add a session
  token and 3.x a grant without breaking peers); unknown envelope **versions**
  and unknown request **types** are hard errors. `run.ref` is validated with
  the canonical `store::EntryId::parse_ref` (reuse, no duplicated syntax); the
  daemon still must check existence and scope. `run.env` must be
  `[A-Za-z_][A-Za-z0-9_]*`. All validation runs on encode *and* decode, so a
  locally built request cannot bypass the contract. Errors carry lengths and a
  truncated (32-char) request type only — never field values (test
  `errors_do_not_echo_request_field_values`).
- `ProtocolError` is a separate enum with `Display` + `std::error::Error`; it
  deliberately does **not** reuse the CLI `Error`/exit-code contract, because
  these are daemon-internal failures. No new dependency (`serde_json` was
  already present). No store/crypto change.
- Tests: 16 new lib tests — round-trip of all three requests, exact framing
  bytes, truncated prefix/body, oversized declared length on `decode` and
  `FrameDecoder`, empty body, trailing bytes, oversized encode (20×4 KiB
  args), versions 0/2/99/u64::MAX, missing/mistyped envelope fields, unknown
  types incl. a 10 000-char type truncated in the error, wire-key pinning,
  all `run` field bounds, fragmented byte-at-a-time decoding, two frames in
  one push, buffer flood, and a deterministic xorshift smoke test over ~3 000
  random buffers (no panics).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 116 passed (70 lib + 19 bin + 27 e2e, ~149 s; e2e is
  Argon2id-bound and serialized). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next is **2.2** (socket setup in
  `$XDG_RUNTIME_DIR/passmgr/`, dir 0700, socket 0600, stale-socket detection,
  single-instance lock). Use `FrameDecoder` for reads and `encode` for writes;
  do not add a request type that returns plaintext. `run.command` is an argv
  vector (no shell); 2.6 must spawn it directly.

