## 2026-11-03 — Escape argv-supplied `--out` paths before echoing them (TODO R.29)

- `src/cli/grant.rs`: new private `display_path(&Path) -> String` renders a path
  through `grant::escape_hidden` (after `to_string_lossy`, so a non-UTF-8 path
  still renders) instead of `Path::display`. Both places that echo `--out` use
  it: the success line, now factored into `grant_created_message(label, out)`
  so a unit test can reach it, and the existing-token-file error inside
  `TokenFile::create`. The label is escaped the same way (its validation
  already refuses hidden characters, so this only guards a future loosening).
- Chose a pure formatting helper over a PTY test because the escaping problem
  is in string construction, not terminal state; the path is the only argv
  value echoed outside the approval summary, which already escaped its text.
- Test: `a_token_path_with_hidden_characters_is_rendered_as_text` builds an
  OSC 52 payload (`\u{1b}]52;c;...`) and a BEL on the success line and an
  ESC/CR file name for the existing-file error, asserting the `\u{..}` text is
  present, no raw ESC/BEL/CR is, and the existing file is untouched. It fails
  (raw escape in the message) when `display_path` is swapped back to
  `path.display()`.
- Docs: `DECISIONS.md` says argv-supplied paths are escaped wherever they are
  echoed; TODO R.29 is checked off with a Done note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.29 was the last Phase R item, so the next
  `- [ ]` item is TODO 3.6 (daemon authorizes `run` by grant). `src/cli/
  grant.rs` is at 971 lines — the next addition there should move the
  summary/rendering helpers into `src/cli/grant/summary.rs` first. Any other
  argv path echoed to a human (e.g. future `--file`/`--out` flags) needs the
  same `display_path` treatment; there is no shared module for it yet.

## 2026-11-03 — `revoke --all` touches only active grants (TODO R.28)

- One predicate now decides "active": `GrantStatus` (`Active`, `Expired`,
  `Exhausted`, `Revoked`) and `Grant::status(now)` live in `src/grant.rs`.
  `Grant::is_active(now)` and the private `check_active` both go through it,
  so authorization, `grant list`/`show` and `revoke --all` cannot disagree.
  `GrantStatus::name()` owns the words "active"/"expired"/"exhausted"/
  "revoked"; the CLI's duplicate `grant_status` helper is gone.
- `revoke_grants` (`src/daemon.rs`) filters `grant.is_active(now)` instead of
  `!grant.is_revoked()`. `--all` therefore leaves expired and exhausted grants
  untouched and reports only the grants it actually revoked. Matching the docs
  was chosen over redefining "active" to mean "not revoked": a human needs the
  count to mean "grants that were in force".
- Docs: `DECISIONS.md` and the `grant_revoke` section of `MCP.md` now state
  that expired, exhausted and already-revoked grants are untouched and never
  counted; `src/cli/help.rs` already said "every active grant" and is now true.
- Test: `src/daemon/tests.rs::revoke_all_leaves_expired_and_exhausted_grants_alone`
  builds one active, one expired and one exhausted grant in a real vault with
  an explicit `now`, calls `revoke_grants(..., All, now)`, and asserts the
  count is 1, the active grant is `Revoked` with `revoked_at == Some(now)`, and
  the others keep their `Expired`/`Exhausted` status and `revoked_at == None`.
  It fails against the previous filter (count 3, all revoked).
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.29 (`--out` escaping, `src/cli/grant.rs`) is
  the next Phase R item. `src/grant.rs` is at ~981 lines; adding another
  model concern should split its tests into `src/grant/tests.rs` first. The
  CLI's `grant list`/`show` output text is unchanged by this item.
## 2026-11-03 — Do not panic when `revoke --all` gets `not_found` (TODO R.27)

- `src/cli/grant.rs` (`command_grant_revoke`): the
  `Response::Error(ResponseError::NotFound)` arm now matches `options.id`
  instead of calling `.expect("not_found implies an id")`. `Some(id)` still
  gives `Error::GrantNotFound(id)` (exit 3); `None`, which only `--all`
  produces, gives `Error::Daemon("the unlock daemon refused the revocation
  (not_found)")` (exit 1). Any same-user process can replace the socket, so a
  hostile or buggy peer must never turn into a panic and a backtrace.
- No behavior change for a real daemon: `revoke_grants` (`src/daemon.rs`)
  answers `not_found` only for an id, so `--all` keeps its current success
  paths.
- Test: `tests/grant_manage_cli.rs::
  grant_revoke_all_reports_a_not_found_answer_without_panicking` binds a stub
  `UnixListener`, decodes the frame and asserts it is
  `GrantRevokeRequest::All`, answers the encoded `not_found` error, then
  requires exit 1, the clean message, no `panicked at`, no
  `not_found implies an id`, and an untouched vault. Verified it fails
  (exit 101, the panic text) against the previous code.
- Docs: `DECISIONS.md` records the `--all` + `not_found` mapping; TODO R.27 is
  checked off with a Done note.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  the full `cargo test` pass. `cargo audit` is not installed; skipped as
  instructed.
- **Next iteration must know:** R.28 (the "active" wording of `--all`) and
  R.29 (`--out` escaping) are the next Phase R items and touch the same file;
  neither was changed here. `tests/grant_manage_cli.rs` is now ~420 lines and
  has the stub-socket pattern this test needs if R.28/R.29 want one.

## 2026-11-03 — Show and confirm a grant before creating it (TODO R.26)

- `pm grant create` now builds the `GrantRequest` first and prints it to
  stderr before anything else: label, scope, canonical commands,
  capabilities, expiry and use limit, plus one warning per allowed program
  runner. The human must answer `y`/`yes`; anything else exits 2 with
  "cancelled; nothing was written". The confirmation sits before
  `load_session`, `TokenFile::create`, the master-password prompt and the
  daemon, so a `n` leaves no file, no socket traffic and no spent approval.
- `terminal::prompt_yes_no`/`is_yes` are the new prompt: only an explicit yes
  (case-insensitive, trimmed) approves; a blank line, another word or EOF is
  no.
- `grant::escape_hidden` (new, display form) escapes only hidden characters,
  so `Bob's token` keeps its apostrophe; the quoted error form that also
  escapes `\` and `'` is now the private `escape_quoted`. The summary and
  warning carry metadata only; no credential value exists at that point.
- The runner warning is bold red only when stderr is a TTY, so piped or
  captured output gains no escape sequences. A command path with a hidden
  character is still refused by `resolve_commands` before the summary, and
  the error names it as text (`\u{1b}`), never as bytes.
- Tests: two new PTY tests — cancelling keeps vault, token file and daemon
  untouched; a hidden-character command is refused before the summary — plus
  ordering/content assertions in the existing create and `--allow-interpreter`
  tests. Unit tests cover `is_yes`, warning colouring, summary contents and
  display escaping.
- `tests/grant_cli.rs` grew past 1,000 lines, so its fixture moved to
  `tests/grant_support/mod.rs` and the list/show/revoke tests to
  `tests/grant_manage_cli.rs`; no test content changed.
- Docs: README, `--help`/`tests/fixtures/help.txt`, the `MCP.md` runner bullet
  and `DECISIONS.md` now describe the summary and the confirmation order.
- Gate: `cargo fmt --check`, `clippy -D warnings` and the full `cargo test`
  pass. `cargo audit` is not installed; skipped as instructed.
- **Next iteration must know:** approving still only proves presence, not
  comprehension — the human must read the summary, and the digest binds the
  same request. The `--out` path is deliberately not in the summary; R.29
  still has to escape it in the success line and the overwrite error. Because
  the summary comes before `load_session`, approving with no daemon running
  shows "no passmgr daemon is running" (exit 1) after the yes; that ordering
  is what makes `n` provably socket-free.

## 2026-11-03 — Refuse program runners, not just interpreters (TODO R.25)

- `grant/validate.rs`: `INTERPRETERS`/`VERSIONED_INTERPRETERS` became
  `PROGRAM_RUNNERS`/`VERSIONED_PROGRAM_RUNNERS` and `is_interpreter` became
  `is_program_runner`. The table now covers what a grant's `argv[0]`-only
  binding makes dangerous: shells, launchers (`env`, `xargs`, `sudo`,
  `timeout`, `tmux`, `strace`, …), editors/pagers/man, tools with an exec
  option (`find`, `sed`, `tar`, `ssh`, `scp`, `nc`, …), alias/plugin CLIs
  (`git`, `gh`, `docker`, `podman`, `kubectl`, `helm`, `terraform`, `ansible`,
  …), build runners (`make`, `cargo`, `npm`, `go`, `mvn`, `bazel`, …) and DB
  clients (`psql`, `mysql`, `sqlite3`). `gh`/`git` are no longer treated as
  safe; matching is still file-name based with the same versioned-suffix rule.
- Chose the broad table over a per-command confirmation: a grant has nowhere
  to record per-command trust, and confirming every command would turn every
  grant into a wall of y/N prompts. The table is documented as best-effort,
  not a boundary — allowing any program is trusting it with the value.
- Docs: README's grant example now passes `--allow-interpreter` (with an
  explanation that `gh` itself is a runner), `--help` (and the byte-exact
  `tests/fixtures/help.txt`) describe the flag and the example the same way,
  `SECURITY.md` limit 2 is rewritten around `argv[0]`, `MCP.md` and
  `DECISIONS.md` name runners and the residual trust.
- Tests: unit table of every documented runner name plus lookalikes
  (`pythonista`, `shadow`, `envoy`, `tar.gz`); e2e with a fake executable
  named `gh` proving exit 5, no master-password prompt, no daemon session and
  no token file, and that `--allow-interpreter` stores the canonical path and
  prints neither token nor secret; docs contracts pin the prose and the
  README example.
- Gate: fmt, clippy -D warnings, full `cargo test` (including the Argon2 CLI
  suite) pass. `cargo audit` not installed, skipped as instructed.
- **Next iteration must know:** the refusal is CLI-only and the grant stores
  no "runner allowed" bit, so `grant show` cannot reveal that a human opted
  into a runner — worth a small follow-up if the approval UX (R.26) starts
  rendering one. `psql`/`mysql`/`sqlite3` are now runners, which matters for
  the Phase 7 presets. Versioned names are matched only for the versioned
  bases (`git-lfs`, `ssh-keygen`, `bash-completion` are plain exact names and
  not matched); that is the accepted best-effort gap.

## 2026-11-03 — Review of 4662526..4a16226

- 5 findings: 2 authorization (R.25, R.26; R.25 also exposes injected
  secrets), 2 unsafe input/output (R.27, R.29), 1 drift/test gap (R.28); 0
  direct secret-printing bugs, 0 crypto, 0 maintainability. Added R.25–R.29 to
  `TODO.md`.
- R.25 (high, authorization/secret exposure): the interpreter denylist omits
  `gh` and `git`. A grant for the README's `/usr/bin/gh` example can run
  `gh alias set --shell`, and `git -c alias...` runs a shell (both verified
  locally with `id -u` output `1000`), so an agent can read injected secrets.
  `src/grant.rs:953-954` currently pins the wrong expectation.
- R.26 (medium, authorization): `grant create` prompts for the master
  password without displaying the request. `MCP.md` and `DECISIONS.md` say the
  approval prompt shows command paths and a red interpreter warning. Presence
  is proved, but not informed consent.
- R.27 (low, unsafe input): `src/cli/grant.rs:369` panics on `not_found` for
  `revoke --all` because `options.id` is `None`.
- R.28 (low, drift/tests): `revoke --all` includes expired and exhausted
  grants despite the "active" wording in the help, decisions and test.
- R.29 (low, unsafe output): `--out` is echoed unescaped at
  `src/cli/grant.rs:226` and `:576`.
- Looked at and judged fine: `grant list`/`show` are metadata-only (no token,
  token hash or value; tests assert it); the token file is 0600 with
  `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, fsynced and unlinked on failure; the
  grant-create write happens only after `grant_approved`, uses
  `lock_for_update` + `save_with_key`, and `check_grant_writable` reuses
  `store::encode`; the presence proof binds the canonical digest;
  token/token-hash `Debug` is redacted and comparison is constant-time; no
  nonce/KDF change or other crypto misuse; no new unbounded read; files remain
  under 1,000 lines.
- Known/accepted, not counted: `run` is not yet grant-gated (TODO 3.6, stated
  in SECURITY.md and PROGRESS); `revoke` needs no proof because it only
  removes access (same-user DoS only); `revoke --all` is available to an agent
  by design.
- Gate: `cargo test --quiet` passes; no source, test or doc changes were made
  apart from `TODO.md` and this entry.

## 2026-11-03 — Add `pm grant list|show|revoke` (TODO 3.5)

- `pm grant list [--json]` / `grant show <id> [--json]`: local vault reads
  (master password, `--db` allowed) printing metadata only — id, label, scope,
  commands, capabilities, timestamps, uses, `status` = active|expired|
  exhausted|revoked. JSON is `{"grants":[...]}` or one grant object; no
  `token`, `token_hash` or secret key ever appears.
- `pm grant revoke <id>|--all [--json]`: daemon round-trip over the session
  token, no password, no TTY, allowed under `--agent`. New `grant_revoke`
  request (`id` xor `all: true`) and `grant_revoked {revoked:N}` response; the
  daemon's `revoke_grants` is its only vault write and reuses the hot key via
  `save_with_key`. Already-revoked id is a successful no-op, unknown id exit 3,
  `--all` counts only active grants. Refuses `--db`/`PASSMGR_DB` like `run`.
- `src/cli/args.rs` grew past 1,000 lines, so it became `src/cli/args/mod.rs`
  with the `grant` parsing in `src/cli/args/grant.rs` (mechanical move).
- Decided: revocation needs no proof (it only removes access) and is safe for
  agents to perform; see DECISIONS.md.
- Tests: protocol round-trip + strict rejections for `grant_revoke`/
  `grant_revoked`; args parsing (one target only, `--db` refusal); metadata
  has no token/hash; e2e list/show/revoke, agent revoke, `--all`, unknown id,
  no daemon, TTY-less revoke with a canary that must not leak.
- Gate green: fmt, clippy `-D warnings`, full `cargo test` (237 lib, 48 bin,
  145 integration, 2 doctests). `cargo audit` skipped as allowed.
- **Next iteration must know:** `run` does not yet consult grants (3.6), so
  "takes effect on the next request" is proven only by the persisted
  `revoked_at` and by `grant list`/`show`. PTY runs echo the typed password
  into stdout, so parse JSON from `run_with_env` piped runs instead.

## 2026-11-03 — Add `pm grant create` CLI (TODO 3.4d, closes R.22b)

- `src/cli/grant.rs` + `Command::Grant(GrantCommand::Create(..))`: resolve
  commands to canonical executables; refuse interpreters unless
  `--allow-interpreter`; TTY/no-agent gate (exit 5); require a daemon; create
  `--out` (`O_EXCL|O_NOFOLLOW`, 0600); prompt once, derive the key, build a
  `GrantRequest` with a fresh 32-byte token; open the vault and
  `check_grant_writable` **before** `challenge` (R.22b); prove, send
  `grant_create`, accept only `grant_approved`; re-lock, add, `save_with_key`
  (daemon key stays valid); commit the token file. Failures before commit
  unlink a file this run created.
- New `GrantToken` (`src/grant/token.rs`, split for the line limit): 32
  random bytes, `Zeroizing`, redacting `Debug`; hex only in `--out`, vault
  keeps SHA-256. `is_interpreter` (shells, runners, versioned
  python/perl/ruby/node/php/lua/pwsh/julia/Rscript) in `grant/validate.rs`.
- Docs: `--help`/golden file, README "Create a grant", SECURITY marker
  removed, DECISIONS policy; MCP.md unchanged.
- Tests: unit parsing/expiry/token-file/cleanup/Debug/interpreter; new
  `tests/grant_cli.rs` (5) proves the token is never printed and is 0600,
  stored scope/commands/hash, the daemon still injects after the write, an
  existing `--out` is refused before the prompt, interpreter/agent refusals,
  and a full vault against a stub socket (exit 2, no connection, no file).
- Gate green: fmt, clippy `-D warnings`, full `cargo test` (234 lib, 41 bin,
  123 integration/docs, 2 doctests); `cargo audit` skipped as allowed.
- **Next iteration must know:** 3.5 is next. `grant create` does not
  auto-unlock; an existing `--out` is detected after the session loads. No
  `--fields` flag yet (Scope fields `None`), deferred to Phase 6. A failure
  after `grant_approved` spends the approval; retry needs a fresh request.
  Grants are stored but not yet enforced (3.6).

## 2026-11-03 — One authoritative `grant_create` frame body (TODO R.24)

- TODO 3.4c's spec line showed the fields nested under a `request` key; they
  are flat like `run`. It now reads `{type:"grant_create", label, refs, tags,
  fields?, commands, capabilities, expires_at, max_uses?, token_hash}` and
  points at MCP.md for the exact body. (The old line was also missing its
  closing backtick, which is why the first scripted edit did not match.)
- `MCP.md` ("The daemon never writes a grant") now carries the exact frame
  body in one fenced `json` block, with every key present, `null` for unset
  `fields`/`max_uses`, the "at least one ref or tag" rule, and a note that
  `token` is the unlock session token and `token_hash` is a SHA-256, so no
  credential value is in the body. `src/protocol/mod.rs`'s illustrative sketch
  now says MCP.md holds the exact bytes.
- Decisions: the wire example lives in exactly one document and is pinned on
  both sides, so a doc edit cannot silently change the contract (DECISIONS.md,
  grant bullet). Ordering matters: the encoder's keys come out
  alphabetically (serde_json's `Map` is a `BTreeMap` here), so the doc body is
  the byte-for-byte encoder output.
- Tests: `src/protocol/tests.rs::mcp_documented_grant_create_body_is_the_wire_format`
  (literal decodes to `grant_create()`; re-encoding equals the literal byte
  for byte) and `tests/docs.rs::mcp_grant_create_example_has_the_encoder_keys`
  (extracts the fenced block, compares envelope + request key sets and the
  whole value to the encoder). Both were verified to fail on a nested example.
  The docs test's `fenced_json_after` helper returns `None` on a missing
  marker or block, so deleting the example fails instead of passing vacuously.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  full `cargo test` green (232 lib tests, docs 13); `cargo audit` not
  installed, skipped as the gate allows.
- **Next iteration must know:** 3.4d (the `pm grant create` CLI) is the next
  unchecked item and builds its encoder from MCP.md's example. The example
  uses the fixture token `0011…eeff` and the SHA-256 of `b"grant-token"`, so
  changing either literal means changing MCP.md, the `src/protocol/tests.rs`
  constant and the `tests/docs.rs` fixture together.

