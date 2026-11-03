# Standing decisions

One line per decision, grouped. Extracted from `PROGRESS.md`,
`PROGRESS-archive.md`, `TODO-done.md` and `MCP.md` by TODO H.1.

When a decision changes, edit its line **and** record why in the
`PROGRESS.md` entry for that iteration. The progress logs are history; do not
rewrite them. "Planned" marks a decision already fixed in `MCP.md` that the
code does not implement yet.

## Scope and naming

- `pm` in `TODO.md`, `MCP.md` and the loop prompt is the CLI binary, which
  ships as `passmgr`; the daemon binary beside it is `pmd`.
- Local, single-user, Unix only (Linux and macOS). No network calls, no HTTP
  transport, no server, no sync, no telemetry.
- Agents may **use** credentials but never read them: every agent-facing
  surface returns refs, names, usernames, tags, field names, URLs and
  timestamps only.
- Plaintext reveal (`get --reveal`, later `--copy`) is for a human at a TTY
  only, with no bypass flag. The MCP module must not be able to reach reveal
  code.
- Known, documented limit (do not "fix" by weakening anything): a same-user
  process can read a child's `/proc/<pid>/environ`, and an allowlisted
  interpreter can exfiltrate. passmgr prevents accidents and makes deliberate
  misuse require an explicit human grant.
- `SECURITY.md` is the canonical list of accepted limits and out-of-scope
  threats. A behavior change that alters one updates it in the same commit;
  `tests/docs.rs` pins the load-bearing statements (it also runs the real
  `passmgr --help`, so a doc contract can compare README, `--help` and
  `SECURITY.md`).
- Child-output redaction replaces only an **exact, contiguous occurrence** of
  the injected value. Encoded or transformed copies (base64, hex,
  percent-encoding, case changes) are not redacted until TODO 4.6; README,
  `--help`, `SECURITY.md` and `MCP.md` must say so, and `tests/run.rs`
  (`redaction_replaces_only_the_exact_secret_not_its_encodings`) proves it.
  `tests/docs.rs` pins the same limit in MCP.md and forbids claiming encoded
  redaction before 4.6.

## Crypto

- Vault encryption: AES-256-GCM, 12-byte random nonce per save, 16-byte tag,
  and the 56-byte header supplied as associated data (`src/crypto.rs`,
  `FORMAT.md`).
- KDF: Argon2id, version 0x13, 32-byte output key, 16-byte random salt per
  save; parameters are stored in the header and validated against strict
  bounds.
- Default parameters written by this build: `m_cost` 65536 KiB, `t_cost` 3,
  `p_cost` 1. Do not change them without a migration note and `FORMAT.md`.
- Accepted bounds: m 8192..=1048576 KiB, t 1..=16, p 1..=8, and m >= 8 * p.
  Out-of-range values are `UnsupportedFormat` (exit 6), never clamped.
- Wrong password and corrupted ciphertext are deliberately indistinguishable
  (`AuthenticationFailed`, exit 4).
- The custom container is final; `age` and other envelopes were rejected and
  the two must not be mixed.
- Password generation uses `getrandom` plus rejection sampling (no modulo
  bias): length 4..=128; presets strong (20 chars, letters/digits/symbols),
  simple (16, alphanumeric), pin (6, digits).
- Keys, master passwords, credential values and decrypted payloads are
  zeroized on drop; `pmd` also `mlock`s its key best-effort.
- Constant-time comparison for tokens and MACs; secret-bearing types have a
  redacting `Debug` (tested).

## Vault format and versions

- Container version (header offset 4) and store version (first payload byte)
  are independent counters; today they are 2 and 4.
- Container version 1 is the legacy C format (PBKDF2, line-oriented). It is
  detected and rejected as `LegacyVault` (exit 6), never read or written.
- Every format change needs a reader for **every** older store version, a
  `FORMAT.md` update, and a migration test.
- Store history: v1 (no ids) -> v2 (ids) -> v3 (tags) -> v4
  (`created`/`last_rotated`). Migration generates ids in memory, decodes
  missing tags as empty and missing timestamps as `0`; the next save writes
  v4.
- Entry id: 16 random bytes, rendered `pm://<32 lowercase hex>`. Full ids
  only: no prefixes, no service-based refs. Upper-case input is accepted and
  lower-cased; anything else is `InvalidInput` (exit 2).
- Ids are metadata, not secrets, but they live inside the encrypted payload
  (so the file does not leak the entry count). Duplicate ids in one payload
  are `MalformedVault`.
- Tags: sorted, deduped, 1-32 bytes, first byte an ASCII lowercase letter or
  digit, then `[a-z0-9._-]`, max 32 per credential. Validated on read and
  write. `list --tag` filters with AND semantics.
- Timestamps: `u64` Unix seconds UTC; `0` means unknown and renders as JSON
  `null`; maximum 253402300799 (9999-12-31T23:59:59Z). `created` never
  changes; `last_rotated` moves only when the password changes. Do not reject
  `created > last_rotated` (backwards clocks are legitimate).
- Field rules: service and password non-empty; no Unicode control characters
  in service/username; each field <= 4096 bytes; <= 10000 credentials; decoded
  payload <= 10 MiB; vault file <= 16 MiB.
- Saves are atomic: temp file in the vault's directory, fsync, rename, and a
  best-effort directory fsync. The vault is mode 0600.
- Writers serialize on an exclusive `flock` over the sidecar `<vault>.lock`
  (0600, `O_NOFOLLOW`, never unlinked), held from before the read until the
  `Vault` is dropped. `Vault::open`/`open_with_key` are read-only and take no
  lock (atomic rename makes reads safe); only `open_for_update`/`open_for_add`
  and `lock_for_update` may `save`, and they give up after 30 s with
  `VaultBusy` (exit 1, nothing changed). Do not unlink a held lock file: a
  second writer would lock a fresh inode.
- Commands that prompt for a secret (`add`, `edit`) must not hold the lock
  while a human types: they read and validate lock-free, prompt, then call
  `Vault::lock_for_update`, which takes the lock and refuses with
  `VaultChanged` (exit 1, nothing changed) if the on-disk bytes differ from
  what was decrypted. The prompts and the mutation are therefore separated by
  only the lock, never by an unattended wait.
- Group- or world-readable vaults are currently **warned about** on use; TODO
  8.10 turns that into a refusal, which is what the invariant requires. Do not
  drop the warning before then.
- One file, no compression or deduplication; the container leaks only its
  total size and the KDF parameters.

## CLI conventions

- Global options come before the command:
  `passmgr [--db PATH] [--agent] <command> [args]`; `--agent` after the
  command is a usage error (exit 2).
- Vault path precedence: `--db PATH`, then `$PASSMGR_DB`, then
  `./passwords.dat`. `--db` takes one non-empty path.
- Prompts and diagnostics go to stderr; command data goes to stdout. With
  `--json`, stdout carries exactly one JSON document plus `\n`.
- `list --json` prints `{"entries":[...]}`; `show --json` prints the entry
  object. Entry keys: `ref`, `service`, `username`, `tags`, `created`,
  `last_rotated`. There is no password key and none may be added.
- No password ever appears in argv. Prompts read without echo; a non-TTY
  stdin reads ordinary lines so the tool stays scriptable.
- `get` is metadata-only; `get --reveal` is the only plaintext path. `add
  --generate` and `edit --generate` store but never print the value.
- Reveal gate: stdin **and** stdout must be TTYs, no agent marker
  (`PASSMGR_AGENT`, `CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`; presence
  counts even when empty) and no `--agent`. Checked before unlocking, so a
  refusal never prompts. The decision lives in `src/agent.rs`.
- `--agent` can only add refusal. `unlock` is human-only under the same rule;
  `lock` and `run` need no TTY because neither reveals a value (`lock` only
  stops the daemon, `run` only uses a reference).
- `run` grammar: `passmgr run --env NAME=<ref> -- <command> [args...]`.
  Exactly one `--env` (the protocol injects one secret per run), required,
  with `NAME` and `<ref>` validated before connecting; `--` is required and
  everything after it is argv, never re-parsed. A malformed spec is exit 2; a
  loader/shell-hook NAME is refused locally with exit 5 before any socket is
  opened (the daemon independently refuses it too). Daemon refusals map to:
  `not_found` -> 3, `spawn_failed`/`bad_request`/`internal`/`unauthorized`/
  `unsupported` -> 1. A normal exit passes through; signal `N` renders as
  `128 + N` at the CLI only (the wire keeps the two cases distinct).
- `rm` is a pure alias of `delete` (same message, same exit code).
- `edit` rotation rule: a bare `edit` or one with `--generate` rotates the
  password; `--username`/`--rename`/`--tag`/`--clear-tags` alone is a
  metadata-only edit and does not prompt.
- Validate non-secret input before unlocking: bad refs, tags, options and
  unknown services fail (2 or 3) without a password prompt.
- Unknown options, extra arguments and misplaced flags are usage errors
  (exit 2). `-h`/`--help` and `-V`/`--version` are accepted globally and as
  commands.
- A broken stdout pipe (`BrokenPipe` while writing command data) exits 0.
- `generate` prints a fresh value on stdout. It exposes no stored secret, but
  whether agent mode should refuse it is still open (see "Open questions").
- CLI code lives in `src/cli/`: `mod.rs` (entry, dispatch, output, tests),
  `args.rs` (parsing), `commands.rs` (local commands and prompts),
  `unlock.rs` (daemon commands) and `help.rs` (`USAGE`/`HELP`). `src/main.rs`
  is only `mod cli;` plus `fn main`. `--help` output is pinned byte-for-byte
  by `tests/fixtures/help.txt` and a CLI test.

## Exit codes

Defined in `src/error.rs`; this is a contract, never renumber. Use the
`EXIT_*` constants, never a literal.

- 0 success.
- 1 runtime failure: `Io`, `Crypto`, `DuplicateService`, `Daemon`.
- 2 usage error or invalid input (including invalid input at a prompt).
- 3 not found: `VaultNotFound`, `ServiceNotFound`, `EntryNotFound`.
- 4 wrong master password / failed vault authentication.
- 5 refused (non-TTY or agent reveal, `unlock` in agent context).
- 6 malformed, truncated or unsupported vault.
- `Error::Crypto` stays 1, not 6: it also covers RNG and cipher-setup
  failures, which are not a malformed file. Read-time corruption is
  `MalformedVault` (6) or `AuthenticationFailed` (4).
- Daemon-internal error enums (`SocketError`, `ProtocolError`,
  `SessionError`) stay module-local; the CLI boundary maps them to
  `Error::Daemon` (exit 1) with a message that never contains secrets.

## Daemon and protocol

- `pmd` holds only the derived 32-byte key, never a decrypted vault; it
  decrypts on demand per request and drops the plaintext immediately.
- Key handover: `pm unlock` derives and authenticates the key, spawns the
  `pmd` found next to its own executable, and writes exactly 32 bytes to its
  stdin, then EOF. The key never appears in argv, the environment or any
  output; `pmd` refuses a short, long or trailing handover.
- Startup order: harden (`RLIMIT_CORE` 0 and Linux `PR_SET_DUMPABLE` 0, both
  fail closed) -> signal handlers -> `setsid` best effort -> verify the key
  against the vault -> bind the socket. A wrong key never creates a socket.
- `unlock` refuses when a daemon is already running (tells the human to run
  `passmgr lock`), so a second unlock can never silently replace a key.
- Runtime directory: `$XDG_RUNTIME_DIR/passmgr`, else
  `<temp_dir>/passmgr-<euid>`; must be a real directory owned by us with mode
  exactly 0700, otherwise refused (`InsecurePath`). Bad modes are refused, not
  repaired, and parent directories are never created.
- Files: `pmd.sock` 0600 (chmod after bind), `pmd.lock` 0600 (flock target),
  `session` 0600 (session token). Paths are capped at 104 bytes so anything
  that works on Linux also works on macOS.
- Single instance: non-blocking exclusive `flock` on `pmd.lock`, retried every
  5 ms for up to 250 ms (a just-exited holder can linger briefly), then
  `AlreadyRunning`. The lock file is never unlinked; the socket is unlinked on
  drop only if its inode still matches the one recorded at bind time.
- Stale sockets: never steal a socket that answers `connect`; replace it only
  after `ECONNREFUSED`. A symlink or non-socket at the path is refused
  untouched.
- Peer check before any read: `SO_PEERCRED` on Linux/Android, `getpeereid` on
  macOS; any other Unix target fails closed. A mismatched uid is closed with
  no reply. The pid is informational and never used for authorization.
- Framing: 4-byte big-endian length prefix + JSON body, 64 KiB body cap
  checked before slicing, one request per connection, 5 s read/write timeout,
  200 ms accept poll.
- Envelope: `{"version":3,"token":"<64 lowercase hex>","request":{...}}`. The
  token is parsed before the request. Unknown envelope **fields** are
  ignored; unknown versions and request types are hard errors. Requests are
  validated on encode *and* decode.
- **No request type returns plaintext, ever.** Any same-user process can reach
  the socket, so client-side checks protect nothing; every authorization
  decision is made in `pmd`.
- Responses: one-shot `pong`, `locked`, or a fixed error code (`bad_request`,
  `unsupported`, `unauthorized`, `not_found`, `spawn_failed`, `internal`,
  `busy`), and for `run` a
  stream of `RunFrame`s: zero or more `stdout`/`stderr` chunks (lowercase hex
  of at most 16 KiB raw bytes each), then exactly one terminal `exit` or
  `error`. Errors never echo field values or the token.
- `RunFrame` is a separate type from `Response`, so a `ping` can never answer
  with child output and a `run` stream can never answer `pong`. `RunStream`
  refuses any frame after a terminal one.
- An `exit` frame carries either `code` (0..=255) or `signal` (1..=127), never
  both; "killed by signal N" stays distinct from exit code 128+N.
- `not_found` also covers a reference outside the caller's scope, so a client
  cannot use the daemon as an existence oracle for refs it may not use.
- `run` carries the caller's absolute `cwd`, and `command[0]` must be an
  absolute path. The CLI resolves a bare name through **its own** `PATH` and
  a relative program through **its own** cwd before sending the request; the
  daemon never resolves a program through its own cwd/`PATH` (those belong to
  the shell that ran `unlock`) and starts the child in the requested `cwd`.
  An unresolvable program is a CLI usage error (exit 2). This is why the
  protocol version is 3: a version-2 daemon would silently ignore `cwd`.
- `run` does not accept an explicit vault: `--db` and a non-empty
  `PASSMGR_DB` are a usage error (exit 2) before the CLI resolves the program
  or connects. The daemon injects from the vault it was unlocked with, so
  honouring the flag is impossible and ignoring it could inject a value from
  a vault the human did not name (TODO R.4). Other commands still choose
  their vault by flag > env > default.
- Protocol code layout: `src/protocol/mod.rs` owns framing, requests and
  errors; `src/protocol/response.rs` owns one-shot responses and the `run`
  stream. `crate::protocol::*` re-exports the public API unchanged.
- Session token: 32 OS-random bytes as 64 lowercase hex in
  `$XDG_RUNTIME_DIR/passmgr/session`. Loading requires a regular 0600 file
  owned by the user, opened `O_NOFOLLOW`, at most 512 bytes; anything else is
  an error, never repaired.
- The session token authorizes `ping`, `lock` and `run` today. It is **not** a
  human/agent boundary and must never be enough to use a secret. TODO 3.6
  makes `run` (and every credential-touching request) require a grant.
  **Transitional gap (2.6c until 3.6):** `pmd` authorizes `run` with the
  session token alone. Token checking and the no-plaintext response contract
  are already in place, but any same-user process that can read the 0600
  session file can inject a stored value into a command of its choosing. The
  MCP server must not expose any `run`-equivalent tool before 3.6.
  `revoke` over the session token is an accepted DoS-at-worst trade-off.
- `run` child policy (TODO 2.6c): argv only, never a shell string; stdin is
  `/dev/null`; the environment is built from scratch from `PATH`, `HOME`,
  `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ`, `TMPDIR`, `TERM` plus exactly one
  injected variable. The daemon refuses loader and shell-hook names
  (`LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `IFS`, `PATH`,
  `HOME`, `SHELLOPTS`, `PS4`) before spawning, even though the protocol's env
  grammar already allows them. stdout and stderr each get their own streaming
  redactor; frames are split at 16 KiB after redaction, so a value never
  straddles a frame. `internal` is the fixed code for "the daemon could not
  read its own vault"; it never names a path or value.
- An `unauthorized` request does not refresh the idle timer.
- Idle timeout: default 900 s (`pmd --idle-timeout SECS`,
  `passmgr unlock --idle-timeout SECS`); zero is refused. Activity means a
  successfully decoded request after the peer check; malformed frames and
  rejected tokens do not count. Accepting a `run` is activity, and the idle
  deadline is suspended while any run is in flight: a command longer than the
  remaining budget finishes instead of being killed mid-work. Such a run is
  bounded by `lock`/signals (and, from TODO 4.5, the run timeout). When the
  last run finishes, the timer starts again.
- At most `MAX_CONCURRENT_RUNS` (16) `run` workers exist at once. A request
  over the cap is answered with the terminal error `busy` before the vault is
  opened: nothing is decrypted or spawned and no worker is created. A worker
  thread that cannot be spawned is answered `busy` too, and cannot panic out
  of the scope (which would skip the join, the socket unlink and the key
  wipe). Adding an error code is additive and keeps the protocol at version 3:
  an older client treats an unknown code as a closed decode failure.
- `lock`, `SIGTERM` and `SIGINT` wipe the key, remove
  the socket, and remove the session file only if it still holds this
  daemon's token. A `run` is served on a worker thread so the accept loop
  stays responsive; those events set a shared cancel flag, and every in-flight
  child is killed and reaped before the daemon drops the key and exits. An
  interrupted run writes no terminal frame: the client sees EOF and reports a
  `Daemon` error. The idle timeout uses the same wipe path, but only once no
  run is in flight.
- Each child is spawned into its own process group (`setpgid(0, 0)`), and a
  cancel kills the group with `SIGTERM` then, after a 100 ms grace, `SIGKILL`.
  The relay never calls `try_wait` while a pipe is still open: the leader stays
  an unreaped zombie, so its pid (and therefore the pgid) cannot be recycled
  before a later group signal, however long a grandchild holds the pipes. Only
  the completed path reaps, once both pipes reached EOF. The pipe readers poll
  the cancel flag before every blocking read, so a
  grandchild that inherits the output pipes and outlives the child can keep
  neither the relay nor the shutdown waiting. The `lock` acknowledgement is
  written only after the workers are joined, the socket and session file are
  removed and the key is zeroized: when `passmgr lock` prints, it is done.
  `serve_run` re-checks the flag before decrypting and before spawning, so no
  child starts once the shutdown has begun.
- The streaming client (`client::run`) reads frames until the terminal frame,
  with no idle/read timeout: a legitimate child may stay silent for minutes,
  and the daemon closes the socket when it exits. EOF before a terminal frame
  is a `Daemon` error, never a silent success. The CLI relays only
  non-terminal frames and stops at the first terminal frame.
- `client`, `daemon`, `session` and `socket` are `#[cfg(unix)]`; the CLI has
  non-Unix stubs, and no unchecked accept path exists on an unsupported
  platform.

## Grants, approval and MCP (planned, per `MCP.md`)

- The grant model lives in `src/grant.rs` (TODO 3.2a) and is pure: no I/O,
  no clock. `Grant::authorizes(&AccessRequest, now)` is the single decision
  point. It checks, in order: revoked, `now >= expires_at` (expiry is
  exclusive), uses exhausted, missing capability, then scope and (for `run`
  only) command. `AccessRequest` is an enum whose `List` and `Run` variants
  both carry a `Target`, so no request can be authorized without a scope
  check (TODO R.11). There is no target-less "may I list" request:
  enumeration authorizes each candidate entry and filters, so the daemon
  cannot trust a separate scope test that might be forgotten.
- Scope matching: an entry is in scope when its id is listed, **or** when it
  carries **every** tag the grant lists. A grant must list at least one ref
  or tag. `pm list --tag` AND semantics are reused, so "all" is consistent.
- Field scope: `Scope::fields = None` covers every field; `Some(names)`
  covers exactly those names, and a request that names no field is out of
  scope for a field-restricted grant (conservative until 6.1 defines the bare
  ref). Field names are `[a-z0-9_-]{1,32}`.
- Commands: a command must equal an allowlisted absolute path exactly
  (`Path` equality). `src/grant.rs` never touches the filesystem; the daemon
  canonicalizes first (TODO 3.6/4.5) and hands the check a canonical path.
  A run-capable grant needs at least one command; a list-only grant may have
  none. Commands are sorted and deduplicated, max 32, each <= `MAX_PATH_BYTES`
  and valid UTF-8.
- Grant limits: label 1..=64 bytes with no control characters, at least one
  capability, expiry in `(now, now + 30 days]`, and `max_uses = Some(0)` is
  refused (omit it for unlimited). Capabilities are a bit field
  (`list` = 1, `run` = 2) with unknown bits rejected on decode.
- A grant stores `TokenHash` = SHA-256 of the raw 32 token bytes, never the
  token. `Debug` renders `TokenHash(<redacted>)`; there is no `Display` and no
  hex rendering. `TokenHash::matches` is constant-time.
- `sha2` (RustCrypto, `0.10`, sharing `digest` 0.10 with the existing
  `blake2`/Argon2 tree) is the only dependency added by 3.2a. `hmac` moves to
  TODO 3.3, its first use; adding an unused crate now would hide that.
- Grant persistence (grant list in the store payload, next store version) is
  TODO 3.2b; until then nothing in the vault or CLI can create a grant.
- Agents get access only through grants stored in the encrypted vault: scope
  (refs, tags, optional field names), a command allowlist of canonical
  absolute paths, capabilities, `expires_at` (max 30 days), optional
  `max_uses`, `revoked_at`, `last_used`. Only the SHA-256 of the grant token
  is stored.
- Creating or approving a grant requires the master password at a TTY, proved
  with `HMAC-SHA256(vault_key, "passmgr-approve-v1" || nonce || digest)` using
  a single-use 60 s nonce, compared in constant time. Revoking needs no proof.
- The daemon canonicalizes `command[0]` itself (symlinks resolved), requires
  the result to stay absolute, and checks that canonical path against the
  grant's command allowlist immediately before spawning; a path it cannot
  canonicalize is refused. The MCP server resolves a bare/relative name for
  the agent's convenience, but the result is untrusted input: any same-user
  process can call the daemon, so only a check inside `pmd` counts. Planned
  with TODO 3.6/4.5; `src/protocol/mod.rs` today only requires an absolute
  path.
- Interpreters and shells in a command allowlist are refused unless the human
  passes `--allow-interpreter`.
- `pm mcp serve` is a hand-written synchronous JSON-RPC 2.0 stdio server (no
  MCP SDK, no async runtime): 1 MiB line cap with resync to the next newline,
  batches rejected, stdout carries only JSON-RPC, diagnostics on stderr, and
  requests are handled sequentially.
- Dual era: legacy `2025-11-25` handshake and modern stateless `2026-07-28`
  (`_meta` validation, `server/discover`, `resultType`, `serverInfo`); an
  unknown modern version gets `-32022` with the supported list.
- An out-of-scope ref answers exactly like a nonexistent one (no existence
  oracle). Agent-supplied text shown to a human is sanitized (control and
  bidi characters stripped) and labelled untrusted.
- Grant tokens reach only the MCP server, via a one-time claim exchange, live
  in memory, and never appear in tool output or the audit log.
- Audit: append-only `$XDG_STATE_HOME/passmgr/audit.jsonl` (fallback
  `~/.local/state`), 0600, one JSON object per line, hash-chained with `prev`
  = SHA-256 of the previous line. No secrets, no tokens; `pm audit verify`
  reports the first broken link with exit 6.

## Dependencies

- Allowed: `aes-gcm`, `argon2`, `getrandom`, `libc`, `serde_json`, `sha2`,
  `tempfile`, `zeroize`; `hmac` joins them in TODO 3.3; `proptest` as a
  dev-dependency only (TODO 9.2).
- Rejected: an MCP SDK, an async runtime, a CLI framework (hand-written
  argument parsing is deliberate), any HTTP/network crate, and `serde` derive
  on `Credential` (it could add a password field by accident).
- Justify every new dependency in `PROGRESS.md`.
- `cargo audit` is not installed on this machine: skip that gate step and say
  so in the `PROGRESS.md` entry; do not install it. A `Cargo.lock` grep test
  for banned crates is planned (9.6).

## Testing conventions

- Every behavior change has a test that fails without it; every security
  property has a test proving it, usually with a per-test random canary value
  that must not appear in stdout, stderr, logs, audit records, socket bytes or
  MCP output.
- Deterministic tests: a temp dir per test, `XDG_*`/`HOME` set per test, no
  real credentials, no network, no dependency on test order, and polling with
  a deadline instead of fixed sleeps as synchronization.
- Documentation contracts are scoped to the section that must carry the
  claim: `tests/docs.rs` extracts a `### N.` limit and asserts contiguous
  phrases from its body, so an unrelated sentence elsewhere in the file cannot
  satisfy it (TODO R.5).
- Test through public interfaces and keep pure logic reachable by unit tests.
  CLI e2e tests run the real binary with the real default KDF parameters (the
  suite is Argon2-bound and slow).
- `tests/daemon.rs` builds its own fixture vaults with deliberately cheap KDF
  parameters because it does not test the KDF; the shipped defaults are never
  lowered, and no test may weaken a shipped parameter or check.
- PTY tests use `posix_openpt` and are Linux-only; macOS relies on the pure
  decision-logic unit tests.
- Never delete, `#[ignore]` or weaken a test to pass the gate. If a test is
  wrong, fix it and explain why in `PROGRESS.md`.
- Gate per iteration: `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`, then
  `cargo audit` where it exists.
- Keep files under ~1,000 lines and split before growing past that;
  `src/main.rs` is already over (TODO H.2 splits it).

## Open questions (not decided; do not cite as decisions)

- Should `generate` refuse or redact in agent context? It prints a fresh
  value, not a stored secret, but it is still plaintext on stdout.
- Should `pmd` warn when `mlock` fails? It is currently silent and non-fatal.
