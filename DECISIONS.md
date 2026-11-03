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
  interpreter or program runner can exfiltrate. passmgr prevents accidents and
  makes deliberate misuse require an explicit human grant.
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
- Redaction always holds back the last `len - 1` bytes of relayed output until
  more output or EOF, where `len` is the secret's length. The choice is
  content-independent so relay timing is not a prefix oracle (R.36); the cost
  is that tail output is delayed by up to `len - 1` bytes. `src/redact.rs`
  implements it and `tests/redaction_timing.rs` proves a correct and a wrong
  prefix are held identically. Do not go back to holding only a *matching*
  prefix.
- The redaction marker is `[REDACTED]` only when it is safe; `marker_is_safe`
  rejects it if the marker contains the secret, the secret contains the
  marker, the marker starts with a proper suffix of the secret, or the secret
  starts with a proper suffix of the marker (output around a substitution can
  supply the missing part). Otherwise the marker is a run of a byte absent
  from the secret (R.36a). A future marker change must keep this rule.

## Crypto

- Vault encryption: AES-256-GCM, 12-byte random nonce per save, 16-byte tag,
  and the 56-byte header supplied as associated data (`src/crypto.rs`,
  `FORMAT.md`).
- KDF: Argon2id, version 0x13, 32-byte output key; a **new** vault takes a
  16-byte random salt, and every later save reuses the salt and parameters in
  the file it was read from. Parameters are stored in the header and
  validated against strict bounds. Re-salting on save was rejected (TODO
  R.40): it invalidates a running `pmd`'s key on the next `run` or
  `grant revoke`, and writing the defaults would silently downgrade
  parameters a human raised. Every save still takes a fresh nonce. Reusing
  a header is only allowed after authenticating the container it came from
  (`crypto::encrypt_with_template`, `crypto::encrypt_with_key`), so a wrong
  password or key writes nothing. Upgrading parameters is a separate,
  explicit action (TODO 8.2).
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
  are independent counters; today they are 2 and 5.
- Container version 1 is the legacy C format (PBKDF2, line-oriented). It is
  detected and rejected as `LegacyVault` (exit 6), never read or written.
- Every format change needs a reader for **every** older store version, a
  `FORMAT.md` update, and a migration test.
- Store history: v1 (no ids) -> v2 (ids) -> v3 (tags) -> v4
  (`created`/`last_rotated`) -> v5 (grant list). Migration generates ids in
  memory, decodes missing tags as empty, missing timestamps as `0` and a
  missing grant list as empty; the next save writes v5.
- A v5 payload keeps the credential records byte-identical to v4 and appends
  `u32 grant count` plus one record per grant after them, so the credential
  codec did not change for the grant work. Optional grant fields are encoded
  behind a flags byte instead of a magic timestamp, because `None` and a real
  timestamp must stay distinguishable; unknown capability or flag bits are
  malformed rather than ignored.
- The grant codec lives in `src/store.rs` (the single owner of the payload
  format); `src/grant.rs` stays a pure model. Decoding builds `StoredGrant`
  and re-enters `Grant::from_stored`, which re-checks every `Grant::create`
  invariant, so the vault reader and the grant creator cannot drift apart.
  Encoding builds the same `StoredGrant` (`Grant::to_stored`), runs
  `Grant::check_stored` on it and serializes **that** value, so a save can
  never write a grant its own reader would refuse (TODO R.17). A grant that
  fails the check is `InvalidInput` (exit 2) and nothing is written.
- `Grant::mark_used` and `Grant::revoke` refuse a `now` above
  `MAX_TIMESTAMP_UNIX` with `UpdateError::TimestampOutOfRange` and change
  nothing. `UpdateError` is deliberately separate from `Denied`, which stays
  an authorization answer that the daemon renders and audits; `Grant::create`
  applies the same upper bound to its own `now`.
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
- The 10 MiB payload limit bounds **content**, not the bytes a grant gains
  after creation. `revoked_at` and `last_used` add 8 bytes each, up to 16 KiB
  over all 1,024 grants; `store::encode` subtracts those present-fields bytes
  before comparing against `MAX_PLAINTEXT_BYTES`, and crypto/`decode` accept
  `MAX_PAYLOAD_BYTES` = 10 MiB + 16 KiB. A vault written at the cap can
  therefore always save a revocation or a recorded use (TODO R.46). Chosen
  over refusing grant growth at the cap because the kill switch must not fail
  on a full vault. Readers accept 16 KiB more plaintext than writers produce.
- Saves are atomic: temp file in the vault's directory, fsync, rename, and a
  best-effort directory fsync. The vault is mode 0600.
- Writers serialize on an exclusive `flock` over the sidecar `<vault>.lock`
  (0600, `O_NOFOLLOW`, never unlinked), held from before the read until the
  `Vault` is dropped. `Vault::open`/`open_with_key` are read-only and take no
  lock (atomic rename makes reads safe); only `open_for_update`,
  `open_for_add` and `open_with_key_for_update` may `save` (the last one takes
  the lock and *then* reads, so a writer that got in first is seen, not
  refused), and they give up after 30 s with
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
- Envelope: `{"version":4,"token":"<64 lowercase hex>","request":{...}}`. The
  token is parsed before the request. Version 4 added the required
  `run.grant`; a version-3 daemon would ignore it and authorize with the
  session token alone, so the bump is a hard downgrade guard. Unknown envelope **fields** are
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
  cannot use the daemon as an existence oracle for refs it may not use. `pmd`
  also decides the credential-independent checks (grant state, `run`
  capability, command allowlist) before it looks a reference up, so a revoked,
  expired or exhausted grant answers the same for an existing and a
  nonexistent ref (TODO R.31).
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
- The session token alone authorizes `ping`, `lock` and the human-presence
  handshake (`challenge`/`prove`/`grant_create`), plus `grant_revoke`. It is
  **not** a human/agent boundary and is never enough to use a secret.
  `run` requires a second credential: a grant token whose SHA-256 matches an
  active, in-scope, command-allowing grant in the vault (TODO 3.6). `pmd`
  records the use in the vault before it copies the secret or spawns the
  child, so a crash cannot exceed `max_uses`, and any vault-write failure
  fails closed. A same-user process that can read the session file still
  cannot use a secret without also obtaining a grant token file.
  `grant_revoke` over the session token is an accepted DoS-at-worst
  trade-off.
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
- `run` authorization order (TODO 3.6): parse the ref/env/command, reject
  loader variables, canonicalize `command[0]`, then match the grant token and
  check active status, scope, capability and the canonical command. Any
  failure — including a path that cannot be canonicalized — is the same
  opaque `denied`. The use is written to the vault before the secret is copied
  or the child is spawned; a spawn failure therefore still consumes a use.
  This favors never exceeding `max_uses` over not charging a failed exec.
- `run` authorization reads the clock **after** the vault write lock is
  acquired, and re-reads it on every retry (TODO R.45). The wait can last up
  to the 30 s lock timeout per attempt, so a time read before it would
  authorize a grant that expired while waiting. Expiry is always decided
  against the vault the use is recorded in.
- Grant progress is monotonic while one `pmd` serves (TODO R.44). The vault
  is an ordinary file and a same-user process can put an older copy back;
  that copy still opens with the daemon's key. `pmd` keeps an in-memory,
  per-grant-id high-water mark of `uses` and revocation, checked under the
  vault write lock before a `run` is authorized and raised only after a
  successful save. A vault with fewer uses, or one that cleared a seen
  revocation, is refused `denied`; a failed write does not raise the mark.
  Revocation is exempt from the check (it can only remove access, and the
  kill switch must survive a rollback) but still raises the mark. The mark is
  not persisted: a marker file is rollbackable like the vault, and a restart
  accepts the file as it finds it (`SECURITY.md` limit 7).
- An `unauthorized` request does not refresh the idle timer.
- Idle timeout: default 900 s (`pmd --idle-timeout SECS`,
  `passmgr unlock --idle-timeout SECS`); zero is refused. Activity means a
  successfully decoded request after the peer check; malformed frames and
  rejected tokens do not count. Accepting a `run` is activity, and the idle
  deadline is suspended while any run is in flight: a command longer than the
  remaining budget finishes instead of being killed mid-work. Such a run is
  bounded by `lock`/signals (and, from TODO 4.5, the run timeout). When the
  last run finishes, the timer starts again.
- A `run` whose client closes its connection is cancelled (TODO R.37): the
  runner checks the condition in both the relay loop and the wait-for-exit
  loop, and the client socket is polled with a zero timeout, so a silent child
  cannot delay it. `POLLHUP`/`POLLERR`/`POLLNVAL` mean the connection is gone;
  a client that shuts down only its write half is still reading and keeps its
  run. Without this, an agent host that dropped a timed-out tool call left the
  child running with the secret in its environment and suspended the idle
  deadline for the child's lifetime.
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
  A run that finishes normally kills whatever is left in the group with
  `SIGKILL` before it returns: a child can background a daemon that inherits
  the injected value and redirect its output, so without this the value
  survives the run, `lock` and `pmd`. A descendant that starts a new session
  (`setsid`) leaves the group and escapes the kill; that is accepted and
  documented in `SECURITY.md` limit 1. The relay never reaps while a pipe is
  still open: the leader stays an unreaped zombie, so its pid (and therefore
  the pgid) cannot be recycled before a later group signal, however long a
  grandchild holds the pipes. The completed path detects the leader's exit
  with `waitid(.., WNOWAIT)`, signals the group while the zombie still pins
  the pid, and only then reaps. The pipe readers poll the cancel flag before
  every blocking read, so a
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
  canonicalizes first (TODO 4.5) and hands the check a canonical path.
  A run-capable grant needs at least one command; a list-only grant may have
  none. Commands are sorted and deduplicated, max 32, each <= `MAX_PATH_BYTES`
  and valid UTF-8. A command path is untrusted text that the approval prompt
  and `pm grant show` render, and it may come from an agent request, so it is
  held to the label's character table: no control, bidi, zero-width/format,
  line-separator or variation-selector character can be stored (TODO R.21).
  Unlike a label, a bad command is named in the error, but with every hidden
  character written as a `\u{..}` escape, so the error itself cannot move the
  cursor or erase the line around it. Create and decode share the check, so
  stored grants need no migration.
- Grant limits: label 1..=64 bytes with no control, bidi, zero-width/format,
  line-separator or variation-selector characters (TODO R.14). The label is
  stored verbatim and later rendered by `pm grant list`, so validation
  **rejects** the whole class instead of stripping it: a silently altered
  label would not match what a human approved. A visible combining accent,
  an emoji that uses no variation selector or zero-width joiner, or a
  non-Latin script is allowed. VS15/VS16 (U+FE0E/U+FE0F) are refused like
  every other selector even though they pick a visible presentation: an
  approved label must render exactly as stored, and accepting a subset would
  reintroduce the invisible-mark class (TODO R.18). The rejection error names
  the same class list as `FORMAT.md` and this file, via
  `grant::LABEL_FORBIDDEN_CLASSES`, pinned by `tests/docs.rs`. At
  least one
  capability, expiry in `(now, now + 30 days]`, and `max_uses = Some(0)` is
  refused (omit it for unlimited). Capabilities are a bit field
  (`list` = 1, `run` = 2) with unknown bits rejected on decode.
- A grant stores `TokenHash` = SHA-256 of the raw 32 token bytes, never the
  token. `Debug` renders `TokenHash(<redacted>)`; there is no `Display` and no
  hex rendering. `TokenHash` deliberately has **no** `PartialEq`/`Eq`: the only
  comparison is `TokenHash::matches`, which is constant-time. A `compile_fail`
  doctest in `src/grant.rs` fails the gate if `==` becomes usable again
  (TODO R.13); `as_bytes` is for payload encoding only.
- `sha2` (RustCrypto, `0.10`, sharing `digest` 0.10 with the existing
  `blake2`/Argon2 tree) is the only dependency added by 3.2a. `hmac` moves to
  TODO 3.3, its first use; adding an unused crate now would hide that.
- Grant persistence is done (TODO 3.2b): grants are stored in the v5 payload
  and reachable through `Vault::grants`/`grant`/`grant_mut`/`add_grant`.
  `pm grant create` (TODO 3.4d) creates grants in the human's CLI; `pmd`
  still has no request type that writes one (see the write-path decision
  below).
- Grant rows are pruned, not immortal (TODO R.42): a vault caps the whole
  grant list at `MAX_GRANTS` (1,024), so `pm grant create` drops grants that
  are revoked or expired **and** died at least `DEAD_GRANT_RETENTION_SECS`
  (7 days) before the write, in the same write that adds the new grant. The
  window keeps `pm grant list`/`show` able to explain a recent denial.
  Active and exhausted-but-unexpired grants are never pruned; the daemon's
  revocation and use-recording writes do not prune, so the kill switch stays
  a pure state change. Implemented as the pure `grant::prune_dead(grants, now)`
  and `Vault::prune_dead_grants`; `Vault::check_grant_writable(grant, now)`
  prunes its candidate copy, so the pre-approval check asks exactly what the
  write will do.
- Agents get access only through grants stored in the encrypted vault: scope
  (refs, tags, optional field names), a command allowlist of canonical
  absolute paths, capabilities, `expires_at` (max 30 days), optional
  `max_uses`, `revoked_at`, `last_used`. Only the SHA-256 of the grant token
  is stored.
- Creating or approving a grant requires the master password at a TTY, proved
  with `HMAC-SHA256(vault_key, "passmgr-approve-v1" || nonce || digest)` using
  a single-use 60 s nonce, compared in constant time. Revoking needs no proof.
- `pm grant list`/`show` are local vault reads with the master password and
  deliberately accept `--db`. `pm grant revoke` goes through the daemon over
  the session token, because the daemon holds the key and can write without a
  prompt; it refuses `--db`/`PASSMGR_DB` like `run`, since it can only act on
  the daemon's own vault (TODO 3.5). The daemon's only vault write is setting
  `revoked_at` with `Vault::save_with_key`, which reuses the container's salt
  and KDF parameters so the hot key stays valid. Revoking an already-revoked
  id is a successful no-op (`revoked: 0`), an unknown id is `not_found`, and
  `--all` targets only grants that are active at the daemon's captured `now`
  (one `Grant::status` predicate, shared with `grant list`/`show`), so expired,
  exhausted and already-revoked grants are left untouched and never counted. The CLI maps a `not_found` answer to exit 3 only when
  it named an id; `--all` has no id to name, so that answer becomes a daemon
  error (exit 1) and never a panic, since any same-user process may replace
  the socket (TODO R.27).
- The presence proof is implemented in `src/presence.rs` (TODO 3.3). The MAC
  message is `DOMAIN || nonce || digest`, all fixed length, so the fields
  cannot be shifted into one another. The daemon issues nonces through the
  `challenge` request and checks them through `prove`; both requests carry
  only public values (nonce, digest) plus the MAC. Design choices:
  - The nonce is spent **before** the MAC is checked. One issue therefore
    allows exactly one attempt, so a peer cannot test many candidate proofs
    against one challenge. A typo means asking for a new challenge, which is
    cheap for a human and costly for a guesser.
  - Every rejection is `denied`: unknown, expired and already-spent nonces
    answer identically to a wrong MAC, so the socket is not an oracle for
    which part of a guess was right.
  - A verified proof records the digest it covered as a **one-shot approval**
    (`presence::Approvals`, TODO R.15a): in memory, 60 s, at most 16, and the
    oldest makes room because only a key holder can add one. `proven`
    authorizes nothing by itself; the request that writes must call
    `Approvals::take` with the digest of exactly what it is about to do and
    may proceed only on `Ok`, which spends the approval once. Approved A can
    therefore never authorize B, and a stale `Proven` cannot be read as
    consent for a later request. The first consumer is the grant write (TODO
    3.4/4.9, tracked as R.15b).
  - At most 16 unspent nonces are held (in memory, never persisted). A full
    pool never refuses a challenge: the **oldest** nonce is evicted, because
    `challenge` needs only the session token that an agent holds by design,
    and the approval path must not be starvable by the party it constrains
    (TODO R.16). A single burst of sixteen challenges — an agent retrying in a
    loop — therefore cannot block a human who asks afterwards. The rule is
    deliberately oldest-first and not per-connection or per-holder: every
    request is a fresh connection, the peer UID is the same for the human and
    the agent, and no identity distinguishes them, so any cleverer rule would
    either be spoofable or need data that does not exist. A peer that keeps
    issuing challenges faster than one human round trip can still evict a
    fresh nonce, exactly as it can already kill `pmd`; that residual same-user
    DoS is documented in `SECURITY.md` and is not a privilege escalation.
    Expired nonces are pruned before eviction, so the window is one minute.
    Spending a nonce removes only that entry and leaves the rest in issue
    order, so the entry at index 0 stays the oldest even when a non-last
    challenge is consumed; `swap_remove` would have promoted the newest and
    the next eviction would have destroyed it (TODO R.19).
  - `Proof` zeroizes, `Debug` renders `Proof(<redacted>)`, and equality is
    implemented as the constant-time `matches` (there is no early-exit `==`).
    The nonce and digest are public and may appear in `Debug`/errors.
  - `hmac` 0.12 (RustCrypto) is the dependency added by 3.3; it shares
    `digest` 0.10 with `sha2`, unlike 0.13. Its `verify_slice` is the
    constant-time tag check.
  - The protocol version stays 3: the two request types are additive, so old
    clients keep working and an old daemon answers `bad_request` to a newer
    client rather than misinterpreting it.
- A grant write is authorized by a digest of the canonical request (TODO
  3.4a, `src/grant/request.rs`). `GrantRequest::new` applies the same shape
  rules as `Grant::create` and stores the normalized form; `digest()` is
  SHA-256 over a length-prefixed encoding with the domain string
  `passmgr-grant-create-v1`. It covers the label, refs, tags, optional field
  names, canonical commands, capability bits, absolute expiry, optional
  max-uses and the token hash. The grant id and `created` are assigned by the
  CLI at write time and are **not** covered: neither can widen what the
  human approved. The token hash **is** covered, so an approval for a request
  that writes one token can never write another. Every variable-length field
  is length-prefixed, so two different field assignments cannot produce the
  same byte stream. The digest is public and collision-resistant, not a MAC;
  the presence proof binds it to the vault key (TODO 3.3). A change to the
  encoding must bump `DIGEST_DOMAIN`; approvals live 60 s, so no migration is
  needed. A pinned digest test fails if the bytes change silently.
- Grant writes happen in the human's CLI, **not** in `pmd` (TODO 3.4b/3.4c).
  The daemon holds the derived key and could re-encrypt, but giving it a
  write request would mean a bug on the agent-reachable socket could mint a
  grant. Instead `pmd` only spends the digest-bound approval
  (`grant_create` -> `grant_approved`) and has no request type that writes a
  grant; the CLI, which has the password, opens the vault, takes the write
  lock and saves. The approval still binds the exact request (TODO 3.4a), and
  the CLI cannot be driven by an agent (TTY + password + no agent context).
  The CLI must **not** derive a second key for this write when it already
  holds one. It saves with
  `crypto::encrypt_with_key(plaintext, key, template_container)`, which first
  authenticates the template with the key (a wrong key never writes an
  unopenable vault) and then reuses the header's salt and KDF parameters with
  a fresh random 96-bit nonce and the same AEAD AAD. Keeping the salt is safe
  because the nonce is fresh; the GCM random-nonce birthday bound (~2^32
  writes for one key) is far beyond a local vault's lifetime. The file stays
  readable by the master password, the daemon's key stays valid, and `pm add`
  keeps the same header too (see the next bullet). `lock_for_update`
  byte-compares the container the CLI read before saving, so a concurrent
  human write becomes `VaultChanged`, not a lost
  update; that compare-and-lock is for commands with an unattended wait
  (a human typing) and stays local to them. A writer with no such wait in
  front of it — the daemon's `record_use` and `grant_revoke`, and
  `pm grant create` once the approval is spent — instead opens with
  `Vault::open_with_key_for_update`, which takes the lock *first* and reads
  the newest container, so a busily used vault can never turn a revocation or
  an approved creation into `internal` (TODO R.39). Interpreters are refused
  at approval time (`--allow-interpreter`),
  not by the digest: the CLI enforces it before proving the request.
  Implemented in TODO 3.4b as `crypto::encrypt_with_key` plus
  `Vault::save_with_key`; the latter also refuses, with `Error::Crypto`, a
  vault that has no source container (a brand-new file has no salt or KDF
  parameters to reuse).
  Implemented in TODO 3.4c: `grant_create` decodes into `GrantCreateRequest`,
  re-runs `GrantRequest::new` so the digest is always over the normalized
  request, and refuses an expiry outside `(now, now + 30 days]` with
  `bad_request` **before** `Approvals::take`, so the expiry rule can never
  spend a human's approval. Vault-level limits are a different owner: the
  daemon never opens the vault for this request, so `pm grant create` checks
  `Vault::check_grant_writable` (the writer's own `store::encode`) **before**
  it asks for the proof, and refuses a full vault with no approval spent
  (TODO R.22). That pre-check is advisory against a concurrent writer; the
  write lock still refuses a lost update. The wire fields
  are flat like `run` (no nested `request` object) and `grant_approved`
  carries nothing but its type. `MCP.md` carries the exact body the encoder
  emits for this request; `src/protocol/tests.rs` pins it as a literal and
  `tests/docs.rs` compares the document's example to the encoder, so the
  example cannot drift from the wire again (TODO R.24). The daemon still
  never writes; the CLI in 3.4d owns the vault write.
- The daemon canonicalizes `command[0]` itself (symlinks resolved), requires
  the result to stay absolute, and checks that canonical path against the
  grant's command allowlist. It then **spawns exactly that canonical path**,
  which also becomes the child's `argv[0]` (TODO R.34); the caller's path and
  name are never used for the exec. Before R.34 the daemon checked the
  canonical path but spawned the request path, so a symlink swapped after the
  check ran an unlisted program with the secret, and a caller-chosen link name
  selected the applet of a multi-call binary. A path it cannot canonicalize is
  refused. The MCP server resolves a bare/relative name for
  the agent's convenience, but the result is untrusted input: any same-user
  process can call the daemon, so only a check inside `pmd` counts. The
  protocol only requires an absolute path; canonicalization and the grant
  check are the daemon's job (TODO 3.6, extended by 4.5).
- A shell, interpreter or program runner in a command allowlist is refused
  unless the human passes `--allow-interpreter` (TODO 3.4d, R.25). Detection
  lives in `grant/validate.rs::is_program_runner` and is name-based on the
  canonical file name: a fixed table of shells and launchers, editors and
  pagers, tools with an exec option (`find`, `sed`, `tar`, `ssh`, `nc`),
  aliases/plugins CLIs (`git`, `gh`, `docker`, `kubectl`, …), build runners
  (`make`, `cargo`, `npm`, `go`, …), database clients (`psql`, `sqlite3`) and
  versioned `python`/`perl`/`ruby`/`node`/`php`/`lua`/`pwsh`/`julia`/`Rscript`
  names whose suffix starts with a digit or `.`. This is because a grant binds
  only `argv[0]`, which makes `git`, `gh` or `find` as powerful as a shell.
  Over-refusal is preferred (`pythonista` is not a runner; `python3.12` is),
  and `--allow-interpreter` is the human override. The table is best-effort and
  deliberately not treated as a boundary: allowing any program is trusting it
  with the value. Refusal happens before the password prompt, file creation or
  any daemon request; `src/grant.rs` and `tests/grant_cli.rs` (a fake `gh`) pin
  both the table and the end-to-end refusal.
- `pm grant create` shows the request and asks the human to confirm it before
  anything is written or the daemon is contacted (TODO R.26, R.41). The
  summary is stderr-only metadata: escaped label, the credentials behind the
  scope (each ref as `service (username) [pm://ref]`, each tag with every
  credential it currently matches), canonical commands, capabilities, expiry
  and use limit, plus one red warning per allowed program runner (bold ANSI
  only when stderr is a terminal, so a piped log gains no escapes). The master
  password comes *before* the summary, because those names live only in the
  encrypted vault and recognizing the credential is the point of the approval
  (TODO R.41 reversed the R.26 order here); the vault is dropped before the
  y/N so plaintext is not held while the human reads. Confirmation reads one
  line and accepts only `y`/`yes`, case-insensitive; a blank line, any other
  word or EOF exits 2 with "cancelled; nothing was written". Ordering is
  deliberate: request build, `--out` availability, password and vault unlock,
  vault-limit check and scope resolution (an unknown ref exits 3), then the
  summary and confirmation, then `load_session`, the token file and the
  daemon. A `n` therefore leaves no file, and an existing `--out` is still
  refused before the password. Display text uses `grant::escape_hidden`, which
  escapes only hidden characters so `Bob's token` keeps its apostrophe; error
  messages keep the quoted variant that also escapes quotes and backslashes.
  Paths taken from argv (`--out`) go through the same escape before they are
  echoed, on success and in the existing-file error, because an agent may
  have suggested the path (TODO R.29).
- Escaping lives in `src/text.rs`, which owns the hidden-character table and
  the three renderers (`escape_hidden`, `escape_quoted`, `escape_path`);
  `store` and `grant` validators escape the value they echo, and the CLI
  printer in `src/cli/mod.rs` escapes every error line again as a backstop
  (TODO R.30). The second pass is a no-op on already escaped text, so a
  message added later that forgets its own escape still cannot drive the
  terminal. `tests/cli_args_escape.rs` drives the real binary with an OSC 52
  payload in `--env` name/reference, `--ref`, `--expires`, `--length`, an
  unknown flag and `--db`, and fails on any raw ESC/BEL in either stream.
- `pm grant create` mints a `GrantToken` of 32 random bytes, held in
  `Zeroizing`, with a redacting `Debug`. Its lowercase hex is written only to
  `--out` (opened `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, then `fsync`); an
  existing file is refused, and a newly created file is unlinked if a later
  step fails. The token never goes to stdout/stderr. The vault stores only
  its SHA-256. The CLI derives the key once, opens the vault read-only to run
  `Vault::check_grant_writable` before `challenge`, then proves and sends
  `grant_create`, and only after `grant_approved` opens the vault with
  `open_with_key_for_update` (lock first, fresh state) and saves with
  `save_with_key` so the daemon's key stays valid. The lock is taken after the
  approval on purpose: a run that recorded a use while the human was deciding
  must not make the approved creation fail, and the grant is added to the
  state read under the lock, so that use is kept (TODO R.39).
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
- Grant tokens are minted by the MCP server itself (the claim secret) and
  sent to the daemon only as a SHA-256; the daemon never holds a token. They
  live in the MCP server's memory, are zeroized, and never appear in tool
  output or the audit log.
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
- Keep files under ~1,000 lines and split before growing past that.
  `tests/layout.rs` enforces the limit for every `src/**` and `tests/**` file;
  `PENDING_SPLITS` was a shrinking-only allowlist for the files TODO R.20 had
  not split yet and is now empty, so a new oversized file fails immediately.
  A split moves code mechanically (byte-identical bodies) into a sibling
  module, and its tests move with it rather than being rewritten.

## Open questions (not decided; do not cite as decisions)

- Should `generate` refuse or redact in agent context? It prints a fresh
  value, not a stored secret, but it is still plaintext on stdout.
- Should `pmd` warn when `mlock` fails? It is currently silent and non-fatal.
