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

## 2026-11-02 — Tags and timestamps in JSON (TODO 1.2b)

- TODO 1.2b: `list --json`, `show --json` entries now carry all six keys:
  `ref`, `service`, `username`, `tags`, `created`, `last_rotated`. The schema
  is unchanged elsewhere; `list` still prints exactly `{"entries":[...]}` and
  `show --json` the entry object. No password key exists by construction:
  `entry_metadata` only calls metadata getters.
- **Representation decision:** `tags` is always an array (sorted, deduped, as
  stored). `created` / `last_rotated` are RFC 3339 UTC strings
  (`2026-11-02T18:20:02Z`) and **`null` when the stored value is 0** (unknown,
  i.e. entries migrated from a pre-v4 payload). Chose strings over raw epoch
  integers because JSON here is the agent-facing surface: a UTC string is
  self-describing, has no timezone ambiguity, and fixed-width `...Z` strings
  sort chronologically, so an agent can use `>`. Storage still keeps raw
  `u64` seconds; this is presentation only.
- No new dependency. New module `src/timestamp.rs` exposes `format_utc(u64)
  -> String` and `to_json(u64) -> serde_json::Value`. `civil_from_days` is
  Howard Hinnant's exact proleptic-Gregorian algorithm, private, and total
  over the whole `u64` range (a value beyond the store bound would render a
  five-digit year instead of panicking; the store rejects those first). Values
  up to `store::MAX_TIMESTAMP_UNIX = 253402300799` all format with 4-digit
  years, up to `9999-12-31T23:59:59Z`.
- Tests: 13 known formatting vectors from `date -u` (epoch, day boundary,
  2000-02-29 leap century, 2024-02-29, 2100-01-01 non-leap century, y2038,
  max timestamp); leap-year contiguity test (each day strictly increasing,
  fixed 20-byte width, Feb 29 -> Mar 1); `to_json(0)` is `null` while
  `format_utc(0)` is the epoch. Two bin tests decode a hand-built store-v4
  payload (private `STORE_VERSION` is not exported, so the literal `4` is
  documented there) to prove zero timestamps render `null` and nonzero ones
  render exact strings, tags render sorted, and the password is absent from
  both the `Value` and its serialization. E2E
  `show_and_list_json_expose_metadata_only` now tags the entry during the
  rename edit, asserts the sorted `tags` array, asserts `created` is a
  20-byte `...Z` string, and asserts `created == last_rotated` after a
  metadata-only edit. `tags_are_stored_filtered_and_metadata_only` was
  updated from "JSON omits tags for now" to asserting the sorted tag arrays
  (same intent, new schema).
- Docs: README machine-readable section now shows a full entry example and
  documents `null`; Tags and Timestamps (security) bullets corrected.
- Gate: `cargo fmt --check` clean, clippy `--all-targets -D warnings` clean,
  `cargo test` 100 passed (54 lib + 19 bin + 27 e2e). `cargo audit` still not
  installed (`error: no such command: audit`); dependencies unchanged.
- **Next iteration must know:** Phase 1 is complete. Next is **2.1**
  (length-prefixed JSON protocol module, pure functions, max message size).
  The JSON schema for entry metadata should be treated as stable; if a field
  is ever added, agents already tolerate new keys, but never add `password`.
  `src/timestamp.rs` is the only place timestamp formatting lives.

## 2026-11-02 — Created/last-rotated timestamps (TODO 1.4, unblocks 1.2b)

- TODO 1.2b was the first unchecked item but was **blocked on 1.4**, so this
  iteration did 1.4 (the blocker). 1.2b is now unblocked and is next.
- Store **version 4**: each credential in the encrypted payload now carries
  `u64 created` and `u64 last_rotated` immediately after the 16-byte id. Both
  are Unix seconds UTC. Layout: `u8 version | u32 count | { id[16], created,
  last_rotated, service, username, password, tags }`. Container and crypto are
  unchanged (still container v2, same Argon2id/AES-GCM params).
- `created` is set by `Credential::new` together with `last_rotated` (adding a
  credential counts as its first rotation) and never changes afterwards.
  `Credential::set_password` is the only mutator that moves `last_rotated`; it
  reads the clock **before** validating/replacing, so a rejected password (e.g.
  empty) leaves both password and timestamp untouched. Public getters
  `created_unix()` / `last_rotated_unix()`.
- Migration: versions 1, 2 and 3 still decode. Pre-v4 entries get `created =
  last_rotated = 0`, documented as "unknown", rather than inventing a date at
  migration time; the next save writes version 4 and preserves the zeros. So a
  migrated entry has no known creation time; 1.2b must render `0` as
  unknown/absent, not 1970-01-01.
- Validation: timestamps above `store::MAX_TIMESTAMP_UNIX = 253_402_300_799`
  (9999-12-31T23:59:59Z) are `MalformedVault` (exit 6) on read and
  `InvalidInput` (exit 2) on write, so a hand-crafted payload cannot overflow
  future date rendering. `created > last_rotated` is **not** rejected: a clock
  that moves backwards is legitimate, and enforcing order would fail closed on
  real vaults for no security gain.
- Clock failure (system time before the Unix epoch or past the bound) returns
  `Error::Io` (exit 1) instead of adding an error variant; it is an environment
  failure, not user input.
- Precision is whole seconds. A rotation within the same second as the previous
  one leaves `last_rotated` numerically unchanged; tests therefore assert `>=`
  where the real clock is involved and use a crafted private field for the
  deterministic "rotation moves the timestamp" proof.
- Tests: store unit tests for the v4 round-trip (timestamps preserved), a new
  hand-built **v3** payload migrating with id/tags intact and timestamps 0,
  empty vault now `04 00 00 00 00`, v1/v2 migration timestamps 0, timestamp
  range rejection on both read and write, and a deterministic rotation test
  (created immutable, last_rotated moves, rejected password does not move it).
  Vault test `timestamps_survive_saves_and_rotation_keeps_created`; e2e
  `edit_rotates_the_password_without_printing_it` now captures `created`
  before the edit and asserts it is unchanged after rotating. No secret bytes
  are involved (timestamps are metadata).
- Docs: `FORMAT.md` payload v4, migration and timestamp rules; README security
  section gains a Timestamps bullet; `store.rs` module doc updated.
- Gate: `cargo fmt --check` clean, clippy `--all-targets -D warnings` clean,
  `cargo test` 95 passed (51 lib + 17 bin + 27 e2e, ~147 s). `cargo audit`
  still not installed (`error: no such command: audit`); no dependency changed.
- **Next iteration must know:** do **1.2b** (add `tags`, `created`,
  `last_rotated` to `entry_metadata` in `src/main.rs` and to text output if
  desired). Decide the JSON representation there: raw Unix seconds are the
  stored form; if ISO-8601 is wanted, either hand-roll days-from-civil or add a
  justified date dependency. Do not put `password` anywhere near that struct.

## 2026-11-02 — Tags on credentials (TODO 1.3)

- Implemented per-credential tags and store **version 3**. Payload gains
  `u32 tag count` plus `u32 length + UTF-8 bytes` per tag, sorted and
  duplicate-free. Versions 1 (no ids) and 2 (no tags) are still read and are
  rewritten as version 3 on save; the container stays v2 and the crypto
  parameters are unchanged.
- Tag rules (enforced on write **and** read, so a hand-crafted payload fails
  closed): 1-32 bytes, first byte ASCII lowercase letter or digit, remaining
  bytes `[a-z0-9._-]`, max 32 tags per credential. Invalid tags map to
  `InvalidInput`/exit 2 at the CLI, before any password prompt; malformed
  payload tags map to `MalformedVault`.
- CLI: `add --tag TAG` and `edit --tag TAG` (repeatable; `edit` replaces the
  whole set), `edit --clear-tags`, `list [--json] [--tag TAG]`. `list --tag` is
  an AND filter. Text output adds a `tags: a, b` line under each listing entry
  and a `Tags: a, b` line in `get`/`show`; both are omitted when untagged.
  Tags are metadata only and are deliberately **not** in JSON output yet:
  TODO 1.2b adds `tags`/`created`/`last_rotated` together in one schema change.
- `edit` now treats `--tag`/`--clear-tags` (without `--generate`) as
  metadata-only: it does not rotate the password and does not prompt for a new
  one. `--clear-tags` combined with `--tag` is a usage error.
- No new dependencies. `serde_json` was already present.
- Tests: store round-trip, v1→v3 and v2→v3 migration, tag validation (case,
  whitespace, control chars, non-ASCII, leading `-`/`_`/`.`, length, count),
  malformed payload duplicate/excess tags, vault filtering + persistence,
  CLI parser tests, and an e2e test covering add/list/filter/edit/clear,
  invalid-tag exit code 2, JSON omitting tags, and the secret never appearing
  on stdout/stderr.
- Gate: `cargo fmt --check` clean, clippy clean, `cargo test` 64 unit (47 lib + 17 bin) + 27 e2e
  passed (~141 s; e2e is Argon2id-bound and serialized). `cargo audit` is still
  not installed (`error: no such command: audit`), so that gate step remains
  skipped; no dependency changed this iteration.
- README (`Tags` section, `get`/`list`/`edit` examples) and `FORMAT.md`
  (payload v3, migration, tag validation) updated.
- **Next iteration must know:** 1.2b is still blocked on 1.4 but tags are now
  available to add to the JSON schema. Nothing about the daemon/grant work has
  started. `Vault::list_tagged` returns `&Credential` references; grant scope
  can reuse `Credential::has_all_tags`.

# Progress log

Newest entries first. Date, what was done, what the next iteration must know.

## 2026-11-02 — TODO 1.2a: `list --json` and `show <ref>`

- TODO 1.2 was split: this iteration did the JSON/reference half with the
  metadata that exists today. **1.2b** (adding `tags`, `created`,
  `last_rotated` to the JSON entry) stays unchecked until 1.3 and 1.4 land;
  adding keys later is backward compatible, so the schema is stable in the
  "agents must tolerate unknown keys" sense.
- New command `show [--json] <ref>`: accepts **only** a full `pm://<32 hex>`
  reference (parsed with `store::EntryId::parse_ref` *before* unlocking, so a
  bad reference is exit 2 and costs no password prompt). A well-formed but
  unknown reference returns the new `Error::EntryNotFound` (exit 3,
  "no credential found for reference '<ref>'"). Text output is `Ref`,
  `Service`, `Username` — no password line at all. A service name passed to
  `show` is a usage error (exit 2); references are the unambiguous handle.
- `list --json` prints exactly one JSON document, `{"entries":[{"ref":...,
  "service":...,"username":...}]}`, plus a newline, and nothing else on stdout
  (no "Stored Services:" header; the empty-vault "No credentials stored." prose
  goes to stderr only in text mode, so an empty vault is `{"entries":[]}`).
  `show --json` prints the entry object directly. The flag may appear before or
  after the positional argument.
- No-value guarantee is structural: `entry_metadata(&Credential)` in
  `src/main.rs` only ever reads `reference()`, `service()` and `username()`;
  `Credential::password()` is never called there. Do not "tidy" it into a
  serde-derived struct on `Credential`, which could add a password field by
  accident.
- **Dependency added:** `serde_json = "1"` (pulls `serde`, `serde_core`,
  `itoa`, `memchr`, `zmij`; no derive feature). Justification: correct JSON
  escaping of arbitrary UTF-8 metadata (quotes, backslashes, non-ASCII) is
  security-relevant output encoding; hand-rolling it risks malformed or
  ambiguous documents for agents to parse. It makes no network calls. No
  `serde` derive is enabled, so there is no `Serialize` impl on `Credential`.
- Library additions: `Vault::get_by_ref(&self, EntryId) -> Option<&Credential>`
  and `Error::EntryNotFound(String)` (mapped to `EXIT_NOT_FOUND`); unrelated
  error variants untouched. No store-format or crypto change.
- CLI parsing: `Command::List { json }` and `Command::Show { reference, json }`;
  `parse_list` rejects any argument other than `--json`; `parse_show` mirrors
  `parse_get` (supports `--`, rejects `--reveal` with exit 2).
- Docs: `--help` lists both commands and the JSON keys, README gains a
  "Machine-readable metadata" section.
- Tests: 2 new `src/main.rs` parser tests (`parses_list_and_show_json` and
  updated `Command::List` patterns), 1 new `src/vault.rs` test
  (`lookup_by_reference_is_stable_across_renames`), 1 new error-code case,
  3 new e2e tests in `tests/cli.rs`:
  `show_and_list_json_expose_metadata_only`,
  `json_output_escapes_metadata` (service `quote"back\slashé` round-trips),
  `show_rejects_bad_and_unknown_references` (exit 2 without prompting, exit 3
  for unknown, empty vault JSON, `--help` mentions both commands). All e2e
  assertions check the stored password is absent from stdout and stderr.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings`
  clean, `cargo test` 84 passed (42 lib unit + 16 main unit + 26 e2e, ~125 s;
  e2e serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** next unchecked item is **1.3 tags**
  (`--tag`, `list --tag`). Tags will also need a store-format bump (version 3)
  with a v2 migration reader, reusing the 1.1 pattern; keep `Credential::new`'s
  signature stable or add `with_tags`. Add tag filtering to `list` and a
  `--tag` field in `entry_metadata` only in 1.2b.

## 2026-11-02 — TODO 1.1: stable entry references (`pm://<id>`)

- `src/store.rs` store version 2: each credential now begins with a 16-byte
  random `EntryId` in the encrypted payload. `Credential::new` generates the id
  from `getrandom::fill` (no new dependency); decode checks uniqueness and
  rejects duplicate ids as `MalformedVault`.
- New public API in `src/store.rs`: `EntryId` (`generate`, `to_hex`, `to_ref`,
  `from_hex`, `parse_ref`, `Hash`/`Eq`, `Display`/`Debug`), `ENTRY_ID_BYTES`,
  `Credential::id()` and `Credential::reference()`. `Credential::with_id` is the
  private constructor used by the decoder; validation is unchanged.
- Reference syntax is `pm://` + exactly 32 hex chars, lower-cased on parse;
  upper-case input is accepted. **Decision:** no `pm://<service>#<prefix>` form
  and no id prefixes — a partial reference would be ambiguous, so the full id is
  required. Parse failures are `InvalidInput` (exit 2). The id is metadata, not
  a secret, so it is safe on stdout/stderr.
- Migration: `decode` accepts store version 1 (same layout without ids), gives
  each credential a fresh id in memory, and the next `save` writes version 2.
  No crypto or container change; the container format version stays 2 and the
  salt/nonce handling is untouched. Empty vault is now `02 00 00 00 00`;
  version 1 empty payloads are still accepted.
- CLI: `get` output gains a leading `Ref: pm://<id>` line (both metadata and
  `--reveal` modes, since the ref is not a secret); `list` lines are now
  `- <service> (<username>) [pm://<id>]`. `--help` and README document the
  reference. No new commands yet; `show <ref>` is TODO 1.2.
- `FORMAT.md`: payload section updated to version 2 with the id field, plus
  migration and duplicate-id rules.
- Tests: 6 new/updated unit tests in `src/store.rs` (v2 round-trip preserving
  ids, v1 payload migration with no data loss, unique/stable ids across
  encode/decode, hex/ref parsing incl. rejects, duplicate-id rejection,
  oversized-length now with an id) and 1 new `src/vault.rs` test
  (`entry_ids_are_stable_across_vault_saves`, including rename stability).
  1 new e2e test `entry_references_are_stable_and_leak_no_secrets`; exact-output
  e2e assertions updated for the new `Ref:`/`[pm://...]` formats (still assert
  `EXAMPLE_SECRET` is absent).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 79 passed (41 lib unit + 15 main unit + 23 e2e, ~97 s;
  e2e serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** TODO 1.2 (`list --json` + `show <ref>`). Resolve
  references with `passmgr::store::EntryId::parse_ref` and compare against
  `Credential::id()`; there is deliberately no `Vault::get_by_ref` yet, add one
  if it keeps 1.2 clean. Old vaults (store v1) are migrated on the first save,
  so ids are stable from that point on but a v1 vault gets new ids once.

## 2026-11-02 — TODO 0.6: `rm` alias and `edit`

- `rm <service>` is a pure alias for `delete`: `parse_command` routes both
  through `parse_single_argument(&command, rest).map(Command::Delete)`, so
  messages and exit code 3 for an unknown service are identical.
- New `edit <service> [--username U] [--rename NAME] [--generate]
  [--strong|--simple|--pin] [--length N]`. `--rename` was added beyond the
  TODO wording so a service can actually be renamed (the item's test list
  required it).
- Rotation rule is a pure function, `edit_rotates_password(&EditOptions)`:
  a bare `edit` or `--generate` rotates; `--username` and/or `--rename`
  without `--generate` is a metadata-only edit and does **not** prompt for a
  password. Rotating prompts for the new value twice through the existing
  no-echo `terminal::prompt_password` (`prompt_credential_password`), then
  saves. `--generate` stores a fresh value and prints only the entry name, so
  no secret reaches stdout/stderr.
- Ordering: non-secret inputs are validated before `unlock`; the service is
  looked up before any replacement-password prompt, so an unknown service
  exits 3 without consuming a password prompt. Renaming onto an existing
  service fails with `DuplicateService` (exit 1); renaming to the same name is
  a no-op. Renaming happens before the username/password update, and all
  follow-up mutations use the new name.
- New library API: `store::validate_service`, `store::validate_username`
  (`validate_identity` now composes them), `Credential::set_service`,
  `set_username`, `set_password` (each validates and leaves the value
  untouched on error), `Vault::get_mut` and `Vault::rename`.
- Docs: `--help`, README (new "Edit a credential" section, `rm` alias) updated.
  No store-format or crypto changes.
- Tests: one new setter unit test in `src/store.rs` and one new vault test
  (`renaming_and_editing_credentials`), 3 new parsing/decision tests in
  `src/main.rs` (`parses_edit_metadata_and_generation_options`,
  `edit_rejects_bad_arguments`, `rm_is_an_alias_for_delete`), and 5 new e2e
  tests in `tests/cli.rs` (rotate with no secret bytes, rename+username with
  the old name returning 3, generated replacement not printed, unknown service
  exits 3 before the password prompt, `rm` parity).
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 73 passed (36 lib unit + 15 main unit + 22 e2e, ~77 s;
  e2e is serialized on Argon2 memory). `cargo audit` still not installed
  (`error: no such command: audit`).
- **Next iteration must know:** Phase 0 is complete; next is TODO 1.1 (stable
  entry ids + store version 2 migration). There is no `run`/daemon yet, so
  `edit` still opens the vault directly with a TTY prompt.

## 2026-11-02 — TODO 0.5: stable exit codes

- `src/error.rs` now owns the CLI exit-code contract: public `EXIT_OK` (0),
  `EXIT_FAILURE` (1), `EXIT_USAGE` (2), `EXIT_NOT_FOUND` (3),
  `EXIT_AUTH_FAILED` (4), `EXIT_REFUSED` (5), `EXIT_MALFORMED_VAULT` (6), plus
  `Error::exit_code()`. Re-exported from `src/lib.rs`.
- Mapping: `VaultNotFound`/`ServiceNotFound` → 3; `AuthenticationFailed` → 4;
  `Refused` → 5; `NotAVault`/`LegacyVault`/`UnsupportedVersion`/
  `UnsupportedFormat`/`MalformedVault` → 6; `InvalidInput` → 2 (invalid input at
  a prompt is treated as usage, e.g. empty master password); `Io`/`Crypto`/
  `DuplicateService` → 1 (generic failure).
- Decision: `Crypto` stays at 1, not 6. It also covers RNG and cipher-setup
  failures during save, which are not a malformed vault file. Vault corruption
  at read time surfaces as `MalformedVault` (6) or `AuthenticationFailed` (4).
- `src/main.rs`: `main()` no longer hardcodes 1/5; it prints via
  `report_runtime_error` and exits with `error.exit_code()`. BrokenPipe still
  exits 0. `CliError::Usage` uses `EXIT_USAGE`. The removed
  `CliError::Runtime(Error::Refused(..))` arm produced identical output because
  `Error::Refused` Display is the message and `report_runtime_error` adds no
  hint for it.
- `--help` and README now document all six codes (README table replaced).
- Tests: new `error.rs` unit test asserts every variant's code and the numeric
  constants; new e2e `exit_codes_are_stable` covers unknown service (3), wrong
  password (4), truncated vault (6 + "malformed vault"), non-vault file (6),
  empty master password (2), unknown option (2), and greps `--help` for each
  documented code. Existing e2e expectations updated: wrong password 1→4,
  missing vault 1→3, legacy vault 1→6.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 63 passed (34 lib unit + 12 main unit + 17 e2e, ~51 s).
  `cargo audit` still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.6 (`rm` alias + `edit`) is next. Use the
  `EXIT_*` constants for any new exit path; do not hardcode numbers. `rm` is a
  pure alias, so route it to `Command::Delete`. `edit` will need the vault
  password re-prompted twice for a rotation and should return 3 for an unknown
  service.

## 2026-11-02 — TODO 0.4: global `--agent` flag

- `src/agent.rs` now models the signal source explicitly: new
  `pub enum AgentSource { Env(&'static str), Flag }` and
  `RevealRefusal::AgentContext(AgentSource)`. `reveal_refusal` takes
  `Option<AgentSource>` (was `Option<&'static str>`), and the message renders
  either "`NAME` is set" or "the --agent flag was passed".
- New `agent::agent_source(agent_flag: bool)` resolves env marker first, then
  the flag; `agent::check_reveal(agent_flag: bool)` now takes the flag. The flag
  can only *add* refusal — `agent_source(false)` is `None` and every existing
  terminal/marker decision is unchanged.
- `src/main.rs`: `Parsed { db_path, agent, command }`; `--agent` is parsed in
  the global-option loop beside `--db` and is a bare boolean (repeating it is
  harmless). `command_get(service, reveal, agent_mode, path)` passes it to
  `check_reveal`, still **before** `unlock`, so a refused reveal never prompts
  or opens the vault. `USAGE`, `HELP` and README updated, including
  "global options must come before the command".
- Decision: `--agent` is global-prefix only (`passmgr --agent get ...`).
  `passmgr get --agent ...` is a usage error (exit 2) rather than silently
  ignored — one placement rule, no ambiguity with `--`. Documented in help and
  asserted by a test.
- Tests: 3 new unit tests in `src/agent.rs` (flag refuses with two terminals;
  flag cannot weaken the check; env marker reported before the flag) plus an
  extended message test. 2 new unit tests in `src/main.rs` (parsing before the
  command, including repeats and `--help`; bare-flag/placement errors). 4 new
  e2e tests in `tests/cli.rs`: `--agent` blocks reveal on a full pty, blocks it
  over pipes (exit 5, stderr names `--agent`, no secret bytes), metadata
  `get`/`list` still work under `--agent`, and `--agent` is documented/rejected
  after the command.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 61 passed (33 lib unit + 12 main unit + 16 e2e, ~47 s).
  `cargo audit` still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.5 (stable exit codes) is next;
  `Error::Refused` maps to 5, everything else still exits 1. `--agent` currently
  affects only reveal; TODO 4.x will extend it to JSON/help behavior.

## 2026-11-02 — TODO 0.3: `add --generate` no longer prints the password

- `src/main.rs::command_add` no longer prints `Generated password: <value>`.
  The generated value is still stored; stdout is now empty for `add --generate`
  and stderr prints `Credential '<service>' added successfully with a generated
  password.` (entry name only). The non-generate path still prints
  `Credential added successfully.` so existing assertions hold.
- The generated value is only obtainable through the TTY-gated
  `get --reveal` (or in-process `Vault::open`). No new bypass.
- `tests/cli.rs::generated_add_then_get_returns_same_password` now reads the
  stored value in-process via `vault_password`, asserts stdout is exactly empty,
  asserts neither stream contains the generated bytes, asserts the confirmation
  names the entry, and re-checks the stored value is unchanged.
- README (`add` section) and `--help` updated: `--generate` stores but never
  prints; read back with `get --reveal`.
- Gate: `cargo fmt --check` clean, `cargo clippy --all-targets -- -D warnings`
  clean, `cargo test` 52 passed (30 lib unit + 10 main unit + 12 e2e, ~34 s).
  `cargo audit` is still not installed (`error: no such command: audit`).
- **Next iteration must know:** TODO 0.4 is next (`--agent` global flag wired
  into `agent::check_reveal`). Note for review: the standalone `generate`
  command (`src/main.rs::command_generate`) still prints a freshly generated
  password to stdout. It exposes no stored secret and is a human-facing
  generator, so it is out of scope for 0.3, but decide in a later item whether
  agent mode should refuse or redact it too.

## 2026-11-02 — TODO 0.2: `--reveal` gated on a TTY and agent context

- New `src/agent.rs`: `AGENT_MARKERS` (`PASSMGR_AGENT`, `CLAUDECODE`,
  `CURSOR_AGENT`, `CODEX_SANDBOX`), `agent_marker()`, `is_agent_context()`,
  pure decision fn `reveal_refusal(stdin_tty, stdout_tty, marker)` returning
  `RevealRefusal` (`AgentContext(marker)` / `StdinNotTerminal` /
  `StdoutNotTerminal`), and `check_reveal()` which wires in `IsTerminal` + env.
- `command_get` calls `check_reveal()` **before** `unlock`, so a refused reveal
  never opens the vault or prompts for the master password. No bypass flag.
- `Error::Refused(String)` added (`src/error.rs`, Display prints the message
  verbatim) and `main()` maps it to exit code 5. This is the first piece of TODO
  0.5; other errors still exit 1.
- Design choice: an agent marker counts when **present**, even with an empty
  value (conservative). Precedence in the refusal reason: marker → stdin →
  stdout.
- `src/lib.rs` exposes `pub mod agent`.
- Tests: 5 new unit tests in `src/agent.rs` (all markers, unrelated vars,
  all four terminal combinations, marker precedence, message text). `tests/cli.rs`
  now strips agent markers from the test environment (`base_command`), asserts
  piped `get --reveal` → exit 5 with no secret, loops all four markers, and adds
  Linux-only pty tests via `posix_openpt`/`ptsname` (`run_on_pty`, `read_pty`,
  handles EIO after child exit): stdout-piped refusal, success on a real pty, and
  `PASSMGR_AGENT=1` refused even on a pty. Piped reveal success assertions were
  replaced with an in-process `passmgr::Vault::open` read (`vault_password`).
- README and `--help` updated: exit 5 meaning, both-terminals rule, marker list,
  "no bypass".
- Gate: `cargo fmt --check` clean, clippy `-D warnings` clean, `cargo test`
  52 passed (30 lib unit + 10 main unit + 12 e2e, ~35 s). `cargo audit` still not
  installed on this machine (only unverified gate step).
- **Next iteration must know:** TODO 0.4's `--agent` flag must feed into
  `agent::check_reveal` so it *adds* refusal; `agent.rs` already holds the
  decision. TODO 0.3 (`add --generate` printing the secret) is untouched.
  Piped `--reveal` in docs/tests is now expected to fail with 5. The pty tests
  are `#[cfg(target_os = "linux")]`; macOS relies on the unit tests for the
  decision logic.

## 2026-11-02 — TODO 0.1: `get` is metadata-only, `--reveal` added

- `passmgr get <service>` now prints `Password: <redacted>` and never the stored
  value. Plaintext requires `get --reveal <service>`; `--reveal` is parsed before
  or after the service name. This is the only plaintext path from `get`.
- `src/main.rs`: `Command::Get` became `Command::Get { service, reveal }`, added
  `parse_get` (mirrors `parse_add` arg handling: `--`, `-h/--help`, rejects
  unknown flags and more than one positional). Unit tests
  `get_reveals_only_with_the_flag` / `get_rejects_bad_arguments` assert the
  default is not-reveal.
- `tests/cli.rs`: `EXAMPLE_SECRET` fixture replaced plain `secret`; new assertions
  prove plain `get` contains no secret bytes on stdout or stderr, and that
  `--reveal` still returns the value. Tests still use the piped CLI for
  `--reveal` — TODO 0.2 must change that to an in-process read once the TTY gate
  lands (a piped `--reveal` will then be refused).
- Gate: `cargo fmt --check` clean, clippy clean, `cargo test` 17 passed (10 unit
  + 7 e2e). `cargo audit` still not installed (see previous entry).
- **Next iteration must know:** `add --generate` still prints
  `Generated password: <value>` to stdout — that is TODO 0.3, untouched here.
  `--reveal` currently has **no TTY/agent check** (TODO 0.2); do not ship before
  0.2.
- README updated in the same commit (the `get` section and the flag semantics).

## 2026-11-02 — Bootstrap plan (no feature work)

- Repo state: existing Rust CLI (commit `f93b765` "rust rewrite") with Argon2id +
  AES-256-GCM, atomic saves, 0600 vault, password generator, `add`/`get`/`delete`/
  `list`/`generate`. Legacy C implementation archived in `legacy-c/`. No
  `PROGRESS.md`/`TODO.md` existed, so this iteration only wrote them (per the
  iteration protocol).
- Gate baseline at start of this iteration: `cargo fmt --check` clean,
  `cargo clippy --all-targets -- -D warnings` clean, `cargo test` 15 passed
  (8 unit + 7 e2e in `tests/cli.rs`, ~20 s — e2e cost is Argon2id at default
  params, acceptable). `cargo audit` is **not installed** on this machine; the
  gate step is skipped until it is, verify manually with `cargo tree` if needed.
- Wrote `TODO.md`: 5 phases, 24 items, ordered. Phase 0 fixes existing invariant
  violations before any new feature.
- Decisions recorded:
  - **Crypto approach stays the custom container** (Argon2id + AES-256-GCM,
    `FORMAT.md` v2), not `age`. Already implemented and documented; do not mix
    the two. No crypto parameter changes without a migration note.
  - Store format is versioned separately from the container; adding entry ids,
    tags and timestamps (TODO 1.1/1.3/1.4) requires store version 2 **with a
    version 1 reader**, no crypto change.
- **Known invariant violations in current code** (must be fixed in Phase 0, listed
  so they are not forgotten):
  - `src/main.rs::command_get` prints `Password: <plaintext>` to stdout with no
    TTY check and no `--reveal` flag.
  - `src/main.rs::command_add` prints `Generated password: <plaintext>` on
    `--generate`.
- README documents `get` as printing the password; it must be updated in the same
  commit as TODO 0.1/0.2.
- No `NEEDS HUMAN REVIEW` items yet.
