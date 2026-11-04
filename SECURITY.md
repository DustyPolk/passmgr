# Security

passmgr exists so an AI agent can **use** a credential without ever seeing its
value. This document states what that guarantee covers, what it does not cover,
and which residual risks are accepted on purpose.

It is the canonical list of limits. If code and this document disagree, either
the code is wrong or this document must be updated in the same commit. Do not
"fix" a limit listed here by weakening a check (for example, by removing the
TTY gate or the redactor).

## Current status

Grant-based authorization is implemented for `run` (TODO 3.1–3.6): every
agent-facing use needs a grant token that matches an active, in-scope grant in
the vault, and the daemon records the use before it injects. Every `run` that
reaches `pmd` appends one metadata-only record to the hash-chained audit log
at `$XDG_STATE_HOME/passmgr/audit.jsonl` (TODO 3.8); the `pm audit` reader and
`pm audit verify` are still open (TODO 3.9). `run` also has a human-only local
path (TODO 3.7): without a grant token, at a terminal, the CLI prompts for the
master password, opens the named vault, and injects under the same TTY/agent
gate as reveal. A local run is audited too, with `source: local` and no grant.
Any process running as the same user can read the 0600 session file, so:

- `passmgr run` is the agent-facing way to use a secret, and it prevents
  *accidental* exposure: the value never crosses the socket, and relayed child
  output is redacted before it leaves `pmd`.
- `run` requires a human-created grant token in addition to the session
  token. The session token authorizes only `ping`, `lock`, `challenge`,
  `prove`, `grant_create` and `grant_revoke`; it can never inject a secret by
  itself, and `grant_create` still requires the human-presence proof. A
  same-user process that can read the session file still needs a grant token
  file whose grant covers the credential and command.

The MCP server (`pm mcp serve`, `MCP.md`) is a contract at this point, not
implemented code. Once implemented it is a thin client of the same daemon and
inherits every limit below.

## What passmgr protects

- **No plaintext request.** The daemon has no request type that returns a
  plaintext value, and never will. Every agent-facing surface returns
  references and metadata only: refs, names, usernames, tags, field names,
  URLs and timestamps.
- **Use, not read.** Secrets reach a child through the daemon (environment
  injection today; stdin and 0600 temp-file injection are planned, TODO 5.x),
  except on the human-only local `run`, where the CLI injects after the same
  TTY/agent gate and the value never crosses a socket.
- **Reveal is human-only.** `get --reveal` requires stdin *and* stdout to be
  terminals, no agent marker environment variable (`PASSMGR_AGENT`,
  `CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`), and no `--agent` flag. The
  master password is prompted on every invocation, and no flag bypasses the
  check. Refusal happens before the vault is opened or a password is prompted.
- **Redaction.** Child stdout and stderr are passed through a streaming
  redactor in `pmd`, or by the CLI for a human-only local `run`, that replaces
  exact occurrences of the injected value, including values split across read
  and frame boundaries.
- **Terminal safety for untrusted text.** Text passmgr prints about a value
  from an argument or from the vault is rendered with hidden characters (C0/C1
  controls, bidi controls, zero-width and other format characters, line
  separators and variation selectors) written as visible `\u{..}` escapes.
  This covers every error line and every argv value the CLI echoes (a
  reference, tag, field name, `--env` name, duration, flag or `--db`/`--out`
  path), plus stored names printed by `list`, `get`, `show` and the grant
  approval summary. New service names, usernames, grant labels, command paths,
  tags and field names are refused at validation when they contain one of
  those characters, so a name this build writes is shown exactly as stored; a
  vault written by an earlier build may hold one, and it is escaped wherever
  it is printed. Validators escape the value they reject and the CLI printer
  escapes every error line again as a backstop, so agent-supplied argv cannot
  emit an OSC 52 clipboard write or erase the line it is printed on. `--json`
  is a data channel, not a terminal: it keeps the stored bytes.
- **Daemon hardening.** `pmd` keeps only the derived 32-byte vault key, not a
  decrypted vault, in `mlock`ed memory. It disables core dumps
  (`RLIMIT_CORE=0`, inherited by its children) and, on Linux, sets
  `PR_SET_DUMPABLE=0`. Every request is checked against the peer uid before it
  is read; malformed and unauthorized requests never refresh the idle timer.
  Accepting a `run` does refresh it, and the idle deadline is suspended while
  a run is in flight, so a long command is not killed mid-work; `lock` and
  signals still cancel it. A run whose client connection is closed is
  cancelled as well (its whole process group is killed), so an agent host that
  drops a timed-out tool call cannot keep the key alive or leave the child
  running with the secret in its environment. A client that shuts down only
  its write half is still reading and keeps its run. At most 16 `run` requests
  are served at once; a request beyond that is answered `busy` before the
  vault is opened, so no child starts and no reader thread or injected
  environment is created.
- **Vault.** Argon2id + AES-256-GCM, authenticated header, atomic 0600 writes,
  zeroized keys and plaintext. Mutating commands hold an exclusive `flock` on
  the sidecar `<vault>.lock` across the whole read-modify-write, so concurrent
  writers cannot lose an update; interactive prompts happen before the lock is
  taken, and a vault that changed meanwhile is refused rather than overwritten.
  Details are in `README.md` and `FORMAT.md`.
- **No network.** passmgr makes no network calls and links no network-capable
  crate. MCP is stdio only.
- **Grants, per `MCP.md`:** scoped, expiring, use-limited, revocable grants
  that a human approves with the master password at a TTY. `pm grant create`
  mints the token in the human's CLI; the vault stores only its SHA-256, and
  `run` requires a token whose grant covers the credential and command.
  Grants can be listed and revoked; revocation needs no password or TTY
  because it only removes access, and the daemon persists it in the vault
  with the key it already holds. A running `pmd` also remembers the furthest
  `uses` and any revocation it has seen per grant id, so putting an older
  vault back cannot undo either (limit 7). The hash-chained audit log records
  every allowed and denied `run` without values or tokens (TODO 3.8); the
  `pm audit` reader and chain verifier are still open (TODO 3.9).

## Known limits

These are consequences of the design, not bugs to paper over. Each is accepted
deliberately; removing one requires a different injection or sandboxing
mechanism, not a weaker check.

### 1. A same-user process can read an injected value from `/proc`

The child receives the value in its environment. While the child is running,
**any process running as the same user can read `/proc/<pid>/environ`** on
Linux and obtain the value. `PR_SET_DUMPABLE=0` hardens `pmd` itself (it blocks
`/proc/<pid>/mem` and `ptrace` of the daemon by same-uid processes on Linux);
it does not apply to the child, which is a separate process. macOS has no
`PR_SET_DUMPABLE` equivalent set by passmgr, so same-user `ptrace`/memory
inspection of `pmd` is not closed here, even though core dumps are disabled.

The run's whole process group is killed when the run ends -- on a cancel and
on normal completion -- so a background process that a child leaves behind
(an `ssh` `ControlPersist` master, a build daemon, a credential cache) does
not keep the value after the run, after `lock` or after `pmd` exits. A
descendant that starts a new session (`setsid`) leaves the group and escapes
that cleanup: passmgr cannot find it afterwards, so such a survivor can keep
the value in its environment indefinitely. Start long-lived services outside
a passmgr run, without the credential.

Consequences:

- passmgr prevents accidents and makes deliberate misuse require an explicit
  human grant. It does not defend against malware already running as you.
- A grant bounds what a *cooperating* agent may do. It cannot stop a hostile
  same-user process, which can read the value directly and does not need the
  grant.
- Stdin injection or a 0600 temp file (TODO 5.x) narrows the window but does
  not close this class of attack: a same-user process can still read
  `/proc/<pid>/mem`, open the temp file, or attach to the child when permitted.

### 2. A shell, interpreter or program runner in a command allowlist can exfiltrate

A grant binds a canonical absolute path and the daemon checks only `argv[0]`,
so any allowed program that can execute another one is equivalent to handing
the agent the secret: a shell or language runtime obviously, but equally `git`
(`git -c alias.pwn='!cmd' pwn`), `gh` (`gh alias set --shell pwn ...`), `find
-exec`, `tar --to-command`, `sed`'s `e` command, `ssh`'s `ProxyCommand`, an
editor or pager with a shell escape, `docker`/`podman`/`kubectl`, `make`,
`cargo`, `npm`, `psql`, `sqlite3` and many others. The program can read the
injected variable, transform it, and write it anywhere, and redaction cannot
follow a transformation (see limit 3).

Mitigations: a name table of well-known shells, interpreters and program
runners is refused in a grant's command allowlist unless the human passes
`--allow-interpreter`; grant the specific binary a workflow needs. The table
is best-effort, not a boundary: it can never enumerate every program that can
spawn another, so allowlisting a program is trusting it with the value.
Passing `--allow-interpreter` is a deliberate decision to trust the agent with
that program's full reach.

### 3. Redaction is output-only and best-effort

The redactor replaces only an exact, contiguous occurrence of the value in the
bytes relayed from the child. It is streaming and safe across chunk boundaries,
but it does not and cannot:

- follow encodings or transformations (base64, hex, percent-encoding, case
  changes, compression, a substring the agent extracts itself); encoded-form
  redaction is planned (TODO 4.6) and will still be best-effort;
- see data the child writes to a file, a socket, a terminal, an environment
  variable of another process, or any channel other than its stdout/stderr;
- protect against a hostile child that deliberately holds and forwards the
  value.

To keep the relay's timing from revealing guesses, the redactor always holds
back the last `len - 1` bytes of output (`len` is the secret's length) until
more output arrives or the stream ends; the decision never depends on whether
those bytes match the value. The visible cost is that the last `len - 1` bytes
of a stream are relayed only when the child writes more or exits. The delay
depends on the secret's length, never its content.

Redaction protects the agent's context from accidental leakage. It is not a
sandbox.

### 4. Plaintext shown to a human leaves passmgr's control

`get --reveal` prints the value to the terminal. Scrollback, terminal
multiplexers, screen capture, shell session logging and shoulder surfing are
outside passmgr. The same applies to future `pm render` (TODO 5.5) and
`--copy` (TODO 8.8): once plaintext reaches a terminal, a clipboard or a file
readable by the user, anything running as that user can read it.

### 5. Vault permissions are warned about, not yet refused

A group- or world-readable vault currently produces a warning with a `chmod
600` hint. TODO 8.10 turns this into a refusal, which is what the design
requires. Until then, check the mode yourself: `ls -l` on the vault and the
directory that contains it.

### 6. Swap, hibernation and memory

Secret buffers are zeroized on drop and the daemon's key is `mlock`ed
best-effort; a failed `mlock` is currently silent and non-fatal. The kernel can
still write process memory to unencrypted swap or a hibernation image. Use
encrypted swap and disable hibernation on a machine that holds credentials you
care about.

One copy of an injected value cannot be wiped by this process.
`std::process::Command` keeps its own copies — the `OsString` in its
environment map and the `NAME=value` string it builds for `execve` — and frees
them, unwiped, as soon as the spawn returns. Its API has no way to hand those
buffers out or clear them, and the only alternative is to replace
`Command`/`Child` with a hand-written `posix_spawn` plus pipe, process-group
and reap handling (TODO R.50b considered and rejected that for the risk).
Everything passmgr owns *is* wiped: the redaction window including when it
grows, the reader's raw-output buffer, the redactors themselves, and every
buffer the wire codec copies a request into (the frame it returns, the encoder's
JSON tree, the decoder's buffer and the body it hands back — TODO R.50c), plus
the daemon's 4 KiB read chunk, which is wiped before a rejected `push` returns
its error (TODO R.66). The
decoder wipes its parsed tree on every path, including a rejected request, so
a malformed frame cannot leave the session-token hex in freed memory. A
`run` never creates such a copy for itself — `tests/secret_copies.rs` runs under
an allocator that scans every freed block for a canary and requires that a `run`
leaves no more secret-bearing freed blocks than a bare `std::process::Command`
spawn of the same child leaves, and that encoding then decoding a request
leaves no copy of the session-token hex at all.

Two more residues are not ours to wipe: the kernel's socket buffers, which hold
a frame until both ends have copied it out, and object *keys* in a parsed JSON
tree, which are protocol field names and never a secret. The socket lives in
the 0700 runtime directory and is peer-UID checked, so reading it needs the same
same-user access that reading the session file needs.

### 7. An older `vault.dat` can be put back

The vault is an ordinary 0600 file owned by you, and grant state (`uses`,
`revoked_at`) lives inside it. Any process running as the same user can copy
it and later put an older copy back. That older container still opens with the
daemon's key, because the header it authenticates keeps the same salt and KDF
parameters.

A running `pmd` remembers, in memory and for its own lifetime, the furthest
`uses` and any revocation it has seen for each grant id, and answers a `run`
that would go backwards with `denied` before it authorizes or spawns anything.
A rollback therefore cannot resurrect a spent use or clear a revocation while
that daemon is serving. Revocation itself is still accepted against a
rolled-back vault, so the kill switch keeps working; it can only remove access.

The mark is deliberately **not** persisted: a same-user process can roll back a
marker file exactly as easily as the vault, so a marker would not be a
boundary, and it would be one more artifact to protect. A `pmd` restart starts
with an empty mark and accepts the file it finds, so restoring a backup while a
daemon is running needs a `pm lock`/restart (or it answers `denied` until one).
This is the same class as limit 1 -- a hostile same-user process -- and is not
defended against beyond the running daemon's memory.

### 8. Out of scope

passmgr does not and cannot protect against:

- root, a compromised kernel, or a compromised operating system;
- keyloggers, screen capture, or a malicious process running as the same user
  (see limits 1 and 4);
- denial of service by a same-user process: it can kill `pmd`, hold the
  socket, or keep issuing `challenge` requests faster than a human can approve
  and so evict a fresh nonce (TODO R.16 keeps a single burst from doing it,
  but not a sustained one). No secret is exposed either way;
- a compromised agent host, or one that ignores the TTY/agent rules — the
  agent markers and terminal checks are honest signals for cooperating hosts,
  not proof of who is running the binary;
- physical access to an unlocked machine;
- a forgotten master password: there is no recovery key, backdoor or hint;
- the security of third-party binaries named in a grant's allowlist.

## If you find a problem

A vulnerability here means a way to get a secret value onto an agent-reachable
surface without the human-only TTY reveal: CLI stdout/stderr, the daemon
socket, the MCP stream, the audit log, or an error/Debug rendering. Report it
with the smallest reproduction and **fake** credentials only; never include a
real secret. Do not weaken a test to make it pass.
