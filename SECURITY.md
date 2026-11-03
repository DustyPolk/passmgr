# Security

passmgr exists so an AI agent can **use** a credential without ever seeing its
value. This document states what that guarantee covers, what it does not cover,
and which residual risks are accepted on purpose.

It is the canonical list of limits. If code and this document disagree, either
the code is wrong or this document must be updated in the same commit. Do not
"fix" a limit listed here by weakening a check (for example, by removing the
TTY gate or the redactor).

## Current status

Grant-based authorization is **not implemented yet** (TODO 3.1–3.9). Today the
daemon's `run` request is authorized by the session token (TODO 2.5), and any
process running as the same user can read the 0600 session file. Therefore,
today:

- `passmgr run` is the agent-facing way to use a secret, and it prevents
  *accidental* exposure: the value never crosses the socket, and relayed child
  output is redacted before it leaves `pmd`.
- `run` is **not** an agent/human boundary. A same-user process that can read
  the session file can inject any stored credential into a command of its
  choosing. TODO 3.6 makes human-created grant tokens mandatory for every
  credential-touching request; the session token will then authorize only
  `ping`, `lock`, `status` and `revoke`.

The MCP server (`pm mcp serve`, `MCP.md`) is a contract at this point, not
implemented code. Once implemented it is a thin client of the same daemon and
inherits every limit below.

## What passmgr protects

- **No plaintext request.** The daemon has no request type that returns a
  plaintext value, and never will. Every agent-facing surface returns
  references and metadata only: refs, names, usernames, tags, field names,
  URLs and timestamps.
- **Use, not read.** Secrets reach a child through the daemon: environment
  injection today; stdin and 0600 temp-file injection are planned (TODO 5.x).
- **Reveal is human-only.** `get --reveal` requires stdin *and* stdout to be
  terminals, no agent marker environment variable (`PASSMGR_AGENT`,
  `CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`), and no `--agent` flag. The
  master password is prompted on every invocation, and no flag bypasses the
  check. Refusal happens before the vault is opened or a password is prompted.
- **Redaction.** Child stdout and stderr are passed through a streaming
  redactor in `pmd` that replaces exact occurrences of the injected value,
  including values split across read and frame boundaries.
- **Daemon hardening.** `pmd` keeps only the derived 32-byte vault key, not a
  decrypted vault, in `mlock`ed memory. It disables core dumps
  (`RLIMIT_CORE=0`, inherited by its children) and, on Linux, sets
  `PR_SET_DUMPABLE=0`. Every request is checked against the peer uid before it
  is read; malformed and unauthorized requests never refresh the idle timer.
- **Vault.** Argon2id + AES-256-GCM, authenticated header, atomic 0600 writes,
  zeroized keys and plaintext. Mutating commands hold an exclusive `flock` on
  the sidecar `<vault>.lock` across the whole read-modify-write, so concurrent
  writers cannot lose an update. Details are in `README.md` and `FORMAT.md`.
- **No network.** passmgr makes no network calls and links no network-capable
  crate. MCP is stdio only.
- **Planned, per `MCP.md`:** scoped, expiring, use-limited, revocable grants
  that a human approves with the master password at a TTY, and a hash-chained
  audit log that records every allowed and denied credential use without
  values or tokens.

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

Consequences:

- passmgr prevents accidents and makes deliberate misuse require an explicit
  human grant. It does not defend against malware already running as you.
- A grant bounds what a *cooperating* agent may do. It cannot stop a hostile
  same-user process, which can read the value directly and does not need the
  grant.
- Stdin injection or a 0600 temp file (TODO 5.x) narrows the window but does
  not close this class of attack: a same-user process can still read
  `/proc/<pid>/mem`, open the temp file, or attach to the child when permitted.

### 2. An interpreter or shell in a command allowlist can exfiltrate

A grant that allows `bash`, `sh`, `python`, `node`, `perl` and similar
programs is equivalent to handing the agent the secret: the interpreter can
read the injected variable, transform it, and write it anywhere. Redaction
cannot follow a transformation (see limit 3).

Mitigations: interpreters and shells are refused in a grant's command
allowlist unless the human passes `--allow-interpreter` (TODO 3.4); grant the
specific binary a workflow needs, not a general-purpose interpreter. Passing
`--allow-interpreter` is a deliberate decision to trust the agent with the
value.

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

### 7. Out of scope

passmgr does not and cannot protect against:

- root, a compromised kernel, or a compromised operating system;
- keyloggers, screen capture, or a malicious process running as the same user
  (see limits 1 and 4);
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
