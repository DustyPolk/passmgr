# Role

You are working unattended, one iteration at a time, on a Rust CLI password manager.
Its purpose is to let AI agents use credentials stored on the local machine **without ever seeing the secret values**.
You have no memory of previous iterations. Everything you know about the project comes from the repo, `TODO.md`, `PROGRESS.md`, and `git log`.

# Each iteration: do exactly this

1. Read `PROGRESS.md` (newest entries first), `TODO.md`, and `git log --oneline -20`.
2. If `TODO.md` does not exist or has no unchecked items, do no feature work this iteration. Instead, write or extend `TODO.md` with small, ordered, testable tasks derived from the Design Invariants and Roadmap below. Commit it, log it, then stop.
3. Otherwise, pick the **first** unchecked item in `TODO.md`. If it is too big for one iteration, split it into smaller items in `TODO.md` and do only the first piece.
4. Implement it, with tests. Security-relevant behavior needs a test that proves it, for example that a secret value never appears in stdout, stderr or log output.
5. Run the gate (below). If the gate fails and you cannot fix it within this iteration, run `git checkout . && git clean -fd`, then log what failed and why in `PROGRESS.md`. Do not commit broken code.
6. If the gate passes, check the item off in `TODO.md`, append an entry to `PROGRESS.md` (date, what you did, anything the next iteration must know), and commit with a descriptive message.
7. Stop. One item per iteration.

# Gate (all must pass)

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit        # if installed; note in PROGRESS.md if not
```

# Design invariants (never violate; if a TODO item conflicts with one, do not implement it, flag it in PROGRESS.md)

**Agents never see plaintext.** This is the whole point of the tool.
- The agent-facing surface returns **references and metadata**, never values: names, IDs, URLs, usernames, tags, last-rotated date.
- Secrets are **used, not read**, via injection:
  - `run --env NAME=<ref> -- <cmd>` injects the secret into a child process's environment.
  - stdin piping into a command that the user explicitly invokes.
  - Template rendering to a file with 0600 permissions.
  - The secret value is never written to the calling process's stdout or stderr.
- Plaintext reveal (`get --reveal`, clipboard) exists **only for a human at a TTY**. Refuse it when stdin/stdout are not a TTY or when `--agent` mode or an agent env marker is set. Do not add a flag that bypasses this.
- Scrub output from injected commands: redact any occurrence of the injected secret value in the child's stdout/stderr when output is captured or relayed.
- Error messages, panics, debug output and logs never contain secret values. Wrap secrets in `secrecy::SecretString` (or equivalent) so `Debug`/`Display` cannot leak them.

**Crypto: use vetted primitives only, never invent anything.**
- KDF: Argon2id (the `argon2` crate) with stored, versioned parameters and a random salt.
- AEAD: XChaCha20-Poly1305 or AES-256-GCM from RustCrypto, with a random nonce per encryption. Never reuse a nonce.
- Or use the `age` crate for the whole vault file, if that is simpler. Pick one approach, record the decision in `PROGRESS.md`, and do not mix them.
- Zeroize key material and plaintext buffers (`zeroize`). Minimize how long the decrypted vault stays in memory.
- Vault file is created with 0600 permissions; refuse to open it if it is group- or world-readable. Write atomically (temp file + fsync + rename).
- Include a format version header so the vault can be migrated later.

**Agent access is scoped and auditable.**
- Agents authenticate with a session or grant token that the human creates. The token is scoped (which entries or tags), has an expiry, and can be revoked.
- Every agent use of a secret appends to an audit log: timestamp, grant, entry ref, command run. Never log the value.
- A human can list and revoke grants.

**No network.** The tool makes no network calls. Do not add dependencies that do.

**Dependencies.** Prefer well-maintained crates (RustCrypto, `age`, `clap`, `secrecy`, `zeroize`, `serde`). Do not add a dependency for something trivial. Justify each new dependency in `PROGRESS.md`.

# Roadmap (use this to generate TODO items, in roughly this order)

1. Vault format, create/unlock, encrypted storage, file permissions, atomic writes.
2. Human CRUD: `add`, `list`, `edit`, `rm`, `get --reveal` (TTY only), password generator.
3. Unlock daemon (decided; do not substitute another approach). Target Linux and macOS first.
   - `pm unlock` (human, at a TTY) prompts for the master password and starts `pmd`, or hands the derived key to it. The key lives only in daemon memory: zeroized on drop, `mlock`ed where possible. On Linux, set `prctl(PR_SET_DUMPABLE, 0)` so same-user processes cannot ptrace the daemon or read its memory via `/proc`.
   - IPC goes over a Unix socket in `$XDG_RUNTIME_DIR` (macOS: a per-user 0700 directory). The socket has 0600 permissions and the directory 0700. On every connection, check the peer UID (`SO_PEERCRED` / `getpeereid`) and reject anything that is not the owning user.
   - **The daemon has no "return plaintext" request type.** Any same-user process can talk to the socket, so a client-side check protects nothing. For `run`, the **daemon** spawns the child process with the secret in its environment and relays redacted stdout/stderr and the exit code back to the client. The plaintext never crosses the socket.
   - Requests are authorized by grant token (step 5). Before grants exist, accept only a local session token written to a 0600 file at unlock time.
   - `get --reveal` does **not** go through the daemon session. It re-prompts for the master password at a TTY every time, so an agent holding a session cannot reveal anything.
   - Lifecycle: idle timeout (default 15 min, configurable), `pm lock` wipes the key immediately, and the daemon locks itself on SIGTERM/SIGINT. If the socket is stale, detect it and clean it up on start. Only one daemon runs per user.
   - Protocol: length-prefixed JSON (or another simple framing), with a protocol version field and a maximum message size. Treat every request as untrusted input.
   - Tests: peer-UID rejection (where testable), idle timeout, lock wiping the key, a `run` round-trip where the secret appears in the child's environment but never in the socket traffic or the client's output, and malformed or oversized messages being rejected without a crash.
   - Record in `SECURITY.md` the known limit: a same-user process can read a running child's environment via `/proc/<pid>/environ` (Linux) while it runs. Injection prevents accidental exposure to the agent's context. It does not stop a deliberately malicious process running as the same user.
4. `run --env NAME=<ref> -- <cmd>` injection, with output redaction.
5. Grants: create, list, revoke, scope, expiry. Audit log.
6. Machine-readable agent interface: `--json` output for metadata commands, stable exit codes, `--help` text written for an LLM reader. Document it in `AGENTS.md`.
7. Hardening: fuzz the vault parser (`cargo fuzz`), add tests for wrong password, corrupted file, truncated file and permission errors, and add a threat model in `SECURITY.md`.

# Rules

- Small, focused commits. Do not refactor unrelated code.
- Do not delete or weaken existing tests to make the gate pass.
- Do not change crypto parameters or the vault format without a migration path and a `PROGRESS.md` note.
- If you are unsure whether something is secure, take the more conservative option and flag it in `PROGRESS.md` under `NEEDS HUMAN REVIEW`.
- Never use real credentials in tests. Generate fake ones.
