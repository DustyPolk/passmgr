# Coding standards

The judgement rules a reviewer applies to a passmgr diff. Mechanical rules are
enforced by `scripts/gate.sh` and are out of scope here: formatting
(`rustfmt`), lints (`clippy -D warnings`, including the `std::thread::sleep`
ban in `clippy.toml`), and the ~1,000-line file limit (`tests/layout.rs`).

The design invariants in `PROMPT.md` ("Design invariants") and the standing
decisions in `DECISIONS.md` bind every change. A diff that contradicts either
is a finding, even if it passes the gate.

Code moved verbatim is in scope: apply every rule to moved and split code as if
it were new.

## What to look for, in priority order

1. **Secret exposure.** Any path where a secret value or grant token could
   reach stdout, stderr, a log, the audit log, an error message, `Debug`
   output, the socket, the MCP stream, argv, or a file with loose permissions.
   Check every new `println!`/`eprintln!`/`format!`/`{:?}` and every new
   serialize call.
2. **Authorization holes.** A check done only on the client side; scope,
   expiry or allowlist not enforced in `pmd`; an agent able to mint, widen or
   approve a grant; TTY gates that can be bypassed; reveal code reachable from
   agent context.
3. **Unsafe input handling.** Unbounded reads or allocations, panics on
   malformed input (`unwrap`/`expect`/indexing on untrusted data), path
   traversal, symlink following, TOCTOU on files, integer overflow in length
   math, environment-variable injection.
4. **Tests that don't prove what they claim.** See **Tests** below.
5. **Crypto misuse.** Nonce reuse, non-constant-time comparisons, missing
   zeroize, parameters changed without migration.
6. **Drift.** A TODO item checked off but not fully done; docs (`README.md`,
   `FORMAT.md`, `MCP.md`, `SECURITY.md`, `AGENTS.md`, `--help`) that no longer
   match the code; a lasting decision made in code but not recorded in
   `DECISIONS.md`.
7. **Maintainability.** Duplicated logic that should be one function, dead
   code, workaround code that hides a root cause.

## Design

- Illegal states are unrepresentable in the types.
- Untrusted input is parsed at the boundary; core logic is pure functions that
  unit tests can reach.
- New code follows the surrounding style and the module's own error enum (see
  `DECISIONS.md` on module-local error enums).

## Tests

- Every behaviour change has a test that fails without the change.
- Every security property has a test that proves it, usually with a **canary
  secret** (random and unique per test) that must not appear in stdout,
  stderr, logs, socket bytes, the audit log or MCP output. A canary that is
  never actually injected proves nothing.
- Tests exercise behaviour through public interfaces.
- Tests are deterministic: no dependency on test order, no real credentials,
  no network, a temp dir per test with `XDG_*`/`HOME` set per test.
- A test synchronizes on an observable condition (the poll helper, a channel),
  so it cannot pass before the behaviour it claims has run. Each
  `#[expect(clippy::disallowed_methods)]` on a sleep carries a reason; check
  the reason is true.
- A refactor that edits an existing test states why in the commit message. A
  test changed only so the refactor passes is a finding: the refactor changed
  behaviour.
