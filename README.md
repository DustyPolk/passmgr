# passmgr

A small, local password manager written in Rust. Credentials live in one
encrypted vault file; there is no server, account, or network access.

> **Vault format changed.** This Rust implementation uses a new vault format
> (version 2). Vaults created by the original C version are detected and
> rejected with a clear error instead of being modified. The C implementation
> is archived under [`legacy-c/`](legacy-c/) and can still read old vaults.

## Features

- Authenticated encryption with AES-256-GCM.
- Argon2id key derivation with a random salt for every save.
- Atomic vault replacement, owner-only file permissions, and warnings for
  insecure permissions.
- Password generation with rejection sampling for unbiased output.
- Passwords are never accepted as command-line arguments and are not echoed
  while typing.
- Sensitive buffers are zeroized when dropped.
- A small dependency set: `aes-gcm`, `argon2`, `getrandom`, `tempfile`,
  `zeroize`, and `libc` for terminal handling.

## Build

Rust 1.85 or newer is required.

```bash
cargo build --release
# binary: target/release/passmgr
```

To install it into Cargo's binary directory:

```bash
cargo install --path .
```

The code targets Unix-like systems (Linux and macOS). Windows is not supported
because the secure password prompt uses POSIX termios.

## Usage

```text
passmgr [--db PATH] [--agent] <command> [arguments]
```

Global options must appear before the command. The vault path is chosen in this
order:

1. `--db PATH`
2. the `PASSMGR_DB` environment variable
3. `./passwords.dat`

The master password is prompted for every command except `generate`, `help`,
and `version`. Prompts are written to stderr, so stdout only contains command
data. When stdin is a pipe, passwords are read as ordinary lines, which makes
the tool scriptable:

```bash
printf 'master\nmaster\nsecret\nsecret\n' |
  passmgr --db ~/.secrets/work.dat add example.com alice
```

Creating a new vault asks for the master password twice. Manual credential
entry asks for the credential password twice as well, and so does rotating it
with `edit`.

### Add a credential

```bash
passmgr add example.com alice
```

You are prompted for the master password, then for the credential password.

Generate the credential password instead:

```bash
passmgr add --generate example.com alice
passmgr add --generate --simple --length 24 example.com alice
passmgr add --generate --pin --length 8 example.com alice
```

`add` rejects a service that already exists. Delete the old entry first if you
want to replace it. With `--generate`, the generated password is stored but
never printed: stdout stays empty and only a confirmation naming the entry is
written to stderr. Read the value back with the TTY-gated `get --reveal`.

### Tags

Tags are lowercase metadata labels for grouping entries, for example by
environment or purpose. They are never secrets and never appear in JSON
output; they are stored inside the encrypted payload.

```bash
passmgr add --tag work --tag prod example.com alice
passmgr list --tag prod              # entries tagged prod
passmgr list --tag prod --tag work   # entries tagged prod AND work
passmgr edit --tag prod example.com  # replace the tag set
passmgr edit --clear-tags example.com
```

Repeating `--tag` adds several tags. `list --tag` filters with AND semantics
and no `--tag` lists everything. Tags are normalized to a sorted,
duplicate-free list. A tag must be 1-32 bytes: an ASCII lowercase letter or
digit followed by lowercase letters, digits, `.`, `_`, or `-` (no spaces,
uppercase, or slashes). Each credential may carry at most 32 tags. Invalid
tags are rejected with exit code 2 before any password prompt.

### Get a credential

```bash
passmgr get example.com
```

Output:

```text
Ref: pm://5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5
Service: example.com
Username: alice
Tags: prod, work
Password: <redacted>
```

The `Tags:` line is omitted when the entry has no tags. It lists only
metadata, and is printed by both `get` modes.

`Ref` is the entry's stable reference: `pm://` followed by 32 lowercase hex
characters (a 16-byte random id). It identifies the entry without exposing any
secret, and it survives renames, password rotations, and re-saves. Agents and
scripts should use references rather than service names when they need to name
an entry.

`get` is metadata-only by default: it never writes the stored password to
stdout, so it is safe to run from a script or an agent. Printing the password
requires the explicit `--reveal` flag:

```bash
passmgr get --reveal example.com
```

`--reveal` is strictly for a human at a terminal. It is refused with exit
code 5 unless **both** stdin and stdout are terminals, no agent environment
marker is set (`PASSMGR_AGENT`, `CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`),
and the global `--agent` flag was not passed. `--agent` can only add refusal: it
makes metadata commands explicitly agent-safe and is never a way to obtain a
secret. There is no bypass flag, and the check happens before the vault is
opened, so a pipe or an agent never reaches the plaintext. Do not try to feed secrets to
another program with `--reveal`. Injection commands (planned `run --env`) are
the supported way to use a secret without reading it.

### List services

```bash
passmgr list
```

Output:

```text
Stored Services:
- example.com (alice) [pm://5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5]
  tags: prod, work
```

Only the service name, username, reference, and tags are printed; a `tags:`
line appears only when the entry has tags. Passwords are never written to
stdout by `list`. `list --tag <tag>` (repeatable) filters to entries carrying
all of the named tags.

### Machine-readable metadata

```bash
passmgr list --json
passmgr show pm://5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5
passmgr show --json pm://5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5
```

`list --json` prints one JSON document, `{"entries":[...]}`, and nothing else
on stdout. `show <ref>` looks a credential up by its full `pm://` reference and
prints `Ref`, `Service`, and `Username`; `show --json` prints the entry object
directly. The only keys in an entry are `ref`, `service`, and `username`:
there is no password field in any JSON output, by construction. `show` accepts
references only (a service name is a usage error, exit 2), and an unknown
reference exits 3. References survive renames, so they are the stable handle
for scripts and agents.

### Edit a credential

```bash
passmgr edit example.com                      # rotate the password
passmgr edit example.com --username bob       # metadata only
passmgr edit example.com --rename github.example
passmgr edit --tag prod --tag work example.com
passmgr edit --clear-tags example.com
passmgr edit --generate --simple example.com
```

A bare `edit` rotates the credential password: you are prompted for the new
value twice. Metadata-only changes (`--username`, `--rename`, `--tag`, and/or
`--clear-tags` without `--generate`) do not touch the password and do not
prompt for it. `--tag` replaces the whole tag set, and `--clear-tags` removes
all tags; combining them is a usage error. `--generate`
replaces the password with a generated value without prompting; the generated
value is never printed, only a confirmation naming the entry is written to
stderr. Read it back with the TTY-gated `get --reveal`. Renaming onto an
existing service is rejected, and an unknown service exits with code 3.

### Delete a credential

```bash
passmgr delete example.com
passmgr rm example.com        # alias
```

### Generate a password without touching a vault

```bash
passmgr generate
passmgr generate --simple --length 24
passmgr generate --pin --length 8
```

| Preset | Characters | Default length |
| --- | --- | --- |
| `--strong` (default) | uppercase, lowercase, digits, symbols | 20 |
| `--simple` | uppercase, lowercase, digits | 16 |
| `--pin` | digits | 6 |

Lengths must be between 4 and 128. If multiple presets are given, the last one
wins.

### Help and version

```bash
passmgr --help
passmgr help
passmgr --version
```

## Security design

- **Key derivation:** Argon2id, version 1.3, with 64 MiB of memory, 3 passes,
  and 1 lane by default. The parameters are stored in the vault header so they
  can be raised later without breaking existing vaults. Bounds on accepted
  parameters prevent a malicious header from requesting unbounded memory.
- **Encryption:** AES-256-GCM with a fresh 12-byte nonce and 16-byte salt on
  every save. The complete 56-byte header is authenticated as associated data.
- **Atomic saves:** the new container is written to a temporary file in the
  vault's directory, fsynced, and renamed over the old file. The temporary file
  is created with mode `0600`.
- **Permissions:** new vaults are owner-only. Existing vaults with group or
  other permission bits produce a warning with a suggested `chmod` command.
- **Entry references:** each credential carries a random 16-byte id written in
  the encrypted payload. Store version 2 added the id; version 1 payloads are
  read and migrated on the next save by generating ids (no data loss, no crypto
  change).
- **Tags:** tags are metadata stored in the same encrypted payload. Store
  version 3 added per-credential tags; version 2 and version 1 payloads read
  as untagged and are rewritten as version 4 on the next save. Tag names are
  validated on both write and read, so a malformed payload fails closed.
- **Timestamps:** each credential records `created` and `last_rotated` as Unix
  seconds inside the encrypted payload. Store version 4 added them; payloads
  from version 3 and older decode with `0` ("unknown") and are rewritten as
  version 4 on the next save. Rotation never changes `created`. Timestamps are
  metadata and are not printed by any command yet; the JSON schema will expose
  them in a later change.
- **Memory handling:** decrypted payloads, master passwords, generated
  passwords, keys, and credential fields use `zeroize` containers. Credential
  `Debug` output redacts the password.
- **No shell leaks:** passwords are read from stdin, not from arguments or the
  environment.
- **Integrity:** GCM authentication covers the ciphertext and all header fields,
  including the KDF parameters, salt, nonce, and length. Truncated, extended,
  or modified files fail closed.
- **Limits:** vault files are limited to 16 MiB and credentials to 10,000
  entries. These bounds are checked before expensive allocations or decryption.
- **No recovery:** losing the master password means losing the vault. There is
  no backdoor, recovery key, or password hint.

A local password manager cannot protect against a compromised machine,
keyloggers, or an attacker who can read process memory. Use a strong, unique
master password and keep backups of the vault file.

## Vault format

The binary format is documented in [`FORMAT.md`](FORMAT.md). Version 2 uses:

- magic `PMGR`, format version 2;
- an explicit KDF id (Argon2id) and AEAD id (AES-256-GCM);
- little-endian length fields and a versioned plaintext store.

The old C implementation used PBKDF2-SHA256, a different header, and a
line-oriented plaintext store. Those files begin with `PMGR` version byte `1`
and are reported as legacy vaults.

## Migrating from the C version

No automatic importer is included. To move credentials manually:

```bash
cd legacy-c
make
./passmgr list
./passmgr get example.com
```

Then add each entry to a new Rust vault in a different file:

```bash
passmgr --db ~/.secrets/new.dat add example.com alice
```

Do not point the Rust binary at the old vault file: it will refuse to read it,
and the old binary should remain the only tool used to modify it.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The library crate exposes the crypto, storage, password generation, and vault
modules for testing. End-to-end CLI tests live in `tests/cli.rs`; they run
serially because each unlock uses 64 MiB for Argon2.

Repository layout:

```text
src/            Rust implementation
tests/cli.rs    end-to-end tests
legacy-c/       archived C implementation and its README
FORMAT.md       vault format specification
```

## Exit codes

These codes are stable: scripts and agents may rely on them.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Other runtime error (duplicate entry, I/O failure, crypto setup failure) |
| 2 | Usage error (unknown command or option, bad arguments) or invalid input at a prompt |
| 3 | Not found (missing vault file or unknown service) |
| 4 | Authentication failed (wrong master password) |
| 5 | Refused (plaintext reveal without a terminal, in an agent context, or with `--agent`) |
| 6 | Malformed, truncated, or unsupported vault file |

## License

MIT
