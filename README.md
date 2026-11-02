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
passmgr [--db PATH] <command> [arguments]
```

The vault path is chosen in this order:

1. `--db PATH` (must appear before the command)
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
entry asks for the credential password twice as well.

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
want to replace it. With `--generate`, the generated password is printed to
stdout after the vault has been saved successfully.

### Get a credential

```bash
passmgr get example.com
```

Output:

```text
Service: example.com
Username: alice
Password: <redacted>
```

`get` is metadata-only by default: it never writes the stored password to
stdout, so it is safe to run from a script or an agent. Printing the password
requires the explicit `--reveal` flag:

```bash
passmgr get --reveal example.com
```

`--reveal` is meant for a human at a terminal; do not use it to feed secrets to
another program. Injection commands (planned `run --env`) are the supported way
to use a secret without reading it.

### List services

```bash
passmgr list
```

Output:

```text
Stored Services:
- example.com (alice)
```

Only service names and usernames are printed; passwords are never written to
stdout by `list`.

### Delete a credential

```bash
passmgr delete example.com
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

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Runtime error (wrong password, missing vault, I/O failure, etc.) |
| 2 | Usage error (unknown command or option, bad arguments) |

## License

MIT
