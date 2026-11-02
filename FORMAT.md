# passmgr vault format

This document specifies on-disk vault format version 2. All multi-byte integers
are **little-endian**. A vault is a single file containing a header, a
ciphertext, and a 16-byte GCM authentication tag.

## Container layout

```text
offset  size  field
------  ----  --------------------------------------------------------------
0       4     magic "PMGR"
4       1     format version = 2
5       1     KDF id = 1 (Argon2id)
6       1     AEAD id = 1 (AES-256-GCM)
7       1     flags = 0
8       4     Argon2 memory cost m_cost, in KiB
12      4     Argon2 time cost t_cost
16      4     Argon2 parallelism p_cost
20      16    salt
36      12    nonce
48      8     ciphertext length, including the 16-byte tag
56      ...   ciphertext
...     16    GCM authentication tag
```

`ciphertext length` must equal `file length - 56`. The length field includes
the tag, so a valid vault is at least 72 bytes (empty plaintext).

The first 56 bytes (the entire header) are supplied to AES-256-GCM as
associated data. The tag therefore authenticates the magic, version, algorithm
ids, KDF parameters, salt, nonce, and declared length in addition to the
ciphertext. Any change to a header field causes decryption to fail, except for
changes that are rejected earlier as malformed or unsupported.

## Header fields

| Field | Accepted values |
| --- | --- |
| Magic | `50 4d 47 52` (`PMGR`) |
| Format version | `2` for this document; `1` is the legacy C format |
| KDF id | `1` only |
| AEAD id | `1` only |
| Flags | `0` only; reserved for future use |
| `m_cost` | 8192 through 1,048,576 KiB |
| `t_cost` | 1 through 16 |
| `p_cost` | 1 through 8, and `m_cost >= 8 * p_cost` |
| Salt | 16 random bytes |
| Nonce | 12 random bytes, fresh for every save |

The defaults written by this implementation are:

```text
m_cost = 65536 KiB (64 MiB)
t_cost = 3
p_cost = 1
```

Argon2 version `0x13` (1.3), Argon2id, with a 32-byte output key. The master
password is used as UTF-8 bytes with Argon2's normal password input handling
(no pre-hashing). The salt is the 16-byte header salt.

Strict bounds are intentional. Without them, a modified header could make an
unlock allocate gigabytes or spin for a very long time. Unsupported values fail
with an `UnsupportedFormat` error rather than being clamped or silently
ignored.

## Plaintext payload

After successful decryption, the plaintext is versioned binary data:

```text
u8          store version = 2
u32         credential count
repeat count times:
    byte[16]    entry id (random, stable per credential)
    u32         service length in bytes
    byte[]      service, UTF-8
    u32         username length in bytes
    byte[]      username, UTF-8
    u32         password length in bytes
    byte[]      password, UTF-8
```

The entry id is 16 random bytes from the operating system RNG. It is rendered
to users and agents as the reference `pm://<32 lowercase hex characters>` and
is independent of the service name, so it survives renames. Ids must be unique
within a payload; a duplicate is rejected as malformed. Ids are metadata, not
secrets, but they live inside the encrypted payload so the vault file does not
leak how many entries exist.

Store version 1 has the same layout without the 16-byte id field. It is read
for migration: ids are generated in memory while decoding, and the next save
writes store version 2. Credential fields are preserved unchanged.

The payload has no trailing bytes. Fields are length-prefixed rather than
line-oriented, so the encoding can represent service names, usernames, and
passwords containing `:`, newlines, NUL, and other Unicode text. This
implementation applies additional validation when reading and writing:

- service and password must not be empty;
- service and username must not contain Unicode control characters (so
  newlines and NUL are allowed in passwords, but not in service names or
  usernames);
- each field is at most 4096 bytes;
- at most 10,000 credentials;
- the decoded payload is at most 10 MiB.

An empty vault encodes as `02 00 00 00 00`: store version 2 and a count of zero.
A version 1 empty payload (`01 00 00 00 00`) is also accepted and upgraded on save.

## Versioning

- The container version at offset 4 controls the envelope layout and crypto
  algorithms.
- The KDF and AEAD ids provide algorithm agility inside a container version.
- The plaintext store version at the start of the decrypted payload controls
  the credential encoding. Version 1 (no entry ids) is accepted for migration
  and rewritten as version 2 on save; unknown versions are rejected.

A reader must reject unknown versions rather than guessing. Version 1 is
reserved for the legacy C vault:

```text
"PMGR" | u8 version=1 | salt(16) | iv(12) | tag(16) | u32 length | ciphertext
```

It uses PBKDF2-SHA256 with 600,000 iterations and a line-oriented plaintext
store (`service:username:password\n`). The Rust implementation detects this
version and returns `LegacyVault`; it never writes to a legacy file.

## Security properties and limits

- A vault file is limited to 16 MiB. The header's declared ciphertext length
  must match the actual file size and is checked before decryption.
- Decryption is attempted only after the header has been structurally validated.
- AES-GCM authentication failure is reported as a wrong master password or a
  corrupted vault; the two cases are indistinguishable by design.
- Saves use a fresh salt and nonce, so identical credentials produce different
  ciphertext each time.
- The format does not compress, deduplicate, or encrypt field lengths. Length
  metadata is visible only after decryption; the outer container leaks only its
  total size and the KDF parameters needed to unlock it.
- Atomic replacement is a file-system behavior, not part of the format: a new
  container is written to a temporary file in the same directory and renamed
  over the target.

## Compatibility notes

This format is not byte-compatible with the C implementation. The version byte
and magic were kept so old files can be recognized and rejected clearly. Tools
that only need to identify a vault can check for `50 4d 47 52` followed by
version `2`.
