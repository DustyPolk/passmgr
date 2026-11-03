# passmgr vault format

This document specifies on-disk vault format version 2 (container) with
credential store version 5. All multi-byte integers
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
| Salt | 16 random bytes; reused only by a key-preserving re-encryption |
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
u8          store version = 5
u32         credential count
repeat count times:
    byte[16]    entry id (random, stable per credential)
    u64         created, Unix seconds UTC (0 = unknown)
    u64         last_rotated, Unix seconds UTC (0 = unknown)
    u32         service length in bytes
    byte[]      service, UTF-8
    u32         username length in bytes
    byte[]      username, UTF-8
    u32         password length in bytes
    byte[]      password, UTF-8
    u32         tag count
    repeat tag count times:
        u32     tag length in bytes
        byte[]  tag, UTF-8
u32         grant count
repeat grant count times:
    byte[16]    grant id (random, stable per grant)
    byte[32]    SHA-256 of the grant token
    u8          capability bits: 1 = list, 2 = run
    u8          flags: bit 0 revoked_at present, bit 1 last_used present,
                bit 2 max_uses present; any other bit is malformed
    u64         created, Unix seconds UTC
    u64         expires_at, Unix seconds UTC
    u64         revoked_at (present only with flag bit 0)
    u64         last_used (present only with flag bit 1)
    u32         max_uses (present only with flag bit 2)
    u32         uses
    u32         label length in bytes
    byte[]      label, UTF-8
    u32         ref count
    repeat:     byte[16] entry id
    u32         tag count
    repeat:     u32 tag length in bytes, byte[] tag, UTF-8
    u8          field scope mode: 0 = every field, 1 = listed fields
    if mode 1:  u32 field count
                repeat: u32 name length in bytes, byte[] field name, UTF-8
    u32         command count
    repeat:     u32 path length in bytes, byte[] absolute path, UTF-8
```

The entry id is 16 random bytes from the operating system RNG. It is rendered
to users and agents as the reference `pm://<32 lowercase hex characters>` and
is independent of the service name, so it survives renames. Ids must be unique
within a payload; a duplicate is rejected as malformed. Ids are metadata, not
secrets, but they live inside the encrypted payload so the vault file does not
leak how many entries exist.

Store version 4 has the same layout up to the end of the credential list and
no grant list. Store version 2 has the same credential layout without the tag
fields. Store version 1 has no ids and no tags. Store version 3 has ids and
tags but no timestamps. Versions 1-4 are read for migration: missing ids are
generated in memory, missing tags decode as an empty list, missing timestamps
decode as `0`, a missing grant list decodes as empty, and the next save writes
store version 5. Credential fields are preserved unchanged, and the encoded
credential records of a v5 payload are byte-identical to v4.

Timestamps are unsigned 64-bit Unix seconds (UTC) and are metadata, not
secrets. `created` is set when the credential is added and never changes.
`last_rotated` is set at creation and updated on every password rotation. A
value of `0` means "unknown": it is what payloads migrated from store version
3 or older decode to, so no creation date is invented. Values above
253402300799 (9999-12-31T23:59:59Z) are rejected as malformed on read and as
invalid on write, so date rendering cannot overflow. Second precision means a
rotation within the same second as the previous one leaves `last_rotated`
unchanged; it never moves backwards under a normal clock.

Grants carry only the SHA-256 of the grant token, never the token itself, so a
stolen vault cannot be replayed against the daemon. Grant ids must be unique
within a payload and duplicates are rejected as malformed. Optional fields use
flags rather than a magic `0` timestamp, so "no last use" stays distinct from
a real timestamp. Every rule `Grant::create` enforces is checked again on
read **and before every write**: `store::encode` validates the stored form
(`Grant::to_stored` -> `Grant::check_stored`) and then serializes exactly that
value, so neither a hand-edited payload nor a buggy writer can produce a grant
this build would never have created. At most 1,024 grants; label 1-64 bytes
without control, bidi, zero-width/format, line-separator or
variation-selector characters; capability bits and flag bits limited to the
known set; `created` and `expires_at` at most 253402300799 and at most 30 days
apart; at most 256 refs, 32 tags, 32 field names (each 1-32 bytes matching
`[a-z0-9_-]+`) and 32 commands (absolute UTF-8 paths of at most 4096 bytes,
with no control, bidi, zero-width/format, line-separator or variation-selector
characters -- the same classes the label rule below refuses);
no duplicate refs, tags, field names or commands inside one grant; a `run`
grant needs at least one command; `max_uses`, when present, is at least 1 and
not below `uses`.

Tags are lowercase metadata labels used for scoped agent access. On disk each
credential stores a sorted, duplicate-free list: each tag must be 1-32 bytes,
start with an ASCII lowercase letter or digit, and otherwise contain only
`a-z`, `0-9`, `.`, `_` or `-`. At most 32 tags are allowed per credential.
Duplicate tags within one credential, or unknown characters, make the payload
malformed. Tags are not secrets, but they live inside the encrypted payload.

The payload has no trailing bytes. Fields are length-prefixed rather than
line-oriented, so the encoding can represent service names, usernames, and
passwords containing `:`, newlines, NUL, and other Unicode text. This
implementation applies additional validation when reading and writing:

- service and password must not be empty;
- service and username must not contain Unicode control characters (so
  newlines and NUL are allowed in passwords, but not in service names or
  usernames);
- each service/username/password field is at most 4096 bytes;
- at most 10,000 credentials and at most 1,024 grants;
- the decoded payload is at most 10 MiB, credentials and grants together.

An empty vault encodes as `05 00 00 00 00 00 00 00 00`: store version 5, a
credential count of zero and a grant count of zero. Version 4
(`04 00 00 00 00`), version 3 (`03 00 00 00 00`), version 2 (`02 00 00 00 00`)
and version 1 (`01 00 00 00 00`) empty payloads are also accepted and upgraded
on save.

## Versioning

- The container version at offset 4 controls the envelope layout and crypto
  algorithms.
- The KDF and AEAD ids provide algorithm agility inside a container version.
- The plaintext store version at the start of the decrypted payload controls
  the credential and grant encoding. Versions 1 (no entry ids), 2 (no tags),
  3 (no timestamps) and 4 (no grants) are accepted for migration and rewritten
  as version 5 on save; unknown versions are rejected.

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
- Every save uses a fresh random 96-bit nonce, so identical credentials
  produce different ciphertext each time. An existing vault also keeps its
  header: its 16-byte salt and KDF parameters are reused, so a running `pmd`'s
  derived key stays valid and KDF parameters a human raised are not reset to
  the current defaults. Only a brand-new file takes a fresh salt and the
  current defaults. Reusing the header is safe because the nonce is fresh, and
  it is authenticated before reuse: `crypto::encrypt_with_template` (the
  password path) and `crypto::encrypt_with_key` (a writer holding the key, such
  as the CLI writing a grant while `pmd` is unlocked) both decrypt the current
  container first, so a wrong password or key writes nothing.
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
