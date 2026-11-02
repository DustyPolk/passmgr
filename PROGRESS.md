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
