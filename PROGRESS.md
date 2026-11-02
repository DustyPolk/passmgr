# Progress log

Newest entries first. Date, what was done, what the next iteration must know.

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
