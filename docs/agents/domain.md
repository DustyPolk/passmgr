# Domain docs

How the engineering skills consume this repo's domain documentation.

## Before exploring, read these

- **`DECISIONS.md`** at the repo root: one line per standing decision, grouped by area. It takes the place of `docs/adr/` in this repo. Read the groups that touch the area you're about to work in.
- **`SECURITY.md`**: the canonical list of accepted limits and out-of-scope threats.
- **`GLOSSARY.md`** at the repo root, if it exists. It doesn't yet; `/domain-modeling` creates it when a term gets resolved.

## Recording decisions

Record a resolved decision as a line in the matching group of `DECISIONS.md`, not as a new file under `docs/adr/`. When a decision changes, edit its line.

## Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a hypothesis, a test name), use the term `DECISIONS.md` or `GLOSSARY.md` uses for it.

## Flag decision conflicts

If your output contradicts a line in `DECISIONS.md` or a limit in `SECURITY.md`, surface it explicitly rather than silently overriding it:

> _Contradicts DECISIONS.md ("<the decision line>"), but worth reopening because…_
