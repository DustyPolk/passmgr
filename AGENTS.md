## Before committing

Run `scripts/gate.sh` (fmt, clippy, tests; CI runs the same script). The tests take several minutes.

## Reviewing a diff

Apply `CODING_STANDARDS.md`.

## Decisions and limits

Before designing or speccing a change, check `DECISIONS.md` (standing decisions; it plays the ADR role here) and `SECURITY.md` (accepted limits). Record new lasting decisions in `DECISIONS.md`. See `docs/agents/domain.md`.

## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues (`DustyPolk/passmgr`) via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five default canonical triage labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.
