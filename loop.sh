#!/usr/bin/env bash
# Agent loop for pi. Run from the project root, next to PROMPT.md.
#
#   ./loop.sh                          # run until stopped, using pi's default model
#   MAX_ITERS=20 ./loop.sh             # cap iterations
#   PI_ARGS="--thinking high" ./loop.sh  # extra pi flags
#   EXPECT_MODEL= ./loop.sh            # skip the model check
#
# Uses the default provider/model from pi's settings. Before starting, it makes one
# tiny pi call and aborts unless the serving model matches EXPECT_MODEL, so a changed
# default (or a provider alias being re-routed) can't silently swap the model.
#
# Stop gracefully:  touch STOP   (finishes the current iteration, then exits)
# Stop now:         Ctrl+C

set -uo pipefail

PROMPT_FILE="${PROMPT_FILE:-PROMPT.md}"
MAX_ITERS="${MAX_ITERS:-0}"              # 0 = unlimited
ITER_TIMEOUT="${ITER_TIMEOUT:-45m}"      # hard cap per iteration
SLEEP_SECS="${SLEEP_SECS:-5}"
MAX_IDLE="${MAX_IDLE:-3}"                # stop after N iterations with no new commits
MAX_FAILS="${MAX_FAILS:-5}"              # stop after N consecutive failed iterations
VERIFY="${VERIFY:-1}"                    # re-run the gate after each iteration, roll back on failure
PI_ARGS="${PI_ARGS:-}"
EXPECT_MODEL="${EXPECT_MODEL-deepseek-flash}"   # empty = don't check
LOG_DIR="logs"

die() { echo "loop: $*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------
command -v pi >/dev/null      || die "pi not found on PATH"
command -v git >/dev/null     || die "git not found"
command -v cargo >/dev/null   || die "cargo not found"
command -v timeout >/dev/null || die "timeout not found (macOS: brew install coreutils, then use gtimeout)"
[ -f "$PROMPT_FILE" ]         || die "$PROMPT_FILE not found in $(pwd)"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git repo (run: git init && git add -A && git commit -m init)"
git rev-parse HEAD >/dev/null 2>&1 || die "repo has no commits yet; make an initial commit first"

if [ -n "$(git status --porcelain)" ]; then
  die "working tree is dirty; commit or stash first so the loop starts from a known state"
fi

mkdir -p "$LOG_DIR"
# Keep loop artifacts out of the agent's commits without touching .gitignore
EXCLUDE=".git/info/exclude"
for p in "$LOG_DIR/" "STOP"; do
  grep -qxF "$p" "$EXCLUDE" 2>/dev/null || echo "$p" >> "$EXCLUDE"
done
rm -f STOP

# Confirm which model pi actually uses (asking the model itself is unreliable).
if [ -n "$EXPECT_MODEL" ]; then
  # shellcheck disable=SC2086
  probe=$(timeout 2m pi --mode json -p "reply with OK" $PI_ARGS </dev/null 2>&1)
  models=$(printf '%s' "$probe" | grep -o '"model":"[^"]*"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
  providers=$(printf '%s' "$probe" | grep -o '"provider":"[^"]*"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
  [ -n "$models" ] || die "could not read the model from pi's JSON output; check pi works, or set EXPECT_MODEL= to skip. Output: ${probe:0:300}"
  echo "loop: pi is using provider [${providers% }] model [${models% }]" | tee -a "$LOG_DIR/loop.log"
  case " $models" in
    *" $EXPECT_MODEL "*) ;;
    *) die "expected model '$EXPECT_MODEL' but pi reports '${models% }'. Fix pi's default or set EXPECT_MODEL." ;;
  esac
fi

CHILD=""
cleanup() {
  echo; echo "loop: interrupted, stopping."
  [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null
  exit 130
}
trap cleanup INT TERM

gate() {
  cargo fmt --check >/dev/null 2>&1 &&
  cargo clippy --all-targets -q -- -D warnings >/dev/null 2>&1 &&
  cargo test -q >/dev/null 2>&1
}

# --- loop ------------------------------------------------------------------
i=0; idle=0; fails=0
while :; do
  [ -f STOP ] && { echo "loop: STOP file found, exiting."; rm -f STOP; break; }
  if [ "$MAX_ITERS" -gt 0 ] && [ "$i" -ge "$MAX_ITERS" ]; then
    echo "loop: reached MAX_ITERS=$MAX_ITERS"; break
  fi

  i=$((i+1))
  ts=$(date +%Y%m%d-%H%M%S)
  log="$LOG_DIR/iter-$(printf %04d "$i")-$ts.log"
  before=$(git rev-parse HEAD)
  echo "=== iteration $i  $(date)  (HEAD ${before:0:8}) ===" | tee -a "$LOG_DIR/loop.log"

  # shellcheck disable=SC2086
  timeout "$ITER_TIMEOUT" pi -p "$(cat "$PROMPT_FILE")" $PI_ARGS </dev/null >"$log" 2>&1 &
  CHILD=$!
  wait "$CHILD"; rc=$?
  CHILD=""

  after=$(git rev-parse HEAD)
  status="ok"

  if [ "$rc" -eq 124 ]; then
    status="timeout"
  elif [ "$rc" -ne 0 ]; then
    status="pi-exit-$rc"
  fi

  # Leftover uncommitted changes = unfinished work. Stash so next iteration starts clean.
  if [ -n "$(git status --porcelain)" ]; then
    git stash push -u -q -m "loop iter $i leftovers ($status)"
    echo "  stashed uncommitted leftovers (git stash list)" | tee -a "$LOG_DIR/loop.log"
    [ "$status" = "ok" ] && status="dirty"
  fi

  # Independent check: don't trust the agent's claim that the gate passed.
  if [ "$VERIFY" = "1" ] && [ "$after" != "$before" ]; then
    if ! gate; then
      echo "  gate FAILED after agent commits; rolling back to ${before:0:8}" | tee -a "$LOG_DIR/loop.log"
      git branch -q "failed/iter-$i-$ts" "$after"   # keep the bad work for inspection
      git reset -q --hard "$before"
      {
        echo
        echo "## $(date +%F) loop note (iteration $i)"
        echo "Commits from this iteration failed the gate (fmt/clippy/test) and were rolled back."
        echo "Inspect branch failed/iter-$i-$ts. Retry the same TODO item more carefully."
      } >> PROGRESS.md
      git add PROGRESS.md && git commit -q -m "loop: roll back failed iteration $i"
      after=$(git rev-parse HEAD)
      status="gate-failed"
    fi
  fi

  commits=$(git rev-list --count "$before..$after" 2>/dev/null || echo 0)
  echo "  result: $status, $commits new commit(s), log: $log" | tee -a "$LOG_DIR/loop.log"

  # Stop conditions
  if [ "$status" = "ok" ]; then fails=0; else fails=$((fails+1)); fi
  if [ "$after" = "$before" ]; then idle=$((idle+1)); else idle=0; fi

  if [ "$fails" -ge "$MAX_FAILS" ]; then
    echo "loop: $fails consecutive failed iterations, stopping. Check $LOG_DIR/."; break
  fi
  if [ "$idle" -ge "$MAX_IDLE" ]; then
    echo "loop: $idle iterations with no commits, stopping (stuck or done)."; break
  fi

  # Back off on failures to avoid hammering rate limits
  if [ "$fails" -gt 0 ]; then sleep $((SLEEP_SECS * 2 ** fails)); else sleep "$SLEEP_SECS"; fi
done

echo "loop: finished after $i iteration(s)."
