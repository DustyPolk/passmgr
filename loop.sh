#!/usr/bin/env bash
# Agent loop for pi. Run from the project root, next to PROMPT.md.
#
#   ./loop.sh                            # run until stopped, using pi's default model
#   UNTIL=07:30 ./loop.sh                # stop starting new iterations after 07:30
#   MAX_ITERS=20 ./loop.sh               # cap iterations for this run
#   PI_ARGS="--thinking high" ./loop.sh  # extra pi flags
#   EXPECT_MODEL= ./loop.sh              # skip the model check
#   REVIEW_EVERY=0 ./loop.sh             # disable review iterations
#
# What it does each iteration:
#   - Housekeeping: moves old PROGRESS.md entries to PROGRESS-archive.md and
#     finished TODO.md phases to TODO-done.md, so the agent's reading stays short.
#   - Runs pi with PROMPT.md (a work iteration), or with REVIEW.md every
#     REVIEW_EVERY productive iterations (a review of the commits since the last review).
#   - Re-runs the gate itself and rolls back commits that fail it.
#   - Leaves a "loop note" at the top of PROGRESS.md after every failure so the next
#     iteration knows what happened, and marks a TODO item [!] blocked after
#     MAX_ITEM_FAILS failed attempts so one hard item can't end the night.
#   - Treats provider/pi failures (fast exit, no work) separately: long capped backoff,
#     they don't count toward MAX_FAILS.
#   - Writes logs/summary.txt when it exits.
#
# Stop gracefully:  touch STOP   (finishes the current iteration, then exits)
# Stop now:         Ctrl+C

set -uo pipefail

PROMPT_FILE="${PROMPT_FILE:-PROMPT.md}"
REVIEW_FILE="${REVIEW_FILE:-REVIEW.md}"
REVIEW_EVERY="${REVIEW_EVERY:-12}"       # review after N productive work iterations; 0 = off
MAX_ITERS="${MAX_ITERS:-0}"              # iterations for this run; 0 = unlimited
UNTIL="${UNTIL:-}"                       # wall-clock time (e.g. 07:30) after which no new iteration starts
ITER_TIMEOUT="${ITER_TIMEOUT:-45m}"      # hard cap per iteration
SLEEP_SECS="${SLEEP_SECS:-5}"
MAX_IDLE="${MAX_IDLE:-3}"                # stop after N work iterations in a row with no commits
MAX_FAILS="${MAX_FAILS:-6}"              # stop after N agent failures in a row (gate/timeout/dirty)
MAX_ITEM_FAILS="${MAX_ITEM_FAILS:-2}"    # mark a TODO item [!] blocked after N failed attempts
MAX_INFRA_FAILS="${MAX_INFRA_FAILS:-40}" # stop after N pi/provider failures in a row
MAX_BACKOFF="${MAX_BACKOFF:-900}"        # cap for the infra-failure backoff, seconds
MIN_ITER_SECS="${MIN_ITER_SECS:-60}"     # an iteration shorter than this with no work = infra failure
KEEP_PROGRESS="${KEEP_PROGRESS:-8}"      # PROGRESS.md entries kept when archiving (runs at 2x this)
VERIFY="${VERIFY:-1}"                    # re-run the gate after each iteration, roll back on failure
GATE_CMD="${GATE_CMD:-}"                 # override the gate (used to test this script)
PI_ARGS="${PI_ARGS:-}"
EXPECT_MODEL="${EXPECT_MODEL-deepseek-v4.1-flash}"   # empty = don't check
LOG_DIR="logs"
STATE_DIR="$LOG_DIR/state"

die() { echo "loop: $*" >&2; exit 1; }
say() { echo "$*" | tee -a "$LOG_DIR/loop.log"; }

# --- preflight -------------------------------------------------------------
command -v pi >/dev/null      || die "pi not found on PATH"
command -v git >/dev/null     || die "git not found"
command -v timeout >/dev/null || die "timeout not found (macOS: brew install coreutils, then use gtimeout)"
[ -n "$GATE_CMD" ] || command -v cargo >/dev/null || die "cargo not found"
[ -f "$PROMPT_FILE" ]         || die "$PROMPT_FILE not found in $(pwd)"
if [ "$REVIEW_EVERY" -gt 0 ] && [ ! -f "$REVIEW_FILE" ]; then
  die "$REVIEW_FILE not found (set REVIEW_EVERY=0 to run without reviews)"
fi
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git repo (run: git init && git add -A && git commit -m init)"
git rev-parse HEAD >/dev/null 2>&1 || die "repo has no commits yet; make an initial commit first"

if [ -n "$(git status --porcelain)" ]; then
  die "working tree is dirty; commit or stash first so the loop starts from a known state"
fi

prompt_bytes=$(wc -c <"$PROMPT_FILE")
[ "$prompt_bytes" -lt 120000 ] || die "$PROMPT_FILE is $prompt_bytes bytes; pi gets it as one argument, keep it under 120000"

deadline=0
if [ -n "$UNTIL" ]; then
  deadline=$(date -d "$UNTIL" +%s 2>/dev/null) || die "cannot parse UNTIL='$UNTIL'"
  [ "$deadline" -le "$(date +%s)" ] && deadline=$((deadline + 86400))
fi

mkdir -p "$LOG_DIR" "$STATE_DIR"
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
  say "loop: pi is using provider [${providers% }] model [${models% }]"
  case " $models" in
    *" $EXPECT_MODEL "*) ;;
    *) die "expected model '$EXPECT_MODEL' but pi reports '${models% }'. Fix pi's default or set EXPECT_MODEL." ;;
  esac
fi

# --- helpers ---------------------------------------------------------------
START_HEAD=$(git rev-parse HEAD)

gate() {
  if [ -n "$GATE_CMD" ]; then bash -c "$GATE_CMD"; return; fi
  cargo fmt --check &&
  cargo clippy --all-targets -q -- -D warnings &&
  cargo test -q
}

# First unchecked TODO item id, e.g. "3.4a" or "R.2" ("" if none).
current_item() {
  [ -f TODO.md ] || return 0
  grep -m1 -E '^[[:space:]]*- \[ \] \*\*' TODO.md | sed -E 's/^[[:space:]]*- \[ \] \*\*([^ *]+).*/\1/'
}

item_is_open() {   # $1 = id
  grep -qF -- "- [ ] **$1 " TODO.md 2>/dev/null || grep -qF -- "- [ ] **$1**" TODO.md 2>/dev/null
}

# Insert a note at the top of PROGRESS.md (entries are newest-first). Keeps file mode.
progress_note() {   # $1 = title, rest = bullet lines
  local title="$1"; shift
  local tmp; tmp=$(mktemp)
  {
    printf '## %s — loop note: %s (iteration %s)\n\n' "$(date +%F)" "$title" "$i"
    for line in "$@"; do printf -- '- %s\n' "$line"; done
    echo
    [ -f PROGRESS.md ] && cat PROGRESS.md
  } >"$tmp"
  cat "$tmp" >PROGRESS.md; rm -f "$tmp"
}

loop_commit() {   # $1 = message, rest = paths
  local msg="$1"; shift
  git add -A -- "$@" 2>/dev/null
  git diff --cached --quiet || git commit -q -m "loop: $msg"
}

fail_count() { cat "$STATE_DIR/item-$1.fails" 2>/dev/null || echo 0; }

block_item() {   # $1 = id, $2 = attempts
  local id="$1" n="$2" tmp; tmp=$(mktemp)
  awk -v id="$id" -v n="$n" '
    !done {
      p = index($0, "- [ ] **" id)
      if (p) {
        c = substr($0, p + 8 + length(id), 1)
        if (c == " " || c == "*") {
          sub(/- \[ \]/, "- [!]"); print
          match($0, /^[[:space:]]*/)
          printf "%s      (blocked by loop after %d failed attempts; see the loop notes in PROGRESS.md / PROGRESS-archive.md)\n", substr($0, 1, RLENGTH), n
          done = 1; next
        }
      }
    }
    { print }' TODO.md >"$tmp"
  cat "$tmp" >TODO.md; rm -f "$tmp"
}

# Move all but the newest KEEP_PROGRESS entries of PROGRESS.md to PROGRESS-archive.md.
archive_progress() {
  [ -f PROGRESS.md ] || return 0
  local n; n=$(grep -c '^## ' PROGRESS.md)
  [ "$n" -gt $((KEEP_PROGRESS * 2)) ] || return 0   # batch it, so this is not a commit per iteration
  local keep old arch; keep=$(mktemp); old=$(mktemp); arch=$(mktemp)
  awk -v k="$KEEP_PROGRESS" -v keepf="$keep" -v oldf="$old" '
    /^## / { c++ }
    { if (c <= k) print > keepf; else print > oldf }' PROGRESS.md
  {
    echo "# Progress archive (older entries, newest first)"
    echo
    cat "$old"
    [ -f PROGRESS-archive.md ] && sed '1{/^# Progress archive/d}' PROGRESS-archive.md
  } >"$arch"
  cat "$arch" >PROGRESS-archive.md
  cat "$keep" >PROGRESS.md
  rm -f "$keep" "$old" "$arch"
  echo "  archived $((n - KEEP_PROGRESS)) PROGRESS entries" >>"$LOG_DIR/loop.log"
}

# Move "## " sections of TODO.md whose items are all [x] to TODO-done.md.
archive_todo() {
  [ -f TODO.md ] || return 0
  local keep done; keep=$(mktemp); done=$(mktemp)
  awk -v keepf="$keep" -v donef="$done" '
    function flush() {
      if (buf == "") return
      if (hdr && hasx && !open) printf "%s", buf > donef; else printf "%s", buf > keepf
      buf = ""
    }
    /^## / { flush(); hdr = 1; hasx = 0; open = 0 }
    {
      buf = buf $0 "\n"
      if ($0 ~ /^[[:space:]]*- \[[xX]\]/) hasx = 1
      if ($0 ~ /^[[:space:]]*- \[[ !]\]/) open = 1
    }
    END { flush() }' TODO.md
  if [ -s "$done" ]; then
    [ -f TODO-done.md ] || printf '# Completed TODO phases (archived by loop.sh)\n\n' >TODO-done.md
    cat "$done" >>TODO-done.md
    cat "$keep" >TODO.md
    echo "  archived finished TODO phases" >>"$LOG_DIR/loop.log"
  fi
  rm -f "$keep" "$done"
}

kill_orphans() {
  # Test- or agent-spawned daemons and MCP servers from this checkout's target dir.
  pkill -u "$(id -u)" -f "^$PWD/target/debug/(deps/)?(pmd|passmgr|pm)( |$)" 2>/dev/null || true
}

summary() {
  {
    echo "loop summary — $(date)"
    echo "iterations this run: $n   (last iteration number: $i)"
    echo "commits since start: $(git rev-list --count "$START_HEAD..HEAD" 2>/dev/null)"
    echo "TODO items committed: $(git log --format=%s "$START_HEAD..HEAD" 2>/dev/null | grep -c '(TODO ')"
    echo "reviews: $(git log --format=%s "$START_HEAD..HEAD" 2>/dev/null | grep -c '^Review ')"
    echo
    echo "blocked items:"
    grep -E '^[[:space:]]*- \[!\]' TODO.md 2>/dev/null | sed 's/^[[:space:]]*/  /' || true
    echo
    echo "NEEDS HUMAN REVIEW lines added this run:"
    git log -p "$START_HEAD..HEAD" -- PROGRESS.md 2>/dev/null | grep -E '^\+.*NEEDS HUMAN REVIEW' | sed 's/^+/  /' || true
    echo
    echo "rolled-back work (branches): $(git branch --list 'failed/*' | wc -l)"
    echo "stashed leftovers: $(git stash list | wc -l)"
    echo "next item: $(current_item)"
  } >"$LOG_DIR/summary.txt"
  cat "$LOG_DIR/summary.txt" >>"$LOG_DIR/loop.log"
}

i=0; n=0; idle=0; fails=0; infra=0; since_review=0
CHILD=""
cleanup() {
  echo; echo "loop: interrupted, stopping."
  [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null
  summary
  exit 130
}
trap cleanup INT TERM

# --- state -----------------------------------------------------------------
# Continue iteration numbering from earlier runs so log names stay ordered.
i=$(find "$LOG_DIR" -maxdepth 1 -name 'iter-*.log' 2>/dev/null | sed -E 's|.*/iter-0*([0-9]+)-.*|\1|' | sort -n | tail -1)
i=${i:-0}
last_review=$(cat "$STATE_DIR/last-review" 2>/dev/null || true)
git cat-file -e "${last_review:-x}^{commit}" 2>/dev/null || last_review=$START_HEAD
echo "$last_review" >"$STATE_DIR/last-review"

# --- loop ------------------------------------------------------------------
while :; do
  [ -f STOP ] && { say "loop: STOP file found, exiting."; rm -f STOP; break; }
  if [ "$MAX_ITERS" -gt 0 ] && [ "$n" -ge "$MAX_ITERS" ]; then say "loop: reached MAX_ITERS=$MAX_ITERS"; break; fi
  if [ "$deadline" -gt 0 ] && [ "$(date +%s)" -ge "$deadline" ]; then say "loop: reached UNTIL=$UNTIL"; break; fi

  # Housekeeping on a clean tree, before the agent reads anything.
  archive_progress
  archive_todo
  loop_commit "archive old PROGRESS entries and finished TODO phases" PROGRESS.md PROGRESS-archive.md TODO.md TODO-done.md

  i=$((i+1)); n=$((n+1))
  ts=$(date +%Y%m%d-%H%M%S)
  log="$LOG_DIR/iter-$(printf %04d "$i")-$ts.log"
  before=$(git rev-parse HEAD)

  kind="work"
  if [ "$REVIEW_EVERY" -gt 0 ] && [ "$since_review" -ge "$REVIEW_EVERY" ] && [ "$last_review" != "$before" ]; then
    kind="review"
  fi
  item=""
  if [ "$kind" = "work" ]; then
    item=$(current_item)
    prompt=$(cat "$PROMPT_FILE")
  else
    prompt="$(cat "$REVIEW_FILE")

Review range: ${last_review}..${before}"
  fi

  say "=== iteration $i  $(date)  (HEAD ${before:0:8})  $kind${item:+ item $item} ==="

  started=$(date +%s)
  # shellcheck disable=SC2086
  timeout --kill-after=2m "$ITER_TIMEOUT" pi -p "$prompt" $PI_ARGS </dev/null >"$log" 2>&1 &
  CHILD=$!
  wait "$CHILD"; rc=$?
  CHILD=""
  dur=$(( $(date +%s) - started ))
  kill_orphans

  after=$(git rev-parse HEAD)
  dirty=$([ -n "$(git status --porcelain)" ] && echo 1 || echo 0)

  # Provider / pi failure: no work done and pi errored or bailed out fast.
  if [ "$after" = "$before" ] && [ "$dirty" = 0 ] && [ "$rc" -ne 124 ] && [ "$rc" -ne 137 ] &&
     { [ "$rc" -ne 0 ] || [ "$dur" -lt "$MIN_ITER_SECS" ]; }; then
    infra=$((infra+1))
    wait_s=$(( SLEEP_SECS * (2 ** (infra < 10 ? infra : 10)) ))
    [ "$wait_s" -gt "$MAX_BACKOFF" ] && wait_s=$MAX_BACKOFF
    say "  result: infra-failure (pi exit $rc after ${dur}s, no work) #$infra; retrying in ${wait_s}s. Last log lines:"
    tail -n 3 "$log" | sed 's/^/    | /' | tee -a "$LOG_DIR/loop.log"
    if [ "$infra" -ge "$MAX_INFRA_FAILS" ]; then say "loop: $infra pi/provider failures in a row, stopping."; break; fi
    sleep "$wait_s"
    continue
  fi
  infra=0

  status="ok"
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then status="timeout"
  elif [ "$rc" -ne 0 ]; then status="pi-exit-$rc"
  fi

  # Leftover uncommitted changes = unfinished work. Stash so the next iteration starts clean.
  if [ "$dirty" = 1 ]; then
    git stash push -u -q -m "loop iter $i leftovers ($status)"
    say "  stashed uncommitted leftovers as stash@{0}"
    [ "$status" = "ok" ] && status="dirty"
  fi

  # Independent check: don't trust the agent's claim that the gate passed.
  if [ "$VERIFY" = "1" ] && [ "$after" != "$before" ]; then
    if ! gate >"$log.gate" 2>&1; then
      say "  gate FAILED after agent commits; rolling back to ${before:0:8}"
      git branch -q "failed/iter-$i-$ts" "$after"   # keep the bad work for inspection
      git reset -q --hard "$before"
      excerpt=$(grep -m 8 -E 'error(\[|:)|FAILED|panicked|^Diff in|^warning: ' "$log.gate" | cut -c1-200)
      notes=("Commits from this ${kind} iteration${item:+ (TODO $item)} failed the gate and were rolled back."
             "The work is kept on branch failed/iter-$i-$ts; you may cherry-pick from it and fix it.")
      while IFS= read -r l; do [ -n "$l" ] && notes+=("gate: \`$l\`"); done <<<"$excerpt"
      progress_note "gate failed" "${notes[@]}"
      loop_commit "roll back failed iteration $i" PROGRESS.md
      after=$(git rev-parse HEAD)
      status="gate-failed"
    fi
  fi

  if [ "$status" = "timeout" ]; then
    progress_note "timeout" \
      "The ${kind} iteration${item:+ on TODO $item} hit the ${ITER_TIMEOUT} limit before committing." \
      "Uncommitted work (if any) is in \`git stash list\` as \"loop iter $i leftovers\"." \
      "Next attempt: split ${item:-the item} into smaller sub-items first and do only the first one."
    loop_commit "note timeout in iteration $i" PROGRESS.md
    after=$(git rev-parse HEAD)
  elif [ "$dirty" = 1 ]; then
    progress_note "unfinished" \
      "The ${kind} iteration${item:+ on TODO $item} ended ($status) without committing its changes." \
      "They are in \`git stash list\` as \"loop iter $i leftovers\". Finish smaller and commit."
    loop_commit "note unfinished iteration $i" PROGRESS.md
    after=$(git rev-parse HEAD)
  fi

  # Agent commits only (not the loop's own notes).
  agent_commits=$(git log --format=%s "$before..$after" 2>/dev/null | grep -vc '^loop: ')
  say "  result: $status, $agent_commits agent commit(s), ${dur}s, log: $log"

  if [ "$kind" = "review" ]; then
    if [ "$status" = "ok" ]; then
      fails=0; since_review=0
      last_review=$before; echo "$last_review" >"$STATE_DIR/last-review"
    else
      fails=$((fails+1))
    fi
  else
    if [ "$status" = "ok" ] && [ "$agent_commits" -gt 0 ]; then
      fails=0; idle=0; since_review=$((since_review+1))
      [ -n "$item" ] && rm -f "$STATE_DIR/item-$item.fails"
    else
      [ "$status" = "ok" ] && idle=$((idle+1)) || fails=$((fails+1))
      # Same item still open after a failed attempt: count it, and block it at the limit.
      if [ -n "$item" ] && item_is_open "$item"; then
        c=$(( $(fail_count "$item") + 1 )); echo "$c" >"$STATE_DIR/item-$item.fails"
        if [ "$c" -ge "$MAX_ITEM_FAILS" ]; then
          block_item "$item" "$c"
          progress_note "blocked TODO $item" \
            "TODO $item failed $c attempts in a row (last: $status); marked [!] so the loop can move on." \
            "A review or refill iteration may split it into smaller items. NEEDS HUMAN REVIEW if it stays blocked."
          loop_commit "block TODO $item after $c failed attempts" TODO.md PROGRESS.md
          rm -f "$STATE_DIR/item-$item.fails"
          say "  blocked TODO $item after $c failed attempts"
          idle=0
        fi
      fi
    fi
  fi

  if [ "$fails" -ge "$MAX_FAILS" ]; then say "loop: $fails failed iterations in a row, stopping. Check $LOG_DIR/."; break; fi
  if [ "$idle" -ge "$MAX_IDLE" ]; then say "loop: $idle work iterations with no commits, stopping (stuck or done)."; break; fi

  if [ "$fails" -gt 0 ]; then sleep $(( SLEEP_SECS * (2 ** fails) )); else sleep "$SLEEP_SECS"; fi
done

summary
say "loop: finished after $n iteration(s) this run. Summary: $LOG_DIR/summary.txt"
