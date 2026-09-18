#!/usr/bin/env bash
# ship.sh — one-shot ship: tests → commit → push (gitlab) → auto jobs → deploy_dev.
#
# Usage (chmod is blocked on the NFS share, so invoke via bash):
#   bash scripts/ship.sh -m "message" [paths...]   # paths = what to stage (default: all changes)
#   bash scripts/ship.sh -m "message" --no-deploy # stop once the auto jobs are green
#
# Why a script (memory-bank/decisions.md — "Fast ship workflow"):
#   * polls JOBS, never the pipeline status — with pending manual jobs the
#     pipeline sticks at "manual" forever, so a "wait-for-finished" poller
#     spins until someone aborts it;
#   * every step is non-interactive (this NFS terminal hangs git on pager /
#     ssh prompts — see the gotchas in decisions.md);
#   * 10s poll cadence → wall time ≈ tests (10s) + pipeline (~4 min)
#     + deploy (~1 min) ≈ 6 min end to end.
#   * deploy_dev is triggered automatically (sandbox box); deploy_test /
#     deploy_production are NEVER touched — they still need explicit user
#     confirmation.

set -euo pipefail
cd "$(dirname "$0")/.."

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=true
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o ConnectTimeout=20}"
GIT="git -c core.pager=cat"
GITLAB_URL="${GITLAB_URL:-http://192.168.86.38:32769}"
GITLAB_PROJECT_ID="${GITLAB_PROJECT_ID:-4}"
GITLAB_TOKEN_VAR="${GITLAB_TOKEN_VAR:-GITLAB_PIPELINE_TOKEN}"

T0=$(date +%s)
say()  { local s=$(( $(date +%s) - T0 )); printf '[%02dm %02ds] %s\n' $((s/60)) $((s%60)) "$*"; }
step() { printf '\n== %s ==\n' "$*"; }

# ---------------- args ----------------
MSG=""; DEPLOY=1; PATHS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -m) MSG="${2:-}"; shift 2 ;;
    --no-deploy) DEPLOY=0; shift ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | head -25; exit 0 ;;
    *) PATHS+=("$1"); shift ;;
  esac
done
[ -n "$MSG" ] || { echo 'usage: scripts/ship.sh -m "commit message" [paths...]' >&2; exit 2; }

# ---------------- 1. tests + lint (fail fast) ----------------
step "1/5 tests + lint"
say "pytest tests/ -q"
python3 -m pytest tests/ -q
say "ruff check"
python3 -m ruff check app/ scripts/ tests/

# ---------------- 2. commit ----------------
step "2/5 commit"
[ ${#PATHS[@]} -eq 0 ] && PATHS=(.)
$GIT add -- "${PATHS[@]}" </dev/null
if $GIT diff --cached --quiet </dev/null; then
  say "nothing to commit — resuming: will wait on the pipeline for current HEAD, then deploy"
  SKIP_PUSH=1
else
  $GIT commit -m "$MSG" </dev/null
  SKIP_PUSH=0
fi
SHA=$($GIT rev-parse HEAD </dev/null)
say "HEAD = ${SHA:0:7}"

# ---------------- 3. push to gitlab (primary) ----------------
step "3/5 push → gitlab"
if [ "$SKIP_PUSH" = 1 ]; then
  say "no new commit — push skipped (re-run/resume)"
else
  timeout 180 $GIT push gitlab HEAD:main </dev/null
  say "pushed ${SHA:0:7}"
fi
# ---------------- 4. wait for the pipeline's auto jobs ----------------
# NB: poll the JOBS, not the pipeline status — with pending manual jobs the
# pipeline status is "manual" forever.
step "4/5 pipeline auto jobs for ${SHA:0:7}"
[ -f .env.local ] || { echo ".env.local missing at repo root — cannot poll gitlab" >&2; exit 1; }
set -a; . ./.env.local; set +a
TOKEN="${!GITLAB_TOKEN_VAR:-}"
[ -n "$TOKEN" ] || { echo "$GITLAB_TOKEN_VAR is not set in .env.local" >&2; exit 1; }
API="$GITLAB_URL/api/v4/projects/$GITLAB_PROJECT_ID"

PID=""
for _ in $(seq 1 60); do
  PID=$(WANT="$SHA" curl -s -m 10 -H "PRIVATE-TOKEN: $TOKEN" "$API/pipelines?ref=main&per_page=5" \
    | python3 -c '
import sys, json, os
try:
    for p in json.load(sys.stdin):
        if p["sha"].startswith(os.environ["WANT"]):
            print(p["id"]); break
except Exception:
    pass' || true)
  [ -n "$PID" ] && break
  sleep 5
done
[ -n "$PID" ] || { echo "no pipeline for ${SHA:0:7} appeared within 5 min (runner lag?)" >&2; exit 1; }
say "pipeline $PID created — watching auto jobs (10s cadence)"

DD=""
DEADLINE=$(( $(date +%s) + 1800 ))
while :; do
  ST=$(curl -s -m 10 -H "PRIVATE-TOKEN: $TOKEN" "$API/pipelines/$PID/jobs" \
    | python3 -c '
import sys, json
try:
    jobs = json.load(sys.stdin)
except Exception:
    print("WARMUP"); sys.exit()
auto = [j for j in jobs if j["name"] in ("lint", "unit_tests", "build_image")]
bad = [j for j in auto if j["status"] in ("failed", "canceled")]
if bad:
    print("FAILED " + ",".join(j["name"] for j in bad)); sys.exit()
if any(j["status"] in ("pending", "created", "running") for j in auto):
    print("RUNNING")
else:
    dd = next((str(j["id"]) for j in jobs if j["name"] == "deploy_dev"), "")
    print("READY " + dd)' || true)
  case "$ST" in
    FAILED*)
      say "auto jobs failed: ${ST#FAILED }"
      curl -s -m 10 -H "PRIVATE-TOKEN: $TOKEN" "$API/pipelines/$PID/jobs" \
        | python3 -c '
import sys, json
for j in json.load(sys.stdin):
    if j["status"] == "failed":
        print(j["id"], j["name"])' \
        | while read -r JID JNAME; do
            echo "--- trace: $JNAME ---"
            curl -s -m 15 -H "PRIVATE-TOKEN: $TOKEN" "$API/jobs/$JID/trace" | tail -40
          done
      exit 1 ;;
    READY\ *) say "auto jobs green — deploy_dev job: ${ST#READY }"; DD="${ST#READY }"; break ;;
    RUNNING*) say "auto jobs running ($ST)" ;;
    *) say "pipeline warming up ($ST)" ;;
  esac
  [ "$(date +%s)" -lt "$DEADLINE" ] || { echo "timed out after 30 min waiting for auto jobs" >&2; exit 1; }
  sleep 10
done

# ---------------- 5. deploy_dev (manual play) ----------------
if [ "$DEPLOY" = 1 ] && [ -n "$DD" ]; then
  step "5/5 deploy_dev (job $DD) — playing manual job"
  curl -s -m 15 -X POST -H "PRIVATE-TOKEN: $TOKEN" "$API/jobs/$DD/play" >/dev/null || true
  DEADLINE=$(( $(date +%s) + 900 ))
  JS="pending"
  while :; do
    JS=$(curl -s -m 10 -H "PRIVATE-TOKEN: $TOKEN" "$API/jobs/$DD" \
      | python3 -c '
import sys, json
try:
    print(json.load(sys.stdin)["status"])
except Exception:
    print("pending")' || true)
    case "$JS" in
      success)   say "deploy_dev SUCCESS" ;;
      failed)    say "deploy_dev FAILED — trace tail:"
                 curl -s -m 15 -H "PRIVATE-TOKEN: $TOKEN" "$API/jobs/$DD/trace" | tail -40
                 exit 1 ;;
      canceled)  say "deploy_dev CANCELED — trace tail:"
                 curl -s -m 15 -H "PRIVATE-TOKEN: $TOKEN" "$API/jobs/$DD/trace" | tail -40
                 exit 1 ;;
      *)         say "deploy_dev: $JS" ;;
    esac
    case "$JS" in success|failed|canceled) break ;; esac
    [ "$(date +%s)" -lt "$DEADLINE" ] || { echo "deploy_dev timed out after 15 min" >&2; exit 1; }
    sleep 10
  done
  code=$(curl -s -o /dev/null -m 10 -w "%{http_code}" "http://192.168.86.38:8787/" || echo 000)
  say "dev UI check: GET http://192.168.86.38:8787/ -> HTTP $code"
  say "SHIP OK — ${SHA:0:7} is live on dev (pipeline $PID)"
else
  step "5/5 deploy"
  say "skipped (--no-deploy or no deploy_dev job in pipeline $PID)"
fi
say "done in $(( ($(date +%s) - T0 ) / 60 ))m $(( ($(date +%s) - T0 ) % 60 ))s"
