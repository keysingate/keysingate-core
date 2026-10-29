#!/usr/bin/env bash
# Hackathon demo, steps 1 and 9: the orchestrator hands the claim to the agent
# through the ACP-A2A gateway; the agent records every step through the ksg MCP
# tools (scripts/ksg_mcp.py) — including every Muse Spark call and the SAM mask —
# exports the pages the expert will get, and writes the explanation for the
# judge. The program checks what that explanation points at.
#
#   scripts/demo_orchestrator.sh [agent_id] [case_file]
#
# agent_id defaults to hermes-cloud (Muse Spark through Meta Model API, owner 26.10);
# the agent must have the `ksg` MCP server (scripts/ksg_mcp.py) with MODEL_API_KEY,
# KSG_PANEL, KSG_VERIFY, KSG_WORK set, and the Meta Model API provider (Muse Spark).
#
# Owner's decision 27.10: the explanation for the judge is written by the agent
# itself (Hermes, Muse Spark) — it ends its answer with an `EXPLANATION:` block and
# this script checks that block's [p:N] links. So the orchestrator needs no Meta
# key of its own: the key load below only serves the old mode (judge_explain.py
# without --text, where the program asks the model itself).
#
# Environment of this script: MODEL_API_KEY (optional, old mode only; when it is
# empty the key is read from the file named by KSG_META_KEY_FILE — but only when
# that variable is set: there is no default key path, and the value is never
# printed), KSG_WORK (default: ./ksg-work), KSG_PANEL, KSG_VERIFY, KSG_CLASS.
#
# KSG_WORK must be the same directory the agent's `ksg` MCP server writes to
# (its own `env:` block in the gateway's Hermes config): the orchestrator reads
# the pages the agent exported from there in step 9.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT=${1:-hermes-cloud}
CASE=${2:-$ROOT/demo/case_4417.md}
WORK=${KSG_WORK:-$ROOT/ksg-work}
export KSG_WORK="$WORK"
export KSG_CLASS=${KSG_CLASS:-light}
export KSG_PANEL=${KSG_PANEL:-$ROOT/target/release/ksg-remote-panel}
export KSG_VERIFY=${KSG_VERIFY:-$ROOT/target/release/ksg-verify-v2}
[ -x "$KSG_PANEL" ] || KSG_PANEL=$ROOT/target/debug/ksg-remote-panel
[ -x "$KSG_VERIFY" ] || KSG_VERIFY=$ROOT/target/debug/ksg-verify-v2
export KSG_PANEL KSG_VERIFY

# The Meta Model API key is not needed for step 9: the agent writes the explanation
# and this script only checks its [p:N] links. A key is loaded best-effort for the
# old mode only (judge_explain.py without --text): the environment first, then the
# file named by KSG_META_KEY_FILE — and that file only when the variable is set.
# There is no default key path here; the value never reaches stdout, stderr or the
# trace of this script.
if [ -z "${MODEL_API_KEY:-}" ] && [ -n "${KSG_META_KEY_FILE:-}" ]; then
  KEY_FILE=$KSG_META_KEY_FILE
  if [ -r "$KEY_FILE" ]; then
    MODEL_API_KEY=$(head -n 1 "$KEY_FILE" | tr -d '[:space:]')
    if [ -n "$MODEL_API_KEY" ]; then
      export MODEL_API_KEY
    else
      unset MODEL_API_KEY
    fi
  else
    echo "note: KSG_META_KEY_FILE ($KEY_FILE) is not readable; only the old model-written mode needs a key" >&2
  fi
fi
if [ -z "${MODEL_API_KEY:-}" ]; then
  echo "note: no Meta key (MODEL_API_KEY unset, no readable KSG_META_KEY_FILE): the old mode" >&2
  echo "(judge_explain.py without --text, the program asks the model) is unavailable here;" >&2
  echo "the agent-written mode below (judge_explain.py --text) needs no key" >&2
fi

# Steps of the demo (ops/supervisor/spec_demo_checklist.md item 1): each step is
# a SEPARATE gateway task with a short timeout (<=300 s) and one retry on a
# cut or empty answer. The agent's reply to a step is exactly one line
# `STEP <n> OK page=<p>` (or `STEP <n> FAIL <reason>`); the page itself is
# written through the `ksg` MCP tools. The last step appends the EXPLANATION
# block after its STEP line. Step→page recording ($KSG_WORK/steps.json) is the
# next stage (N7); step 9 below re-discovers the pages the agent exported.
STEP_TIMEOUT=300
# Steps that call Muse Spark / SAM 3.1 or export+verify every page take longer.
step_timeout() {
  case "$1" in
    3|4|6|7) echo 600 ;;
    *) echo "$STEP_TIMEOUT" ;;
  esac
}
LAST_STEP=7

# step_prompt <n>: print the prompt for step <n> on stdout. Every step is
# self-contained (the gateway may start a fresh task): it re-opens the
# container with ksg_get_container and does exactly one tool step.
step_prompt() {
  case "$1" in
    1) cat <<'STEP'
New task. You are an insurance claims agent. Record this step as a journal page
with the ksg tools, at the moment you take it:
1. Call ksg_get_container once (it returns the existing container if there is
   one); keep the returned name (it is the `name` argument below).
2. ksg_write_page: "input: ..." — the claim as you read it (the case is
   appended below).
Reply with exactly one line: `STEP 1 OK page=<p>` where <p> is the page number
the tool gave you. The case (synthetic data):
STEP
      ;;
    2) cat <<'STEP'
New task. You are an insurance claims agent. Record this step as a journal page:
1. Call ksg_get_container once (returns the existing container); keep `name`.
2. ksg_write_page: "tool call: policy_lookup(P-88) -> ..." — the clauses you
   rely on for the claim (water damage, apartment 4417, policy P-88).
Reply with exactly one line: `STEP 2 OK page=<p>`.
STEP
      ;;
    3) cat <<'STEP'
New task. You are an insurance claims agent:
1. Call ksg_get_container once (returns the existing container); keep `name`.
2. ksg_model_call(name, prompt="...", tool_args={...}) — ask Muse Spark to read
   the evidence (claim: water damage, apartment 4417, policy P-88) and name the
   clause; the tool journals the call itself (model, sha256 of the request,
   sha256 of the answer, the arguments, the time) and tells you the page
   number. Quote its answer in the next page (ksg_write_page).
Reply with exactly one line: `STEP 3 OK page=<p>` where <p> is the quote page.
STEP
      ;;
    4) cat <<'STEP'
New task. You are an insurance claims agent:
1. Call ksg_get_container once (returns the existing container); keep `name`.
2. ksg_mask_damage(name, image_path="demo/damage_4417.png",
   box=[600, 380, 1120, 1080]) — one damage picture; the tool journals the
   model, sha256 of the picture, the box and sha256 of the mask, and tells you
   the page number.
Reply with exactly one line: `STEP 4 OK page=<p>`.
STEP
      ;;
    5) cat <<'STEP'
New task. You are an insurance claims agent:
1. Call ksg_get_container once (returns the existing container); keep `name`.
2. ksg_write_page: "result: ..." — the decision, the reason and the clause
   (claim: water damage, apartment 4417, policy P-88).
Reply with exactly one line: `STEP 5 OK page=<p>`.
STEP
      ;;
    6) cat <<'STEP'
New task. You are an insurance claims agent:
1. Call ksg_get_container once (returns the existing container); keep `name`.
2. ksg_export_page for every page you wrote (1 through the last number the
   tools gave you), then ksg_verify each file.
Reply with exactly one line: `STEP 6 OK page=<p>` where <p> is the last page
you exported and verified ACCEPTED.
STEP
      ;;
    7) cat <<'STEP'
New task. You are an insurance claims agent. Last step, and part of your reply:
1. Call ksg_get_container once (returns the existing container).
2. Finish the answer with a block that starts with the line `EXPLANATION:` —
   the decision explained to the hackathon judge in plain language, no jargon,
   at most 120 words. Every statement in it must carry a citation `[p:N]` to
   its own page, N being a page you wrote above. The program checks those
   links; a citation of a page that does not exist is a failed demo.
First line of your reply: `STEP 7 OK`. Then the `EXPLANATION:` block. Also
report: the container name and identifier, the decision, and for each exported
page its number, its file and whether it was ACCEPTED.
STEP
      ;;
  esac
}

ANSWERS_DIR="$WORK/answers"
mkdir -p "$ANSWERS_DIR"
# spec_demo_checklist item 3 (N7): the orchestrator records step→page here;
# judge_page.py --steps reads it in N8. Written fresh on every run.
STEPS_JSON="$WORK/steps.json"
echo '{}' >"$STEPS_JSON"
# One agent session for the whole checklist: step 1 opens it, every later step
# continues it (A2A contextId), so the agent keeps the claim in its context.
CTX_FILE="$WORK/context_id"
rm -f "$CTX_FILE"
# Seconds per step (for the judge page and the anchoring-time budget).
TIMES_JSON="$WORK/step_times.json"
echo '{}' >"$TIMES_JSON"
STEP=1
STEP7_ANSWER=""
while [ "$STEP" -le "$LAST_STEP" ]; do
  PROMPT_FILE=$(mktemp /tmp/ksg-step.XXXXXX.txt)
  if [ "$STEP" -eq 1 ]; then
    { step_prompt 1; cat "$CASE"; } >"$PROMPT_FILE"
  else
    step_prompt "$STEP" >"$PROMPT_FILE"
  fi
  ATTEMPT=0
  while :; do
    ATTEMPT=$((ATTEMPT + 1))
    STEP_ANSWER="$ANSWERS_DIR/step-$STEP.attempt-$ATTEMPT.txt"
    if [ "$ATTEMPT" -ge 2 ]; then
      # N10: idempotent retry — the first attempt may have written the page
      # but its answer got cut. Tell the agent not to redo the step.
      {
        echo
        echo "Retry note: if step $STEP is already done and its page is written, do NOT do it again — just reply STEP $STEP OK page=<the number of the page you already wrote>."
      } >>"$PROMPT_FILE"
    fi
    T0=$(date +%s)
    set +e
    if [ -s "$CTX_FILE" ]; then
      GW_CONTEXT_ID=$(cat "$CTX_FILE") "$ROOT/scripts/gw_ask.sh" "$AGENT" "$PROMPT_FILE" "$(step_timeout "$STEP")" >"$STEP_ANSWER" 2>"$STEP_ANSWER.err"
    else
      GW_CONTEXT_OUT="$CTX_FILE" "$ROOT/scripts/gw_ask.sh" "$AGENT" "$PROMPT_FILE" "$(step_timeout "$STEP")" >"$STEP_ANSWER" 2>"$STEP_ANSWER.err"
    fi
    GW_RC=$?
    set -e
    python3 - "$TIMES_JSON" "$STEP" "$ATTEMPT" "$(( $(date +%s) - T0 ))" "$GW_RC" <<'PY'
import json, sys
path, step, attempt, secs, rc = sys.argv[1:]
try:
    data = json.load(open(path))
except Exception:
    data = {}
data.setdefault(step, []).append({"attempt": int(attempt), "seconds": int(secs), "gw_rc": int(rc)})
json.dump(data, open(path, "w"), indent=1, sort_keys=True)
PY
    echo "step $STEP attempt $ATTEMPT: $(( $(date +%s) - T0 )) s (gw rc=$GW_RC)" >&2
    # N10: the STEP line may sit anywhere in the answer (no newline before
    # it), so it is searched anywhere — no ^ anchor — and the OK/FAIL verdict
    # plus page=<n> are read from that line, not from the whole answer.
    STEP_LINE=$(grep -oE "STEP $STEP (OK|FAIL)[^[:cntrl:]]*" "$STEP_ANSWER" | tail -1 || true)
    if [ "$GW_RC" -eq 0 ] && [ -n "$STEP_LINE" ] && echo "$STEP_LINE" | grep -qE "STEP $STEP OK"; then
      echo "step $STEP OK (attempt $ATTEMPT): $STEP_LINE"
      # N7: record step→page (step 7 has no page — its line is bare `STEP 7 OK`).
      PAGE=$(echo "$STEP_LINE" | grep -oE "page=[0-9]+" | head -1 | cut -d= -f2 || true)
      python3 - "$STEPS_JSON" "$STEP" "${PAGE:-}" <<'PY'
import json, sys
path, step, page = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
if page:
    data[str(step)] = int(page)
with open(path, "w") as f:
    json.dump(data, f, indent=1, sort_keys=True)
PY
      break
    fi
    if [ "$GW_RC" -eq 0 ] && [ -n "$STEP_LINE" ] && echo "$STEP_LINE" | grep -qE "STEP $STEP FAIL"; then
      echo "step $STEP refused by the agent: $STEP_LINE" >&2
      echo "the agent's answer: $STEP_ANSWER" >&2
      rm -f "$PROMPT_FILE"
      exit 1
    fi
    # A cut task (timeout, an agent crash) or an empty answer: retry once.
    if [ "$ATTEMPT" -ge 2 ]; then
      echo "step $STEP gave no usable answer twice (gw rc=$GW_RC): not retrying" >&2
      echo "the agent's partial answer: $STEP_ANSWER" >&2
      rm -f "$PROMPT_FILE"
      exit 1
    fi
    echo "step $STEP attempt $ATTEMPT cut or empty (gw rc=$GW_RC): retrying once" >&2
  done
  rm -f "$PROMPT_FILE"
  if [ "$STEP" -eq "$LAST_STEP" ]; then STEP7_ANSWER="$STEP_ANSWER"; fi
  STEP=$((STEP + 1))
done

# Step 9 reads the explanation from the last step's answer.
ANSWER="$STEP7_ANSWER"

# Step 9: the explanation for the judge, written by the agent itself (Muse Spark).
# This script only cuts the `EXPLANATION:` block out of the agent's answer and lets
# judge_explain.py check that every [p:N] points at a page that exists and was
# ACCEPTED offline — no model is called here.
BOX=$(ls -dt "$WORK"/c-* 2>/dev/null | head -1 || true)
if [ -z "${BOX:-}" ]; then
  echo "no container under $WORK: the agent wrote no pages" >&2
  exit 1
fi
NAME=$(basename "$BOX")
PAGES=()
for file in "$BOX"/page-*.json; do
  [ -e "$file" ] || continue
  number=$(basename "$file" .json); number=${number#page-}
  PAGES+=(--page "$number=$file")
done
if [ ${#PAGES[@]} -eq 0 ]; then
  echo "no exported pages under $BOX: nothing to explain" >&2
  exit 1
fi

# The block starts at the line `EXPLANATION:` and runs to the end of the answer; text
# on that same line counts too (the agent may write `EXPLANATION: the claim ...`).
EXPLANATION=$(mktemp /tmp/ksg-explanation.XXXXXX.txt)
awk 'found { print; next }
     /^[[:space:]]*EXPLANATION:/ { found = 1
       sub(/^[[:space:]]*EXPLANATION:[[:space:]]*/, "")
       if (length($0)) print }' "$ANSWER" > "$EXPLANATION"
if [ ! -s "$EXPLANATION" ]; then
  echo "the agent's answer has no EXPLANATION: block: nothing to check for the judge" >&2
  echo "the agent's answer: $ANSWER" >&2
  echo "the agent's explanation: $EXPLANATION (empty)" >&2
  exit 1
fi

python3 "$ROOT/scripts/judge_explain.py" --name "$NAME" --work "$WORK" "${PAGES[@]}" --text "$EXPLANATION"
echo
echo "explanation of the agent: $EXPLANATION"
echo "answer of the agent: $ANSWER"
