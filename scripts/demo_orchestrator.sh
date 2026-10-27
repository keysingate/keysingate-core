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

ANSWER=$(mktemp /tmp/ksg-answer.XXXXXX.txt)

TASK=$(cat <<'TASK'
New task. You are an insurance claims agent. Every step of your work must be recorded
as a journal page with the ksg tools, at the moment you take it:
1. Call ksg_get_container once; keep the returned name (it is the `name` argument below).
2. ksg_write_page: "input: ..." — the claim as you read it.
3. ksg_write_page: "tool call: policy_lookup(P-88) -> ..." — the clauses you rely on.
4. ksg_model_call(name, prompt="...", tool_args={...}) — ask Muse Spark to read the
   evidence and name the clause; the tool journals the call itself (model, sha256 of
   the request, sha256 of the answer, the arguments, the time) and tells you the page
   number. Quote its answer in the next page.
5. ksg_mask_damage(name, image_path="demo/damage_4417.png", box=[600, 380, 1120, 1080])
   — one damage picture; the tool journals the model, sha256 of the picture, the box
   and sha256 of the mask, and tells you the page number.
6. ksg_write_page: "result: ..." — the decision, the reason and the clause.
7. ksg_export_page for every page you wrote (1 through the last number the tools gave
   you), then ksg_verify each file.
8. Last step, and part of your reply: finish the answer with a block that starts with
   the line `EXPLANATION:` — the decision explained to the hackathon judge in plain
   language, no jargon, at most 120 words. Every statement in it must carry a
   citation `[p:N]` to its own page, N being a page you wrote above. The program
   checks those links; a citation of a page that does not exist is a failed demo.
Reply with: the container name and identifier, the decision, and for each exported page
its number, its file and whether it was ACCEPTED — then the `EXPLANATION:` block. The
case (synthetic data):

TASK
)

# A task the gateway cut (first-chunk timeout, an agent crash) leaves pages half
# written: the explanation of step 9 would then stand on an unfinished run.
if ! { printf '%s\n' "$TASK"; cat "$CASE"; } | "$ROOT/scripts/gw_ask.sh" "$AGENT" - 1800 | tee "$ANSWER"; then
  echo "the agent did not complete the task: no explanation is made from a cut run" >&2
  echo "the agent's partial answer: $ANSWER" >&2
  exit 1
fi

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
