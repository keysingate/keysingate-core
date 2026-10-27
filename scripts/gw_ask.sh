#!/usr/bin/env bash
# Give a task to a local agent through the ACP-A2A gateway and print its answer.
#
#   scripts/gw_ask.sh <agent_id> <task-file|-> [max_seconds]
#
# agent_id: opencode-cloud | hermes-cloud (agents in the owner's gateway config).
# The task goes as a non-blocking message/send (configuration.blocking: false):
# the gateway answers at once with a task id, the script polls tasks/get every
# 5 s until the state is not "working". No connection stays open while the
# agent works, so the cloud egress proxy cannot cut it (~30 s of silence).
# The bearer token is added by the cloud proxy (Network secrets for the host),
# the script never sees it.
set -euo pipefail

AGENT=${1:?agent_id}
SRC=${2:?task file or -}
MAX=${3:-1800}
BASE=${GW_BASE:-https://gw.keysingate.com}
URL="$BASE/agents/$AGENT/rpc"

if [ "$SRC" = "-" ]; then TEXT=$(cat); else TEXT=$(cat "$SRC"); fi

START=$(python3 -I -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "message/send",
  "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": sys.argv[1]}]},
             "configuration": {"blocking": False}}}, ensure_ascii=False))' "$TEXT" \
  | curl -sS --max-time 60 -X POST "$URL" -H 'Content-Type: application/json' --data-binary @-)

TASK=$(printf '%s' "$START" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d: sys.exit("gateway error: " + json.dumps(d["error"], ensure_ascii=False))
print(d["result"]["id"])')
echo "task $TASK started" >&2

DEADLINE=$(( $(date +%s) + MAX ))
while :; do
  GOT=$(curl -sS --max-time 30 -X POST "$URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tasks/get\",\"params\":{\"id\":\"$TASK\"}}")
  STATE=$(printf '%s' "$GOT" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("result", {}).get("status", {}).get("state", "error"))')
  if [ "$STATE" != "working" ]; then break; fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then echo "timeout: task $TASK still working" >&2; exit 2; fi
  sleep 5
done

printf '%s' "$GOT" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d: sys.exit("gateway error: " + json.dumps(d["error"], ensure_ascii=False))
st = d["result"]["status"]
for p in (st.get("message") or {}).get("parts", []):
    if p.get("kind") == "text": print(p["text"])
print("[state: " + st["state"] + "]")'
