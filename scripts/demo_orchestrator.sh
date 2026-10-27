#!/usr/bin/env bash
# Hackathon demo, step 1: the orchestrator hands the claim to the agent through the
# ACP-A2A gateway; the agent records every step through the ksg MCP tools
# (scripts/ksg_mcp.py) and exports the pages the expert will get.
#
#   scripts/demo_orchestrator.sh [agent_id] [case_file]
#
# agent_id defaults to hermes-cloud (Muse Spark through Meta Model API, owner 26.10); the agent must have the `ksg` MCP server
# (scripts/ksg_mcp.py) and the Meta Model API provider (Muse Spark) configured.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT=${1:-hermes-cloud}
CASE=${2:-$ROOT/demo/case_4417.md}

{
  cat <<'TASK'
New task. You are an insurance claims agent. Every step of your work must be recorded
as a journal page with the ksg tools, at the moment you take it:
1. Call ksg_get_container once; keep the returned name.
2. ksg_write_page: "input: ..." — the claim as you read it.
3. ksg_write_page: "tool call: policy_lookup(P-88) -> ..." — the clauses you rely on.
4. ksg_write_page: "tool call: classify_damage(...) -> ..." — your reading of the evidence.
5. ksg_write_page: "result: ..." — the decision, the reason and the clause.
6. ksg_export_page for pages 1, 2 and 4, then ksg_verify each file.
Reply with: the container name and identifier, the decision, and for each exported page
its file and whether it was ACCEPTED. The case (synthetic data):

TASK
  cat "$CASE"
} | "$ROOT/scripts/gw_ask.sh" "$AGENT" - 1800
