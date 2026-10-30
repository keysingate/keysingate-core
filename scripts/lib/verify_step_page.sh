#!/usr/bin/env bash
# 1.6a(b): verify that the page number the agent claimed in its STEP line
# really exists as a file in the run's box. The agent must call the ksg
# tools (ksg_get_container, ksg_write_page, ...) — a bare "STEP N OK page=<p>"
# line without a matching page-<p>.json is an unusable answer (the N14
# .current guard alone only proves *some* container exists, not that the
# claimed page was written).
#
# Usage: verify_step_page "$WORK" "$PAGE"  (step 7 has no page: skip it)
# Prints the box dir used and returns 0 when page-<PAGE>.json exists there,
# 1 otherwise. Box resolution: $WORK/.current first, else the newest c-*
# directory under $WORK.
# Pure function of its arguments + $WORK on disk: safe to source in tests.
verify_step_page() {
  local work="$1" page="$2" box=""
  [ -n "$page" ] || return 1
  if [ -s "$work/.current" ]; then
    box="$work/$(cat "$work/.current")"
  fi
  if [ -z "$box" ] || [ ! -d "$box" ]; then
    box=$(ls -dt "$work"/c-* 2>/dev/null | head -1 || true)
  fi
  [ -n "$box" ] && [ -f "$box/page-$page.json" ] || return 1
  printf '%s\n' "$box"
  return 0
}
