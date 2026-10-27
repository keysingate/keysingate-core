#!/usr/bin/env bash
# The anchoring paths of core v2 against a real Solana node: the scenarios of
# `crates/ksg-cli-v2/tests/devnet.rs`, which run there against a mock node,
# run here against `solana-test-validator` on this machine.
#
#   S1  an older copy of the container does not open: the seal chain says so
#   S2  an older copy is caught by its status history, before any seal
#   S3  a payer that never held SOL anchors nothing
#   S4  light anchors no seal; Pro does from the form page on; back to light
#       anchors none again; the export verifies on the node
#   S5  a hand-off in Pro is anchored; the export verifies, the report names
#       the transfer
#   S6  a `bare` attaches to a Pro leader (13.10): the attachment anchors
#       nothing, the leader's slot 2 is one seal memo, the pair verifies from
#       both exports, the detachment burns the copy
#
# At the end: how many transactions the payer sent and how many lamports they
# cost - the gas of the run, read from the node.
#
# Needs: a running local node (`solana-test-validator --limit-ledger-size 500000`:
# with the default limit the node purges slot history mid-run and the seal
# memo count and the verify steps fail), `solana-keygen`,
# python3, and PAYER — a key file with SOL on that node.
#
#   PAYER=payer.json [RPC=http://127.0.0.1:8899] demo/localnet_suite.sh
#
# Prints PASS / FAIL per check and exits 1 if any check failed. The anchors are
# on a local node and prove nothing to anyone else (`ksg-verify-v2` says so).
set -uo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
RPC=${RPC:-http://127.0.0.1:8899}
PAYER=${PAYER:?PAYER=keyfile.json with SOL on the local node}
WORK=${WORK:-$(mktemp -d)}

# A missing tool would show as failed scenarios that are not the code's.
for t in solana-keygen python3 cargo; do
  command -v "$t" >/dev/null || { echo "missing: $t (not on PATH)" >&2; exit 2; }
done
python3 -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('$RPC', b'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}', {'Content-Type': 'application/json'}))" \
  || { echo "no node at $RPC" >&2; exit 2; }

cargo build -q --manifest-path "$HERE/Cargo.toml" -p ksg-cli-v2 -p ksg-verify-v2 || exit 2
KSG="$HERE/target/debug/ksg-remote-panel"
VERIFY="$HERE/target/debug/ksg-verify-v2"
ANCHOR=(--anchor solana:localnet --payer "$PAYER" --rpc "$RPC")

failed=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=1; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }

# Seal memos (`ksg:bs:v1`) the payer has sent so far, read from the node.
seal_memos() {
  python3 - "$RPC" "$(solana-keygen pubkey "$PAYER")" <<'EOF'
import json, sys, urllib.request
rpc, who = sys.argv[1], sys.argv[2]
def call(m, p):
    r = urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]
n = 0
for s in call("getSignaturesForAddress", [who, {"limit": 1000, "commitment": "confirmed"}]):
    if s["err"] is not None:
        continue
    t = call("getTransaction", [s["signature"], {"commitment": "confirmed", "maxSupportedTransactionVersion": 0}])
    if t and any("ksg:bs:v1" in l for l in t["meta"]["logMessages"] or []):
        n += 1
print(n)
EOF
}

# The payer's balance in lamports and its transaction count, from the node.
payer_state() {
  python3 - "$RPC" "$(solana-keygen pubkey "$PAYER")" <<'EOF'
import json, sys, urllib.request
rpc, who = sys.argv[1], sys.argv[2]
def call(m, p):
    r = urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]
bal = call("getBalance", [who, {"commitment": "confirmed"}])["value"]
txs = len(call("getSignaturesForAddress", [who, {"limit": 1000, "commitment": "confirmed"}]))
print(bal, txs)
EOF
}
read -r START_LAMPORTS START_TXS <<<"$(payer_state)"

# The mobile half is born at initiation (`to_work`), not at printing (CH-5b).
init() { "$KSG" --home "$1" init --class "$2" "${ANCHOR[@]}"; }
to_work() {
  "$KSG" --home "$1" packet && "$KSG" --home "$1" buyer-key &&
    "$KSG" --home "$1" --mobile "$2" initiate && "$KSG" --home "$1" --mobile "$2" open-journal
}
copy_home() {
  mkdir -p "$2"
  for f in container.ksg container.json layer.key scan.key parties.json; do cp "$1/$f" "$2/$f"; done
}
# Reads a `ksg-verify-v2 --json` report on stdin; exits 0 if `expr` holds.
report_has() {
  python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1"
}
container_id() { sed -n 's/.*"id": "\(1220[0-9a-f]*\)".*/\1/p' "$1/container.json"; }
verify() { # home class export keys
  "$KSG" --home "$1" scan-key --out "$1.scan" >/dev/null
  "$VERIFY" --export "$3" --container "$(container_id "$1")" --class "$2" --keys "$4" \
    --rpc "$RPC" --cluster localnet --forks --scan-key "$1.scan" --json 2>/dev/null
}

echo "== S1 an older copy does not open (seal chain)"
H=$WORK/s1; M=$WORK/s1.half
init "$H" heavy "$M" >/dev/null && to_work "$H" "$M" >/dev/null || fail "S1 setup"
copy_home "$H" "$WORK/s1.old"
"$KSG" --home "$H" --mobile "$M" work --did "the real step" >/dev/null || fail "S1 real step"
out=$("$KSG" --home "$WORK/s1.old" --mobile "$M" work --did "the other step" 2>&1)
if [ $? -ne 0 ] && grep -q "rolled back" <<<"$out"; then pass "S1 old copy refused: rolled back"; else fail "S1 old copy: $out"; fi
check "S1 current file goes on" "$KSG" --home "$H" --mobile "$M" work --did "the next step"

echo "== S2 an older copy is caught by its status history"
H=$WORK/s2; M=$WORK/s2.half
init "$H" heavy "$M" >/dev/null && "$KSG" --home "$H" packet >/dev/null || fail "S2 setup"
copy_home "$H" "$WORK/s2.old"
"$KSG" --home "$H" buyer-key >/dev/null || fail "S2 buyer-key"
out=$("$KSG" --home "$WORK/s2.old" buyer-key 2>&1)
if [ $? -ne 0 ] && grep -q "rolled back" <<<"$out" && grep -q "status" <<<"$out"; then
  pass "S2 old copy refused by the status chain"; else fail "S2 old copy: $out"; fi
check "S2 current file goes on" "$KSG" --home "$H" --mobile "$M" initiate

echo "== S3 a payer that never held SOL anchors nothing"
EMPTY=$WORK/empty.json
solana-keygen new --no-bip39-passphrase --silent --outfile "$EMPTY" >/dev/null
out=$("$KSG" --home "$WORK/s3" init --class heavy \
  --anchor solana:localnet --payer "$EMPTY" --rpc "$RPC" 2>&1)
if [ $? -ne 0 ]; then pass "S3 refused: $(tail -1 <<<"$out")"; else fail "S3 an unfunded payer anchored"; fi

echo "== S4 light, Pro, light again"
H=$WORK/s4; M=$WORK/s4.half
init "$H" light "$M" >/dev/null && to_work "$H" "$M" >/dev/null || fail "S4 setup"
before=$(seal_memos)
"$KSG" --home "$H" --mobile "$M" work --did "offline step" >/dev/null || fail "S4 light step"
[ "$(seal_memos)" -eq "$before" ] && pass "S4 light: no seal memo" || fail "S4 light sent a seal memo"
"$KSG" --home "$H" --mobile "$M" form --to pro >/dev/null || fail "S4 form pro"
"$KSG" --home "$H" --mobile "$M" work --did "anchored step" >/dev/null || fail "S4 pro step"
pro=$(seal_memos)
[ "$pro" -eq $((before + 2)) ] && pass "S4 Pro: the form page and the step anchored" \
  || fail "S4 Pro: expected $((before + 2)) seal memos, got $pro"
"$KSG" --home "$H" --mobile "$M" form --to light >/dev/null || fail "S4 form light"
"$KSG" --home "$H" --mobile "$M" work --did "offline again" >/dev/null || fail "S4 light again"
[ "$(seal_memos)" -eq "$pro" ] && pass "S4 back to light: no seal memo" || fail "S4 back to light sent a seal memo"
"$KSG" --home "$H" finalize >/dev/null && "$KSG" --home "$H" --mobile "$M" export-final --out "$WORK/s4.final.json" >/dev/null &&
  "$KSG" --home "$H" keys --out "$WORK/s4.keys.json" >/dev/null || fail "S4 export"
rep=$(verify "$H" light "$WORK/s4.final.json" "$WORK/s4.keys.json")
report_has 'r["accepted"] and any("local node" in l for l in r["limits"])' <<<"$rep" \
  && pass "S4 export verified on the node, marked local" || fail "S4 verify: $rep"

echo "== S5 a hand-off in Pro is anchored"
H=$WORK/s5; M=$WORK/s5.half; TWO=$WORK/s5.two.half
init "$H" heavy "$M" >/dev/null && to_work "$H" "$M" >/dev/null || fail "S5 setup"
before=$(seal_memos)
"$KSG" --home "$H" --mobile "$M" handoff --name did:key:zAgentTwo --new-mobile "$TWO" >/dev/null || fail "S5 handoff"
"$KSG" --home "$H" --mobile "$TWO" work --did "second agent" >/dev/null || fail "S5 second agent"
[ "$(seal_memos)" -eq $((before + 2)) ] && pass "S5 hand-off and work anchored" \
  || fail "S5 expected $((before + 2)) seal memos, got $(seal_memos)"
"$KSG" --home "$H" finalize >/dev/null && "$KSG" --home "$H" --mobile "$TWO" export-final --out "$WORK/s5.final.json" >/dev/null &&
  "$KSG" --home "$H" keys --out "$WORK/s5.keys.json" >/dev/null || fail "S5 export"
rep=$(verify "$H" heavy "$WORK/s5.final.json" "$WORK/s5.keys.json")
report_has 'r["accepted"]' <<<"$rep" && pass "S5 export verified on the node" || fail "S5 verify: $rep"
report_has 'len(r["transfers"]) == 1' <<<"$rep" && pass "S5 report names the transfer" || fail "S5 transfers: $rep"

echo "== S6 a bare attaches to a Pro leader and detaches"
L=$WORK/s6.leader; LM=$WORK/s6.leader.half
B=$WORK/s6.bare; BM=$WORK/s6.bare.half; AM=$WORK/s6.agent.half
init "$L" heavy >/dev/null && to_work "$L" "$LM" >/dev/null || fail "S6 leader setup"
# `bare` anchors nothing (G1-4): printed with no --anchor at all.
"$KSG" --home "$B" init --class bare >/dev/null && "$KSG" --home "$B" buyer-key >/dev/null &&
  "$KSG" --home "$B" --mobile "$BM" initiate >/dev/null && "$KSG" --home "$B" --mobile "$BM" open-journal >/dev/null &&
  "$KSG" --home "$B" --mobile "$BM" work --did "before the attachment" >/dev/null || fail "S6 bare setup"
before=$(seal_memos)
"$KSG" --home "$B" --mobile "$BM" attach-to --leader-home "$L" --agent did:key:zLeaderAgent \
  --new-mobile "$AM" >/dev/null || fail "S6 attach-to"
[ "$(seal_memos)" -eq "$before" ] && pass "S6 the attachment anchors nothing" || fail "S6 the attachment sent a seal memo"
status_of() { "$KSG" --home "$1" status | sed -n "s/^$2 *//p"; }
[ "$(status_of "$B" coupling)" = "attached as a trailer: read-only" ] && pass "S6 bare is attached, read-only" \
  || fail "S6 coupling: $(status_of "$B" coupling)"
"$KSG" --home "$L" --mobile "$LM" pull --trailer "$(status_of "$B" container)" \
  --trailer-seal "$(status_of "$B" 'top seal')" >/dev/null || fail "S6 pull"
[ "$(seal_memos)" -eq $((before + 1)) ] && pass "S6 the leader's slot 2 anchored: one seal memo" \
  || fail "S6 expected $((before + 1)) seal memos, got $(seal_memos)"
"$KSG" --home "$B" --mobile "$AM" export-final --out "$WORK/s6.bare.json" >/dev/null || fail "S6 bare export"
"$KSG" --home "$L" finalize >/dev/null && "$KSG" --home "$L" --mobile "$LM" export-final --out "$WORK/s6.leader.json" >/dev/null \
  || fail "S6 leader export"
check "S6 the pair verifies from both exports" "$VERIFY" --pair "$WORK/s6.bare.json" "$WORK/s6.leader.json"
check "S6 detached by the owner and the former client" "$KSG" --home "$B" detach --former-mobile "$BM"
[ "$(status_of "$B" coupling)" = "detached, the copy burned" ] && pass "S6 the copy is burned" \
  || fail "S6 after detach: $(status_of "$B" coupling)"

echo "== S7 a Pro agent publishes its ID in the chain (KS-8 C-10, step 1)"
# Memos with this tag the payer has sent; the last one's text with `last`.
tag_memos() {
  python3 - "$RPC" "$(solana-keygen pubkey "$PAYER")" "$1" "${2:-count}" <<'EOF2'
import json, sys, urllib.request
rpc, who, tag, what = sys.argv[1:5]
def call(m, p):
    r = urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r))["result"]
found = []
for s in call("getSignaturesForAddress", [who, {"limit": 1000, "commitment": "confirmed"}]):
    if s["err"] is not None:
        continue
    t = call("getTransaction", [s["signature"], {"commitment": "confirmed", "maxSupportedTransactionVersion": 0}])
    for l in (t["meta"]["logMessages"] or []) if t else []:
        if tag in l:
            found.append(l)
print(len(found) if what == "count" else (found[0] if found else ""))
EOF2
}
P=$WORK/s7.pro; PM=$WORK/s7.pro.half; LT=$WORK/s7.light; LTM=$WORK/s7.light.half
ID=did:web:agent.example.com
init "$P" heavy >/dev/null && to_work "$P" "$PM" >/dev/null || fail "S7 setup"
before=$(tag_memos "ksg:id:v1")
out=$("$KSG" --home "$P" --mobile "$PM" publish-id --id "$ID" 2>&1)
grep -q "anchored   Solana, tx" <<<"$out" && pass "S7 published: $(grep anchored <<<"$out")" || fail "S7 publish-id: $out"
[ "$(tag_memos "ksg:id:v1")" -eq $((before + 1)) ] && pass "S7 one ksg:id:v1 memo on the node" \
  || fail "S7 expected $((before + 1)) id memos, got $(tag_memos "ksg:id:v1")"
memo=$(tag_memos "ksg:id:v1" last)
grep -q "$ID" <<<"$memo" && ! grep -q "$(container_id "$P")" <<<"$memo" \
  && pass "S7 the memo names the ID, not the container" || fail "S7 memo: $memo"
"$KSG" --home "$P" --mobile "$PM" publish-id --id did:web:other.example.com >/dev/null 2>&1 \
  && fail "S7 a second publication went through" || pass "S7 a second publication is refused"
"$KSG" --home "$LT" init --class light >/dev/null && to_work "$LT" "$LTM" >/dev/null || fail "S7 light setup"
"$KSG" --home "$LT" --mobile "$LTM" publish-id --id "$ID" >/dev/null 2>&1 \
  && fail "S7 light published an ID" || pass "S7 light publishes no ID"

read -r END_LAMPORTS END_TXS <<<"$(payer_state)"
echo
echo "gas: $((END_TXS - START_TXS)) transactions, $((START_LAMPORTS - END_LAMPORTS)) lamports (local node, test SOL)"
echo "directories: $WORK"
[ "$failed" -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$failed"
