#!/usr/bin/env bash
# The MVP's insurance scenario, end to end, every party a separate directory.
#
#   insurer (issuer) -> distributor -> agent -> enterprise -> container
#   -> policy page -> work -> export -> an auditor verifies alone
#
# Serials are what the channel sells, as policy blank numbers are in agency
# sales of insurance: the insurer grants a range to a distributor, the
# distributor grants part of it to its agent, the agent sells a packet to an
# enterprise, and the enterprise prints a container on one serial of it.
#
# The auditor receives four files and the insurer's public keys, nothing else,
# and asks nobody.
#
#   CLASS=light  (default) the journal runs in the light form: sealed, not
#                anchored, no network needed; verifies today.
#   CLASS=heavy ANCHOR=solana:devnet PAYER=keyfile.json [RPC=url]
#   CLASS=heavy ANCHOR=solana:localnet PAYER=keyfile.json
#                the same against `solana-test-validator` on this machine:
#                a real Solana node, free SOL, anchors nobody else sees
#                the journal runs in Pro: every seal anchored on Solana with a
#                blind memo; the holder hands the auditor its scan key, and the
#                auditor reads the anchors with it.
#   WORK=dir     where the directories go (default: a fresh temporary one).
# Core v2 (`core-v2/`): `ksg-remote-panel` and `ksg-verify-v2`, documents of major
# version 3. Core v1's scenario is `demo/insurance.sh` in the archive (LEGACY.md).
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$(mktemp -d)}
CLASS=${CLASS:-light}
ANCHOR=${ANCHOR:-}
case "$CLASS" in light) SIZE=10000 ;; *) SIZE=10 ;; esac

#   KSG=path, VERIFY=path  the binaries (default: built here)
if [ -z "${KSG:-}" ] || [ -z "${VERIFY:-}" ]; then
  cargo build -q --manifest-path "$HERE/Cargo.toml" -p ksg-cli-v2 -p ksg-verify-v2
  KSG=${KSG:-"$HERE/target/debug/ksg-remote-panel"}
  VERIFY=${VERIFY:-"$HERE/target/debug/ksg-verify-v2"}
fi

step() { printf '\n== %s\n' "$*"; }

ANCHOR_FLAGS=()
RPC_FLAGS=()
if [ -n "$ANCHOR" ]; then
  ANCHOR_FLAGS=(--anchor "$ANCHOR" --payer "${PAYER:?PAYER=keyfile.json is needed with ANCHOR}")
  if [ -n "${RPC:-}" ]; then ANCHOR_FLAGS+=(--rpc "$RPC"); fi
  CLUSTER=${ANCHOR#solana:}
  if [ "$CLUSTER" = localnet ]; then
    # solana-test-validator on its default port
    DEFAULT_RPC=http://127.0.0.1:8899
  else
    DEFAULT_RPC=https://api.$CLUSTER.solana.com
  fi
  RPC_FLAGS=(--rpc "${RPC:-$DEFAULT_RPC}" --cluster "$CLUSTER" --forks)
fi

step "1. The insurer issues release ksg:em:test:000001, serials 1-1000000"
"$KSG" issuer init --desk "$WORK/insurer" --release ksg:em:test:000001 --range 1-1000000

step "2. A distributor opens its desk; the insurer grants it 200000 serials"
"$KSG" distributor init --desk "$WORK/distributor" --name did:key:zDistributorAlpha
"$KSG" issuer grant --desk "$WORK/insurer" --to did:key:zDistributorAlpha \
  --keys "$WORK/distributor/keys.json" --size 200000 --out "$WORK/grant-distributor.json"
"$KSG" distributor accept --desk "$WORK/distributor" --grant "$WORK/grant-distributor.json" \
  --emission "$WORK/insurer/emission.json"

step "3. The distributor builds its channel: an agent, 50000 serials of its own range"
"$KSG" distributor init --desk "$WORK/agent" --name did:key:zAgentBeta
"$KSG" distributor grant --desk "$WORK/distributor" --to did:key:zAgentBeta \
  --keys "$WORK/agent/keys.json" --size 50000 --out "$WORK/grant-agent.json"
"$KSG" distributor accept --desk "$WORK/agent" --grant "$WORK/grant-agent.json" \
  --emission "$WORK/insurer/emission.json"

step "4. The agent sells a packet of $SIZE $CLASS serials to the enterprise"
# The enterprise names its key first; the packet is sold to that key (KS-5).
HOLDER=$("$KSG" --home "$WORK/box" holder)
# The order takes no serials; the agent confirms payment by hand, and the
# packet is issued at that moment.
ORDER=$("$KSG" distributor order --desk "$WORK/agent" --to "$HOLDER" \
  --class "$CLASS" --size "$SIZE" | awk '{print $2}')
"$KSG" distributor confirm-payment --desk "$WORK/agent" --order "$ORDER" \
  --out "$WORK/sale.json"

step "5. A container is printed on the packet's first serial (the insurer prints)"
"$KSG" --home "$WORK/box" init --sale "$WORK/sale.json" --issuer-desk "$WORK/insurer" \
  "${ANCHOR_FLAGS[@]}"

step "6. Its life: packet, buyer's key, initiation (the client's key is born), journal, policy, work, export"
B=(--home "$WORK/box")
M=(--mobile "$WORK/client.half")
printf 'POLICY 0001: third-party liability, Enterprise Gamma\n' > "$WORK/policy.txt"
"$KSG" "${B[@]}" packet > /dev/null
"$KSG" "${B[@]}" buyer-key > /dev/null
"$KSG" "${B[@]}" "${M[@]}" initiate > /dev/null
"$KSG" "${B[@]}" "${M[@]}" open-journal > /dev/null
"$KSG" "${B[@]}" "${M[@]}" attach --type urn:ksg:page:policy:v1 --file "$WORK/policy.txt" --mime text/plain > /dev/null
"$KSG" "${B[@]}" "${M[@]}" work --did "claim 17 reviewed" > /dev/null
"$KSG" "${B[@]}" finalize > /dev/null
"$KSG" "${B[@]}" "${M[@]}" export-final --out "$WORK/export.json" > /dev/null
"$KSG" "${B[@]}" keys --out "$WORK/keys.json"
"$KSG" "${B[@]}" channel --out "$WORK/channel.json" > /dev/null
ID=$(sed -n 's/.*"id": "\(1220[0-9a-f]*\)".*/\1/p' "$WORK/box/container.json")
echo "container $ID exported"

step "7. The auditor, with four files and the insurer's public keys, asks nobody"
mkdir -p "$WORK/auditor"
cp "$WORK/export.json" "$WORK/keys.json" "$WORK/channel.json" "$WORK/insurer/issuer-keys.json" "$WORK/auditor/"
if [ -n "$ANCHOR" ]; then
  # The anchors are blind: without the holder's scan key they are noise.
  "$KSG" "${B[@]}" scan-key --out "$WORK/auditor/scan.key"
  RPC_FLAGS+=(--scan-key "$WORK/auditor/scan.key")
fi
# All keys of the prototype are public test keys: without --test the auditor's
# check refuses the release; with it, the report says it is a test.
if "$VERIFY" --export "$WORK/auditor/export.json" --container "$ID" \
  --keys "$WORK/auditor/keys.json" \
  --channel "$WORK/auditor/channel.json" --issuer-keys "$WORK/auditor/issuer-keys.json" \
  "${RPC_FLAGS[@]}"; then
  echo "a test release was accepted without --test" >&2
  exit 1
fi
"$VERIFY" --export "$WORK/auditor/export.json" --container "$ID" \
  --keys "$WORK/auditor/keys.json" \
  --channel "$WORK/auditor/channel.json" --issuer-keys "$WORK/auditor/issuer-keys.json" \
  --test "${RPC_FLAGS[@]}"
echo
echo "directories: $WORK"
