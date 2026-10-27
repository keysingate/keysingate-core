#!/usr/bin/env bash
# Test key kits: every party of the channel with its keys, ready for the
# scenarios and for printing containers from packet templates.
#
# Core v2 (`core-v2/`): the programs `ksg-remote-panel` and `ksg-verify-v2`, documents
# of major version 3. Core v1's kit is `demo/testkit.sh` in the archive (LEGACY.md).
#
# Every key here is a public test key (`ksg_verify_v2::testkeys`): derived from a
# label anybody can recompute, so nothing signed with them has any force.
# The releases are named ksg:em:test:…, and ksg-verify-v2 refuses them unless
# asked to check a test.
#
#   KIT=dir   where the kit goes (default: a fresh temporary directory)
#   KSG=path  the ksg-remote-panel binary (default: built here)
#
# What it makes, each a directory of its own:
#
#   issuer/        release ksg:em:test:000001, serials 1-10000 (heavy and bare)
#   issuer-light/  release ksg:em:test:000002, serials 1-10000 (one light packet:
#                  a light packet is 10000..100000 serials)
#   distributor/   granted 5000 serials by the issuer          (level 1)
#   agent-1/       granted 1000 by the distributor             (level 2)
#   agent-2/       granted  100 by agent-1                     (level 3)
#   holders/holder-a, holder-b, holder-c   buyers: owner and buyer keys
#   sales/sale-a.json   10 heavy serials, agent-2 -> holder-a
#   sales/sale-b.json   20 bare serials,  agent-1 -> holder-b
#   sales/sale-c.json   10000 light,      issuer-light -> holder-c
#   MANIFEST.json  every public key: role, label, key identifier, file
#
# Client keys are made when a container is printed, from the label
# client:<home>:<release>:<serial>; the manifest names the rule.
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
KIT=${KIT:-$(mktemp -d)}
if [ -z "${KSG:-}" ]; then
  cargo build -q --manifest-path "$HERE/Cargo.toml" -p ksg-cli-v2
  KSG="$HERE/target/debug/ksg-remote-panel"
fi
if [ -e "$KIT/MANIFEST.json" ]; then
  echo "$KIT already holds a kit" >&2
  exit 1
fi
mkdir -p "$KIT/holders" "$KIT/sales"

# order + confirm-payment: the seller's two steps; prints the packet line.
sell() { # role desk to class size out
  local id
  id=$("$KSG" "$1" order --desk "$KIT/$2" --to "$3" --class "$4" --size "$5" | awk '{print $2}')
  "$KSG" "$1" confirm-payment --desk "$KIT/$2" --order "$id" --out "$KIT/sales/$6"
}
# a desk of the channel, granted `size` serials by `from`.
level() { # role-of-granter from name size
  "$KSG" distributor init --desk "$KIT/$3" --name "did:key:zTest-$3" > /dev/null
  "$KSG" "$1" grant --desk "$KIT/$2" --to "did:key:zTest-$3" \
    --keys "$KIT/$3/keys.json" --size "$4" --out "$KIT/$3/grant.json" > /dev/null
  "$KSG" distributor accept --desk "$KIT/$3" --grant "$KIT/$3/grant.json" \
    --emission "$KIT/issuer/emission.json" > /dev/null
}

"$KSG" issuer init --desk "$KIT/issuer" --release ksg:em:test:000001 --range 1-10000 > /dev/null
"$KSG" issuer init --desk "$KIT/issuer-light" --release ksg:em:test:000002 --range 1-10000 > /dev/null
level issuer issuer distributor 5000
level distributor distributor agent-1 1000
level distributor agent-1 agent-2 100
for h in holder-a holder-b holder-c; do
  mkdir -p "$KIT/holders/$h"
  "$KSG" --home "$KIT/holders/$h" holder > "$KIT/holders/$h/holder.txt"
done
sell distributor agent-2 "$(cat "$KIT/holders/holder-a/holder.txt")" heavy 10 sale-a.json > /dev/null
sell distributor agent-1 "$(cat "$KIT/holders/holder-b/holder.txt")" bare 20 sale-b.json > /dev/null
sell issuer issuer-light "$(cat "$KIT/holders/holder-c/holder.txt")" light 10000 sale-c.json > /dev/null

python3 - "$KIT" <<'PY'
import json, os, sys
kit = sys.argv[1]
def load(p):
    with open(os.path.join(kit, p)) as f:
        return json.load(f)
parties = []
def add(role, label, keys, where):
    for k in keys:
        parties.append({"role": role, "label": label, "kid": k["kid"],
                        "alg": k["alg"], "key": k["key"], "file": where})
add("issuer", "issuer", load("issuer/issuer-keys.json"), "issuer/issuer-keys.json")
for d in ("distributor", "agent-1", "agent-2"):
    add("channel", "distributor:did:key:zTest-" + d, load(d + "/keys.json"), d + "/keys.json")
for h in ("holder-a", "holder-b", "holder-c"):
    with open(os.path.join(kit, "holders", h, "holder.txt")) as f:
        uri = f.read().strip()
    key = uri.rsplit(":", 1)[1]
    parties.append({"role": "holder", "label": "owner:" + h, "kid": "did:key:zKsgOwner#k1",
                    "alg": "Ed25519", "key": key, "file": "holders/%s/holder.txt" % h,
                    "holder_uri": uri})
manifest = {
    "type": "KsgTestKit",
    "v": 1,
    "core": "v2",
    "notice": "TEST KEYS ONLY: every secret is SHA-256(fields 'ksg:test-key:v1', label) "
              "and public; nothing signed with them has any force.",
    "releases": ["ksg:em:test:000001", "ksg:em:test:000002"],
    "parties": parties,
    "derived_at_print": {
        "seal": "seal",
        "buyer": "buyer:<home>",
        "client": "client:<home>:<release>:<serial> (both halves and ML-DSA, from one stream)",
        "storage": "layer:<home>:<release>:<serial>",
    },
    "sales": {
        "sales/sale-a.json": "heavy, 10 serials, agent-2 -> holder-a",
        "sales/sale-b.json": "bare, 20 serials, agent-1 -> holder-b",
        "sales/sale-c.json": "light, 10000 serials, issuer-light -> holder-c",
    },
}
with open(os.path.join(kit, "MANIFEST.json"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY
echo "kit: $KIT"
