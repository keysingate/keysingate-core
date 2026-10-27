#!/usr/bin/env bash
# Sh-12 of the Shamir audit ([doc:AUDIT-SHAMIR]): the field
# arithmetic of `ksg-custody-v2` must compile without a conditional branch, on
# the platform the release is built for. The source is written branch-free on
# secret data; this checks what the compiler made of it.
#
# `src/gf.rs` is compiled on its own at the release optimisation level, each
# function kept out of line under its own symbol, and the assembly of `mul`,
# `inv` and `div` is searched for conditional branches of the target
# architecture. Any found — exit 1.
#
# Lives in `core-v2/` so the separate core v2 repository runs it too; the
# main repository calls it as `core-v2/scripts/check_ct_gf.sh`.
#
# Run: scripts/check_ct_gf.sh [--target TRIPLE]   (default: the host)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/crates/ksg-custody-v2/src/gf.rs"
TARGET=${2:-$(rustc -vV | sed -n 's/^host: //p')}
[ "${1:-}" = "--target" ] || TARGET=$(rustc -vV | sed -n 's/^host: //p')
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Out of line and unmangled, so each function has its own symbol to read.
sed -e 's/pub const fn/#[inline(never)] #[no_mangle] pub fn/' -e '/^\/\/!/d' \
    -e 's/#\[must_use\]//' "$SRC" > "$WORK/gf.rs"
rustc --edition 2021 --crate-type=cdylib -C opt-level=3 --target "$TARGET" \
    --emit asm -o "$WORK/gf.s" "$WORK/gf.rs"

case "$TARGET" in
  x86_64*|i686*) BRANCH='^[[:space:]]+j(a|ae|b|be|c|e|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z|cxz|ecxz|rcxz)[[:space:]]' ;;
  aarch64*)      BRANCH='^[[:space:]]+(b\.[a-z]+|cbn?z|tbn?z)[[:space:]]' ;;
  *) echo "check_ct_gf: no branch pattern for $TARGET" >&2; exit 2 ;;
esac

fail=0
for f in mul inv div; do
  body=$(awk -v f="$f" '$0 ~ "^_?"f":" {on=1; next} on && /\.cfi_endproc|^[[:space:]]*\.size/ {exit} on' "$WORK/gf.s")
  if [ -z "$body" ]; then
    echo "check_ct_gf: $f not found in the assembly for $TARGET" >&2; fail=1; continue
  fi
  if grep -Eq "$BRANCH" <<<"$body"; then
    echo "check_ct_gf: $f has a conditional branch on $TARGET:" >&2
    grep -E "$BRANCH" <<<"$body" >&2
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "check_ct_gf: mul, inv, div have no conditional branch on $TARGET"
exit "$fail"
