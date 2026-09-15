#!/usr/bin/env bash
# Bounty GUI source contract (Fund Bounty / Award / Refund + Bounties tab).
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "e2e-bounty-gui-gates: $*" >&2; exit 1; }
PAGE="$ROOT/src/qt/modelnetpage.cpp"
UI="$ROOT/src/qt/forms/modelnetpage.ui"
HDR="$ROOT/src/qt/modelnetpage.h"
grep -n 'searchbounties' "$PAGE" >/dev/null || die "searchbounties missing"
grep -n 'onResultFundBounty' "$PAGE" >/dev/null || die "Fund Bounty slot missing"
grep -n 'onResultAward' "$PAGE" >/dev/null || die "Award slot missing"
grep -n 'onResultRefund' "$PAGE" >/dev/null || die "Refund slot missing"
grep -n 'Fund Bounty' "$PAGE" >/dev/null || die "Fund Bounty button missing"
grep -n 'QMessageBox' "$PAGE" >/dev/null || die "QMessageBox confirmation missing"
grep -n 'preparebountyfunding' "$PAGE" >/dev/null || die "preparebountyfunding missing"
grep -n 'preparebountyrefund' "$PAGE" >/dev/null || die "preparebountyrefund missing"
grep -n 'inspectbountyaward' "$PAGE" >/dev/null || die "inspectbountyaward missing"
grep -n 'name="tabScopeBounties"' "$UI" >/dev/null || die "Bounties tab missing in .ui"
grep -n 'onResultFundBounty' "$HDR" >/dev/null || die "Fund Bounty slot not declared"
python3 - "$PAGE" "$UI" "$HDR" <<'PY' || exit 1
from pathlib import Path
import sys
page, ui, hdr = (Path(p).read_text() for p in sys.argv[1:4])
for s in ("onResultFundBounty", "onResultAward", "onResultRefund", "searchbounties", "Fund Bounty"):
    if s not in page:
        raise SystemExit(s)
if 'name="tabScopeBounties"' not in ui:
    raise SystemExit("tabScopeBounties missing")
if "onResultFundBounty" not in hdr:
    raise SystemExit("header slot missing")
print("BOUNTY-GUI source contract")
PY
if [[ -x "$ROOT/build-gcc13/bin/btx-qt" ]]; then
  echo "btx-qt present"
else
  echo "btx-qt not built (BUILD_GUI=OFF); source gates executed"
fi
echo "BOUNTY-GUI-GATE PASS"
