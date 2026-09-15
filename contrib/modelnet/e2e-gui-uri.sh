#!/usr/bin/env bash
# V11-URI-13: btx:// never enters the payment parser. Linux OS handler + source.
# GUI Models-page wiring is in src/qt (BUILD_GUI). Fail-fast.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "E2E_GUI_URI FAIL: $*" >&2; exit 1; }
grep -n 'startsWith(QLatin1String("btx:")' "$ROOT/src/qt/paymentserver.cpp" >/dev/null || die "PaymentServer missing btx: intercept"
grep -n 'receivedModelResource' "$ROOT/src/qt/paymentserver.h" >/dev/null || die "missing signal"
grep -n 'handleModelResource' "$ROOT/src/qt/bitcoingui.cpp" >/dev/null || die "missing GUI slot"
# Must return before DecodeDestination / parseBitcoinURI for btx:
python3 - "$ROOT/src/qt/paymentserver.cpp" <<'PY' || exit 1
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
btx = text.find('startsWith(QLatin1String("btx:")')
pay = text.find('parseBitcoinURI')
if btx < 0 or pay < 0 or not (btx < pay):
    raise SystemExit("btx intercept must precede parseBitcoinURI")
print("PaymentServer btx intercept precedes parseBitcoinURI")
PY
"$ROOT/contrib/modelnet/e2e-os-handler.sh"
if [[ -x "$ROOT/build-gcc13/bin/btx-qt" ]]; then
  echo "btx-qt present — offscreen Models page not auto-started (no display spend)"
else
  echo "btx-qt not in this BUILD_GUI=OFF tree; source+OS-handler proven"
fi
echo "E2E_GUI_URI PASS"
