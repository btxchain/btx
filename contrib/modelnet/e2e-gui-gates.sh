#!/usr/bin/env bash
# SEARCH-GUI-GATE + GOV-GUI: source contract for search-first Models page, Details,
# creator Publish tab, intro spare-resources / mining-idle, governor RPC name.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "e2e-gui-gates: $*" >&2; exit 1; }

grep -n 'searchmodels' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "searchmodels missing"
grep -n 'onResultDetails' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "Details slot missing"
grep -n 'getmodeldirectoryentry' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "Details RPC missing"
grep -n 'publishmodelsearchrecord' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "creator publish RPC missing"
grep -n 'onPublishSearchRecord' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "creator slot missing"
grep -n 'getrecentreleases' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "release discovery RPC missing"
grep -n 'publishButton' "$ROOT/src/qt/forms/modelnetpage.ui" >/dev/null || die "Publish button missing in .ui"
grep -n 'Publish search record' "$ROOT/src/qt/forms/modelnetpage.ui" >/dev/null || die "Publish label missing"
grep -n 'Search open models' "$ROOT/src/qt/forms/modelnetpage.ui" >/dev/null || die "search-first placeholder missing"
grep -n 'name="tabScopeReleases"' "$ROOT/src/qt/forms/modelnetpage.ui" >/dev/null || die "Releases tab missing"
grep -n 'getresourcegovernorinfo' "$ROOT/src/qt/modelnetpage.cpp" >/dev/null || die "governor status RPC missing"
grep -n 'getSpareResourcesChecked' "$ROOT/src/qt/intro.cpp" >/dev/null || die "intro spare-resources getter missing"
grep -n 'getMiningIdleChecked' "$ROOT/src/qt/intro.cpp" >/dev/null || die "intro mining-idle getter missing"
grep -n 'Use spare resources automatically' "$ROOT/src/qt/forms/intro.ui" >/dev/null || die "intro spare checkbox missing"
grep -n 'Mining when idle' "$ROOT/src/qt/forms/intro.ui" >/dev/null || die "intro mining checkbox missing"
grep -n 'resourcegovernor' "$ROOT/src/qt/bitcoin.cpp" >/dev/null || die "intro does not ForceSetArg resourcegovernor"
grep -n 'automining' "$ROOT/src/qt/bitcoin.cpp" >/dev/null || die "intro does not ForceSetArg automining"

python3 - "$ROOT/src/qt/modelnetpage.cpp" "$ROOT/src/qt/forms/modelnetpage.ui" "$ROOT/src/qt/bitcoin.cpp" <<'PY' || exit 1
from pathlib import Path
import sys
page, ui, btc = (Path(p).read_text() for p in sys.argv[1:4])
if "runModelSearch" not in page:
    raise SystemExit("runModelSearch missing")
if "onResultDetails" not in page:
    raise SystemExit("onResultDetails missing")
if "onPublishSearchRecord" not in page:
    raise SystemExit("onPublishSearchRecord missing")
if "publishmodelsearchrecord" not in page:
    raise SystemExit("publish RPC missing")
if "getrecentreleases" not in page:
    raise SystemExit("release discovery RPC missing")
if "getresourcegovernorinfo" not in page:
    raise SystemExit("governor RPC missing")
if "publishButton" not in ui:
    raise SystemExit("publishButton missing in ui")
if 'name="tabScopeReleases"' not in ui:
    raise SystemExit("Releases tab missing in ui")
if 'ForceSetArg("-resourcegovernor"' not in btc:
    raise SystemExit("bitcoin.cpp missing resourcegovernor ForceSetArg")
print("GUI source contract: search-first + Details + Publish + governor")
PY

"$ROOT/contrib/modelnet/e2e-gui-uri.sh"
if [[ -x "$ROOT/build-gcc13/bin/btx-qt" ]]; then
  echo "btx-qt present"
else
  echo "btx-qt not built (BUILD_GUI=OFF); source gates executed"
fi
echo "SEARCH-GUI-GATE + GOV-GUI PASS"
