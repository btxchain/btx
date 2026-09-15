#!/usr/bin/env bash
# ECON GUI source contract: feed tabs, Fund Release, economy RPCs (extends e2e-gui-gates).
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "e2e-economy-gui: $*" >&2; exit 1; }
PAGE="$ROOT/src/qt/modelnetpage.cpp"
UI="$ROOT/src/qt/forms/modelnetpage.ui"
grep -n 'getmodelfeed' "$PAGE" >/dev/null || die "getmodelfeed missing"
grep -n 'getmodeleconomyentry' "$PAGE" >/dev/null || die "getmodeleconomyentry missing"
grep -n 'QMessageBox' "$PAGE" >/dev/null || die "QMessageBox funding confirmation missing"
grep -n 'Confirm funding inspection' "$PAGE" >/dev/null || die "funding confirmation title missing"
grep -n 'Fund Release' "$PAGE" >/dev/null || die "Fund Release button missing"
grep -n 'getrecentlyunlockedmodels' "$PAGE" >/dev/null || die "just-released RPC missing"
grep -n 'NEARLY_FUNDED' "$PAGE" >/dev/null || die "Nearly funded tab wiring missing"
grep -n 'Cache Encrypted' "$PAGE" >/dev/null || die "Cache Encrypted button missing"
grep -n 'getmodelfeedsequence' "$PAGE" >/dev/null || die "feed sequence poll missing"
grep -n 'searchcollections' "$PAGE" >/dev/null || die "searchcollections GUI missing"
grep -n 'searchpublishers' "$PAGE" >/dev/null || die "searchpublishers GUI missing"
grep -n 'name="tabScopePublishers"' "$UI" >/dev/null || die "Publishers tab missing"
grep -n 'name="tabScopeCollections"' "$UI" >/dev/null || die "Collections scope tab missing"
grep -n 'name="tabScopeJustReleased"' "$UI" >/dev/null || die "Just Released tab missing"
grep -n 'Search open models' "$UI" >/dev/null || die "search placeholder missing"
"$ROOT/contrib/modelnet/e2e-gui-gates.sh"
echo "ECON-GUI source contract PASS"
