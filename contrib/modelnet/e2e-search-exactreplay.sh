#!/usr/bin/env bash
# SEARCH-EXACTREPLAY: search is model-plane only; must not starve ExactReplay.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
die() { echo "e2e-search-exactreplay: $*" >&2; exit 1; }
[[ -x "$TEST" ]] || die "missing $TEST"

if grep -n 'trusted_exact_replay\|ExactReplay' "$ROOT/src/modelnet/search.cpp" "$ROOT/src/modelnet/search.h"; then
  die "search sources must not call ExactReplay"
fi
"$TEST" --run_test=modelnet_search_tests/search_exactreplay_isolation
"$TEST" --run_test=modelnet_iso_isolation_tests
"$TEST" --run_test=resource_governor_tests/gov_e2e_val_lat
echo "SEARCH-EXACTREPLAY PASS"
