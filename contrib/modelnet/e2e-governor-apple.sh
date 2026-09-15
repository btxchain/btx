#!/usr/bin/env bash
# Apple Silicon governor E2E via METAL thermal/battery policy (injected samples).
# Packaging recipe is e2e-apple-pkg-recipe.sh; this host is not Darwin.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
[[ -x "$TEST" ]] || { echo "missing $TEST" >&2; exit 1; }
"$TEST" --run_test=resource_governor_tests/gov_e2e_apple_metal
"$TEST" --run_test=resource_governor_tests/gov_pol_04_thermal_hot_blocks_mining
"$TEST" --run_test=resource_governor_tests/gov_pwr_02_laptop_battery_pauses_mining
echo "GOV-APPLE-E2E PASS (METAL policy; not a Darwin .pkg)"
