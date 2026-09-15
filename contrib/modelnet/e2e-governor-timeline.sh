#!/usr/bin/env bash
# Compressed overnight / active-day / validation-latency / bufferbloat / battery.
# Observe(now_ms) is the governor clock; wall 8–12h is not required to execute the policy.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
[[ -x "$TEST" ]] || { echo "missing $TEST" >&2; exit 1; }
"$TEST" --run_test=resource_governor_tests/gov_e2e_overnight_12h
"$TEST" --run_test=resource_governor_tests/gov_e2e_active_day
"$TEST" --run_test=resource_governor_tests/gov_e2e_val_lat
"$TEST" --run_test=resource_governor_tests/gov_e2e_bufferbloat_shaped
"$TEST" --run_test=resource_governor_tests/gov_e2e_battery_sysfs
"$TEST" --run_test=resource_governor_tests/gov_net_03_latency_inflation_reduces_upload
echo "GOV-OVERNIGHT/ACTIVE-DAY/VAL-LAT/BUFFERBLOAT/BATTERY-HW PASS"
