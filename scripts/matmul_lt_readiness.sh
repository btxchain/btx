#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-btx}"
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
TEST_BIN="$BUILD_DIR/bin/test_btx"
REPORTS_DIR="${MATMUL_LT_REPORTS_DIR:-}"

if [[ ! -x "$TEST_BIN" ]]; then
  echo "error: missing test binary at $TEST_BIN" >&2
  exit 1
fi

run_step() {
  local label="$1"
  shift
  echo "==> $label"
  "$@"
}

run_step "ENC-DR-LT unit tests" \
  "$TEST_BIN" --run_test='matmul_v4_lt_tests'

run_step "BMX4C regression (still required)" \
  "$TEST_BIN" --run_test='matmul_v4_bmx4_tests'

run_step "Cross-vendor determinism harness (CPU; GPU rows warn unless BTX_REQUIRE_GPU_GOLDEN=1)" \
  "$TEST_BIN" --run_test='matmul_v4_backend_determinism_tests,matmul_v4_determinism_vectors' \
  --log_level=warning

# The LT GO/NO-GO checklist steps (contrib/matmul-v4/lt-gate.py --check-inert /
# --check-g4) were REMOVED: lt-gate.py was retired in commit a645c3b4 together
# with the legacy matmul-v4-report tooling (v4.1/v4.2/v4.4 gates fully
# superseded by ENC_RC). The ENC_RC successors are contrib/matmul-v4/rc-gate.py
# (fed by rc-stage-g-campaign.py / measure-hardware.sh <backend> rc) and
# contrib/matmul-v4/run-full-benchmark.py. The G4 MI350 FER / OCP MX silicon
# question has no LT-specific gate anymore; device evidence flows through the
# rc-gate.py report schema instead ($REPORTS_DIR is no longer consumed here).
if [[ -n "$REPORTS_DIR" ]]; then
  echo "note: MATMUL_LT_REPORTS_DIR is set but the retired lt-gate.py G4 step no longer runs;"
  echo "      feed device reports to contrib/matmul-v4/rc-gate.py instead"
fi

echo "MATMUL_LT_READINESS: PASS"
echo "note: PASS covers the LT/BMX4C unit suites + CPU determinism harness only;"
echo "      it is not a Rank-1 GO and carries no silicon (G4-class) evidence"
