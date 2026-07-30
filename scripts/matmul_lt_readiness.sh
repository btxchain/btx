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

run_step "LT GO/NO-GO checklist (inert scaffolding)" \
  python3 "$ROOT_DIR/contrib/matmul-v4/lt-gate.py" --check-inert

# G4: MI350 FER / OCP MX — PENDING until device JSON appears; FAIL only when
# BTX_REQUIRE_GPU_GOLDEN=1 and no qualifying report is present.
g4_args=(--check-g4)
if [[ -n "$REPORTS_DIR" ]]; then
  g4_args+=(--reports "$REPORTS_DIR")
fi
run_step "LT G4 readiness (MI350 FER / OCP MX; no invented PASS)" \
  python3 "$ROOT_DIR/contrib/matmul-v4/lt-gate.py" "${g4_args[@]}"

echo "MATMUL_LT_READINESS: PASS"
echo "note: G4 may still be PENDING (silicon); that is not a Rank-1 GO"
