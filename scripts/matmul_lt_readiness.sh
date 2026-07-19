#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-btx}"
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
TEST_BIN="$BUILD_DIR/bin/test_btx"

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

run_step "LT GO/NO-GO checklist" \
  python3 "$ROOT_DIR/contrib/matmul-v4/lt-gate.py" --check-inert

echo "MATMUL_LT_READINESS: PASS"
