#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-btx}"
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
TEST_BIN="$BUILD_DIR/bin/test_btx"
CONFIG_TEMPLATE=""
FUNCTIONAL_BACKEND="${BTX_FUNCTIONAL_MATMUL_BACKEND:-cpu}"
TMP_CONFIG_BASE="$(mktemp -t btx-matmul-config.XXXXXX)"
TMP_CONFIG="${TMP_CONFIG_BASE}.ini"
mv "${TMP_CONFIG_BASE}" "${TMP_CONFIG}"

cleanup() {
  rm -f "$TMP_CONFIG"
}
trap cleanup EXIT

if [[ ! -x "$TEST_BIN" ]]; then
  echo "error: missing test binary at $TEST_BIN" >&2
  exit 1
fi

if [[ -f "${BUILD_DIR}/test/config.ini" ]]; then
  CONFIG_TEMPLATE="${BUILD_DIR}/test/config.ini"
elif [[ -f "${ROOT_DIR}/test/config.ini" ]]; then
  # Fallback for local dev setups that drop a config.ini into the source tree.
  CONFIG_TEMPLATE="${ROOT_DIR}/test/config.ini"
else
  echo "error: missing functional test config (expected ${BUILD_DIR}/test/config.ini). Run scripts/build_btx.sh first." >&2
  exit 1
fi

sed \
  -e "s|^SRCDIR=.*$|SRCDIR=${ROOT_DIR}|" \
  -e "s|^BUILDDIR=.*$|BUILDDIR=${BUILD_DIR}|" \
  "${CONFIG_TEMPLATE}" > "${TMP_CONFIG}"

run_step() {
  local label="$1"
  shift
  echo "==> $label"
  "$@"
}

run_functional_step() {
  local label="$1"
  shift
  echo "==> $label (BTX_MATMUL_BACKEND=${FUNCTIONAL_BACKEND})"
  env BTX_MATMUL_BACKEND="${FUNCTIONAL_BACKEND}" "$@"
}

run_step "MatMul unit tests" \
  "$TEST_BIN" --run_test='matmul_*'

run_functional_step "Functional: feature_btx_block_capacity.py" \
  python3 "$ROOT_DIR/test/functional/feature_btx_block_capacity.py" --configfile="$TMP_CONFIG"
run_functional_step "Functional: feature_btx_subsidy_schedule.py" \
  python3 "$ROOT_DIR/test/functional/feature_btx_subsidy_schedule.py" --configfile="$TMP_CONFIG"
run_functional_step "Functional: feature_btx_fast_mining_phase.py" \
  python3 "$ROOT_DIR/test/functional/feature_btx_fast_mining_phase.py" --configfile="$TMP_CONFIG"
run_functional_step "Functional: mining_matmul_basic.py" \
  python3 "$ROOT_DIR/test/functional/mining_matmul_basic.py" --configfile="$TMP_CONFIG"
run_functional_step "Functional: feature_btx_matmul_consensus.py" \
  python3 "$ROOT_DIR/test/functional/feature_btx_matmul_consensus.py" --configfile="$TMP_CONFIG"
run_functional_step "Functional: p2p_matmul_dos_mitigation.py" \
  python3 "$ROOT_DIR/test/functional/p2p_matmul_dos_mitigation.py" --configfile="$TMP_CONFIG"

if [[ "${BTX_RUN_MATMUL_METAL_REPRO:-0}" == "1" ]]; then
  run_step "Functional: feature_btx_matmul_metal_high_hash_repro.py" \
    env BTX_MATMUL_BACKEND=metal BTX_MATMUL_DIAG_COMPARE_CPU_METAL=1 \
      python3 "$ROOT_DIR/test/functional/feature_btx_matmul_metal_high_hash_repro.py" --configfile="$TMP_CONFIG"
fi

echo "MATMUL_POW_READINESS: PASS"
