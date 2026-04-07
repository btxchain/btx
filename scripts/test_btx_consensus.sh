#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-btx}"
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
PORT_SEED="${BTX_FUNCTIONAL_PORT_SEED:-$(( (RANDOM << 15) | RANDOM ))}"
FUNCTIONAL_TMPDIR="${BTX_FUNCTIONAL_TMPDIR:-${TMPDIR:-/tmp}/btx-functional-consensus-${PORT_SEED}}"
CONFIG_TEMPLATE=""
TMP_CONFIG_BASE="$(mktemp -t btx-consensus-config.XXXXXX)"
TMP_CONFIG="${TMP_CONFIG_BASE}.ini"
mv "${TMP_CONFIG_BASE}" "${TMP_CONFIG}"

cleanup() {
  rm -f "${TMP_CONFIG}"
}
trap cleanup EXIT

rm -rf "${FUNCTIONAL_TMPDIR}"

if [[ -f "${BUILD_DIR}/test/config.ini" ]]; then
  CONFIG_TEMPLATE="${BUILD_DIR}/test/config.ini"
elif [[ -f "${ROOT_DIR}/test/config.ini" ]]; then
  CONFIG_TEMPLATE="${ROOT_DIR}/test/config.ini"
else
  echo "error: missing functional test config (expected ${BUILD_DIR}/test/config.ini). Run scripts/build_btx.sh first." >&2
  exit 1
fi

sed \
  -e "s|^SRCDIR=.*$|SRCDIR=${ROOT_DIR}|" \
  -e "s|^BUILDDIR=.*$|BUILDDIR=${BUILD_DIR}|" \
  "${CONFIG_TEMPLATE}" > "${TMP_CONFIG}"

"${BUILD_DIR}/bin/test_btx" --run_test=pow_tests --catch_system_error=no --log_level=test_suite
"${BUILD_DIR}/bin/test_btx" --run_test=matmul_validation_tests,matmul_trust_model_tests --catch_system_error=no --log_level=test_suite
python3 "${ROOT_DIR}/test/functional/feature_btx_matmul_consensus.py" \
  --configfile="${TMP_CONFIG}" \
  --portseed="${PORT_SEED}" \
  --tmpdir="${FUNCTIONAL_TMPDIR}"
