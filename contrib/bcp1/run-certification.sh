#!/usr/bin/env bash
# BCP/1 / BTX_EXCHANGE_PROFILE_V1 certification runner.
# Isolated-regtest only. Never /var/lib/btxd. Never production ports 18443/18444.
# No cmake/ninja. One functional at a time. --timeout-factor=1.
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
PROD_DATADIR="/var/lib/btxd"
PASS_ROWS=(
  "address generation"
  "deposit detection"
  "1→N confirmations"
  "reorg handling"
  "unsigned withdrawal"
  "external PQ signature"
  "signature import"
  "corrupt signature rejection"
  "broadcast"
  "batch withdrawal"
  "UTXO consolidation"
  "double-spend rejection"
  "node restart"
  "wallet recovery"
)

die() { echo "BCP/1 certification FAIL: $*" >&2; exit 1; }

realpath_py() {
  python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

refuse_prod() {
  local path="$1"
  local resolved
  resolved="$(realpath_py "$path")"
  if [[ "${resolved}" == "${PROD_DATADIR}" || "${resolved}" == "${PROD_DATADIR}/"* ]]; then
    die "refusing production datadir ${resolved}"
  fi
}

find_config() {
  if [[ -n "${BCP1_CONFIGFILE:-${CONFIGFILE:-}}" ]]; then
    printf '%s' "${BCP1_CONFIGFILE:-$CONFIGFILE}"
    return 0
  fi
  local cand
  for cand in \
    "${ROOT}/test/config.ini" \
    "${ROOT}/build-gcc13/test/config.ini" \
    "${ROOT}/build/test/config.ini"
  do
    if [[ -f "${cand}" ]]; then
      printf '%s' "${cand}"
      return 0
    fi
  done
  return 1
}

find_btxd() {
  if [[ -n "${BTXD:-}" && -x "${BTXD}" ]]; then
    printf '%s' "${BTXD}"
    return 0
  fi
  local cand
  for cand in \
    "${ROOT}/build-gcc13/bin/btxd" \
    "${ROOT}/build/bin/btxd"
  do
    if [[ -x "${cand}" ]]; then
      printf '%s' "${cand}"
      return 0
    fi
  done
  if command -v btxd >/dev/null 2>&1; then
    command -v btxd
    return 0
  fi
  return 1
}

write_scratch_config() {
  local out="$1"
  local btxd="$2"
  local bindir builddir
  bindir="$(cd "$(dirname "${btxd}")" && pwd)"
  builddir="$(cd "${bindir}/.." && pwd)"
  cat >"${out}" <<EOF
[environment]
CLIENT_NAME=Btx
CLIENT_BUGREPORT=
SRCDIR=${ROOT}
BUILDDIR=${builddir}
EXEEXT=
RPCAUTH=${ROOT}/share/rpcauth/rpcauth.py

[components]
ENABLE_WALLET=true
USE_SQLITE=true
ENABLE_CLI=true
ENABLE_BITCOIND=true
ENABLE_EXTERNAL_SIGNER=true
ENABLE_ZMQ=true
ENABLE_WALLET_TOOL=false
ENABLE_BITCOIN_UTIL=false
ENABLE_UTIL_TX=false
ENABLE_UTIL_UTIL=false
ENABLE_FUZZ_BINARY=false
ENABLE_USDT_TRACEPOINTS=false
EOF
}

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/bcp1-cert.XXXXXX")"
trap 'rm -rf "${SCRATCH}" /tmp/test_runner_bcp1_* 2>/dev/null || true' EXIT
refuse_prod "${SCRATCH}"

CONFIG=""
if CONFIG="$(find_config)"; then
  :
else
  BTXD_BIN="$(find_btxd)" || die "no config.ini and no btxd (set BTXD or BCP1_CONFIGFILE)"
  CONFIG="${SCRATCH}/config.ini"
  write_scratch_config "${CONFIG}" "${BTXD_BIN}"
  export BTXD="${BTXD_BIN}"
fi
[[ -f "${CONFIG}" ]] || die "missing config ${CONFIG}"
refuse_prod "${CONFIG}"

FUNC="${ROOT}/test/functional/feature_bcp1.py"
[[ -f "${FUNC}" ]] || die "missing ${FUNC}"
[[ -f "${HERE}/mock_signer.py" ]] || die "missing mock_signer.py"

LOG="${SCRATCH}/feature_bcp1.log"
set +e
python3 "${FUNC}" \
  --configfile="${CONFIG}" \
  --timeout-factor=1 \
  --tmpdir="${SCRATCH}/regtest" \
  "$@" | tee "${SCRATCH}/stdout.log"
RC=$?
set -e

if [[ -f "${SCRATCH}/regtest/test_framework.log" ]]; then
  cp -f "${SCRATCH}/regtest/test_framework.log" "${LOG}" || true
else
  cp -f "${SCRATCH}/stdout.log" "${LOG}" || true
fi

if [[ "${RC}" -eq 77 ]]; then
  echo
  echo "BTX Exchange Integration Profile v1 (BCP/1)"
  echo "0/${#PASS_ROWS[@]} PASS"
  echo "BCP/1 certification SKIPPED (RPCs not in this binary, or module missing)"
  exit 77
fi

echo
echo "=== BCP/1 PASS rows ==="
PASS_COUNT=0
FAIL_LIST=()
for row in "${PASS_ROWS[@]}"; do
  if grep -F -q "PASS ${row}" "${LOG}" 2>/dev/null \
    || grep -F -q "PASS ${row}" "${SCRATCH}/stdout.log" 2>/dev/null; then
    echo "PASS ${row}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL ${row}"
    FAIL_LIST+=("${row}")
  fi
done

TOTAL="${#PASS_ROWS[@]}"
echo
echo "BTX Exchange Integration Profile v1 (BCP/1)"
echo "${PASS_COUNT}/${TOTAL} PASS"

if [[ "${RC}" -ne 0 ]]; then
  die "feature_bcp1.py exited ${RC}"
fi

if [[ "${PASS_COUNT}" -ne "${TOTAL}" ]]; then
  die "missing PASS rows: ${FAIL_LIST[*]}"
fi

exit 0
