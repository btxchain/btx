#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"

# Graceful skip when build directory or required binaries are absent.
if ! [[ -x "${BUILD_DIR}/bin/btxd" && -x "${BUILD_DIR}/bin/btx-cli" ]]; then
  echo "m7_parallel_readiness_test: SKIP (binaries not built)"
  exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m7-parallel.XX""XX""XX")"
ARTIFACT="${TMP_DIR}/m7-e2e.json"
TIMEOUT_SECONDS="${BTX_M7_PARALLEL_TIMEOUT_SECONDS:-240}"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

if ! [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "error: BTX_M7_PARALLEL_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 1
fi

log1="${TMP_DIR}/m7_readiness.log"
log2="${TMP_DIR}/m7_pool_e2e.log"

set +e
"${ROOT_DIR}/scripts/m7_mining_readiness.sh" "${BUILD_DIR}" >"${log1}" 2>&1 &
pid1=$!
BTX_M7_RPC_CLIENT_TIMEOUT_SECONDS=120 \
"${ROOT_DIR}/scripts/m7_miner_pool_e2e.py" "${BUILD_DIR}" --artifact "${ARTIFACT}" >"${log2}" 2>&1 &
pid2=$!

wait_with_timeout() {
  local pid="$1"
  local timeout_seconds="$2"
  local log_file="$3"
  local task_name="$4"
  local start_ts
  start_ts="$(date +%s)"

  while kill -0 "${pid}" >/dev/null 2>&1; do
    local now_ts
    now_ts="$(date +%s)"
    if (( now_ts - start_ts >= timeout_seconds )); then
      echo "error: ${task_name} timed out after ${timeout_seconds}s" >&2
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" 2>/dev/null || true
      cat "${log_file}" >&2
      return 124
    fi
    sleep 1
  done
  wait "${pid}"
}

wait_with_timeout "${pid1}" "${TIMEOUT_SECONDS}" "${log1}" "m7_mining_readiness.sh"
rc1=$?
wait_with_timeout "${pid2}" "${TIMEOUT_SECONDS}" "${log2}" "m7_miner_pool_e2e.py"
rc2=$?
set -e

if (( rc1 != 0 )); then
  echo "error: m7_mining_readiness.sh failed in parallel run" >&2
  cat "${log1}" >&2
  exit "${rc1}"
fi

if (( rc2 != 0 )); then
  echo "error: m7_miner_pool_e2e.py failed in parallel run" >&2
  cat "${log2}" >&2
  exit "${rc2}"
fi

test -f "${ARTIFACT}"
rg -q "M7 readiness checks passed" "${log1}"
rg -q "BTX miner/pool readiness checks passed" "${log2}"

echo "m7_parallel_readiness_test: PASS"
