#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify_btx_launch_blockers.sh [options]

Run and record pass/fail status for the three BTX launch blockers:
1) MatMul consensus and block-hash semantics consistency.
2) Genesis freeze tuple consistency (main/testnet/regtest).
3) Miner/pool submission path on strict regtest.
4) Production closure checks (genesis keying, seeds, activations, docs).

Options:
  --build-dir <path>      Build directory (default: build-btx)
  --artifact <path>       Output JSON artifact path
                          (default: .btx-validation/launch-blockers.json)
  --check-timeout-seconds <n>
                          Per-check timeout in seconds (default: 600, 0 disables)
  -h, --help              Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/launch-blockers.json"
CHECK_TIMEOUT_SECONDS=600

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --check-timeout-seconds)
      CHECK_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "${CHECK_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --check-timeout-seconds must be a non-negative integer" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARTIFACT_PATH}")"
LOG_ROOT="${ROOT_DIR}/.btx-validation/launch-blocker-logs"
mkdir -p "${LOG_ROOT}"
RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/btx-launch-blockers.XXXXXX")"
cleanup() {
  rm -f "${RESULTS_FILE}"
}
trap cleanup EXIT

overall_fail=0

json_escape() {
  local text="$1"
  text="${text//\\/\\\\}"
  text="${text//\"/\\\"}"
  text="${text//$'\n'/\\n}"
  printf '%s' "${text}"
}

record_result() {
  local id="$1"
  local status="$2"
  local seconds="$3"
  local description="$4"
  local logfile="$5"
  printf '%s|%s|%s|%s|%s\n' "${id}" "${status}" "${seconds}" "${description}" "${logfile}" >> "${RESULTS_FILE}"
}

run_with_timeout() {
  local timeout_seconds="$1"
  shift
  if [[ "${timeout_seconds}" -eq 0 ]]; then
    "$@"
    return $?
  fi

  python3 - "$timeout_seconds" "$@" <<'PY'
import subprocess
import sys

timeout = int(sys.argv[1])
cmd = sys.argv[2:]
proc = subprocess.Popen(cmd)
try:
    rc = proc.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    print(f"timeout after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
    sys.exit(124)
sys.exit(rc)
PY
}

run_check() {
  local id="$1"
  local description="$2"
  shift 2
  local logfile="${LOG_ROOT}/${id}.log"
  local -a cmd=("$@")

  local upper_id
  upper_id="$(printf '%s' "${id}" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local override_var="BTX_LAUNCH_OVERRIDE_${upper_id}"
  local override_value="${!override_var:-}"
  if [[ -n "${override_value}" ]]; then
    cmd=(bash -c "${override_value}")
  fi

  local start_ts end_ts seconds
  start_ts="$(date +%s)"
  if run_with_timeout "${CHECK_TIMEOUT_SECONDS}" env LC_ALL=C LANG=C "${cmd[@]}" >"${logfile}" 2>&1; then
    end_ts="$(date +%s)"
    seconds=$((end_ts - start_ts))
    record_result "${id}" "pass" "${seconds}" "${description}" "${logfile}"
    echo "[PASS] ${id}: ${description}"
  else
    end_ts="$(date +%s)"
    seconds=$((end_ts - start_ts))
    record_result "${id}" "fail" "${seconds}" "${description}" "${logfile}"
    echo "[FAIL] ${id}: ${description} (see ${logfile})"
    overall_fail=1
  fi
}

run_check "block_hash_semantics" "MatMul consensus and header-field tests" \
  bash -lc "cd '${ROOT_DIR}' && '${BUILD_DIR}/bin/test_btx' --run_test=pow_tests,matmul_* --catch_system_error=no --log_level=test_suite"

run_check "genesis_freeze" "Genesis tuple freeze consistency for main/testnet/regtest" \
  bash -lc "cd '${ROOT_DIR}' && scripts/m5_verify_genesis_freeze.sh --build-dir '${BUILD_DIR}' --artifact '${ROOT_DIR}/.btx-validation/m5-genesis-freeze.json'"

run_check "miner_pool_path" "Strict regtest miner/pool submission path" \
  bash -lc "cd '${ROOT_DIR}' && scripts/m7_miner_pool_e2e.py '${BUILD_DIR}' --artifact '${ROOT_DIR}/.btx-validation/m7-regtest-readiness.json'"

run_check "closure_checks" "Production closure checks are enforced" \
  bash -lc "cd '${ROOT_DIR}' && scripts/verify_btx_todo_closure.py"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
overall_status="pass"
if [[ "${overall_fail}" -ne 0 ]]; then
  overall_status="fail"
fi

{
  echo "{"
  echo "  \"generated_at\": \"${generated_at}\","
  echo "  \"overall_status\": \"${overall_status}\","
  echo "  \"checks\": ["
  first=1
  while IFS='|' read -r id status seconds description logfile; do
    if [[ "${first}" -eq 0 ]]; then
      echo "    ,"
    fi
    first=0
    echo "    {"
    echo "      \"id\": \"$(json_escape "${id}")\","
    echo "      \"status\": \"$(json_escape "${status}")\","
    echo "      \"seconds\": ${seconds},"
    echo "      \"description\": \"$(json_escape "${description}")\","
    echo "      \"log\": \"$(json_escape "${logfile}")\""
    echo -n "    }"
  done < "${RESULTS_FILE}"
  echo
  echo "  ]"
  echo "}"
} > "${ARTIFACT_PATH}"

echo "Launch blocker artifact: ${ARTIFACT_PATH}"
echo "Overall status: ${overall_status}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi
