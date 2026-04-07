#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m8_pow_scaling_suite.sh [options]

Run BTX long-horizon PoW scaling simulations backed by consensus unit tests.

Options:
  --build-dir <path>   Build directory containing bin/test_btx (default: build-btx)
  --artifact <path>    JSON artifact output path
  --log-dir <path>     Directory for per-scenario logs
  -h, --help           Show help
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT="${ROOT_DIR}/.btx-production-readiness/pow-scaling-suite.json"
LOG_DIR="${ROOT_DIR}/.btx-production-readiness/pow-scaling-logs"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
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

TEST_BIN="${BUILD_DIR}/bin/test_btx"
if [[ ! -x "${TEST_BIN}" ]]; then
  echo "error: missing executable: ${TEST_BIN}" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}" "$(dirname "${ARTIFACT}")"

json_escape() {
  local text="$1"
  text="${text//\\/\\\\}"
  text="${text//\"/\\\"}"
  text="${text//$'\n'/\\n}"
  printf '%s' "${text}"
}

scenario_ids=(
  "GetNextWorkRequired_matmul_dgw_steady_state"
  "GetNextWorkRequired_matmul_dgw_long_horizon_scaling"
  "GetNextWorkRequired_matmul_dgw_oscillation_resilience"
  "GetNextWorkRequired_matmul_dgw_timestamp_drift_recovery"
)

results_file="$(mktemp "${TMPDIR:-/tmp}/btx-pow-scaling-results.XXXXXX")"
cleanup() {
  rm -f "${results_file}"
}
trap cleanup EXIT

overall_fail=0

for id in "${scenario_ids[@]}"; do
  test_selector="pow_tests/${id}"
  log_file="${LOG_DIR}/${id}.log"
  start_ts="$(date +%s)"
  if "${TEST_BIN}" --run_test="${test_selector}" >"${log_file}" 2>&1; then
    end_ts="$(date +%s)"
    seconds=$((end_ts - start_ts))
    printf '%s|pass|%s|%s\n' "${id}" "${seconds}" "${log_file}" >> "${results_file}"
    echo "[PASS] ${id}"
  else
    end_ts="$(date +%s)"
    seconds=$((end_ts - start_ts))
    printf '%s|fail|%s|%s\n' "${id}" "${seconds}" "${log_file}" >> "${results_file}"
    echo "[FAIL] ${id} (see ${log_file})"
    overall_fail=1
  fi
done

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
overall_status="pass"
if [[ "${overall_fail}" -ne 0 ]]; then
  overall_status="fail"
fi

{
  echo "{"
  echo "  \"generated_at\": \"${generated_at}\","
  echo "  \"build_dir\": \"$(json_escape "${BUILD_DIR}")\","
  echo "  \"overall_status\": \"${overall_status}\","
  echo "  \"scenarios\": ["
  first=1
  while IFS='|' read -r id status seconds log_file; do
    if [[ "${first}" -eq 0 ]]; then
      echo "    ,"
    fi
    first=0
    echo "    {"
    echo "      \"id\": \"$(json_escape "${id}")\","
    echo "      \"status\": \"$(json_escape "${status}")\","
    echo "      \"seconds\": ${seconds},"
    echo "      \"log\": \"$(json_escape "${log_file}")\""
    echo -n "    }"
  done < "${results_file}"
  echo
  echo "  ]"
  echo "}"
} > "${ARTIFACT}"

echo "PoW scaling artifact: ${ARTIFACT}"
echo "Overall status: ${overall_status}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi

exit 0
