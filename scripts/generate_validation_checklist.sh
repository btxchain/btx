#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/generate_validation_checklist.sh [options]

Run the BTX deep audit checklist by chaining the major verification suites
and emit both a human-readable summary and a JSON artifact.

Options:
  --build-dir <path>   Build directory containing BTX binaries (default: build-btx)
  --log-dir <path>     Directory for per-check logs (default: .btx-validation/logs)
  --artifact <path>    JSON artifact output path (default: .btx-validation/checklist.json)
  --check-timeout-seconds <n>
                       Per-check timeout seconds (default: 1800, 0 disables)
  -h, --help           Show this message

Environment overrides:
  BTX_CHECKLIST_OVERRIDE_CONSENSUS
  BTX_CHECKLIST_OVERRIDE_PARALLEL
  BTX_CHECKLIST_OVERRIDE_BENCHMARK
  BTX_CHECKLIST_OVERRIDE_PRODUCTION
  BTX_CHECKLIST_OVERRIDE_SCALING
  BTX_CHECKLIST_OVERRIDE_MINING

If an override variable is set, its value is used as the command path for the
corresponding check while keeping the original arguments.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
LOG_DIR="${ROOT_DIR}/.btx-validation/logs"
ARTIFACT="${ROOT_DIR}/.btx-validation/checklist.json"
CHECK_TIMEOUT_SECONDS=1800

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT="$2"
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

mkdir -p "${LOG_DIR}" "$(dirname "${ARTIFACT}")"

CHECK_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/btx-checklist.XXXXXX")"
cleanup() {
  rm -f "${CHECK_RESULTS_FILE}"
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
  local description="$2"
  local status="$3"
  local seconds="$4"
  local logfile="$5"
  printf '%s|%s|%s|%s|%s\n' "${id}" "${description}" "${status}" "${seconds}" "${logfile}" >> "${CHECK_RESULTS_FILE}"
}

run_check() {
  local id="$1"
  local description="$2"
  shift 2
  if [[ $# -lt 1 ]]; then
    echo "error: run_check requires a command for ${id}" >&2
    exit 1
  fi

  local logfile="${LOG_DIR}/${id}.log"
  local -a cmd=("$@")
  local upper_id
  upper_id="$(printf '%s' "${id}" | tr '[:lower:]' '[:upper:]')"
  local override_var="BTX_CHECKLIST_OVERRIDE_${upper_id//-/_}"
  local override_value="${!override_var:-}"
  if [[ -n "${override_value}" ]]; then
    cmd=("${override_value}" "${cmd[@]:1}")
  fi

  local start_ts
  start_ts="$(date +%s)"
  local run_rc=0
  if [[ "${CHECK_TIMEOUT_SECONDS}" -eq 0 ]]; then
    set +e
    "${cmd[@]}" >"${logfile}" 2>&1
    run_rc=$?
    set -e
  else
    set +e
    python3 - "${CHECK_TIMEOUT_SECONDS}" "${cmd[@]}" >"${logfile}" 2>&1 <<'PY'
import subprocess
import sys

timeout = int(sys.argv[1])
cmd = sys.argv[2:]
if timeout < 0:
    print("timeout must be >= 0", file=sys.stderr)
    sys.exit(2)
if not cmd:
    print("missing command", file=sys.stderr)
    sys.exit(2)

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
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    print(f"timeout after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
    sys.exit(124)

sys.exit(rc)
PY
    run_rc=$?
    set -e
  fi

  if [[ "${run_rc}" -eq 0 ]]; then
    local end_ts
    end_ts="$(date +%s)"
    local seconds=$((end_ts - start_ts))
    record_result "${id}" "${description}" "pass" "${seconds}" "${logfile}"
    echo "[PASS] ${id}: ${description}"
  else
    local end_ts
    end_ts="$(date +%s)"
    local seconds=$((end_ts - start_ts))
    record_result "${id}" "${description}" "fail" "${seconds}" "${logfile}"
    echo "[FAIL] ${id}: ${description} (see ${logfile})"
    overall_fail=1
  fi
}

run_check "consensus" "Consensus determinism + KAWPOW compatibility" \
  "${ROOT_DIR}/scripts/test_btx_consensus.sh" "${BUILD_DIR}"

run_check "parallel" "Parallel suite (unit, functional, miner readiness, swarm guards)" \
  "${ROOT_DIR}/scripts/test_btx_parallel.sh" "${BUILD_DIR}"

run_check "benchmark" "Benchmark/latency suite (startup, mining, M7 E2E, optional bench_btx)" \
  "${ROOT_DIR}/scripts/m9_btx_benchmark_suite.sh" \
  --build-dir "${BUILD_DIR}" \
  --artifact "${ROOT_DIR}/.btx-validation/benchmark-suite.json" \
  --log-dir "${ROOT_DIR}/.btx-validation/benchmark-suite-logs" \
  --iterations 1

run_check "production" "End-to-end production readiness checks" \
  "${ROOT_DIR}/scripts/verify_btx_production_readiness.sh" \
  --build-dir "${BUILD_DIR}" \
  --skip-parallel-gate \
  --artifact "${ROOT_DIR}/.btx-validation/production-readiness.json"

run_check "scaling" "Long-horizon PoW scaling scenarios" \
  "${ROOT_DIR}/scripts/m8_pow_scaling_suite.sh" \
  --build-dir "${BUILD_DIR}" \
  --artifact "${ROOT_DIR}/.btx-validation/pow-scaling-suite.json" \
  --log-dir "${ROOT_DIR}/.btx-validation/pow-scaling-logs"

run_check "mining" "Strict M7 KawPow mining readiness (GBT + regtest boot)" \
  "${ROOT_DIR}/scripts/m7_mining_readiness.sh" "${BUILD_DIR}"

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
  echo "  \"checks\": ["
  first=1
  while IFS='|' read -r id description status seconds logfile; do
    if [[ "${first}" -eq 0 ]]; then
      echo "    ,"
    fi
    first=0
    echo "    {"
    echo "      \"id\": \"$(json_escape "${id}")\","
    echo "      \"description\": \"$(json_escape "${description}")\","
    echo "      \"status\": \"$(json_escape "${status}")\","
    echo "      \"seconds\": ${seconds},"
    echo "      \"log\": \"$(json_escape "${logfile}")\""
    echo -n "    }"
  done < "${CHECK_RESULTS_FILE}"
  echo
  echo "  ]"
  echo "}"
} > "${ARTIFACT}"

echo
echo "Validation checklist summary:"
while IFS='|' read -r id description status seconds logfile; do
  status_display="$(printf '%s' "${status}" | tr '[:lower:]' '[:upper:]')"
  printf ' - [%s] %s (%ss) %s\n' "${status_display}" "${id}" "${seconds}" "${description}"
  printf '   Log: %s\n' "${logfile}"
done < "${CHECK_RESULTS_FILE}"
echo "JSON artifact: ${ARTIFACT}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi
