#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/verify_btx_production_readiness.sh [options]

Runs a production-readiness checklist for BTX MatMul PoW behavior.
It writes a machine-readable JSON artifact plus per-check logs.

Options:
  --build-dir <path>           Build directory (default: build-btx)
  --artifact <path>            JSON artifact output path
  --log-dir <path>             Directory for per-check logs
                               (default: .btx-production-readiness/logs)
  --check-timeout-seconds <n>  Per-check timeout seconds (default: 600, 0 disables)
  --skip-parallel-gate         Skip scripts/test_btx_parallel.sh
  --skip-lint                  Skip test/lint/lint-files.py
  --skip-m7-readiness          Skip scripts/m7_mining_readiness.sh
  --skip-m7-pool-e2e           Skip scripts/m7_miner_pool_e2e.py
  --skip-m5-genesis-freeze     Skip scripts/m5_verify_genesis_freeze.sh
  --skip-m7-external-miner     Skip optional external-miner template compatibility check
  --skip-m7-external-kawpow    Deprecated alias for --skip-m7-external-miner
  --skip-launch-blockers       Skip scripts/verify_btx_launch_blockers.sh
  --skip-benchmark-suite       Skip scripts/m9_btx_benchmark_suite.sh
  --skip-pow-scaling-suite     Skip scripts/m8_pow_scaling_suite.sh
  --matmul-perf-profile <name>
                               Run MatMul benchmark envelope check with profile
  --matmul-perf-envelope <path>
                               Envelope JSON path for MatMul perf check
  --skip-m7-timeout-check      Skip test/util/m7_mining_readiness_timeout_test.sh
  --skip-m7-parallel-check     Skip test/util/m7_parallel_readiness_test.sh
  --skip-parallel-timeout-check
                               Skip test/util/test_btx_parallel_timeout_guard_test.sh
  --skip-production-loop-guard Skip test/util/verify_btx_production_loop_test.sh
  --skip-live-p2p             Skip dual-node live P2P sync/relay validation
  --skip-live-mining           Skip strict regtest live mining check
  --help                       Show this message
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-production-readiness/production-readiness-report.json"
LOG_ROOT="${ROOT_DIR}/.btx-production-readiness/logs"
CHECK_TIMEOUT_SECONDS=600
SKIP_PARALLEL_GATE=0
SKIP_LINT=0
SKIP_M7_READINESS=0
SKIP_M7_POOL_E2E=0
SKIP_M5_GENESIS_FREEZE=0
SKIP_M7_EXTERNAL_MINER=0
SKIP_LAUNCH_BLOCKERS=0
SKIP_BENCHMARK_SUITE=0
SKIP_POW_SCALING_SUITE=0
MATMUL_PERF_PROFILE="${BTX_MATMUL_PERF_PROFILE:-}"
MATMUL_PERF_ENVELOPE="${ROOT_DIR}/doc/matmul-perf-envelopes.json"
SKIP_M7_TIMEOUT_CHECK=0
SKIP_M7_PARALLEL_CHECK=0
SKIP_PARALLEL_TIMEOUT_CHECK=0
SKIP_PRODUCTION_LOOP_GUARD=0
SKIP_LIVE_P2P=0
SKIP_LIVE_MINING=0

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
    --log-dir)
      LOG_ROOT="$2"
      shift 2
      ;;
    --check-timeout-seconds)
      CHECK_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --skip-parallel-gate)
      SKIP_PARALLEL_GATE=1
      shift
      ;;
    --skip-lint)
      SKIP_LINT=1
      shift
      ;;
    --skip-m7-readiness)
      SKIP_M7_READINESS=1
      shift
      ;;
    --skip-m7-pool-e2e)
      SKIP_M7_POOL_E2E=1
      shift
      ;;
    --skip-m5-genesis-freeze)
      SKIP_M5_GENESIS_FREEZE=1
      shift
      ;;
    --skip-m7-external-miner|--skip-m7-external-kawpow)
      SKIP_M7_EXTERNAL_MINER=1
      shift
      ;;
    --skip-launch-blockers)
      SKIP_LAUNCH_BLOCKERS=1
      shift
      ;;
    --skip-benchmark-suite)
      SKIP_BENCHMARK_SUITE=1
      shift
      ;;
    --skip-pow-scaling-suite)
      SKIP_POW_SCALING_SUITE=1
      shift
      ;;
    --matmul-perf-profile)
      MATMUL_PERF_PROFILE="$2"
      shift 2
      ;;
    --matmul-perf-envelope)
      MATMUL_PERF_ENVELOPE="$2"
      shift 2
      ;;
    --skip-m7-timeout-check)
      SKIP_M7_TIMEOUT_CHECK=1
      shift
      ;;
    --skip-m7-parallel-check)
      SKIP_M7_PARALLEL_CHECK=1
      shift
      ;;
    --skip-parallel-timeout-check)
      SKIP_PARALLEL_TIMEOUT_CHECK=1
      shift
      ;;
    --skip-production-loop-guard)
      SKIP_PRODUCTION_LOOP_GUARD=1
      shift
      ;;
    --skip-live-p2p)
      SKIP_LIVE_P2P=1
      shift
      ;;
    --skip-live-mining)
      SKIP_LIVE_MINING=1
      shift
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

resolve_btx_binary() {
  local canonical="$1"
  local legacy="$2"
  if [[ -x "${canonical}" ]]; then
    printf '%s\n' "${canonical}"
  elif [[ -x "${legacy}" ]]; then
    printf '%s\n' "${legacy}"
  else
    printf '%s\n' "${canonical}"
  fi
}

BTXD_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BTXCLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"

mkdir -p "${LOG_ROOT}" "$(dirname "${ARTIFACT_PATH}")"
PARALLEL_GATE_LOCK_DIR="${LOG_ROOT}/parallel-gate-lock-$$"
PARALLEL_GATE_LOG_DIR="${LOG_ROOT}/parallel-gate-logs-$$"

CHECK_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/btx-production-checks.XXXXXX")"
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
  local status="$2"
  local seconds="$3"
  local description="$4"
  local logfile="$5"
  printf '%s|%s|%s|%s|%s\n' "${id}" "${status}" "${seconds}" "${description}" "${logfile}" >> "${CHECK_RESULTS_FILE}"
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
}

run_check() {
  local id="$1"
  local description="$2"
  shift 2

  local logfile="${LOG_ROOT}/${id}.log"
  local -a cmd=("$@")
  local upper_id
  upper_id="$(printf '%s' "${id}" | tr '[:lower:]' '[:upper:]')"
  local override_var="BTX_PROD_OVERRIDE_${upper_id//-/_}"
  local override_value="${!override_var:-}"
  if [[ -n "${override_value}" ]]; then
    cmd=("${override_value}" "${cmd[@]:1}")
  fi

  if [[ "${#cmd[@]}" -lt 1 ]]; then
    echo "error: empty command for check '${id}'" >&2
    exit 1
  fi

  local start_ts
  start_ts="$(date +%s)"

  local run_ok=0
  if declare -F "${cmd[0]}" >/dev/null 2>&1; then
    if "${cmd[@]}" >"${logfile}" 2>&1; then
      run_ok=1
    fi
  elif [[ "${CHECK_TIMEOUT_SECONDS}" -eq 0 ]]; then
    if env LC_ALL=C LANG=C "${cmd[@]}" >"${logfile}" 2>&1; then
      run_ok=1
    fi
  else
    if run_with_timeout "${CHECK_TIMEOUT_SECONDS}" env LC_ALL=C LANG=C "${cmd[@]}" >"${logfile}" 2>&1; then
      run_ok=1
    fi
  fi

  if [[ "${run_ok}" -eq 1 ]]; then
    local end_ts
    end_ts="$(date +%s)"
    local seconds=$((end_ts - start_ts))
    record_result "${id}" "pass" "${seconds}" "${description}" "${logfile}"
    echo "[PASS] ${id}: ${description}"
  else
    local end_ts
    end_ts="$(date +%s)"
    local seconds=$((end_ts - start_ts))
    record_result "${id}" "fail" "${seconds}" "${description}" "${logfile}"
    echo "[FAIL] ${id}: ${description} (see ${logfile})"
    overall_fail=1
  fi
}

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

check_binaries() {
  [[ -x "${BTXD_BIN}" ]]
  [[ -x "${BTXCLI_BIN}" ]]
  [[ -x "${BUILD_DIR}/bin/test_btx" ]]
  [[ -x "${BUILD_DIR}/bin/btx-genesis" ]]
  [[ -x "${ROOT_DIR}/scripts/test_btx_parallel.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/verify_btx_production_loop.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m7_mining_readiness.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m7_miner_pool_e2e.py" ]]
  [[ -x "${ROOT_DIR}/scripts/m5_verify_genesis_freeze.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/verify_btx_launch_blockers.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m9_btx_benchmark_suite.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m10_validation_checklist.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m8_pow_scaling_suite.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m11_matmul_perf_envelope.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m12_dual_node_p2p_readiness.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m7_mining_readiness_timeout_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m8_pow_scaling_suite_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m9_btx_benchmark_suite_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m10_validation_checklist_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/verify_btx_production_readiness_timeout_guard_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/verify_btx_production_loop_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m7_parallel_readiness_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/test_btx_parallel_timeout_guard_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/verify_btx_production_readiness_parallel_lock_isolation_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/m5_verify_genesis_freeze_test.sh" ]]
  [[ -x "${ROOT_DIR}/test/util/verify_btx_launch_blockers_test.sh" ]]
}

check_live_strict_mining() (
  set -euo pipefail
  datadir="$(mktemp -d "${TMPDIR:-/tmp}/btx-prod-live.XXXXXX")"
  rpc_port="$(find_free_port)"
  pid=""
  cli() {
    "${BTXCLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" "$@"
  }
  cleanup_live() {
    if [[ -n "${pid}" ]]; then
      cli stop >/dev/null 2>&1 || true
      wait "${pid}" 2>/dev/null || true
    fi
    rm -rf "${datadir}"
  }
  trap cleanup_live EXIT

  "${BTXD_BIN}" \
      -regtest \
      -test=matmulstrict \
      -server=1 \
      -fallbackfee=0.0001 \
      -datadir="${datadir}" \
      -rpcport="${rpc_port}" \
      -listen=0 \
      -printtoconsole=0 \
      >/dev/null 2>&1 &
  pid="$!"

  for _ in $(seq 1 60); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "btxd exited before RPC became available" >&2
      return 1
    fi
    if cli getblockcount >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  local noncerange
  noncerange="$(cli getblocktemplate '{"rules":["segwit"]}' | \
    python3 -c 'import json,sys; print(json.load(sys.stdin)["noncerange"])')"
  [[ "${noncerange}" == "0000000000000000ffffffffffffffff" ]]

  cli generatetodescriptor 5 "raw(51)" >/dev/null

  local block_json
  block_json="$(cli -named generateblock "output=raw(51)" "transactions=[]" "submit=false")"
  local block_hash
  block_hash="$(printf '%s' "${block_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"])')"
  local block_hex
  block_hex="$(printf '%s' "${block_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"

  local submit_result
  submit_result="$(cli submitblock "${block_hex}")"
  [[ -z "${submit_result}" || "${submit_result}" == "null" ]]

  local best_hash
  best_hash="$(cli getbestblockhash)"
  [[ "${best_hash}" == "${block_hash}" ]]

  local header_hex
  header_hex="$(cli getblockheader "${block_hash}" false)"
  local nonce64
  nonce64="$(python3 -c 'import sys; b=bytes.fromhex(sys.argv[1]); print(int.from_bytes(b[76:84], "little"))' "${header_hex}")"
  local matmul_digest
  matmul_digest="$(python3 -c 'import sys; b=bytes.fromhex(sys.argv[1]); print(b[84:116][::-1].hex())' "${header_hex}")"
  [[ -n "${nonce64}" ]]
  [[ "${matmul_digest}" != "0000000000000000000000000000000000000000000000000000000000000000" ]]

  cli generatetodescriptor 4 "raw(51)" >/dev/null
  local count
  count="$(cli getblockcount)"
  [[ "${count}" -ge 10 ]]

  cli stop >/dev/null
  wait "${pid}"
  pid=""
)

run_check "binaries" "Required BTX binaries and scripts are present" check_binaries

if [[ "${SKIP_LINT}" -eq 0 ]]; then
  run_check "lint" "Repository lint checks pass" bash -lc "cd '${ROOT_DIR}' && python3 test/lint/lint-files.py"
fi

if [[ "${SKIP_PARALLEL_GATE}" -eq 0 ]]; then
  run_check "parallel_gate" "Parallel BTX test gate passes (unit+functional+script tests)" \
    bash -lc "cd '${ROOT_DIR}' && BTX_PARALLEL_SKIP_RECURSIVE_JOBS=1 BTX_PARALLEL_LOCK_DIR='${PARALLEL_GATE_LOCK_DIR}' BTX_PARALLEL_LOG_DIR='${PARALLEL_GATE_LOG_DIR}' scripts/test_btx_parallel.sh '${BUILD_DIR}'"
fi

if [[ "${SKIP_M7_READINESS}" -eq 0 ]]; then
  run_check "m7_readiness" "Strict MatMul mining readiness script passes" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m7_mining_readiness.sh '${BUILD_DIR}'"
fi

if [[ "${SKIP_M7_POOL_E2E}" -eq 0 ]]; then
  run_check "m7_pool_e2e" "M7 miner/pool E2E submission path passes" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m7_miner_pool_e2e.py '${BUILD_DIR}' --artifact '/tmp/btx-m7-production-readiness-artifact.json'"
fi

if [[ "${SKIP_M5_GENESIS_FREEZE}" -eq 0 ]]; then
  run_check "m5_genesis_freeze" "Genesis tuple freeze matches main/testnet/regtest headers" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m5_verify_genesis_freeze.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-m5-genesis-freeze-artifact.json'"
fi

if [[ "${SKIP_M7_EXTERNAL_MINER}" -eq 0 ]]; then
  run_check "m7_external_miner" "Template-only compatibility path on testnet passes" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m7_miner_pool_e2e.py '${BUILD_DIR}' --chain testnet --template-only --artifact '/tmp/btx-m7-testnet-artifact.json'"
fi

if [[ "${SKIP_LAUNCH_BLOCKERS}" -eq 0 ]]; then
  run_check "launch_blockers" "All launch blocker checks pass via consolidated runner" \
    bash -lc "cd '${ROOT_DIR}' && scripts/verify_btx_launch_blockers.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-launch-blockers-artifact.json'"
fi

if [[ "${SKIP_BENCHMARK_SUITE}" -eq 0 ]]; then
  run_check "benchmark_suite" "Benchmark and latency suite passes" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m9_btx_benchmark_suite.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-benchmark-suite-readiness-artifact.json' --log-dir '/tmp/btx-benchmark-suite-readiness-logs' --iterations 1"
fi

if [[ "${SKIP_POW_SCALING_SUITE}" -eq 0 ]]; then
  run_check "pow_scaling_suite" "Long-horizon DGW/MatMul scaling simulations pass" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m8_pow_scaling_suite.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-pow-scaling-readiness-artifact.json' --log-dir '/tmp/btx-pow-scaling-readiness-logs'"
fi

if [[ -n "${MATMUL_PERF_PROFILE}" ]]; then
  run_check "matmul_perf_envelope" "MatMul solve/Metal digest benchmarks stay within configured profile envelope" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m11_matmul_perf_envelope.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-matmul-perf-envelope-readiness-artifact.json' --log-dir '/tmp/btx-matmul-perf-envelope-readiness-logs' --envelope '${MATMUL_PERF_ENVELOPE}' --profile '${MATMUL_PERF_PROFILE}'"
fi

if [[ "${SKIP_M7_TIMEOUT_CHECK}" -eq 0 ]]; then
  run_check "m7_timeout_guard" "M7 readiness script exits quickly when RPC never comes up" \
    bash -lc "cd '${ROOT_DIR}' && test/util/m7_mining_readiness_timeout_test.sh"
fi

if [[ "${SKIP_M7_PARALLEL_CHECK}" -eq 0 ]]; then
  run_check "m7_parallel_isolation" "M7 scripts pass when run concurrently (no port contention hangs)" \
    bash -lc "cd '${ROOT_DIR}' && test/util/m7_parallel_readiness_test.sh"
fi

if [[ "${SKIP_PARALLEL_TIMEOUT_CHECK}" -eq 0 ]]; then
  run_check "parallel_timeout_guard" "Parallel gate enforces per-job timeout and force-kill semantics" \
    bash -lc "cd '${ROOT_DIR}' && bash test/util/test_btx_parallel_timeout_guard_test.sh"
fi

if [[ "${SKIP_PRODUCTION_LOOP_GUARD}" -eq 0 ]]; then
  run_check "production_loop_guard" "Production loop wrapper enforces bounded retries and preserves artifacts" \
    bash -lc "cd '${ROOT_DIR}' && test/util/verify_btx_production_loop_test.sh"
fi

if [[ "${SKIP_LIVE_P2P}" -eq 0 ]]; then
  run_check "live_dual_node_p2p" "Dual-node P2P sync/relay validation passes (node A canonical, node B peer)" \
    bash -lc "cd '${ROOT_DIR}' && scripts/m12_dual_node_p2p_readiness.sh --build-dir '${BUILD_DIR}' --artifact '/tmp/btx-m12-dual-node-readiness-artifact.json'"
fi

if [[ "${SKIP_LIVE_MINING}" -eq 0 ]]; then
  run_check "live_strict_mining" "Strict regtest mining + submitblock flow mines and validates BTX headers" check_live_strict_mining
fi

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
  done < "${CHECK_RESULTS_FILE}"
  echo
  echo "  ]"
  echo "}"
} > "${ARTIFACT_PATH}"

echo "Production readiness artifact: ${ARTIFACT_PATH}"
echo "Overall status: ${overall_status}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi

exit 0
