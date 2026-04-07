#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m9_btx_benchmark_suite.sh [options]

Run BTX benchmark and latency checks, emit a JSON artifact, and keep per-check logs.

Options:
  --build-dir <path>       Build directory (default: build-btx)
  --artifact <path>        JSON artifact output path
  --log-dir <path>         Directory for benchmark logs
  --iterations <n>         Startup/mining iterations (default: 1)
  --command-timeout-seconds <n>
                           Timeout for external benchmark commands (default: 900, 0 disables)
  --m7-e2e-script <path>   Override M7 E2E script (default: scripts/m7_miner_pool_e2e.py)
  --skip-bench-btx         Skip bench_btx checks
  --skip-startup-latency   Skip btxd startup latency benchmark
  --skip-mining-latency    Skip regtest mining latency benchmark
  --skip-m7-e2e-latency    Skip M7 miner/pool E2E latency benchmark
  -h, --help               Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-production-readiness/benchmark-suite.json"
LOG_DIR="${ROOT_DIR}/.btx-production-readiness/benchmark-logs"
ITERATIONS=1
COMMAND_TIMEOUT_SECONDS=900
M7_E2E_SCRIPT="${ROOT_DIR}/scripts/m7_miner_pool_e2e.py"
SKIP_BENCH_BTX=0
SKIP_STARTUP_LATENCY=0
SKIP_MINING_LATENCY=0
SKIP_M7_E2E_LATENCY=0

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
      LOG_DIR="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --command-timeout-seconds)
      COMMAND_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --m7-e2e-script)
      M7_E2E_SCRIPT="$2"
      shift 2
      ;;
    --skip-bench-btx|--skip-bench-bitcoin)
      SKIP_BENCH_BTX=1
      shift
      ;;
    --skip-startup-latency)
      SKIP_STARTUP_LATENCY=1
      shift
      ;;
    --skip-mining-latency)
      SKIP_MINING_LATENCY=1
      shift
      ;;
    --skip-m7-e2e-latency)
      SKIP_M7_E2E_LATENCY=1
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

if ! [[ "${ITERATIONS}" =~ ^[0-9]+$ ]] || [[ "${ITERATIONS}" -lt 1 ]]; then
  echo "error: --iterations must be a positive integer" >&2
  exit 1
fi
if ! [[ "${COMMAND_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --command-timeout-seconds must be a non-negative integer" >&2
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

BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
BENCH_BIN="${BUILD_DIR}/bin/bench_btx"

if [[ ! -x "${BITCOIND_BIN}" ]]; then
  echo "error: missing executable: ${BITCOIND_BIN}" >&2
  exit 1
fi
if [[ ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing executable: ${BITCOIN_CLI_BIN}" >&2
  exit 1
fi
if [[ ! -x "${M7_E2E_SCRIPT}" ]]; then
  echo "error: missing executable: ${M7_E2E_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}" "$(dirname "${ARTIFACT_PATH}")"

RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/btx-benchmark-results.XXXXXX")"
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

epoch_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

stop_node_process() {
  local pid="$1"
  local datadir="$2"
  local rpc_port="$3"

  "${BITCOIN_CLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" stop >/dev/null 2>&1 || true
  for _ in $(seq 1 10); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" 2>/dev/null || true
}

record_result() {
  local id="$1"
  local status="$2"
  local elapsed_ms="$3"
  local description="$4"
  local logfile="$5"
  local details="$6"
  printf '%s|%s|%s|%s|%s|%s\n' "${id}" "${status}" "${elapsed_ms}" "${description}" "${logfile}" "${details}" >> "${RESULTS_FILE}"
}

run_command_check() {
  local id="$1"
  local description="$2"
  local logfile="$3"
  local details="$4"
  shift 4

  local start_ms
  start_ms="$(epoch_ms)"
  local run_rc=0
  if declare -F "$1" >/dev/null 2>&1 || [[ "${COMMAND_TIMEOUT_SECONDS}" -eq 0 ]]; then
    if "$@" >"${logfile}" 2>&1; then
      run_rc=0
    else
      run_rc=$?
    fi
  else
    if python3 - "${COMMAND_TIMEOUT_SECONDS}" "$@" >"${logfile}" 2>&1 <<'PY'
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
    then
      run_rc=0
    else
      run_rc=$?
    fi
  fi

  if [[ "${run_rc}" -eq 0 ]]; then
    local end_ms
    end_ms="$(epoch_ms)"
    local elapsed_ms=$((end_ms - start_ms))
    record_result "${id}" "pass" "${elapsed_ms}" "${description}" "${logfile}" "${details}"
    echo "[PASS] ${id}"
  else
    local end_ms
    end_ms="$(epoch_ms)"
    local elapsed_ms=$((end_ms - start_ms))
    record_result "${id}" "fail" "${elapsed_ms}" "${description}" "${logfile}" "${details}"
    echo "[FAIL] ${id} (see ${logfile})"
    overall_fail=1
  fi
}

benchmark_startup_latency() {
  local logfile="$1"
  local total_ms=0
  local min_ms=-1
  local max_ms=0

  for iter in $(seq 1 "${ITERATIONS}"); do
    local datadir
    datadir="$(mktemp -d "${TMPDIR:-/tmp}/btx-bench-startup.XXXXXX")"
    local rpc_port
    rpc_port="$(find_free_port)"

    local iter_start_ms
    iter_start_ms="$(epoch_ms)"

    "${BITCOIND_BIN}" -regtest -test=matmulstrict -server=1 -listen=0 -datadir="${datadir}" -rpcport="${rpc_port}" -printtoconsole=0 >/dev/null 2>&1 &
    local node_pid=$!

    local rpc_ready=0
    for _ in $(seq 1 60); do
      if ! kill -0 "${node_pid}" >/dev/null 2>&1; then
        echo "startup benchmark: btxd exited early on iteration ${iter}" >&2
        wait "${node_pid}" 2>/dev/null || true
        rm -rf "${datadir}"
        return 1
      fi
      if "${BITCOIN_CLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" getblockcount >/dev/null 2>&1; then
        rpc_ready=1
        break
      fi
      sleep 1
    done

    local iter_end_ms
    iter_end_ms="$(epoch_ms)"

    if [[ "${rpc_ready}" -ne 1 ]]; then
      echo "startup benchmark: timed out waiting for RPC on iteration ${iter}" >&2
      kill "${node_pid}" >/dev/null 2>&1 || true
      wait "${node_pid}" 2>/dev/null || true
      rm -rf "${datadir}"
      return 1
    fi

    local iter_ms=$((iter_end_ms - iter_start_ms))
    total_ms=$((total_ms + iter_ms))
    if [[ "${min_ms}" -lt 0 || "${iter_ms}" -lt "${min_ms}" ]]; then
      min_ms="${iter_ms}"
    fi
    if [[ "${iter_ms}" -gt "${max_ms}" ]]; then
      max_ms="${iter_ms}"
    fi

    stop_node_process "${node_pid}" "${datadir}" "${rpc_port}"
    rm -rf "${datadir}"
  done

  local avg_ms=$((total_ms / ITERATIONS))
  {
    echo "startup_iterations=${ITERATIONS}"
    echo "startup_avg_ms=${avg_ms}"
    echo "startup_min_ms=${min_ms}"
    echo "startup_max_ms=${max_ms}"
  } >"${logfile}"
}

benchmark_mining_latency() {
  local logfile="$1"
  local datadir
  datadir="$(mktemp -d "${TMPDIR:-/tmp}/btx-bench-mining.XXXXXX")"
  local rpc_port
  rpc_port="$(find_free_port)"

  cleanup_mining() {
    if [[ -n "${node_pid:-}" ]]; then
      stop_node_process "${node_pid}" "${datadir}" "${rpc_port}"
    fi
    rm -rf "${datadir}"
  }

  "${BITCOIND_BIN}" -regtest -test=matmulstrict -server=1 -listen=0 -datadir="${datadir}" -rpcport="${rpc_port}" -printtoconsole=0 >/dev/null 2>&1 &
  node_pid=$!

  local rpc_ready=0
  for _ in $(seq 1 60); do
    if ! kill -0 "${node_pid}" >/dev/null 2>&1; then
      echo "mining benchmark: btxd exited early" >&2
      cleanup_mining
      return 1
    fi
    if "${BITCOIN_CLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" getblockcount >/dev/null 2>&1; then
      rpc_ready=1
      break
    fi
    sleep 1
  done

  if [[ "${rpc_ready}" -ne 1 ]]; then
    echo "mining benchmark: timed out waiting for RPC" >&2
    cleanup_mining
    return 1
  fi

  local start_ms
  start_ms="$(epoch_ms)"
  "${BITCOIN_CLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" generatetodescriptor 64 "raw(51)" >/dev/null
  local end_ms
  end_ms="$(epoch_ms)"

  local elapsed_ms=$((end_ms - start_ms))
  {
    echo "mined_blocks=64"
    echo "elapsed_ms=${elapsed_ms}"
    local count
    count="$("${BITCOIN_CLI_BIN}" -regtest -datadir="${datadir}" -rpcport="${rpc_port}" getblockcount)"
    echo "final_height=${count}"
  } >"${logfile}"

  cleanup_mining
}

if [[ "${SKIP_BENCH_BTX}" -eq 1 ]]; then
  record_result "bench_btx" "skip" 0 "bench_btx benchmark run" "${LOG_DIR}/bench_btx.log" "skipped_by_flag"
  echo "[SKIP] bench_btx"
elif [[ ! -x "${BENCH_BIN}" ]]; then
  record_result "bench_btx" "skip" 0 "bench_btx benchmark run" "${LOG_DIR}/bench_btx.log" "bench_binary_missing"
  echo "[SKIP] bench_btx (missing ${BENCH_BIN})"
else
  run_command_check "bench_btx" "bench_btx CPU benchmark smoke" "${LOG_DIR}/bench_btx.log" "filter=VerifyScript,min_time=20" \
    "${BENCH_BIN}" -filter='^(VerifyScript|SHA256)$' -min-time=20
fi

if [[ "${SKIP_STARTUP_LATENCY}" -eq 1 ]]; then
  record_result "node_startup_latency" "skip" 0 "btxd regtest startup latency" "${LOG_DIR}/node_startup_latency.log" "skipped_by_flag"
  echo "[SKIP] node_startup_latency"
else
  run_command_check "node_startup_latency" "btxd regtest startup latency" "${LOG_DIR}/node_startup_latency.log" "iterations=${ITERATIONS}" \
    benchmark_startup_latency "${LOG_DIR}/node_startup_latency.log"
fi

if [[ "${SKIP_MINING_LATENCY}" -eq 1 ]]; then
  record_result "mining_latency" "skip" 0 "regtest generatetodescriptor latency" "${LOG_DIR}/mining_latency.log" "skipped_by_flag"
  echo "[SKIP] mining_latency"
else
  run_command_check "mining_latency" "regtest generatetodescriptor latency" "${LOG_DIR}/mining_latency.log" "blocks=64" \
    benchmark_mining_latency "${LOG_DIR}/mining_latency.log"
fi

if [[ "${SKIP_M7_E2E_LATENCY}" -eq 1 ]]; then
  record_result "m7_e2e_latency" "skip" 0 "M7 miner/pool E2E latency" "${LOG_DIR}/m7_e2e_latency.log" "skipped_by_flag"
  echo "[SKIP] m7_e2e_latency"
else
  run_command_check "m7_e2e_latency" "M7 miner/pool E2E latency" "${LOG_DIR}/m7_e2e_latency.log" "script=$(basename "${M7_E2E_SCRIPT}")" \
    "${M7_E2E_SCRIPT}" "${BUILD_DIR}" --artifact "${LOG_DIR}/m7_e2e_artifact.json"
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
  echo "  \"iterations\": ${ITERATIONS},"
  echo "  \"overall_status\": \"${overall_status}\","
  echo "  \"benchmarks\": ["
  first=1
  while IFS='|' read -r id status elapsed_ms description logfile details; do
    if [[ "${first}" -eq 0 ]]; then
      echo "    ,"
    fi
    first=0
    echo "    {"
    echo "      \"id\": \"$(json_escape "${id}")\","
    echo "      \"status\": \"$(json_escape "${status}")\","
    echo "      \"elapsed_ms\": ${elapsed_ms},"
    echo "      \"description\": \"$(json_escape "${description}")\","
    echo "      \"details\": \"$(json_escape "${details}")\","
    echo "      \"log\": \"$(json_escape "${logfile}")\""
    echo -n "    }"
  done < "${RESULTS_FILE}"
  echo
  echo "  ]"
  echo "}"
} > "${ARTIFACT_PATH}"

echo "Benchmark artifact: ${ARTIFACT_PATH}"
echo "Overall status: ${overall_status}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi

exit 0
