#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-btx}"
if [[ $# -gt 0 ]]; then
  shift
fi

SKIP_DEFAULT_JOBS="${BTX_PARALLEL_SKIP_DEFAULT_JOBS:-0}"
JOB_TIMEOUT_SECONDS="${BTX_PARALLEL_JOB_TIMEOUT_SECONDS:-900}"
MAX_JOBS="${BTX_PARALLEL_MAX_JOBS:-2}"
LOCK_DIR="${BTX_PARALLEL_LOCK_DIR:-${ROOT_DIR}/.btx-parallel-test.lock}"
LOCK_OWNER_PID_FILE="${LOCK_DIR}/owner.pid"
LOCK_OWNER_CMD_FILE="${LOCK_DIR}/owner.cmd"
LOCK_ACQUIRED=0

if ! [[ "${SKIP_DEFAULT_JOBS}" =~ ^[0-9]+$ ]] || [[ "${SKIP_DEFAULT_JOBS}" -gt 1 ]]; then
  echo "error: BTX_PARALLEL_SKIP_DEFAULT_JOBS must be 0 or 1" >&2
  exit 1
fi

if ! [[ "${JOB_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: BTX_PARALLEL_JOB_TIMEOUT_SECONDS must be a non-negative integer" >&2
  exit 1
fi

if ! [[ "${MAX_JOBS}" =~ ^[0-9]+$ ]] || [[ "${MAX_JOBS}" -lt 1 ]]; then
  echo "error: BTX_PARALLEL_MAX_JOBS must be a positive integer" >&2
  exit 1
fi

if [[ "${BTX_PARALLEL_ACTIVE:-0}" == "1" && "${SKIP_DEFAULT_JOBS}" -eq 0 && "${BTX_PARALLEL_ALLOW_NESTED_DEFAULT_JOBS:-0}" != "1" ]]; then
  echo "error: nested default test_btx_parallel invocation is not allowed; set BTX_PARALLEL_SKIP_DEFAULT_JOBS=1 for nested runs" >&2
  exit 1
fi
export BTX_PARALLEL_ACTIVE=1

if [[ "${SKIP_DEFAULT_JOBS}" -eq 0 ]]; then
  if [[ ! -x "${BUILD_DIR}/bin/test_btx" ]]; then
    echo "error: ${BUILD_DIR}/bin/test_btx is missing. Run scripts/build_btx.sh first." >&2
    exit 1
  fi

  if [[ ! -f "${BUILD_DIR}/test/config.ini" && ! -f "${ROOT_DIR}/test/config.ini" ]]; then
    echo "error: missing functional test config (expected ${BUILD_DIR}/test/config.ini). Run scripts/build_btx.sh first." >&2
    exit 1
  fi

  if [[ ! -f "${ROOT_DIR}/test/functional/feature_btx_matmul_consensus.py" ]]; then
    echo "error: missing functional script ${ROOT_DIR}/test/functional/feature_btx_matmul_consensus.py" >&2
    exit 1
  fi
fi

LOG_DIR="${BTX_PARALLEL_LOG_DIR:-${ROOT_DIR}/.btx-parallel-test-logs}"
mkdir -p "${LOG_DIR}"
PORT_SEED="${BTX_FUNCTIONAL_PORT_SEED:-$(( (RANDOM << 15) | RANDOM ))}"
FUNCTIONAL_TMPDIR="${BTX_FUNCTIONAL_TMPDIR:-${TMPDIR:-/tmp}/btx-functional-parallel-${PORT_SEED}}"
CONFIG_TEMPLATE=""
TMP_CONFIG=""
if [[ "${SKIP_DEFAULT_JOBS}" -eq 0 ]]; then
  TMP_CONFIG_BASE="$(mktemp -t btx-parallel-config.XXXXXX)"
  TMP_CONFIG="${TMP_CONFIG_BASE}.ini"
  mv "${TMP_CONFIG_BASE}" "${TMP_CONFIG}"
  BUILD_DIR_ABS="$(cd "${BUILD_DIR}" && pwd)"
  if [[ -f "${BUILD_DIR_ABS}/test/config.ini" ]]; then
    CONFIG_TEMPLATE="${BUILD_DIR_ABS}/test/config.ini"
  else
    CONFIG_TEMPLATE="${ROOT_DIR}/test/config.ini"
  fi
  sed \
    -e "s|^SRCDIR=.*$|SRCDIR=${ROOT_DIR}|" \
    -e "s|^BUILDDIR=.*$|BUILDDIR=${BUILD_DIR_ABS}|" \
    "${CONFIG_TEMPLATE}" > "${TMP_CONFIG}"
fi
SKIP_RECURSIVE_JOBS="${BTX_PARALLEL_SKIP_RECURSIVE_JOBS:-0}"

if ! [[ "${SKIP_RECURSIVE_JOBS}" =~ ^[01]$ ]]; then
  echo "error: BTX_PARALLEL_SKIP_RECURSIVE_JOBS must be 0 or 1" >&2
  exit 1
fi

lock_owner_is_running() {
  local owner_pid="$1"
  if [[ -z "${owner_pid}" ]]; then
    return 1
  fi
  if ! kill -0 "${owner_pid}" >/dev/null 2>&1; then
    return 1
  fi
  local owner_cmd
  owner_cmd="$(ps -p "${owner_pid}" -o command= 2>/dev/null || true)"
  [[ "${owner_cmd}" == *"scripts/test_btx_parallel.sh"* ]]
}

read_lock_owner_pid() {
  local owner_pid=""
  local retries=0
  while (( retries < 3 )); do
    if [[ -f "${LOCK_OWNER_PID_FILE}" ]]; then
      owner_pid="$(tr -dc '0-9' < "${LOCK_OWNER_PID_FILE}" || true)"
      if [[ -n "${owner_pid}" ]]; then
        printf '%s\n' "${owner_pid}"
        return 0
      fi
    fi
    sleep 0.1
    retries=$((retries + 1))
  done
  printf '\n'
}

acquire_lock() {
  if mkdir "${LOCK_DIR}" >/dev/null 2>&1; then
    printf '%s\n' "$$" > "${LOCK_OWNER_PID_FILE}"
    printf '%s\n' "$0" > "${LOCK_OWNER_CMD_FILE}"
    LOCK_ACQUIRED=1
    return 0
  fi

  local owner_pid
  owner_pid="$(read_lock_owner_pid)"
  if lock_owner_is_running "${owner_pid}"; then
    echo "error: another scripts/test_btx_parallel.sh invocation is already running (lock: ${LOCK_DIR}, pid: ${owner_pid})" >&2
    return 1
  fi

  echo "warning: removing stale parallel test lock at ${LOCK_DIR}" >&2
  rm -rf "${LOCK_DIR}"
  if ! mkdir "${LOCK_DIR}" >/dev/null 2>&1; then
    echo "error: unable to acquire lock after stale lock cleanup (lock: ${LOCK_DIR})" >&2
    return 1
  fi

  printf '%s\n' "$$" > "${LOCK_OWNER_PID_FILE}"
  printf '%s\n' "$0" > "${LOCK_OWNER_CMD_FILE}"
  LOCK_ACQUIRED=1
  return 0
}

if ! acquire_lock; then
  exit 1
fi

if [[ "${SKIP_DEFAULT_JOBS}" -eq 0 ]]; then
  rm -rf "${FUNCTIONAL_TMPDIR}"
fi

declare -a ACTIVE_PIDS=()
declare -a ACTIVE_NAMES=()
failures=0

job_pid_is_active() {
  local target_pid="$1"
  local job_pid
  while read -r job_pid; do
    if [[ -n "${job_pid}" && "${job_pid}" == "${target_pid}" ]]; then
      return 0
    fi
  done < <(jobs -pr || true)
  return 1
}

cleanup_parallel_jobs() {
  for pid in "${ACTIVE_PIDS[@]:-}"; do
    if job_pid_is_active "${pid}"; then
      kill "${pid}" >/dev/null 2>&1 || true
    fi
  done
  for pid in "${ACTIVE_PIDS[@]:-}"; do
    if job_pid_is_active "${pid}"; then
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ -n "${TMP_CONFIG}" ]]; then
    rm -f "${TMP_CONFIG}"
  fi
  if [[ "${LOCK_ACQUIRED}" -eq 1 ]]; then
    local owner_pid=""
    if [[ -f "${LOCK_OWNER_PID_FILE}" ]]; then
      owner_pid="$(tr -dc '0-9' < "${LOCK_OWNER_PID_FILE}" || true)"
    fi
    if [[ "${owner_pid}" == "$$" ]]; then
      rm -rf "${LOCK_DIR}"
    fi
  fi
}
trap cleanup_parallel_jobs EXIT INT TERM

run_with_timeout() {
  local timeout_seconds="$1"
  shift
  python3 - "$timeout_seconds" "$@" <<'PY'
import os
import signal
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

proc = subprocess.Popen(cmd, start_new_session=True)
try:
    rc = proc.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
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

run_with_clean_locale() {
  env LC_ALL=C LANG=C "$@"
}

reap_one_job() {
  if (( ${#ACTIVE_PIDS[@]} == 0 )); then
    return 0
  fi

  local done_pid="${ACTIVE_PIDS[0]}"
  local name="${ACTIVE_NAMES[0]}"
  local wait_rc=0
  set +e
  wait "${done_pid}"
  wait_rc=$?
  set -e

  if (( ${#ACTIVE_PIDS[@]} > 1 )); then
    ACTIVE_PIDS=("${ACTIVE_PIDS[@]:1}")
    ACTIVE_NAMES=("${ACTIVE_NAMES[@]:1}")
  else
    ACTIVE_PIDS=()
    ACTIVE_NAMES=()
  fi

  if (( wait_rc != 0 )); then
    ((failures += 1))
    echo "error: ${name} failed (see ${LOG_DIR}/${name}.log)" >&2
  fi
}

run_job() {
  local name="$1"
  shift
  while (( ${#ACTIVE_PIDS[@]} >= MAX_JOBS )); do
    reap_one_job
  done

  local logfile="${LOG_DIR}/${name}.log"
  (
    trap - EXIT INT TERM
    set -euo pipefail
    if [[ "${JOB_TIMEOUT_SECONDS}" -eq 0 ]]; then
      run_with_clean_locale "$@"
    else
      run_with_timeout "${JOB_TIMEOUT_SECONDS}" env LC_ALL=C LANG=C "$@"
    fi
  ) >"${logfile}" 2>&1 &
  ACTIVE_PIDS+=("$!")
  ACTIVE_NAMES+=("${name}")
}

if [[ "${SKIP_DEFAULT_JOBS}" -eq 1 ]]; then
  if [[ -z "${BTX_PARALLEL_TEST_COMMAND:-}" ]]; then
    echo "error: BTX_PARALLEL_TEST_COMMAND is required when BTX_PARALLEL_SKIP_DEFAULT_JOBS=1" >&2
    exit 1
  fi
  run_job "selftest" bash -lc "${BTX_PARALLEL_TEST_COMMAND}"
else
  run_job "pow_tests" "${BUILD_DIR}/bin/test_btx" --run_test=pow_tests --catch_system_error=no --log_level=test_suite
  run_job "matmul_tests" "${BUILD_DIR}/bin/test_btx" --run_test=matmul_* --catch_system_error=no --log_level=test_suite
  run_job "functional_consensus" \
    python3 "${ROOT_DIR}/test/functional/feature_btx_matmul_consensus.py" \
    --configfile="${TMP_CONFIG}" \
    --portseed="${PORT_SEED}" \
    --tmpdir="${FUNCTIONAL_TMPDIR}" \
    --timeout-factor=4
  run_job "m7_script_tests" python3 "${ROOT_DIR}/test/util/m7_miner_pool_e2e-test.py"
  run_job "m7_readiness_timeout_tests" "${ROOT_DIR}/test/util/m7_mining_readiness_timeout_test.sh"
  run_job "btx_naming_guard_tests" "${ROOT_DIR}/test/util/btx_naming_guard_test.sh"
  run_job "m8_pow_scaling_script_tests" "${ROOT_DIR}/test/util/m8_pow_scaling_suite_test.sh"
  run_job "m14_transition_script_tests" "${ROOT_DIR}/test/util/m14_fast_normal_transition_sim_test.sh"
  run_job "m9_benchmark_script_tests" "${ROOT_DIR}/test/util/m9_btx_benchmark_suite_test.sh"
  run_job "chain_hardening_manifest_tests" "${ROOT_DIR}/test/util/update_chain_hardening_manifest_test.sh"
  run_job "chain_hardening_apply_tests" "${ROOT_DIR}/test/util/apply_chain_hardening_manifest_test.sh"
  run_job "m15_single_node_lifecycle_tests" "${ROOT_DIR}/test/util/m15_single_node_wallet_lifecycle_test.sh"
  run_job "m15_lifecycle_matrix_tests" "${ROOT_DIR}/test/util/m15_full_lifecycle_matrix_test.sh"
  run_job "m15_docs_sync_tests" "${ROOT_DIR}/test/util/m15_docs_sync_test.sh"
  if [[ "${SKIP_RECURSIVE_JOBS}" -eq 0 ]]; then
    run_job "m10_checklist_script_tests" "${ROOT_DIR}/test/util/m10_validation_checklist_test.sh"
  fi
  run_job "m5_genesis_freeze_script_tests" "${ROOT_DIR}/test/util/m5_verify_genesis_freeze_test.sh"
  run_job "m11_metal_validation_tests" "${ROOT_DIR}/test/util/m11_metal_mining_validation_test.sh"
  run_job "m11_feedback_loop_tests" "${ROOT_DIR}/test/util/m11_codex_feedback_loop_test.sh"
  run_job "m11_multi_agent_tests" "${ROOT_DIR}/test/util/m11_multi_agent_continuous_4h_test.sh"
  run_job "launch_blocker_runner_tests" "${ROOT_DIR}/test/util/verify_btx_launch_blockers_test.sh"
  run_job "m8_pow_scaling_suite" "${ROOT_DIR}/scripts/m8_pow_scaling_suite.sh" --build-dir "${BUILD_DIR}" --artifact "${LOG_DIR}/pow-scaling-suite.json" --log-dir "${LOG_DIR}/pow-scaling-suite-logs"
  run_job "m5_swarm_tests" "${ROOT_DIR}/test/util/m5_genesis_search_swarm_test.sh"
  run_job "m7_parallel_readiness_tests" "${ROOT_DIR}/test/util/m7_parallel_readiness_test.sh"
  run_job "swarm_timeout_tests" "${ROOT_DIR}/test/util/codex_swarm_timeout_test.sh"
  run_job "parallel_timeout_guard_tests" bash "${ROOT_DIR}/test/util/test_btx_parallel_timeout_guard_test.sh"
  run_job "production_readiness_parallel_lock_isolation_tests" "${ROOT_DIR}/test/util/verify_btx_production_readiness_parallel_lock_isolation_test.sh"
  if [[ "${SKIP_RECURSIVE_JOBS}" -eq 0 ]]; then
    run_job "production_readiness_timeout_tests" "${ROOT_DIR}/test/util/verify_btx_production_readiness_timeout_guard_test.sh"
  fi
  run_job "production_loop_tests" "${ROOT_DIR}/test/util/verify_btx_production_loop_test.sh"
  if [[ "${SKIP_RECURSIVE_JOBS}" -eq 0 ]]; then
    run_job "production_readiness_tests" "${ROOT_DIR}/test/util/verify_btx_production_readiness_test.sh"
    run_job "validation_checklist_tests" "${ROOT_DIR}/test/util/generate_validation_checklist_test.sh"
  fi
fi

if (( ${#ACTIVE_PIDS[@]} == 0 )); then
  echo "error: no jobs were scheduled" >&2
  exit 1
fi

while (( ${#ACTIVE_PIDS[@]} > 0 )); do
  reap_one_job
done

if (( failures > 0 )); then
  exit 1
fi

echo "All parallel BTX tests passed. Logs: ${LOG_DIR}"
