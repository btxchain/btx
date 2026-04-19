#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m15_full_lifecycle_matrix.sh [options]

Run the final lifecycle matrix with no skipped lifecycle phases:
1) macOS host single-node lifecycle
2) CentOS container single-node lifecycle
3) macOS <-> CentOS bridge lifecycle

Options:
  --build-dir <path>         macOS build directory (default: build-btx)
  --centos-build-dir <path>  CentOS build directory under repo root (default: build-btx-centos)
  --artifact <path>          Output JSON artifact path
                             (default: .btx-validation/m15-full-lifecycle-matrix.json)
  --log-dir <path>           Per-check log directory
                             (default: .btx-validation/m15-full-lifecycle-logs)
  --timeout-seconds <n>      Per-check timeout seconds (default: 1200)
  --skip-centos-build        Reuse existing CentOS build instead of rebuilding
  --help                     Show this message

Environment overrides:
  BTX_M15_CONTAINER_IMAGE       Docker image for CentOS check (default: quay.io/centos/centos:stream10)
  BTX_M15_CONTAINER_PLATFORM    Docker --platform override (optional)
  BTX_M15_OVERRIDE_MAC_HOST_LIFECYCLE
  BTX_M15_OVERRIDE_CENTOS_CONTAINER_LIFECYCLE
  BTX_M15_OVERRIDE_MAC_CENTOS_BRIDGE_LIFECYCLE
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
CENTOS_BUILD_DIR="${ROOT_DIR}/build-btx-centos"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m15-full-lifecycle-matrix.json"
LOG_ROOT="${ROOT_DIR}/.btx-validation/m15-full-lifecycle-logs"
TIMEOUT_SECONDS=1200
SKIP_CENTOS_BUILD=0

CONTAINER_IMAGE="${BTX_M15_CONTAINER_IMAGE:-quay.io/centos/centos:stream10}"
CONTAINER_PLATFORM="${BTX_M15_CONTAINER_PLATFORM:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --centos-build-dir)
      CENTOS_BUILD_DIR="$2"
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
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --skip-centos-build)
      SKIP_CENTOS_BUILD=1
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

if ! [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "error: --timeout-seconds must be a positive integer" >&2
  exit 1
fi

if [[ ! "${BUILD_DIR}" = /* ]]; then
  BUILD_DIR="${ROOT_DIR}/${BUILD_DIR}"
fi
if [[ ! "${CENTOS_BUILD_DIR}" = /* ]]; then
  CENTOS_BUILD_DIR="${ROOT_DIR}/${CENTOS_BUILD_DIR}"
fi
if [[ ! "${ARTIFACT_PATH}" = /* ]]; then
  ARTIFACT_PATH="${ROOT_DIR}/${ARTIFACT_PATH}"
fi
if [[ ! "${LOG_ROOT}" = /* ]]; then
  LOG_ROOT="${ROOT_DIR}/${LOG_ROOT}"
fi

mkdir -p "$(dirname "${ARTIFACT_PATH}")" "${LOG_ROOT}"

RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/btx-m15-matrix-results.XXXXXX")"
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
  local override_var="BTX_M15_OVERRIDE_${upper_id//-/_}"
  local override_value="${!override_var:-}"
  if [[ -n "${override_value}" ]]; then
    cmd=(bash -lc "${override_value}")
  fi

  local start_ts end_ts seconds
  start_ts="$(date +%s)"
  local run_ok=0
  if declare -F "${cmd[0]}" >/dev/null 2>&1; then
    if LC_ALL=C LANG=C "${cmd[@]}" >"${logfile}" 2>&1; then
      run_ok=1
    fi
  else
    if run_with_timeout "${TIMEOUT_SECONDS}" env LC_ALL=C LANG=C "${cmd[@]}" >"${logfile}" 2>&1; then
      run_ok=1
    fi
  fi

  if [[ "${run_ok}" -eq 1 ]]; then
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

check_prerequisites() {
  if [[ ! -x "${BUILD_DIR}/bin/btxd" || ! -x "${BUILD_DIR}/bin/btx-cli" ]]; then
    [[ -x "${BUILD_DIR}/bin/btxd" ]]
    [[ -x "${BUILD_DIR}/bin/btx-cli" ]]
  fi
  [[ -x "${ROOT_DIR}/scripts/m15_single_node_wallet_lifecycle.sh" ]]
  [[ -x "${ROOT_DIR}/scripts/m13_mac_centos_interop_readiness.sh" ]]
  command -v docker >/dev/null 2>&1
  docker info >/dev/null 2>&1
}

run_centos_container_lifecycle() {
  local root_real centos_real centos_rel artifact_path artifact_rel
  root_real="$(python3 - "$ROOT_DIR" <<'PY'
import os,sys
print(os.path.realpath(sys.argv[1]))
PY
)"
  centos_real="$(python3 - "$CENTOS_BUILD_DIR" <<'PY'
import os,sys
print(os.path.realpath(sys.argv[1]))
PY
)"
  if [[ "${centos_real}" != "${root_real}"* ]]; then
    echo "error: --centos-build-dir must be under repository root (${root_real})" >&2
    return 1
  fi
  centos_rel="${centos_real#"${root_real}"/}"

  artifact_path="${ROOT_DIR}/.btx-validation/m15-centos-container-single-node-artifact.json"
  mkdir -p "$(dirname "${artifact_path}")"
  artifact_rel="${artifact_path#"${ROOT_DIR}"/}"

  local -a platform_args=()
  if [[ -n "${CONTAINER_PLATFORM}" ]]; then
    platform_args=(--platform "${CONTAINER_PLATFORM}")
  fi

  if [[ "${SKIP_CENTOS_BUILD}" -ne 1 ]]; then
    docker run --rm "${platform_args[@]}" \
      -v "${root_real}:/workspace" \
      -w /workspace \
      "${CONTAINER_IMAGE}" \
      bash -lc '
        set -euo pipefail
        dnf -y install gcc-c++ glibc-devel libstdc++-devel make git python3 which patch xz procps-ng rsync bison e2fsprogs cmake sqlite-devel libevent-devel boost-devel >/tmp/m15-centos-build-dnf.log
        scripts/build_btx.sh "'"${centos_rel}"'" -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DWITH_ZMQ=OFF
      '
  fi

  docker run --rm "${platform_args[@]}" \
    -v "${root_real}:/workspace" \
    -w /workspace \
    "${CONTAINER_IMAGE}" \
    bash -lc '
      set -euo pipefail
      dnf -y install libevent python3 >/tmp/m15-centos-runtime-dnf.log
      scripts/m15_single_node_wallet_lifecycle.sh \
        --build-dir "/workspace/'"${centos_rel}"'" \
        --artifact "/workspace/'"${artifact_rel}"'" \
        --node-label "centos-container" \
        --timeout-seconds "'"${TIMEOUT_SECONDS}"'"
    '
}

run_mac_centos_bridge_lifecycle() {
  if [[ "${SKIP_CENTOS_BUILD}" -eq 1 ]]; then
    "${ROOT_DIR}/scripts/m13_mac_centos_interop_readiness.sh" \
      --mac-build-dir "${BUILD_DIR}" \
      --centos-build-dir "${CENTOS_BUILD_DIR}" \
      --artifact "${LOG_ROOT}/mac-centos-bridge-artifact.json" \
      --timeout-seconds "${TIMEOUT_SECONDS}" \
      --skip-centos-build
  else
    "${ROOT_DIR}/scripts/m13_mac_centos_interop_readiness.sh" \
      --mac-build-dir "${BUILD_DIR}" \
      --centos-build-dir "${CENTOS_BUILD_DIR}" \
      --artifact "${LOG_ROOT}/mac-centos-bridge-artifact.json" \
      --timeout-seconds "${TIMEOUT_SECONDS}"
  fi
}

check_prerequisites

run_check "mac_host_lifecycle" "macOS host lifecycle: startup/wallet/mining/verify/send/receive/locking" \
  "${ROOT_DIR}/scripts/m15_single_node_wallet_lifecycle.sh" \
  --build-dir "${BUILD_DIR}" \
  --artifact "${LOG_ROOT}/mac-host-single-node-artifact.json" \
  --node-label "mac-host" \
  --timeout-seconds "${TIMEOUT_SECONDS}"

run_check "centos_container_lifecycle" "CentOS container lifecycle: startup/wallet/mining/verify/send/receive/locking" \
  run_centos_container_lifecycle

run_check "mac_centos_bridge_lifecycle" "macOS<->CentOS bridge lifecycle with bi-directional transfer consensus" \
  run_mac_centos_bridge_lifecycle

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
overall_status="pass"
if [[ "${overall_fail}" -ne 0 ]]; then
  overall_status="fail"
fi

{
  echo "{"
  echo "  \"generated_at\": \"${generated_at}\","
  echo "  \"overall_status\": \"${overall_status}\","
  echo "  \"container_image\": \"$(json_escape "${CONTAINER_IMAGE}")\","
  echo "  \"skipped_phases\": [],"
  echo "  \"phase_coverage\": {"
  first=1
  while IFS='|' read -r id status _seconds _description _logfile; do
    if [[ "${first}" -eq 0 ]]; then
      echo ","
    fi
    first=0
    echo -n "    \"$(json_escape "${id}")\": \"$(json_escape "${status}")\""
  done < "${RESULTS_FILE}"
  echo
  echo "  },"
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

echo "M15 lifecycle matrix artifact: ${ARTIFACT_PATH}"
echo "Overall status: ${overall_status}"

if [[ "${overall_fail}" -ne 0 ]]; then
  exit 1
fi

exit 0
