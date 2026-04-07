#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m19_reset_launch_rehearsal.sh [options]

Run the disposable shieldedv2dev reset-network launch rehearsal and write a
machine-readable artifact with logs and teardown evidence.

Options:
  --build-dir <path>        Build directory (default: build-btx)
  --artifact <path>         Top-level JSON artifact output path
                            (default: .btx-validation/m19-reset-launch-rehearsal.json)
  --log-dir <path>          Directory for per-check logs and inner artifacts
                            (default: .btx-validation/m19-reset-launch-logs)
  --config-file <path>      Functional test config.ini
                            (default: <build-dir>/test/config.ini if present,
                            else test/config.ini under repo root)
  --cachedir <path>         Functional test cache dir
                            (default: ${TMPDIR:-/tmp}/btx-functional-manual/cache)
  --timeout-seconds <n>     Per-check timeout in seconds (default: 2400, 0 disables)
  --portseed <n>            Base port seed (default: 34000)
  --help                    Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m19-reset-launch-rehearsal.json"
LOG_DIR="${ROOT_DIR}/.btx-validation/m19-reset-launch-logs"
CACHE_DIR="${TMPDIR:-/tmp}/btx-functional-manual/cache"
TIMEOUT_SECONDS=2400
PORTSEED=34000
CONFIG_FILE=""

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
    --config-file)
      CONFIG_FILE="$2"
      shift 2
      ;;
    --cachedir)
      CACHE_DIR="$2"
      shift 2
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --portseed)
      PORTSEED="$2"
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

if ! [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --timeout-seconds must be a non-negative integer" >&2
  exit 1
fi
if ! [[ "${PORTSEED}" =~ ^[0-9]+$ ]]; then
  echo "error: --portseed must be an integer" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARTIFACT_PATH}")" "${LOG_DIR}" "${CACHE_DIR}"

if [[ -z "${CONFIG_FILE}" ]]; then
  if [[ -f "${BUILD_DIR}/test/config.ini" ]]; then
    CONFIG_FILE="${BUILD_DIR}/test/config.ini"
  else
    CONFIG_FILE="${ROOT_DIR}/test/config.ini"
  fi
fi
if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "error: config file not found: ${CONFIG_FILE}" >&2
  exit 1
fi

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
  local check_id="$1"
  local tmpdir="$2"
  local log_path="$3"
  shift 3

  local started_at
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local start_epoch
  start_epoch="$(python3 - <<'PY'
import time
print(f"{time.time():.6f}")
PY
)"

  set +e
  run_with_timeout "${TIMEOUT_SECONDS}" "$@" >"${log_path}" 2>&1
  local rc=$?
  set -e

  local ended_at
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local end_epoch
  end_epoch="$(python3 - <<'PY'
import time
print(f"{time.time():.6f}")
PY
)"

  local pre_wrapper_absent
  if [[ ! -e "${tmpdir}" ]]; then
    pre_wrapper_absent=1
  else
    pre_wrapper_absent=0
  fi

  local wrapper_removed=0
  if [[ -e "${tmpdir}" ]]; then
    rm -rf "${tmpdir}"
    wrapper_removed=1
  fi

  local final_absent=0
  if [[ ! -e "${tmpdir}" ]]; then
    final_absent=1
  fi

  python3 - <<'PY' \
"${check_id}" "${log_path}" "${tmpdir}" "${started_at}" "${ended_at}" "${start_epoch}" "${end_epoch}" \
"${rc}" "${pre_wrapper_absent}" "${wrapper_removed}" "${final_absent}"
import json
import sys

check_id = sys.argv[1]
log_path = sys.argv[2]
tmpdir = sys.argv[3]
started_at = sys.argv[4]
ended_at = sys.argv[5]
start_epoch = float(sys.argv[6])
end_epoch = float(sys.argv[7])
rc = int(sys.argv[8])
pre_wrapper_absent = bool(int(sys.argv[9]))
wrapper_removed = bool(int(sys.argv[10]))
final_absent = bool(int(sys.argv[11]))

payload = {
    "id": check_id,
    "status": "pass" if rc == 0 else "fail",
    "exit_code": rc,
    "started_at": started_at,
    "ended_at": ended_at,
    "runtime_seconds": round(end_epoch - start_epoch, 3),
    "log": log_path,
    "tmpdir": tmpdir,
    "teardown": {
        "functional_cleanup_confirmed_before_wrapper": pre_wrapper_absent,
        "wrapper_removed_leftover_tmpdir": wrapper_removed,
        "final_tmpdir_absent": final_absent,
    },
}
print(json.dumps(payload))
PY
}

ISOLATION_TMPDIR="${TMPDIR:-/tmp}/btx-functional-manual/m19-shieldedv2dev-isolation"
REHEARSAL_TMPDIR="${TMPDIR:-/tmp}/btx-functional-manual/m19-shieldedv2dev-launch-rehearsal"
ISOLATION_LOG="${LOG_DIR}/feature_shieldedv2dev_datadir_isolation.log"
REHEARSAL_LOG="${LOG_DIR}/feature_shieldedv2dev_launch_rehearsal.log"
REHEARSAL_INNER_ARTIFACT="${LOG_DIR}/feature_shieldedv2dev_launch_rehearsal.artifact.json"

rm -rf "${ISOLATION_TMPDIR}" "${REHEARSAL_TMPDIR}"
rm -f "${REHEARSAL_INNER_ARTIFACT}"

ISOLATION_RESULT="$(
  run_check \
    "feature_shieldedv2dev_datadir_isolation" \
    "${ISOLATION_TMPDIR}" \
    "${ISOLATION_LOG}" \
    python3 "${ROOT_DIR}/test/functional/feature_shieldedv2dev_datadir_isolation.py" \
      --cachedir="${CACHE_DIR}" \
      --configfile="${CONFIG_FILE}" \
      --tmpdir="${ISOLATION_TMPDIR}" \
      --portseed="${PORTSEED}"
)"

REHEARSAL_RESULT="$(
  run_check \
    "feature_shieldedv2dev_launch_rehearsal" \
    "${REHEARSAL_TMPDIR}" \
    "${REHEARSAL_LOG}" \
    python3 "${ROOT_DIR}/test/functional/feature_shieldedv2dev_launch_rehearsal.py" \
      --cachedir="${CACHE_DIR}" \
      --configfile="${CONFIG_FILE}" \
      --tmpdir="${REHEARSAL_TMPDIR}" \
      --portseed="$((PORTSEED + 1))" \
      --artifact="${REHEARSAL_INNER_ARTIFACT}"
)"

python3 - <<'PY' "${ARTIFACT_PATH}" "${BUILD_DIR}" "${LOG_DIR}" "${CACHE_DIR}" "${TIMEOUT_SECONDS}" \
"${ISOLATION_RESULT}" "${REHEARSAL_RESULT}" "${REHEARSAL_INNER_ARTIFACT}"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_path = Path(sys.argv[1])
build_dir = sys.argv[2]
log_dir = sys.argv[3]
cache_dir = sys.argv[4]
timeout_seconds = int(sys.argv[5])
checks = [json.loads(sys.argv[6]), json.loads(sys.argv[7])]
inner_artifact_path = Path(sys.argv[8])

inner_artifact = None
if inner_artifact_path.exists():
    inner_artifact = json.loads(inner_artifact_path.read_text(encoding="utf-8"))

overall_status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
payload = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": overall_status,
    "build_dir": build_dir,
    "log_dir": log_dir,
    "cache_dir": cache_dir,
    "timeout_seconds": timeout_seconds,
    "resources": {
        "cloud_resources": [],
        "cost_usd": 0,
    },
    "checks": checks,
    "launch_rehearsal": inner_artifact,
    "teardown_confirmed": all(check["teardown"]["final_tmpdir_absent"] for check in checks),
}
artifact_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

if [[ "$(python3 - <<'PY' "${ARTIFACT_PATH}"
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(payload["overall_status"])
PY
)" != "pass" ]]; then
  exit 1
fi

echo "Reset launch rehearsal artifact: ${ARTIFACT_PATH}"
