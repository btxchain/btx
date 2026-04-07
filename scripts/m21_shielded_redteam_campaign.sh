#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m21_shielded_redteam_campaign.sh [options]

Run the shielded_v2 malformed-proof red-team campaign on a temporary local
multi-node regtest and write a machine-readable artifact bundle.

Options:
  --build-dir <path>        Build directory (default: build-btx)
  --artifact <path>         Top-level JSON artifact output path
                            (default: .btx-validation/m21-shielded-redteam-campaign.json)
  --log-dir <path>          Directory for logs and inner artifacts
                            (default: .btx-validation/m21-shielded-redteam-logs)
  --config-file <path>      Functional test config.ini
                            (default: <build-dir>/test/config.ini if present,
                            else test/config.ini under repo root)
  --skip-build              Reuse existing binaries without running cmake --build
  --cachedir <path>         Functional test cache dir
                            (default: ${TMPDIR:-/tmp}/btx-functional-manual/cache)
  --timeout-seconds <n>     Per-step timeout in seconds (default: 2400, 0 disables)
  --portseed <n>            Base port seed (default: 35000)
  --help                    Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m21-shielded-redteam-campaign.json"
LOG_DIR="${ROOT_DIR}/.btx-validation/m21-shielded-redteam-logs"
CACHE_DIR="${TMPDIR:-/tmp}/btx-functional-manual/cache"
TIMEOUT_SECONDS=2400
PORTSEED=35000
SKIP_BUILD=0
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
    --skip-build)
      SKIP_BUILD=1
      shift
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

mkdir -p "$(dirname "${ARTIFACT_PATH}")" "${LOG_DIR}" "${CACHE_DIR}"

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

run_step() {
  local step_id="$1"
  local log_path="$2"
  shift 2

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

  python3 - <<'PY' \
"${step_id}" "${log_path}" "${started_at}" "${ended_at}" "${start_epoch}" "${end_epoch}" "${rc}"
import json
import sys

payload = {
    "id": sys.argv[1],
    "status": "pass" if int(sys.argv[7]) == 0 else "fail",
    "exit_code": int(sys.argv[7]),
    "started_at": sys.argv[3],
    "ended_at": sys.argv[4],
    "runtime_seconds": round(float(sys.argv[6]) - float(sys.argv[5]), 3),
    "log": sys.argv[2],
}
print(json.dumps(payload))
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

  local pre_wrapper_absent=0
  if [[ ! -e "${tmpdir}" ]]; then
    pre_wrapper_absent=1
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

payload = {
    "id": sys.argv[1],
    "status": "pass" if int(sys.argv[8]) == 0 else "fail",
    "exit_code": int(sys.argv[8]),
    "started_at": sys.argv[4],
    "ended_at": sys.argv[5],
    "runtime_seconds": round(float(sys.argv[7]) - float(sys.argv[6]), 3),
    "log": sys.argv[2],
    "tmpdir": sys.argv[3],
    "teardown": {
        "functional_cleanup_confirmed_before_wrapper": bool(int(sys.argv[9])),
        "wrapper_removed_leftover_tmpdir": bool(int(sys.argv[10])),
        "final_tmpdir_absent": bool(int(sys.argv[11])),
    },
}
print(json.dumps(payload))
PY
}

BUILD_LOG="${LOG_DIR}/build.log"
REDTEAM_TMPDIR="${TMPDIR:-/tmp}/btx-functional-manual/m21-shielded-redteam-campaign"
REDTEAM_LOG="${LOG_DIR}/feature_shielded_v2_proof_redteam_campaign.log"
REDTEAM_INNER_ARTIFACT="${LOG_DIR}/feature_shielded_v2_proof_redteam_campaign.artifact.json"
CORPUS_PATH="${LOG_DIR}/feature_shielded_v2_proof_redteam_campaign.corpus.json"

rm -rf "${REDTEAM_TMPDIR}"
rm -f "${REDTEAM_INNER_ARTIFACT}" "${CORPUS_PATH}"

if [[ "${SKIP_BUILD}" -eq 1 ]]; then
  BUILD_RESULT="$(
    python3 - <<'PY' "${BUILD_LOG}"
import json
import sys
from datetime import datetime, timezone

timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({
    "id": "build",
    "status": "skip",
    "exit_code": 0,
    "started_at": timestamp,
    "ended_at": timestamp,
    "runtime_seconds": 0.0,
    "log": sys.argv[1],
}))
PY
  )"
  : > "${BUILD_LOG}"
else
  BUILD_RESULT="$(
    run_step \
      "build" \
      "${BUILD_LOG}" \
      cmake --build "${BUILD_DIR}" --target btxd test_btx generate_shielded_v2_adversarial_proof_corpus -j8
  )"
fi

REDTEAM_RESULT="$(
  run_check \
    "feature_shielded_v2_proof_redteam_campaign" \
    "${REDTEAM_TMPDIR}" \
    "${REDTEAM_LOG}" \
    python3 "${ROOT_DIR}/test/functional/feature_shielded_v2_proof_redteam_campaign.py" \
      --cachedir="${CACHE_DIR}" \
      --configfile="${CONFIG_FILE}" \
      --tmpdir="${REDTEAM_TMPDIR}" \
      --portseed="${PORTSEED}" \
      --artifact="${REDTEAM_INNER_ARTIFACT}" \
      --corpus="${CORPUS_PATH}"
)"

python3 - <<'PY' \
"${ARTIFACT_PATH}" "${BUILD_DIR}" "${LOG_DIR}" "${CACHE_DIR}" "${TIMEOUT_SECONDS}" \
"${BUILD_RESULT}" "${REDTEAM_RESULT}" "${REDTEAM_INNER_ARTIFACT}" "${CORPUS_PATH}"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_path = Path(sys.argv[1])
build_dir = sys.argv[2]
log_dir = sys.argv[3]
cache_dir = sys.argv[4]
timeout_seconds = int(sys.argv[5])
build = json.loads(sys.argv[6])
redteam = json.loads(sys.argv[7])
inner_artifact_path = Path(sys.argv[8])
corpus_path = Path(sys.argv[9])

inner_artifact = None
if inner_artifact_path.exists():
    inner_artifact = json.loads(inner_artifact_path.read_text(encoding="utf-8"))

payload = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": "pass" if build["status"] in {"pass", "skip"} and redteam["status"] == "pass" else "fail",
    "build_dir": build_dir,
    "log_dir": log_dir,
    "cache_dir": cache_dir,
    "timeout_seconds": timeout_seconds,
    "steps": [build, redteam],
    "campaign_artifact": inner_artifact,
    "corpus_path": str(corpus_path),
    "teardown_confirmed": redteam["teardown"]["final_tmpdir_absent"],
}

artifact_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

if payload["overall_status"] != "pass":
    raise SystemExit(1)
PY

echo "Shielded red-team campaign artifact: ${ARTIFACT_PATH}"
