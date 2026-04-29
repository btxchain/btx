#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m11_codex_feedback_loop.sh [options]

Run repeated mining validation cycles and optionally invoke Codex to fix issues
based on failed cycle output.

Options:
  --repo <path>                 Repository root (default: git root)
  --build-dir <path>            Build dir (default: build-btx under repo)
  --cycles <n>                  Number of validation cycles (default: 3)
  --delay-seconds <n>           Delay between cycles (default: 5)
  --validation-cmd <cmd>        Validation command to run each cycle
  --codex-bin <path>            Codex binary (default: codex)
  --codex-timeout-seconds <n>   Timeout for codex runs (default: 900, 0 disables)
  --artifact-dir <path>         Directory for logs/artifacts
  --codex-on-pass               Also run Codex optimization pass when validation succeeds
  --codex-cmd <cmd>             Explicit command used instead of 'codex exec ...'
  -h, --help                    Show this message
USAGE
}

REPO_ROOT=""
BUILD_DIR=""
CYCLES=3
DELAY_SECONDS=5
VALIDATION_CMD=""
CODEX_BIN="${CODEX_BIN:-codex}"
CODEX_TIMEOUT_SECONDS=900
ARTIFACT_DIR=""
CODEX_ON_PASS=0
CODEX_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_ROOT="$2"
      shift 2
      ;;
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --cycles)
      CYCLES="$2"
      shift 2
      ;;
    --delay-seconds)
      DELAY_SECONDS="$2"
      shift 2
      ;;
    --validation-cmd)
      VALIDATION_CMD="$2"
      shift 2
      ;;
    --codex-bin)
      CODEX_BIN="$2"
      shift 2
      ;;
    --codex-timeout-seconds)
      CODEX_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --codex-on-pass)
      CODEX_ON_PASS=1
      shift
      ;;
    --codex-cmd)
      CODEX_CMD="$2"
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

if [[ -z "${REPO_ROOT}" ]]; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
fi

if [[ -z "${BUILD_DIR}" ]]; then
  BUILD_DIR="${REPO_ROOT}/build-btx"
fi

if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="${REPO_ROOT}/.btx-metal/m11-feedback-loop"
fi

if [[ -z "${VALIDATION_CMD}" ]]; then
  VALIDATION_CMD="${REPO_ROOT}/scripts/m11_metal_mining_validation.sh --build-dir ${BUILD_DIR} --rounds 2 --artifact ${ARTIFACT_DIR}/validation-last.json"
fi

for n in "${CYCLES}" "${DELAY_SECONDS}" "${CODEX_TIMEOUT_SECONDS}"; do
  if ! [[ "${n}" =~ ^[0-9]+$ ]]; then
    echo "error: cycles, delay, and timeout must be non-negative integers" >&2
    exit 1
  fi
done
if [[ "${CYCLES}" -lt 1 ]]; then
  echo "error: cycles must be >= 1" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}"

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

run_codex_action() {
  local cycle="$1"
  local status="$2"
  local validation_log="$3"
  local codex_log="$4"

  if [[ -n "${CODEX_CMD}" ]]; then
    set +e
    run_with_timeout "${CODEX_TIMEOUT_SECONDS}" bash -lc "${CODEX_CMD}" >"${codex_log}" 2>&1
    local rc=$?
    set -e
    return "${rc}"
  fi

  if ! command -v "${CODEX_BIN}" >/dev/null 2>&1; then
    echo "codex binary not found: ${CODEX_BIN}" >"${codex_log}"
    return 127
  fi

  local prompt
  prompt="Cycle ${cycle} mining validation status: ${status}. Analyze ${validation_log} and apply minimal fixes that improve mining stability and keep consensus behavior unchanged. Run relevant tests and summarize changes."

  set +e
  run_with_timeout "${CODEX_TIMEOUT_SECONDS}" \
    "${CODEX_BIN}" exec \
      -c 'model_reasoning_effort="high"' \
      --dangerously-bypass-approvals-and-sandbox \
      --cd "${REPO_ROOT}" \
      "${prompt}" >"${codex_log}" 2>&1
  local rc=$?
  set -e
  return "${rc}"
}

overall_status="pass"
for cycle in $(seq 1 "${CYCLES}"); do
  validation_log="${ARTIFACT_DIR}/cycle-${cycle}-validation.log"
  codex_log="${ARTIFACT_DIR}/cycle-${cycle}-codex.log"

  set +e
  bash -lc "${VALIDATION_CMD}" >"${validation_log}" 2>&1
  validation_rc=$?
  set -e

  if [[ "${validation_rc}" -eq 0 ]]; then
    echo "cycle ${cycle}: validation pass"
    if [[ "${CODEX_ON_PASS}" -eq 1 ]]; then
      if ! run_codex_action "${cycle}" "pass" "${validation_log}" "${codex_log}"; then
        overall_status="fail"
      fi
    fi
  else
    overall_status="fail"
    echo "cycle ${cycle}: validation failed, invoking codex remediation"
    if ! run_codex_action "${cycle}" "fail" "${validation_log}" "${codex_log}"; then
      echo "cycle ${cycle}: codex remediation failed" >&2
    fi
  fi

  if [[ "${cycle}" -lt "${CYCLES}" && "${DELAY_SECONDS}" -gt 0 ]]; then
    sleep "${DELAY_SECONDS}"
  fi
done

summary_json="${ARTIFACT_DIR}/summary.json"
python3 - <<'PY' "${summary_json}" "${overall_status}" "${CYCLES}" "${ARTIFACT_DIR}"
import json
import pathlib
import sys
from datetime import datetime, timezone

summary_path = pathlib.Path(sys.argv[1])
overall_status = sys.argv[2]
cycles = int(sys.argv[3])
artifact_dir = pathlib.Path(sys.argv[4])

entries = []
for cycle in range(1, cycles + 1):
    entries.append(
        {
            "cycle": cycle,
            "validation_log": str(artifact_dir / f"cycle-{cycle}-validation.log"),
            "codex_log": str(artifact_dir / f"cycle-{cycle}-codex.log"),
        }
    )

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "overall_status": overall_status,
    "cycles": entries,
}
summary_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"summary: {summary_path}")
print(f"overall_status: {overall_status}")
PY

if [[ "${overall_status}" != "pass" ]]; then
  exit 1
fi
