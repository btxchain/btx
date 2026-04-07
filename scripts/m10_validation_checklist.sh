#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m10_validation_checklist.sh [options] [-- <verify-script-extra-args...>]

Generate a consolidated BTX validation checklist from production-readiness checks.
By default this script runs verify_btx_production_readiness.sh first.

Options:
  --build-dir <path>       Build directory to pass to verification (default: build-btx)
  --artifact-json <path>   Checklist JSON output path
  --checklist-md <path>    Checklist Markdown output path
  --verify-script <path>   Verification script path
  --verify-artifact <path> Verification script artifact path
  --verify-timeout-seconds <n>
                           Timeout for verification script run (default: 3600, 0 disables)
  --skip-run               Do not run verification; render checklist from --verify-artifact
  -h, --help               Show this message
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_JSON="${ROOT_DIR}/.btx-production-readiness/validation-checklist.json"
CHECKLIST_MD="${ROOT_DIR}/.btx-production-readiness/validation-checklist.md"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/verify_btx_production_readiness.sh"
VERIFY_ARTIFACT="${ROOT_DIR}/.btx-production-readiness/production-readiness-report.json"
VERIFY_LOG="${ROOT_DIR}/.btx-production-readiness/validation-checklist-verify.log"
VERIFY_TIMEOUT_SECONDS=3600
SKIP_RUN=0
FORWARD_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --artifact-json)
      ARTIFACT_JSON="$2"
      shift 2
      ;;
    --checklist-md)
      CHECKLIST_MD="$2"
      shift 2
      ;;
    --verify-script)
      VERIFY_SCRIPT="$2"
      shift 2
      ;;
    --verify-artifact)
      VERIFY_ARTIFACT="$2"
      shift 2
      ;;
    --verify-timeout-seconds)
      VERIFY_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --skip-run)
      SKIP_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      FORWARD_ARGS+=("$@")
      break
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "${VERIFY_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --verify-timeout-seconds must be a non-negative integer" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARTIFACT_JSON}")" "$(dirname "${CHECKLIST_MD}")" "$(dirname "${VERIFY_ARTIFACT}")"

verify_rc=0
if [[ "${SKIP_RUN}" -eq 0 ]]; then
  if [[ ! -x "${VERIFY_SCRIPT}" ]]; then
    echo "error: verify script not executable: ${VERIFY_SCRIPT}" >&2
    exit 1
  fi

  verify_cmd=(
    "${VERIFY_SCRIPT}"
    --build-dir "${BUILD_DIR}"
    --artifact "${VERIFY_ARTIFACT}"
  )
  if [[ "${#FORWARD_ARGS[@]}" -gt 0 ]]; then
    verify_cmd+=("${FORWARD_ARGS[@]}")
  fi

  set +e
  if [[ "${VERIFY_TIMEOUT_SECONDS}" -eq 0 ]]; then
    "${verify_cmd[@]}" >"${VERIFY_LOG}" 2>&1
    verify_rc=$?
  else
    python3 - "${VERIFY_TIMEOUT_SECONDS}" "${verify_cmd[@]}" >"${VERIFY_LOG}" 2>&1 <<'PY'
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
    verify_rc=$?
  fi
  set -e
fi

if [[ ! -f "${VERIFY_ARTIFACT}" ]]; then
  echo "error: verification artifact not found: ${VERIFY_ARTIFACT}" >&2
  if [[ "${SKIP_RUN}" -eq 0 && -f "${VERIFY_LOG}" ]]; then
    echo "verification log:" >&2
    cat "${VERIFY_LOG}" >&2
  fi
  exit 1
fi

python3 - <<'PY' "${VERIFY_ARTIFACT}" "${ARTIFACT_JSON}" "${CHECKLIST_MD}" "${verify_rc}"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

verify_artifact = Path(sys.argv[1])
artifact_json = Path(sys.argv[2])
checklist_md = Path(sys.argv[3])
verify_rc = int(sys.argv[4])

data = json.loads(verify_artifact.read_text(encoding="utf-8"))
checks = data.get("checks", [])
overall_status = "pass" if (data.get("overall_status") == "pass" and verify_rc == 0) else "fail"

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

summary = {
    "generated_at": generated_at,
    "overall_status": overall_status,
    "verify_exit_code": verify_rc,
    "verify_artifact": str(verify_artifact),
    "check_count": len(checks),
    "checks": checks,
}
artifact_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

lines = []
lines.append("# BTX Validation Checklist")
lines.append("")
lines.append(f"- Generated at: `{generated_at}`")
lines.append(f"- Overall status: `{overall_status}`")
lines.append(f"- Verification artifact: `{verify_artifact}`")
lines.append(f"- Verification exit code: `{verify_rc}`")
lines.append("")

if not checks:
    lines.append("- [ ] No checks were found in the verification artifact.")
else:
    for check in checks:
        status = check.get("status", "unknown")
        checked = "x" if status == "pass" else " "
        check_id = check.get("id", "unknown")
        description = check.get("description", "")
        seconds = check.get("seconds", "")
        log = check.get("log", "")
        lines.append(
            f"- [{checked}] `{check_id}` ({status}, {seconds}s): {description} - `{log}`"
        )

checklist_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "Validation checklist JSON: ${ARTIFACT_JSON}"
echo "Validation checklist Markdown: ${CHECKLIST_MD}"

if [[ "${verify_rc}" -ne 0 ]]; then
  echo "Verification command exited with ${verify_rc}" >&2
  exit "${verify_rc}"
fi

exit 0
