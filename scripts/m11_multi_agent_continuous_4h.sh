#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m11_multi_agent_continuous_4h.sh [options]

Run a multi-agent continuous workflow for up to 4 hours (default), repeatedly:
1) Spawning Codex swarm rounds.
2) Running metal/standard mining validation rounds.
3) Running a Codex feedback loop for mining fixes.

Options:
  --repo <path>                  Repository root (default: git root)
  --build-dir <path>             Build directory (default: build-btx)
  --duration-seconds <n>         Total runtime window (default: 14400)
  --round-delay-seconds <n>      Delay between rounds (default: 30)
  --max-agents <n>               Max agents per swarm round (default: 3)
  --agent-timeout-seconds <n>    Swarm worker timeout (default: 1800)
  --tasks-file <path>            Swarm task file (default: scripts/codex_swarm_tasks_metal.txt)
  --test-cmd <cmd>               Swarm gate command (default: scripts/test_btx_parallel.sh build-btx)
  --artifact-dir <path>          Output directory for logs and summary
  --swarm-cmd <cmd>              Override swarm command (for testing/custom runners)
  --validation-cmd <cmd>         Override mining validation command
  --feedback-cmd <cmd>           Override codex feedback loop command
  -h, --help                     Show this message
USAGE
}

REPO_ROOT=""
BUILD_DIR=""
DURATION_SECONDS=14400
ROUND_DELAY_SECONDS=30
MAX_AGENTS=3
AGENT_TIMEOUT_SECONDS=1800
TASKS_FILE=""
TEST_CMD=""
ARTIFACT_DIR=""
SWARM_CMD_OVERRIDE=""
VALIDATION_CMD_OVERRIDE=""
FEEDBACK_CMD_OVERRIDE=""

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
    --duration-seconds)
      DURATION_SECONDS="$2"
      shift 2
      ;;
    --round-delay-seconds)
      ROUND_DELAY_SECONDS="$2"
      shift 2
      ;;
    --max-agents)
      MAX_AGENTS="$2"
      shift 2
      ;;
    --agent-timeout-seconds)
      AGENT_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --tasks-file)
      TASKS_FILE="$2"
      shift 2
      ;;
    --test-cmd)
      TEST_CMD="$2"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --swarm-cmd)
      SWARM_CMD_OVERRIDE="$2"
      shift 2
      ;;
    --validation-cmd)
      VALIDATION_CMD_OVERRIDE="$2"
      shift 2
      ;;
    --feedback-cmd)
      FEEDBACK_CMD_OVERRIDE="$2"
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
if [[ -z "${TASKS_FILE}" ]]; then
  TASKS_FILE="${REPO_ROOT}/scripts/codex_swarm_tasks_metal.txt"
fi
if [[ -z "${TEST_CMD}" ]]; then
  TEST_CMD="scripts/test_btx_parallel.sh ${BUILD_DIR}"
fi
if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="${REPO_ROOT}/.btx-metal/m11-multi-agent"
fi

for n in "${DURATION_SECONDS}" "${ROUND_DELAY_SECONDS}" "${MAX_AGENTS}" "${AGENT_TIMEOUT_SECONDS}"; do
  if ! [[ "${n}" =~ ^[0-9]+$ ]]; then
    echo "error: duration, delays, and counts must be non-negative integers" >&2
    exit 1
  fi
done
if [[ "${DURATION_SECONDS}" -lt 1 ]]; then
  echo "error: duration-seconds must be >= 1" >&2
  exit 1
fi
if [[ "${MAX_AGENTS}" -lt 1 ]]; then
  echo "error: max-agents must be >= 1" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}"
start_epoch="$(date +%s)"
end_epoch=$((start_epoch + DURATION_SECONDS))
round=0
overall_status="pass"

while [[ "$(date +%s)" -lt "${end_epoch}" ]]; do
  round=$((round + 1))
  round_dir="${ARTIFACT_DIR}/round-$(printf '%03d' "${round}")"
  mkdir -p "${round_dir}"

  swarm_log="${round_dir}/swarm.log"
  validation_log="${round_dir}/validation.log"
  feedback_log="${round_dir}/feedback.log"

  if [[ -n "${SWARM_CMD_OVERRIDE}" ]]; then
    swarm_cmd="${SWARM_CMD_OVERRIDE}"
  else
    swarm_cmd="${REPO_ROOT}/scripts/codex_swarm.sh --repo ${REPO_ROOT} --tasks-file ${TASKS_FILE} --max-agents ${MAX_AGENTS} --agent-timeout-seconds ${AGENT_TIMEOUT_SECONDS} --test-cmd \"${TEST_CMD}\""
  fi

  if [[ -n "${VALIDATION_CMD_OVERRIDE}" ]]; then
    validation_cmd="${VALIDATION_CMD_OVERRIDE}"
  else
    validation_cmd="${REPO_ROOT}/scripts/m11_metal_mining_validation.sh --build-dir ${BUILD_DIR} --rounds 2 --artifact ${round_dir}/m11-validation.json"
  fi

  if [[ -n "${FEEDBACK_CMD_OVERRIDE}" ]]; then
    feedback_cmd="${FEEDBACK_CMD_OVERRIDE}"
  else
    feedback_cmd="${REPO_ROOT}/scripts/m11_codex_feedback_loop.sh --repo ${REPO_ROOT} --build-dir ${BUILD_DIR} --cycles 1 --artifact-dir ${round_dir}/feedback"
  fi

  set +e
  bash -lc "${swarm_cmd}" >"${swarm_log}" 2>&1
  swarm_rc=$?
  bash -lc "${validation_cmd}" >"${validation_log}" 2>&1
  validation_rc=$?
  bash -lc "${feedback_cmd}" >"${feedback_log}" 2>&1
  feedback_rc=$?
  set -e

  if [[ "${swarm_rc}" -ne 0 || "${validation_rc}" -ne 0 || "${feedback_rc}" -ne 0 ]]; then
    overall_status="fail"
  fi

  cat > "${round_dir}/round.json" <<JSON
{
  "round": ${round},
  "swarm_rc": ${swarm_rc},
  "validation_rc": ${validation_rc},
  "feedback_rc": ${feedback_rc},
  "swarm_log": "${swarm_log}",
  "validation_log": "${validation_log}",
  "feedback_log": "${feedback_log}"
}
JSON

  if [[ "$(date +%s)" -ge "${end_epoch}" ]]; then
    break
  fi
  if [[ "${ROUND_DELAY_SECONDS}" -gt 0 ]]; then
    sleep "${ROUND_DELAY_SECONDS}"
  fi
done

python3 - <<'PY' "${ARTIFACT_DIR}" "${overall_status}"
import json
import pathlib
import sys
from datetime import datetime, timezone

artifact_dir = pathlib.Path(sys.argv[1])
overall_status = sys.argv[2]
rounds = []
for path in sorted(artifact_dir.glob("round-*/round.json")):
    rounds.append(json.loads(path.read_text(encoding="utf-8")))
summary = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "overall_status": overall_status,
    "round_count": len(rounds),
    "rounds": rounds,
}
summary_path = artifact_dir / "summary.json"
summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(f"summary: {summary_path}")
print(f"overall_status: {overall_status}")
PY

if [[ "${overall_status}" != "pass" ]]; then
  exit 1
fi
