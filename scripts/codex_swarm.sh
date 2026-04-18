#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/codex_swarm.sh [options]

Runs multiple Codex agents in parallel worktrees and loops until the configured
test gate passes.

Options:
  --tasks-file <path>      Task list file (default: scripts/codex_swarm_tasks.txt)
  --repo <path>            Repository root (default: current git root)
  --max-agents <n>         Max concurrent agents (default: 3)
  --agent-timeout-seconds <n>
                           Max runtime per Codex worker (default: 600, 0 disables timeout)
  --test-cmd <cmd>         Command to validate the repo after each swarm round
                           (default: scripts/test_btx_parallel.sh build-btx)
  --continuous             Keep spawning new rounds until test-cmd passes
  --delay-seconds <n>      Delay between continuous rounds (default: 15)
  --codex-bin <path>       Codex binary path (default: codex in PATH)
  --dry-run                Print actions without executing Codex
  -h, --help               Show this message

Task file format:
  One task per line, using: task_id|prompt
  Lines beginning with # are ignored.
EOF
}

ROOT_REPO=""
TASKS_FILE=""
MAX_AGENTS=3
AGENT_TIMEOUT_SECONDS=600
TEST_CMD="scripts/test_btx_parallel.sh build-btx"
CONTINUOUS=0
DELAY_SECONDS=15
CODEX_BIN="${CODEX_BIN:-codex}"
DRY_RUN=0
SWARM_TASK_IDS=()
SWARM_TASK_PROMPTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tasks-file)
      TASKS_FILE="$2"
      shift 2
      ;;
    --repo)
      ROOT_REPO="$2"
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
    --test-cmd)
      TEST_CMD="$2"
      shift 2
      ;;
    --continuous)
      CONTINUOUS=1
      shift
      ;;
    --delay-seconds)
      DELAY_SECONDS="$2"
      shift 2
      ;;
    --codex-bin)
      CODEX_BIN="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
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

if [[ -z "${ROOT_REPO}" ]]; then
  ROOT_REPO="$(git rev-parse --show-toplevel)"
fi

if [[ -z "${TASKS_FILE}" ]]; then
  TASKS_FILE="${ROOT_REPO}/scripts/codex_swarm_tasks.txt"
fi

if [[ ! -f "${TASKS_FILE}" ]]; then
  echo "error: task file not found: ${TASKS_FILE}" >&2
  exit 1
fi

if ! [[ "${MAX_AGENTS}" =~ ^[0-9]+$ ]] || [[ "${MAX_AGENTS}" -lt 1 ]]; then
  echo "error: --max-agents must be a positive integer" >&2
  exit 1
fi

if ! [[ "${AGENT_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --agent-timeout-seconds must be a non-negative integer" >&2
  exit 1
fi

if ! [[ "${DELAY_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --delay-seconds must be a non-negative integer" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 0 ]] && ! command -v "${CODEX_BIN}" >/dev/null 2>&1; then
  echo "error: codex binary not found: ${CODEX_BIN}" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 0 ]]; then
  if ! git -C "${ROOT_REPO}" diff --quiet || ! git -C "${ROOT_REPO}" diff --cached --quiet; then
    echo "error: repository has uncommitted changes; commit or stash before running codex_swarm" >&2
    exit 1
  fi
fi

SWARM_ROOT="${ROOT_REPO}/.codex-swarm"
WORKTREE_ROOT="${SWARM_ROOT}/worktrees"
LOG_ROOT="${SWARM_ROOT}/logs"
mkdir -p "${WORKTREE_ROOT}" "${LOG_ROOT}"

sanitize() {
  local raw="$1"
  echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-'
}

read_tasks() {
  local file="$1"

  SWARM_TASK_IDS=()
  SWARM_TASK_PROMPTS=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    if [[ "${line}" != *"|"* ]]; then
      echo "warning: skipping malformed task line: ${line}" >&2
      continue
    fi
    local id="${line%%|*}"
    local prompt="${line#*|}"
    id="$(echo "${id}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    prompt="$(echo "${prompt}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "${id}" || -z "${prompt}" ]] && continue
    SWARM_TASK_IDS+=("${id}")
    SWARM_TASK_PROMPTS+=("${prompt}")
  done < "${file}"
}

spawn_agent() {
  local task_id="$1"
  local task_prompt="$2"
  local ts="$3"

  local slug
  slug="$(sanitize "${task_id}")"
  local branch_base="codex/swarm-${slug}-${ts}"
  local worktree_base="${WORKTREE_ROOT}/${slug}-${ts}"
  local log_base="${LOG_ROOT}/${slug}-${ts}"
  local branch="${branch_base}"
  local worktree="${worktree_base}"
  local log_file="${log_base}.log"

  local full_prompt
  full_prompt="$(cat <<EOF
${task_prompt}

Requirements:
1) Work only inside this repository.
2) Run relevant tests before finishing.
3) Reuse existing build artifacts when available; avoid full rebuilds unless required.
4) If you changed files, commit all your changes on your current branch.
5) If no changes are needed, report that explicitly and exit successfully.
6) End with a concise summary of changed files and test commands.
EOF
)"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    {
      echo "[DRY RUN] task_id=${task_id}"
      echo "[DRY RUN] branch=${branch}"
      echo "[DRY RUN] worktree=${worktree}"
      echo "[DRY RUN] log=${log_file}"
      echo "[DRY RUN] agent_timeout_seconds=${AGENT_TIMEOUT_SECONDS}"
    } | tee "${log_file}"
    return 0
  fi

  local suffix=0
  while git -C "${ROOT_REPO}" show-ref --verify --quiet "refs/heads/${branch}" || [[ -e "${worktree}" ]]; do
    suffix=$((suffix + 1))
    branch="${branch_base}-${suffix}"
    worktree="${worktree_base}-${suffix}"
    log_file="${log_base}-${suffix}.log"
  done

  git -C "${ROOT_REPO}" worktree add -b "${branch}" "${worktree}" >/dev/null

  # Reuse existing build artifacts so workers do not waste timeout budget.
  if [[ -d "${ROOT_REPO}/build-btx" && ! -e "${worktree}/build-btx" ]]; then
    ln -s "${ROOT_REPO}/build-btx" "${worktree}/build-btx" >/dev/null 2>&1 || true
  fi

  # Mirror upstream dependencies for worker-relative paths like ../upstream.
  if [[ -d "${ROOT_REPO}/../upstream" ]]; then
    ln -sfn "${ROOT_REPO}/../upstream" "${WORKTREE_ROOT}/upstream" >/dev/null 2>&1 || true
  fi

  if [[ "${AGENT_TIMEOUT_SECONDS}" -eq 0 ]]; then
    (
      set -euo pipefail
      "${CODEX_BIN}" exec \
        -c 'model_reasoning_effort="high"' \
        --dangerously-bypass-approvals-and-sandbox \
        --cd "${worktree}" \
        "${full_prompt}"
    ) >"${log_file}" 2>&1
    return $?
  fi

  (
    set -euo pipefail
    python3 - "${AGENT_TIMEOUT_SECONDS}" "${CODEX_BIN}" "${worktree}" "${full_prompt}" <<'PY'
import subprocess
import sys

timeout = int(sys.argv[1])
codex_bin = sys.argv[2]
worktree = sys.argv[3]
prompt = sys.argv[4]

cmd = [
    codex_bin,
    "exec",
    "-c",
    'model_reasoning_effort="high"',
    "--dangerously-bypass-approvals-and-sandbox",
    "--cd",
    worktree,
    prompt,
]

try:
    subprocess.run(cmd, check=True, timeout=timeout)
except subprocess.TimeoutExpired:
    print(f"error: worker timed out after {timeout}s", file=sys.stderr)
    sys.exit(124)
except subprocess.CalledProcessError as err:
    sys.exit(err.returncode)
PY
  ) >"${log_file}" 2>&1
}

run_round() {
  local round_ts
  round_ts="$(date +%Y%m%d%H%M%S)-${RANDOM}"

  read_tasks "${TASKS_FILE}"

  if [[ "${#SWARM_TASK_IDS[@]}" -eq 0 ]]; then
    echo "No tasks found in ${TASKS_FILE}."
    return 0
  fi

  local index=0
  local any_fail=0
  while [[ "${index}" -lt "${#SWARM_TASK_IDS[@]}" ]]; do
    local batch_pids=()
    local batch_names=()

    local started=0
    while [[ "${started}" -lt "${MAX_AGENTS}" && "${index}" -lt "${#SWARM_TASK_IDS[@]}" ]]; do
      local task_id="${SWARM_TASK_IDS[$index]}"
      local task_prompt="${SWARM_TASK_PROMPTS[$index]}"
      local ts="${round_ts}-${index}"
      (
        spawn_agent "${task_id}" "${task_prompt}" "${ts}"
      ) &
      batch_pids+=("$!")
      batch_names+=("${task_id}")
      ((index += 1))
      ((started += 1))
    done

    for i in "${!batch_pids[@]}"; do
      if ! wait "${batch_pids[$i]}"; then
        any_fail=1
        echo "error: agent failed for task: ${batch_names[$i]}" >&2
      fi
    done
  done

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[DRY RUN] Skipping test gate: ${TEST_CMD}"
    return "${any_fail}"
  fi

  if ! (cd "${ROOT_REPO}" && eval "${TEST_CMD}"); then
    echo "error: test gate failed: ${TEST_CMD}" >&2
    return 1
  fi

  return "${any_fail}"
}

while true; do
  if run_round; then
    echo "Swarm round succeeded."
    exit 0
  fi

  if [[ "${CONTINUOUS}" -ne 1 ]]; then
    echo "Swarm round failed."
    exit 1
  fi

  echo "Swarm round failed; retrying in ${DELAY_SECONDS}s..."
  sleep "${DELAY_SECONDS}"
done
