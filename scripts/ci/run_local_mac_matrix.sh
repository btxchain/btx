#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

MODE="all"
PARALLEL=4
ONLY_CSV=""
KEEP_WORKTREES="false"
ALLOW_DIRTY_HEAD="false"

usage() {
  cat <<'USAGE'
Usage: scripts/ci/run_local_mac_matrix.sh [mode] [options]

Modes:
  all         Run CI + BTX Readiness matrices (default)
  ci          Run CI matrix only
  readiness   Run BTX Readiness matrix only

Options:
  --parallel N        Max concurrent local jobs (default: 4)
  --only a,b,c        Run only matching targets or job names
  --keep-worktrees    Keep per-job worktrees for inspection
  --allow-dirty-head  Run against committed HEAD even if tracked files are dirty
  -h, --help          Show help

This script mirrors macOS/ARM64 workflow jobs locally by:
- using the same targets as .github/workflows/ci.yml and btx-readiness.yml
- running each target in a clean detached worktree at HEAD
- applying per-job timeouts that match workflow timeout-minutes
USAGE
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    all|ci|readiness)
      MODE="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --parallel)
      PARALLEL="$2"
      shift 2
      ;;
    --only)
      ONLY_CSV="$2"
      shift 2
      ;;
    --keep-worktrees)
      KEEP_WORKTREES="true"
      shift
      ;;
    --allow-dirty-head)
      ALLOW_DIRTY_HEAD="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this runner is for macOS only" >&2
  exit 1
fi

if ! [[ "${PARALLEL}" =~ ^[0-9]+$ ]] || [[ "${PARALLEL}" -lt 1 ]]; then
  echo "error: --parallel must be a positive integer" >&2
  exit 1
fi

safe_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'
}

iso_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

epoch_now() {
  date +%s
}

contains_only_filter() {
  local job_name="$1"
  local target="$2"
  if [[ -z "${ONLY_CSV}" ]]; then
    return 0
  fi
  local old_ifs="$IFS"
  IFS=','
  local item
  for item in ${ONLY_CSV}; do
    item="$(printf '%s' "${item}" | xargs)"
    if [[ -n "${item}" && ( "${job_name}" == "${item}" || "${target}" == "${item}" ) ]]; then
      IFS="$old_ifs"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

trim_ws() {
  local input="$1"
  input="${input#"${input%%[![:space:]]*}"}"
  input="${input%"${input##*[![:space:]]}"}"
  printf '%s' "${input}"
}

extract_matrix_entries() {
  local workflow_file="$1"
  awk '
    /^[[:space:]]*-[[:space:]]name:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]name:[[:space:]]*/, "", line)
      name=line
      target=""
      timeout=""
      next
    }
    /^[[:space:]]*target:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*target:[[:space:]]*/, "", line)
      target=line
      next
    }
    /^[[:space:]]*timeout_minutes:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*timeout_minutes:[[:space:]]*/, "", line)
      timeout=line
      if (name != "" && target != "" && timeout != "") {
        printf "%s|%s|%s\n", name, target, timeout
      }
      name=""
      target=""
      timeout=""
      next
    }
  ' "${workflow_file}"
}

workflow_max_parallel() {
  local workflow_file="$1"
  awk '
    /^[[:space:]]*max-parallel:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*max-parallel:[[:space:]]*/, "", line)
      print line
      exit 0
    }
  ' "${workflow_file}"
}

toolchain_info() {
  local workflow="$1"
  echo "=== toolchain info (${workflow}) ==="
  sw_vers || true
  clang --version || true
  cmake --version || true
  python3 --version || true
  if [[ "${workflow}" == "ci" ]]; then
    docker --version || true
  else
    python3.11 --version || true
  fi
}

TIMEOUT_BIN=""
if command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
elif command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
fi

if [[ -z "${TIMEOUT_BIN}" ]]; then
  echo "warning: timeout command not found; local jobs will run without hard timeout" >&2
fi

CI_WORKFLOW=".github/workflows/ci.yml"
READINESS_WORKFLOW=".github/workflows/btx-readiness.yml"
for wf in "${CI_WORKFLOW}" "${READINESS_WORKFLOW}"; do
  if [[ ! -f "${wf}" ]]; then
    echo "error: missing workflow file ${wf}" >&2
    exit 1
  fi
done

HEAD_SHA="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  if [[ "${ALLOW_DIRTY_HEAD}" == "true" ]]; then
    echo "warning: working tree has uncommitted tracked changes; local replica will test committed HEAD ${HEAD_SHA}" >&2
  else
    echo "error: working tree has uncommitted tracked changes" >&2
    echo "error: local CI-replica runs are HEAD-accurate and ignore uncommitted edits" >&2
    echo "error: commit or stash changes first, or rerun with --allow-dirty-head to intentionally test HEAD only" >&2
    exit 1
  fi
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_ROOT="${TMPDIR:-/tmp}/btx-local-mac-matrix"
RUN_DIR="${LOG_ROOT}/${RUN_ID}"
WORKTREE_ROOT="${TMPDIR:-/tmp}/btx-local-mac-worktrees/${RUN_ID}"
SUMMARY_FILE="${RUN_DIR}/summary.tsv"
mkdir -p "${RUN_DIR}/jobs"
mkdir -p "${WORKTREE_ROOT}"

jobs=()
index=0
CI_MAX_PARALLEL="$(trim_ws "$(workflow_max_parallel "${CI_WORKFLOW}")")"
READINESS_MAX_PARALLEL="$(trim_ws "$(workflow_max_parallel "${READINESS_WORKFLOW}")")"

if [[ -z "${CI_MAX_PARALLEL}" || -z "${READINESS_MAX_PARALLEL}" ]]; then
  echo "error: failed to parse max-parallel from workflow files" >&2
  exit 1
fi

if [[ "${MODE}" == "ci" ]]; then
  PARALLEL="${CI_MAX_PARALLEL}"
elif [[ "${MODE}" == "readiness" ]]; then
  PARALLEL="${READINESS_MAX_PARALLEL}"
elif [[ "${PARALLEL}" -gt "${CI_MAX_PARALLEL}" ]]; then
  PARALLEL="${CI_MAX_PARALLEL}"
fi

add_jobs_from_workflow() {
  local workflow="$1"
  local workflow_file="$2"
  local line=""
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    IFS='|' read -r job_name target timeout_mins <<<"${line}"
    job_name="$(trim_ws "${job_name}")"
    target="$(trim_ws "${target}")"
    timeout_mins="$(trim_ws "${timeout_mins}")"
    if [[ -z "${job_name}" || -z "${target}" || -z "${timeout_mins}" ]]; then
      continue
    fi
    if ! [[ "${timeout_mins}" =~ ^[0-9]+$ ]]; then
      echo "error: non-numeric timeout '${timeout_mins}' for target '${target}' in ${workflow_file}" >&2
      exit 1
    fi
    if contains_only_filter "${job_name}" "${target}"; then
      key="$(printf '%03d_%s_%s' "${index}" "${workflow}" "$(safe_name "${target}")")"
      jobs+=("${workflow}|${job_name}|${target}|${timeout_mins}|${key}")
      index=$((index + 1))
    fi
  done < <(extract_matrix_entries "${workflow_file}")
}

if [[ "${MODE}" == "ci" || "${MODE}" == "all" ]]; then
  add_jobs_from_workflow "ci" "${CI_WORKFLOW}"
fi

if [[ "${MODE}" == "readiness" || "${MODE}" == "all" ]]; then
  add_jobs_from_workflow "readiness" "${READINESS_WORKFLOW}"
fi

if [[ ${#jobs[@]} -eq 0 ]]; then
  echo "error: no jobs selected" >&2
  exit 1
fi

printf 'job_key\tworkflow\tjob_name\ttarget\tstatus\tstarted\tfinished\telapsed_s\ttimeout_min\tlog_path\tworktree\n' > "${SUMMARY_FILE}"

active_pids=()
active_job_dirs=()
PASS_COUNT=0
FAIL_COUNT=0
STARTED_COUNT=0

start_job() {
  local job_spec="$1"
  IFS='|' read -r workflow job_name target timeout_mins job_key <<<"${job_spec}"

  local job_dir="${RUN_DIR}/jobs/${job_key}"
  local log_file="${job_dir}/run.log"
  local worktree="${WORKTREE_ROOT}/${job_key}"

  mkdir -p "${job_dir}"
  rm -rf "${worktree}"
  git worktree add --detach "${worktree}" "${HEAD_SHA}" >/dev/null 2>&1

  local started_iso started_epoch
  started_iso="$(iso_now)"
  started_epoch="$(epoch_now)"

  {
    printf 'workflow=%s\n' "${workflow}"
    printf 'job_name=%s\n' "${job_name}"
    printf 'target=%s\n' "${target}"
    printf 'timeout_mins=%s\n' "${timeout_mins}"
    printf 'job_key=%s\n' "${job_key}"
    printf 'worktree=%s\n' "${worktree}"
    printf 'log_file=%s\n' "${log_file}"
    printf 'started_iso=%s\n' "${started_iso}"
    printf 'started_epoch=%s\n' "${started_epoch}"
  } > "${job_dir}/meta.env"

  (
    set -euo pipefail
    cd "${worktree}"
    export GITHUB_ACTIONS=true
    export GITHUB_RUN_ID="local-${RUN_ID}"
    export GITHUB_RUN_ATTEMPT=1
    export GITHUB_JOB="${job_key}"
    export CI=true

    toolchain_info "${workflow}"

    if [[ -n "${TIMEOUT_BIN}" ]]; then
      "${TIMEOUT_BIN}" "${timeout_mins}m" scripts/ci/run_ci_target.sh "${target}"
    else
      scripts/ci/run_ci_target.sh "${target}"
    fi
  ) > "${log_file}" 2>&1 &

  local pid=$!
  active_pids+=("${pid}")
  active_job_dirs+=("${job_dir}")
  STARTED_COUNT=$((STARTED_COUNT + 1))

  echo "[local-matrix] start ${job_key} workflow=${workflow} target=${target} timeout=${timeout_mins}m pid=${pid}"
}

finalize_job() {
  local job_dir="$1"
  local exit_code="$2"

  # shellcheck disable=SC1090,SC1091
  source "${job_dir}/meta.env"

  local finished_iso finished_epoch elapsed status
  finished_iso="$(iso_now)"
  finished_epoch="$(epoch_now)"
  elapsed=$((finished_epoch - started_epoch))

  if [[ "${exit_code}" -eq 0 ]]; then
    status="PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    status="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${job_key}" "${workflow}" "${job_name}" "${target}" "${status}" \
    "${started_iso}" "${finished_iso}" "${elapsed}" "${timeout_mins}" \
    "${log_file}" "${worktree}" >> "${SUMMARY_FILE}"

  if [[ "${KEEP_WORKTREES}" == "true" ]]; then
    :
  else
    git worktree remove --force "${worktree}" >/dev/null 2>&1 || rm -rf "${worktree}" || true
  fi

  if [[ "${status}" == "FAIL" ]]; then
    echo "[local-matrix] FAIL ${job_key} target=${target} elapsed=${elapsed}s exit=${exit_code}" >&2
    echo "[local-matrix] tail ${log_file}" >&2
    tail -n 200 "${log_file}" >&2 || true
  else
    echo "[local-matrix] PASS ${job_key} target=${target} elapsed=${elapsed}s"
  fi
}

collect_finished_jobs() {
  local progressed=0
  local new_pids=()
  local new_job_dirs=()

  local i pid job_dir rc state
  for i in "${!active_pids[@]}"; do
    pid="${active_pids[$i]}"
    job_dir="${active_job_dirs[$i]}"

    state="$(ps -o stat= -p "${pid}" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ -n "${state}" && "${state}" != Z* ]]; then
      new_pids+=("${pid}")
      new_job_dirs+=("${job_dir}")
      continue
    fi

    set +e
    wait "${pid}"
    rc=$?
    set -e

    finalize_job "${job_dir}" "${rc}"
    progressed=1
  done

  active_pids=("${new_pids[@]}")
  active_job_dirs=("${new_job_dirs[@]}")

  if [[ "${progressed}" -eq 1 ]]; then
    return 0
  fi
  return 1
}

next_job=0
while [[ "${next_job}" -lt "${#jobs[@]}" || "${#active_pids[@]}" -gt 0 ]]; do
  while [[ "${next_job}" -lt "${#jobs[@]}" && "${#active_pids[@]}" -lt "${PARALLEL}" ]]; do
    start_job "${jobs[$next_job]}"
    next_job=$((next_job + 1))
  done

  if ! collect_finished_jobs; then
    sleep 2
  fi
done

echo "[local-matrix] done pass=${PASS_COUNT} fail=${FAIL_COUNT} total=${STARTED_COUNT}"
echo "[local-matrix] summary: ${SUMMARY_FILE}"
if command -v column >/dev/null 2>&1; then
  column -t -s $'\t' "${SUMMARY_FILE}"
else
  cat "${SUMMARY_FILE}"
fi

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  exit 1
fi

exit 0
