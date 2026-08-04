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

This script runs the repository's macOS/ARM64 validation matrix locally by:
- using targets pinned in scripts/ci/local-mac-matrix.tsv
- running each target in a clean detached worktree at HEAD
- applying per-job timeouts from that local-only manifest

GitHub Actions is intentionally disabled; this runner does not dispatch or
compare against hosted workflow jobs.
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

manifest_max_parallel() {
  local workflow="$1"
  awk -F'|' -v workflow="${workflow}" '
    $0 !~ /^#/ && $1 == workflow { print $2; exit 0 }
  ' "${MATRIX_MANIFEST}"
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

run_with_timeout() {
  local timeout_mins="$1"
  shift
  python3 - "${timeout_mins}" "$@" <<'PY'
import os
import signal
import subprocess
import sys

timeout_seconds = int(sys.argv[1]) * 60
proc = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    raise SystemExit(proc.wait(timeout=timeout_seconds))
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    raise SystemExit(124)
PY
}

MATRIX_MANIFEST="scripts/ci/local-mac-matrix.tsv"
if [[ ! -f "${MATRIX_MANIFEST}" ]]; then
  echo "error: missing local validation manifest ${MATRIX_MANIFEST}" >&2
  exit 1
fi

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
CI_MAX_PARALLEL="$(trim_ws "$(manifest_max_parallel ci)")"
READINESS_MAX_PARALLEL="$(trim_ws "$(manifest_max_parallel readiness)")"

if [[ -z "${CI_MAX_PARALLEL}" || -z "${READINESS_MAX_PARALLEL}" ]]; then
  echo "error: failed to parse max-parallel from ${MATRIX_MANIFEST}" >&2
  exit 1
fi

MAX_PARALLEL="${CI_MAX_PARALLEL}"
if [[ "${MODE}" == "readiness" ]]; then
  MAX_PARALLEL="${READINESS_MAX_PARALLEL}"
elif [[ "${MODE}" == "all" && "${READINESS_MAX_PARALLEL}" -lt "${MAX_PARALLEL}" ]]; then
  MAX_PARALLEL="${READINESS_MAX_PARALLEL}"
fi
if [[ "${PARALLEL}" -gt "${MAX_PARALLEL}" ]]; then
  PARALLEL="${MAX_PARALLEL}"
fi

add_jobs_from_manifest() {
  local workflow="$1"
  local line=""
  while IFS= read -r line; do
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    local entry_workflow max_parallel job_name target timeout_mins
    IFS='|' read -r entry_workflow max_parallel job_name target timeout_mins <<<"${line}"
    [[ "${entry_workflow}" != "${workflow}" ]] && continue
    job_name="$(trim_ws "${job_name}")"
    target="$(trim_ws "${target}")"
    timeout_mins="$(trim_ws "${timeout_mins}")"
    if [[ -z "${job_name}" || -z "${target}" || -z "${timeout_mins}" ]]; then
      continue
    fi
    if ! [[ "${timeout_mins}" =~ ^[0-9]+$ ]]; then
      echo "error: non-numeric timeout '${timeout_mins}' for target '${target}' in ${MATRIX_MANIFEST}" >&2
      exit 1
    fi
    if contains_only_filter "${job_name}" "${target}"; then
      key="$(printf '%03d_%s_%s' "${index}" "${workflow}" "$(safe_name "${target}")")"
      jobs+=("${workflow}|${job_name}|${target}|${timeout_mins}|${key}")
      index=$((index + 1))
    fi
  done < "${MATRIX_MANIFEST}"
}

if [[ "${MODE}" == "ci" || "${MODE}" == "all" ]]; then
  add_jobs_from_manifest "ci"
fi

if [[ "${MODE}" == "readiness" || "${MODE}" == "all" ]]; then
  add_jobs_from_manifest "readiness"
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

  # This is data, not a shell program. Keep it tab-delimited so job names with
  # spaces cannot be executed accidentally when the result is collected.
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${workflow}" "${job_name}" "${target}" "${timeout_mins}" "${job_key}" \
    "${worktree}" "${log_file}" "${started_iso}" "${started_epoch}" \
    > "${job_dir}/meta.tsv"

  (
    set -euo pipefail
    cd "${worktree}"
    export BTX_LOCAL_VALIDATION=true
    export BTX_LOCAL_RUN_ID="local-${RUN_ID}"
    export BTX_LOCAL_JOB="${job_key}"
    export CI=true

    toolchain_info "${workflow}"

    run_with_timeout "${timeout_mins}" scripts/ci/run_ci_target.sh "${target}"
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

  local workflow job_name target timeout_mins job_key worktree log_file started_iso started_epoch
  IFS=$'\t' read -r workflow job_name target timeout_mins job_key worktree log_file started_iso started_epoch \
    < "${job_dir}/meta.tsv"
  if [[ -z "${workflow}" || -z "${job_name}" || -z "${target}" ||
        -z "${timeout_mins}" || -z "${job_key}" || -z "${worktree}" ||
        -z "${log_file}" || -z "${started_iso}" || -z "${started_epoch}" ]]; then
    echo "error: incomplete local-matrix metadata in ${job_dir}/meta.tsv" >&2
    return 1
  fi

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
