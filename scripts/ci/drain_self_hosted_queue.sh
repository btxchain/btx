#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/ci/drain_self_hosted_queue.sh [options]

Continuously drain queued/in-progress GitHub Actions runs by launching detached
self-hosted runners when no runner is online.

Options:
  --token-file <path>    GitHub API token file (default: ../github.key)
  --repo <owner/name>    Repository slug (default: btxchain/btx-node)
  --head-sha <sha>       Optional commit SHA filter (default: no filter)
  --cancel-non-head-active
                         When --head-sha is set, force-cancel active runs for
                         other SHAs before draining (default: disabled)
  --launch-count <n>     Detached runners to launch when needed (default: 1)
  --max-rounds <n>       Maximum poll rounds before failing (default: 240)
  --poll-seconds <n>     Sleep between polls (default: 15)
  --state-dir <dir>      State directory for detached runner launcher
  --dry-run              Print actions only; do not launch runners
  -h, --help             Show this help
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOKEN_FILE="${ROOT_DIR}/../github.key"
REPO_SLUG="btxchain/btx-node"
HEAD_SHA=""
LAUNCH_COUNT=1
MAX_ROUNDS=240
POLL_SECONDS=15
STATE_DIR="${TMPDIR:-/tmp}/btx-detached-runners"
DRY_RUN=0
CANCEL_NON_HEAD_ACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token-file)
      TOKEN_FILE="$2"
      shift 2
      ;;
    --repo)
      REPO_SLUG="$2"
      shift 2
      ;;
    --head-sha)
      HEAD_SHA="$2"
      shift 2
      ;;
    --launch-count)
      LAUNCH_COUNT="$2"
      shift 2
      ;;
    --max-rounds)
      MAX_ROUNDS="$2"
      shift 2
      ;;
    --poll-seconds)
      POLL_SECONDS="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --cancel-non-head-active)
      CANCEL_NON_HEAD_ACTIVE=1
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

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: missing required command: $cmd" >&2
    exit 1
  fi
done

if [[ ! -f "${TOKEN_FILE}" ]]; then
  echo "error: token file not found: ${TOKEN_FILE}" >&2
  exit 1
fi

if ! [[ "${LAUNCH_COUNT}" =~ ^[0-9]+$ ]] || [[ "${LAUNCH_COUNT}" -lt 1 ]]; then
  echo "error: --launch-count must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MAX_ROUNDS}" =~ ^[0-9]+$ ]] || [[ "${MAX_ROUNDS}" -lt 1 ]]; then
  echo "error: --max-rounds must be a positive integer" >&2
  exit 1
fi
if ! [[ "${POLL_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${POLL_SECONDS}" -lt 1 ]]; then
  echo "error: --poll-seconds must be a positive integer" >&2
  exit 1
fi

API_TOKEN="$(<"${TOKEN_FILE}")"
if [[ -z "${API_TOKEN}" ]]; then
  echo "error: token file is empty: ${TOKEN_FILE}" >&2
  exit 1
fi

api_get() {
  local url="$1"
  curl -fsSL \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${url}"
}

run_query_filter='(.status=="queued" or .status=="waiting" or .status=="in_progress")'
if [[ -n "${HEAD_SHA}" ]]; then
  run_query_filter="(${run_query_filter}) and (.head_sha == \"${HEAD_SHA}\")"
fi

for round in $(seq 1 "${MAX_ROUNDS}"); do
  runs_json="$(api_get "https://api.github.com/repos/${REPO_SLUG}/actions/runs?per_page=100")"

  if [[ -n "${HEAD_SHA}" && "${CANCEL_NON_HEAD_ACTIVE}" -eq 1 ]]; then
    printf '%s' "${runs_json}" \
    | jq -r --arg sha "${HEAD_SHA}" '.workflow_runs[] | select((.status=="queued" or .status=="waiting" or .status=="in_progress") and .head_sha != $sha) | .id' \
    | while IFS= read -r stale_id; do
        [[ -n "${stale_id}" ]] || continue
        if [[ "${DRY_RUN}" -eq 1 ]]; then
          echo "[drain-ci] dry-run: would force-cancel stale run ${stale_id}"
        else
          curl -fsSL \
            -X POST \
            -H "Authorization: Bearer ${API_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${REPO_SLUG}/actions/runs/${stale_id}/force-cancel" >/dev/null
          echo "[drain-ci] force-cancelled stale run ${stale_id}"
        fi
      done
    # Refresh run view after cancellations.
    runs_json="$(api_get "https://api.github.com/repos/${REPO_SLUG}/actions/runs?per_page=100")"
  fi

  queued_count="$(printf '%s' "${runs_json}" | jq "[.workflow_runs[] | select(${run_query_filter} and (.status==\"queued\" or .status==\"waiting\"))] | length")"
  in_progress_count="$(printf '%s' "${runs_json}" | jq "[.workflow_runs[] | select(${run_query_filter} and .status==\"in_progress\")] | length")"

  runners_json="$(api_get "https://api.github.com/repos/${REPO_SLUG}/actions/runners?per_page=100")"
  online_runners="$(printf '%s' "${runners_json}" | jq '[.runners[] | select(.status=="online")] | length')"

  printf '[drain-ci] round=%s queued=%s in_progress=%s online_runners=%s\n' \
    "${round}" "${queued_count}" "${in_progress_count}" "${online_runners}"

  if [[ "${queued_count}" -eq 0 && "${in_progress_count}" -eq 0 ]]; then
    echo "[drain-ci] queue drained"
    exit 0
  fi

  if [[ "${queued_count}" -gt 0 && "${online_runners}" -eq 0 ]]; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      echo "[drain-ci] dry-run: would launch ${LAUNCH_COUNT} detached runner(s)"
    else
      (
        cd "${ROOT_DIR}"
        scripts/launch_detached_ci_runners.sh \
          --count "${LAUNCH_COUNT}" \
          --token-file "${TOKEN_FILE}" \
          --repo "${REPO_SLUG}" \
          --state-dir "${STATE_DIR}"
      )
    fi
  fi

  sleep "${POLL_SECONDS}"
done

echo "[drain-ci] timeout: queue not drained after ${MAX_ROUNDS} rounds" >&2
exit 1
