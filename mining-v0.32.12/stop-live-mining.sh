#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${BTX_MINING_RESULTS_DIR:-}"

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Stop the BTX live-mining supervisor recorded in the results directory.

Options:
  --results-dir=PATH        Directory containing live-mining-loop.pid
  --help, -h                Show this help text
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --help|-h)
      print_usage
      exit 0
      ;;
    --results-dir=*)
      RESULTS_DIR="${arg#*=}"
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${RESULTS_DIR}" ]]; then
  RESULTS_DIR="${PWD}/mining-ops"
fi

PIDFILE="${RESULTS_DIR}/live-mining-loop.pid"

wait_for_pid_exit() {
  local pid="$1"
  local limit="$2"
  local i
  for ((i = 0; i < limit; ++i)); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if [[ -f "${PIDFILE}" ]]; then
  pid="$(cat "${PIDFILE}")"
  if [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    if ! wait_for_pid_exit "${pid}" 5; then
      kill -KILL "${pid}" >/dev/null 2>&1 || true
      wait_for_pid_exit "${pid}" 2 || true
    fi
  fi
  rm -f "${PIDFILE}"
fi

printf 'Stopped live mining loop\n'
