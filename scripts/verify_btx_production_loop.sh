#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_VERIFY_SCRIPT="${REPO_ROOT}/scripts/verify_btx_production_readiness.sh"
DEFAULT_ARTIFACT_DIR="${REPO_ROOT}/.btx-production-readiness/verify-loop"
DEFAULT_MAX_ROUNDS=10
DEFAULT_ROUND_DELAY=60

usage() {
  cat <<'USAGE'
Usage: scripts/verify_btx_production_loop.sh [options] [-- [verify-script args...]]

Options:
  --verify-script PATH   Override readiness script (default: scripts/verify_btx_production_readiness.sh)
  --artifact-dir DIR     Directory where round logs/artifacts are written (default: .btx-production-readiness/verify-loop)
  --max-rounds N         Maximum number of verification rounds to attempt (default: 10)
  --round-delay SECONDS  Delay between rounds in seconds (default: 60, accepts 0)
  -h, --help             Show this help message

All arguments after `--` are forwarded verbatim to the readiness script.
USAGE
}

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
  local level="$1"
  shift
  printf '[%s] %s: %s\n' "$(timestamp)" "${level}" "$*"
}

die() {
  log "ERROR" "$*"
  exit 1
}

resolve_path() {
  local source_path="$1"
  if [[ "${source_path}" == "~" ]]; then
    source_path="${HOME}"
  elif [[ "${source_path}" == \~/* ]]; then
    source_path="${HOME}/${source_path:2}"
  fi

  if [[ "${source_path}" == /* ]]; then
    printf '%s\n' "${source_path}"
  else
    printf '%s/%s\n' "$(pwd)" "${source_path}"
  fi
}

verify_script="${DEFAULT_VERIFY_SCRIPT}"
artifact_dir="${DEFAULT_ARTIFACT_DIR}"
max_rounds="${DEFAULT_MAX_ROUNDS}"
round_delay="${DEFAULT_ROUND_DELAY}"
forward_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-script)
      [[ $# -ge 2 ]] || die "missing value for --verify-script"
      verify_script="$2"
      shift 2
      ;;
    --artifact-dir)
      [[ $# -ge 2 ]] || die "missing value for --artifact-dir"
      artifact_dir="$2"
      shift 2
      ;;
    --max-rounds)
      [[ $# -ge 2 ]] || die "missing value for --max-rounds"
      max_rounds="$2"
      shift 2
      ;;
    --round-delay)
      [[ $# -ge 2 ]] || die "missing value for --round-delay"
      round_delay="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      forward_args+=("$@")
      break
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if ! [[ "${max_rounds}" =~ ^[0-9]+$ ]]; then
  die "max rounds must be a positive integer"
fi
if (( max_rounds < 1 )); then
  die "max rounds must be >= 1"
fi

if ! [[ "${round_delay}" =~ ^[0-9]+$ ]]; then
  die "round delay must be a non-negative integer number of seconds"
fi

verify_script="$(resolve_path "${verify_script}")"
artifact_dir="$(resolve_path "${artifact_dir}")"

if [[ ! -f "${verify_script}" ]]; then
  die "verify script not found: ${verify_script}"
fi
if [[ ! -x "${verify_script}" ]]; then
  die "verify script exists but is not executable: ${verify_script}"
fi

mkdir -p "${artifact_dir}"

on_interrupt() {
  log "ERROR" "Interrupted"
  exit 130
}
trap on_interrupt INT TERM

export BTX_PRODUCTION_LOOP_MAX_ROUNDS="${max_rounds}"
export BTX_PRODUCTION_LOOP_ARTIFACT_DIR="${artifact_dir}"

loop_pid="$$"
last_rc=0
for (( round = 1; round <= max_rounds; round++ )); do
  printf -v round_prefix "round-%03d" "${round}"
  round_dir_timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
  round_dir="${artifact_dir}/${round_prefix}_${round_dir_timestamp}_pid${loop_pid}"

  mkdir -p "${round_dir}"

  stdout_log="${round_dir}/stdout.log"
  stderr_log="${round_dir}/stderr.log"
  exit_code_file="${round_dir}/exit_code"

  log "INFO" "Starting readiness round ${round}/${max_rounds} -> ${round_dir}"

  cmd=("${verify_script}")
  if ((${#forward_args[@]})); then
    cmd+=("${forward_args[@]}")
  fi

  set +e
  BTX_PRODUCTION_LOOP_ROUND="${round}" \
  BTX_PRODUCTION_LOOP_ROUND_DIR="${round_dir}" \
  "${cmd[@]}" \
    > >(tee "${stdout_log}") \
    2> >(tee "${stderr_log}" >&2)
  last_rc=$?
  set -e

  printf '%s\n' "${last_rc}" > "${exit_code_file}"

  if (( last_rc == 0 )); then
    log "INFO" "Readiness script passed in round ${round}. Logs available in ${round_dir}"
    exit 0
  fi

  log "WARN" "Readiness script failed in round ${round} with rc=${last_rc}"
  if (( round == max_rounds )); then
    break
  fi

  if (( round_delay > 0 )); then
    log "INFO" "Sleeping ${round_delay}s before next attempt"
    sleep "${round_delay}"
  fi
done

log "ERROR" "Readiness checks failed after ${max_rounds} rounds. Inspect ${artifact_dir} for details."
exit "${last_rc}"
