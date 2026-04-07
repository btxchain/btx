#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/launch_detached_ci_runners.sh [options]

Launch one or more detached (screen-managed) ephemeral GitHub Actions runners
for btxchain/btx-node. Each detached job executes
scripts/run_ci_self_hosted_runner_once.sh and exits after one CI job.

Options:
  --count <n>             Number of detached runners to launch (default: 1)
  --token-file <path>     GitHub token file (default: ../github.key from repo root)
  --repo <owner/name>     Repository slug (default: btxchain/btx-node)
  --labels <csv>          Runner labels (default: btx-macos)
  --runner-base-dir <dir> Base directory for runner installs
                          (default: ~/.btxchain/actions-runner-btx-node-detached)
  --name-prefix <prefix>  Runner name prefix (default: btx-macos-detached)
  --state-dir <dir>       Directory for launch metadata/log pointers
                          (default: $TMPDIR/btx-detached-runners)
  --dry-run               Print launch commands without executing them
  -h, --help              Show this help
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_FILE="${ROOT_DIR}/../github.key"
REPO_SLUG="btxchain/btx-node"
RUNNER_LABELS="btx-macos"
COUNT=1
RUNNER_BASE_DIR="${HOME}/.btxchain/actions-runner-btx-node-detached"
NAME_PREFIX="btx-macos-detached"
STATE_DIR="${TMPDIR:-/tmp}/btx-detached-runners"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)
      COUNT="$2"
      shift 2
      ;;
    --token-file)
      TOKEN_FILE="$2"
      shift 2
      ;;
    --repo)
      REPO_SLUG="$2"
      shift 2
      ;;
    --labels)
      RUNNER_LABELS="$2"
      shift 2
      ;;
    --runner-base-dir)
      RUNNER_BASE_DIR="$2"
      shift 2
      ;;
    --name-prefix)
      NAME_PREFIX="$2"
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

if ! [[ "${COUNT}" =~ ^[0-9]+$ ]] || [[ "${COUNT}" -lt 1 ]]; then
  echo "error: --count must be a positive integer" >&2
  exit 1
fi

if ! command -v screen >/dev/null 2>&1; then
  echo "error: screen not found (required for detached runner launch)" >&2
  exit 1
fi

if [[ ! -f "${TOKEN_FILE}" ]]; then
  echo "error: token file not found: ${TOKEN_FILE}" >&2
  exit 1
fi

mkdir -p "${STATE_DIR}"
helper_script="${STATE_DIR}/run_ci_self_hosted_runner_once.sh"
token_copy="${STATE_DIR}/github.key"

# Detached background contexts may not have TCC access to ~/Documents paths.
# Copy both helper script and token into STATE_DIR (outside protected folders).
cp "${ROOT_DIR}/scripts/run_ci_self_hosted_runner_once.sh" "${helper_script}"
chmod 700 "${helper_script}"
cp "${TOKEN_FILE}" "${token_copy}"
chmod 600 "${token_copy}"

timestamp="$(date +%s)"
state_file="${STATE_DIR}/launch-${timestamp}.tsv"
: > "${state_file}"

for idx in $(seq 1 "${COUNT}"); do
  runner_dir="${RUNNER_BASE_DIR}-${timestamp}-${idx}"
  runner_name="${NAME_PREFIX}-${timestamp}-${idx}"
  session_name="btx_ci_runner_${timestamp}_${idx}"
  log_file="${STATE_DIR}/${runner_name}.log"
  cmd_string="cd $(printf '%q' "${ROOT_DIR}") && \
$(printf '%q' "${helper_script}") \
--token-file $(printf '%q' "${token_copy}") \
--repo $(printf '%q' "${REPO_SLUG}") \
--labels $(printf '%q' "${RUNNER_LABELS}") \
--runner-dir $(printf '%q' "${runner_dir}") \
--name $(printf '%q' "${runner_name}") \
> $(printf '%q' "${log_file}") 2>&1"

  # Reuse-friendly: clear an old screen session name if it somehow exists.
  screen -S "${session_name}" -X quit >/dev/null 2>&1 || true

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "screen -dmS ${session_name} /bin/bash -lc ${cmd_string}"
  else
    screen -dmS "${session_name}" /bin/bash -lc "${cmd_string}"
  fi

  printf '%s\t%s\t%s\t%s\n' "${session_name}" "${runner_name}" "${runner_dir}" "${log_file}" >> "${state_file}"
done

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "dry-run complete"
else
  echo "launched ${COUNT} detached runner(s)"
fi
echo "state: ${state_file}"
