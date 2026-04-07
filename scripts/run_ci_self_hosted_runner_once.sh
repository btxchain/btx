#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_ci_self_hosted_runner_once.sh [options]

Registers and runs an ephemeral GitHub Actions self-hosted runner for
btxchain/btx-node. The runner exits after completing one job.

Options:
  --token-file <path>   File containing GitHub API token
                        (default: ../github.key from btx-node root)
  --runner-dir <path>   Runner installation directory
                        (default: ~/.btxchain/actions-runner-btx-node)
  --labels <csv>        Additional runner labels (default: btx-macos)
  --name <name>         Runner name (default: btx-macos-<host>-<epoch>)
  --repo <owner/name>   GitHub repository slug (default: btxchain/btx-node)
  -h, --help            Show this message
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_FILE="${ROOT_DIR}/../github.key"
RUNNER_DIR="${HOME}/.btxchain/actions-runner-btx-node"
RUNNER_LABELS="btx-macos"
REPO_SLUG="btxchain/btx-node"
HOST_SHORT="$(hostname | cut -d. -f1)"
RUNNER_NAME="btx-macos-${HOST_SHORT}-$(date +%s)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token-file)
      TOKEN_FILE="$2"
      shift 2
      ;;
    --runner-dir)
      RUNNER_DIR="$2"
      shift 2
      ;;
    --labels)
      RUNNER_LABELS="$2"
      shift 2
      ;;
    --name)
      RUNNER_NAME="$2"
      shift 2
      ;;
    --repo)
      REPO_SLUG="$2"
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

for cmd in curl tar python3; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
done

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  API_TOKEN="${GITHUB_TOKEN}"
elif [[ -f "${TOKEN_FILE}" ]]; then
  API_TOKEN="$(<"${TOKEN_FILE}")"
else
  echo "error: no GitHub token found. Set GITHUB_TOKEN or provide --token-file." >&2
  exit 1
fi

if [[ -z "${API_TOKEN}" ]]; then
  echo "error: GitHub token is empty" >&2
  exit 1
fi

REPO_URL="https://github.com/${REPO_SLUG}"
API_BASE="https://api.github.com/repos/${REPO_SLUG}"

api_post() {
  local endpoint="$1"
  curl -fsSL \
    -X POST \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${API_BASE}${endpoint}"
}

api_get() {
  local url="$1"
  curl -fsSL \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${url}"
}

mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"

if [[ ! -x "./config.sh" ]]; then
  echo "Installing GitHub Actions runner into ${RUNNER_DIR}"
  release_json="$(api_get "https://api.github.com/repos/actions/runner/releases/latest")"
  read -r runner_url runner_file < <(
    python3 - <<'PY' "${release_json}"
import json, sys
rel = json.loads(sys.argv[1])
for asset in rel["assets"]:
    name = asset["name"]
    if name.startswith("actions-runner-osx-arm64-") and name.endswith(".tar.gz"):
        print(asset["browser_download_url"], name)
        break
else:
    raise SystemExit("no osx-arm64 runner asset found")
PY
  )
  curl -fsSL "${runner_url}" -o "${runner_file}"
  tar xzf "${runner_file}"
fi

if [[ -f ".runner" ]]; then
  echo "Removing previous runner configuration"
  remove_token="$(api_post "/actions/runners/remove-token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  ./config.sh remove --token "${remove_token}" || true
fi

echo "Registering ephemeral runner ${RUNNER_NAME} on ${REPO_URL}"
reg_token="$(api_post "/actions/runners/registration-token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
./config.sh \
  --url "${REPO_URL}" \
  --token "${reg_token}" \
  --name "${RUNNER_NAME}" \
  --labels "${RUNNER_LABELS}" \
  --work "_work" \
  --replace \
  --unattended \
  --ephemeral \
  --disableupdate

echo "Runner configured. Waiting for one job..."
./run.sh

echo "Runner exited."
