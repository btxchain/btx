#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SWARM_SCRIPT="${ROOT_DIR}/scripts/codex_swarm.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-codex-swarm-timeout.XX""XX""XX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

REPO_DIR="${TMP_DIR}/repo"
mkdir -p "${REPO_DIR}/scripts"
cd "${REPO_DIR}"
git init >/dev/null
git config user.name "BTX Test"
git config user.email "btx-test@example.com"
git config commit.gpgsign false
cat > README.md <<'EOF'
# temp
EOF
git add README.md
git commit -m "init" >/dev/null

TASKS_FILE="${TMP_DIR}/tasks.txt"
cat > "${TASKS_FILE}" <<'EOF'
hang-task|Sleep long enough to trigger timeout
EOF

FAKE_CODEX="${TMP_DIR}/fake-codex.sh"
cat > "${FAKE_CODEX}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="${FAKE_CODEX_MODE:-hang}"
case "${mode}" in
  hang)
    sleep 5
    ;;
  fast)
    echo "fast worker done"
    ;;
  *)
    echo "unsupported FAKE_CODEX_MODE=${mode}" >&2
    exit 64
    ;;
esac
exit 0
EOF
chmod +x "${FAKE_CODEX}"

# Ensure codex_swarm fails fast on dirty worktrees; otherwise worktree agents
# miss uncommitted local changes and produce misleading failures.
echo "dirty" >> README.md
set +e
FAKE_CODEX_MODE=fast bash "${SWARM_SCRIPT}" \
  --repo "${REPO_DIR}" \
  --tasks-file "${TASKS_FILE}" \
  --max-agents 1 \
  --agent-timeout-seconds 3 \
  --test-cmd "true" \
  --codex-bin "${FAKE_CODEX}" \
  >"${TMP_DIR}/dirty-run.log" 2>&1
dirty_rc=$?
set -e

if (( dirty_rc == 0 )); then
  echo "error: dirty repository scenario unexpectedly succeeded" >&2
  cat "${TMP_DIR}/dirty-run.log" >&2
  exit 1
fi
rg -q "repository has uncommitted changes" "${TMP_DIR}/dirty-run.log"
git checkout -- README.md

start_ts="$(date +%s)"
set +e
FAKE_CODEX_MODE=hang bash "${SWARM_SCRIPT}" \
  --repo "${REPO_DIR}" \
  --tasks-file "${TASKS_FILE}" \
  --max-agents 1 \
  --agent-timeout-seconds 1 \
  --test-cmd "true" \
  --codex-bin "${FAKE_CODEX}" \
  >"${TMP_DIR}/timeout-run.log" 2>&1
timeout_rc=$?
set -e
end_ts="$(date +%s)"
elapsed=$((end_ts - start_ts))

if (( timeout_rc == 0 )); then
  echo "error: timeout scenario unexpectedly succeeded" >&2
  cat "${TMP_DIR}/timeout-run.log" >&2
  exit 1
fi

if (( elapsed > 35 )); then
  echo "error: timeout scenario took too long (${elapsed}s)" >&2
  cat "${TMP_DIR}/timeout-run.log" >&2
  exit 1
fi

TIMEOUT_LOG="$(find "${REPO_DIR}/.codex-swarm/logs" -maxdepth 1 -name 'hang-task-*.log' -print | sort | head -n 1)"
if [[ -z "${TIMEOUT_LOG}" ]]; then
  echo "error: timeout log not found" >&2
  cat "${TMP_DIR}/timeout-run.log" >&2
  exit 1
fi
rg -q "worker timed out after 1s" "${TIMEOUT_LOG}"

set +e
FAKE_CODEX_MODE=fast bash "${SWARM_SCRIPT}" \
  --repo "${REPO_DIR}" \
  --tasks-file "${TASKS_FILE}" \
  --max-agents 1 \
  --agent-timeout-seconds 10 \
  --test-cmd "true" \
  --codex-bin "${FAKE_CODEX}" \
  >"${TMP_DIR}/fast-run.log" 2>&1
fast_rc=$?
set -e

if (( fast_rc != 0 )); then
  # Retry once to smooth transient scheduling blips under heavy parallel load.
  set +e
  FAKE_CODEX_MODE=fast bash "${SWARM_SCRIPT}" \
    --repo "${REPO_DIR}" \
    --tasks-file "${TASKS_FILE}" \
    --max-agents 1 \
    --agent-timeout-seconds 10 \
    --test-cmd "true" \
    --codex-bin "${FAKE_CODEX}" \
    >"${TMP_DIR}/fast-run-retry.log" 2>&1
  fast_retry_rc=$?
  set -e
  if (( fast_retry_rc != 0 )); then
    echo "error: fast scenario failed" >&2
    cat "${TMP_DIR}/fast-run.log" >&2
    cat "${TMP_DIR}/fast-run-retry.log" >&2
    exit 1
  fi
fi

echo "codex_swarm_timeout_test: PASS"
