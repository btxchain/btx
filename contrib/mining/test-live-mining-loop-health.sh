#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

# Keep tests deterministic on Apple Silicon developer machines; individual
# cases opt back into Darwin/arm64 when they are testing those defaults.
export BTX_MINING_HOST_OS_FOR_TEST=Linux
export BTX_MINING_HOST_ARCH_FOR_TEST=x86_64
export BTX_MINING_USE_DEFAULT_BOOTSTRAP_PEERS=0

cleanup_pidfile() {
  local pidfile="$1"
  if [[ ! -f "${pidfile}" ]]; then
    return
  fi
  local pid
  pid="$(tr -d '\n' < "${pidfile}")"
  if [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${pidfile}"
}

write_fake_btxd() {
  local path="$1"
  cat > "${path}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
PIDFILE=""
for arg in "$@"; do
  case "${arg}" in
    -pid=*)
      PIDFILE="${arg#*=}"
      ;;
  esac
done
printf 'start %s\n' "$*" >> "${STATE_DIR}/events.log"
(
  trap 'exit 0' TERM INT
  while true; do
    sleep 1
  done
) &
child_pid=$!
if [[ -n "${PIDFILE}" ]]; then
  printf '%s\n' "${child_pid}" > "${PIDFILE}"
fi
exit 0
EOF
  chmod +x "${path}"
}

printf 'btx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg3kz9d\n' > "${TMPDIR}/address.txt"

STATE_DIR="${TMPDIR}/state-restart"
RESULTS_DIR="${TMPDIR}/results-restart"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"
NODE_PIDFILE="${STATE_DIR}/managed.pid"
UNRELATED_PIDFILE="${STATE_DIR}/unrelated.pid"

cat > "${TMPDIR}/fake-cli-restart" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
NODE_PIDFILE="${BTX_MINING_NODE_PIDFILE:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress|stop)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    count=0
    if [[ -f "${STATE_DIR}/mininginfo-count" ]]; then
      count="$(cat "${STATE_DIR}/mininginfo-count")"
    fi
    count=$((count + 1))
    printf '%s\n' "${count}" > "${STATE_DIR}/mininginfo-count"
    if (( count <= 2 )); then
      cat <<JSON
{"chain_guard":{"healthy":false,"should_pause_mining":false,"reason":"local_tip_ahead_of_peer_median","local_tip":100,"median_peer_tip":95,"peer_count":4,"near_tip_peers":1}}
JSON
    else
      cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    fi
    ;;
  generatetoaddress)
    echo "[]" >> "${STATE_DIR}/generate.log"
    echo '["deadbeef"]'
    ;;
  stop)
    echo stop >> "${STATE_DIR}/events.log"
    if [[ -f "${NODE_PIDFILE}" ]]; then
      pid="$(tr -d '\n' < "${NODE_PIDFILE}")"
      if [[ "${pid}" =~ ^[0-9]+$ ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
    fi
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-restart"
write_fake_btxd "${TMPDIR}/fake-btxd-restart"

STATE_DIR="${STATE_DIR}" "${TMPDIR}/fake-btxd-restart" -pid="${NODE_PIDFILE}"
STATE_DIR="${STATE_DIR}" "${TMPDIR}/fake-btxd-restart" -pid="${UNRELATED_PIDFILE}"
unrelated_pid="$(tr -d '\n' < "${UNRELATED_PIDFILE}")"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-restart" \
BTX_MINING_DAEMON="${TMPDIR}/fake-btxd-restart" \
BTX_MINING_NODE_PIDFILE="${NODE_PIDFILE}" \
BTX_MINING_WAIT_FOR_RPC_SECS=1 \
BTX_MINING_STOP_WAIT_SECS=1 \
BTX_MINING_RESTART_COOLDOWN_SECS=0 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=2 \
BTX_MINING_RPC_RESTART_THRESHOLD=2 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=0 \
BTX_MINING_MAX_LOOPS=6 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "chain-guard-advisory reason=local_tip_ahead_of_peer_median" "${RESULTS_DIR}/live-mining-health.log"
grep -q '\["deadbeef"\]' "${RESULTS_DIR}/live-mining-loop.log"
if grep -q "restarting-node reason=chain_guard" "${RESULTS_DIR}/live-mining-health.log"; then
  echo "chain guard advisory should not restart the node" >&2
  exit 1
fi
if grep -q '^stop$' "${STATE_DIR}/events.log"; then
  echo "chain guard advisory should not stop the supervised node" >&2
  exit 1
fi
[[ "$(grep -c '^start ' "${STATE_DIR}/events.log")" -eq 2 ]]
kill -0 "${unrelated_pid}" >/dev/null 2>&1

cleanup_pidfile "${NODE_PIDFILE}"
cleanup_pidfile "${UNRELATED_PIDFILE}"

STATE_DIR="${TMPDIR}/state-sync"
RESULTS_DIR="${TMPDIR}/results-sync"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-sync" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    count=0
    if [[ -f "${STATE_DIR}/sync-count" ]]; then
      count="$(cat "${STATE_DIR}/sync-count")"
    fi
    count=$((count + 1))
    printf '%s\n' "${count}" > "${STATE_DIR}/sync-count"
    cat <<JSON
{"chain_guard":{"healthy":false,"should_pause_mining":false,"reason":"local_tip_behind_peer_median","local_tip":$((100 + count)),"median_peer_tip":120,"peer_count":2,"near_tip_peers":0}}
JSON
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-sync"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-sync" \
BTX_MINING_HEALTH_RESTART_THRESHOLD=2 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=999 \
BTX_MINING_MAX_LOOPS=5 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

if grep -q "restarting-node reason=chain_guard_local_tip_behind_peer_median" "${RESULTS_DIR}/live-mining-health.log"; then
  echo "syncing node restarted even though local tip kept advancing" >&2
  exit 1
fi

STATE_DIR="${TMPDIR}/state-rpc-start"
RESULTS_DIR="${TMPDIR}/results-rpc-start"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"
NODE_PIDFILE="${STATE_DIR}/managed.pid"

cat > "${TMPDIR}/fake-cli-rpc-start" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

if [[ ! -f "${STATE_DIR}/node-ready" ]]; then
  echo "rpc offline" >&2
  exit 1
fi

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","recommended_action":"continue","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    ;;
  generatetoaddress)
    echo "[]" >> "${STATE_DIR}/generate.log"
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-rpc-start"

cat > "${TMPDIR}/fake-btxd-rpc-start" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
PIDFILE=""
for arg in "$@"; do
  case "${arg}" in
    -pid=*)
      PIDFILE="${arg#*=}"
      ;;
  esac
done
printf 'start %s\n' "$*" >> "${STATE_DIR}/events.log"
touch "${STATE_DIR}/node-ready"
(
  trap 'exit 0' TERM INT
  while true; do
    sleep 1
  done
) &
child_pid=$!
if [[ -n "${PIDFILE}" ]]; then
  printf '%s\n' "${child_pid}" > "${PIDFILE}"
fi
exit 0
EOF
chmod +x "${TMPDIR}/fake-btxd-rpc-start"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-rpc-start" \
BTX_MINING_DAEMON="${TMPDIR}/fake-btxd-rpc-start" \
BTX_MINING_NODE_PIDFILE="${NODE_PIDFILE}" \
BTX_MINING_WAIT_FOR_RPC_SECS=2 \
BTX_MINING_RPC_RESTART_THRESHOLD=5 \
BTX_MINING_MAX_LOOPS=4 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "rpc-unavailable-start-attempt" "${RESULTS_DIR}/live-mining-health.log"
grep -q "rpc-unavailable-start-complete" "${RESULTS_DIR}/live-mining-health.log"
grep -q -- "-pid=${NODE_PIDFILE}" "${STATE_DIR}/events.log"
grep -q '\["deadbeef"\]' "${RESULTS_DIR}/live-mining-loop.log"

cleanup_pidfile "${NODE_PIDFILE}"

STATE_DIR="${TMPDIR}/state-rpc-warmup"
RESULTS_DIR="${TMPDIR}/results-rpc-warmup"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"
NODE_PIDFILE="${STATE_DIR}/managed.pid"

cat > "${TMPDIR}/fake-cli-rpc-warmup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress|stop)
      cmd="${arg}"
      ;;
  esac
done

warmup_err() {
  cat >&2 <<ERR
error code: -28
error message:
Verifying blocks...
ERR
}

case "${cmd}" in
  getblockcount)
    if [[ ! -f "${STATE_DIR}/node-started" ]]; then
      echo "rpc offline" >&2
      exit 1
    fi
    if [[ ! -f "${STATE_DIR}/node-ready" ]]; then
      warmup_err
      exit 1
    fi
    echo 100
    ;;
  getmininginfo)
    if [[ ! -f "${STATE_DIR}/node-started" ]]; then
      echo "rpc offline" >&2
      exit 1
    fi
    count=0
    if [[ -f "${STATE_DIR}/mininginfo-count" ]]; then
      count="$(cat "${STATE_DIR}/mininginfo-count")"
    fi
    count=$((count + 1))
    printf '%s\n' "${count}" > "${STATE_DIR}/mininginfo-count"
    if (( count <= 2 )); then
      warmup_err
      exit 1
    fi
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","recommended_action":"continue","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    ;;
  generatetoaddress)
    count=0
    if [[ -f "${STATE_DIR}/generate-count" ]]; then
      count="$(cat "${STATE_DIR}/generate-count")"
    fi
    count=$((count + 1))
    printf '%s\n' "${count}" > "${STATE_DIR}/generate-count"
    if (( count == 1 )); then
      warmup_err
      exit 1
    fi
    echo "[]" >> "${STATE_DIR}/generate.log"
    echo '["deadbeef"]'
    ;;
  stop)
    echo stop >> "${STATE_DIR}/events.log"
    if [[ -f "${NODE_PIDFILE}" ]]; then
      pid="$(tr -d '\n' < "${NODE_PIDFILE}")"
      if [[ "${pid}" =~ ^[0-9]+$ ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
    fi
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-rpc-warmup"

cat > "${TMPDIR}/fake-btxd-rpc-warmup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
PIDFILE=""
for arg in "$@"; do
  case "${arg}" in
    -pid=*)
      PIDFILE="${arg#*=}"
      ;;
  esac
done
printf 'start %s\n' "$*" >> "${STATE_DIR}/events.log"
touch "${STATE_DIR}/node-started"
(
  sleep 2
  touch "${STATE_DIR}/node-ready"
) &
(
  trap 'exit 0' TERM INT
  while true; do
    sleep 1
  done
) &
child_pid=$!
if [[ -n "${PIDFILE}" ]]; then
  printf '%s\n' "${child_pid}" > "${PIDFILE}"
fi
exit 0
EOF
chmod +x "${TMPDIR}/fake-btxd-rpc-warmup"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-rpc-warmup" \
BTX_MINING_DAEMON="${TMPDIR}/fake-btxd-rpc-warmup" \
BTX_MINING_NODE_PIDFILE="${NODE_PIDFILE}" \
BTX_MINING_WAIT_FOR_RPC_SECS=5 \
BTX_MINING_RPC_RESTART_THRESHOLD=1 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=5 \
BTX_MINING_RESTART_COOLDOWN_SECS=0 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_MAX_LOOPS=7 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "rpc-warmup source=getblockcount" "${RESULTS_DIR}/live-mining-health.log"
grep -q "rpc-warmup source=getmininginfo" "${RESULTS_DIR}/live-mining-health.log"
grep -q "rpc-warmup source=generatetoaddress" "${RESULTS_DIR}/live-mining-health.log"
grep -q '\["deadbeef"\]' "${RESULTS_DIR}/live-mining-loop.log"
if grep -q "restarting-node reason=rpc_unavailable" "${RESULTS_DIR}/live-mining-health.log"; then
  echo "warmup should not trigger rpc_unavailable restart" >&2
  exit 1
fi
if grep -q "restarting-node reason=generate_rpc_failure" "${RESULTS_DIR}/live-mining-health.log"; then
  echo "warmup should not trigger generate_rpc_failure restart" >&2
  exit 1
fi
if grep -q '^stop$' "${STATE_DIR}/events.log"; then
  echo "warmup path should not stop a healthy supervised node" >&2
  exit 1
fi

cleanup_pidfile "${NODE_PIDFILE}"

STATE_DIR="${TMPDIR}/state-bootstrap"
RESULTS_DIR="${TMPDIR}/results-bootstrap"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-bootstrap" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|addnode|setnetworkactive)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":false,"should_pause_mining":false,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
JSON
    ;;
  addnode)
    printf '%s\n' "$*" >> "${STATE_DIR}/addnode.log"
    echo null
    ;;
  setnetworkactive)
    printf '%s\n' "$*" >> "${STATE_DIR}/setnetworkactive.log"
    echo true
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-bootstrap"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-bootstrap" \
BTX_MINING_BOOTSTRAP_ADDNODES="node-a.example:19335,node-b.example:19335" \
BTX_MINING_PEER_REMEDIATION_THRESHOLD=2 \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=999 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=99 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_MAX_LOOPS=4 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=2 succeeded=2 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "addnode node-a.example:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "addnode node-b.example:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "setnetworkactive true" "${STATE_DIR}/setnetworkactive.log"

STATE_DIR="${TMPDIR}/state-bootstrap-disabled"
RESULTS_DIR="${TMPDIR}/results-bootstrap-disabled"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"
printf '%s node-a.example:19335 previous_failure\n' "$(($(date +%s) + 3600))" > "${RESULTS_DIR}/disabled-peer-mesh.txt"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-bootstrap" \
BTX_MINING_BOOTSTRAP_ADDNODES="node-a.example:19335,node-b.example:19335" \
BTX_MINING_PEER_REMEDIATION_THRESHOLD=2 \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=999 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=99 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_MAX_LOOPS=4 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=1 succeeded=1 failed=0" "${RESULTS_DIR}/live-mining-health.log"
if grep -q "addnode node-a.example:19335 onetry" "${STATE_DIR}/addnode.log"; then
  echo "disabled mesh peer should not be retried during bootstrap refresh" >&2
  exit 1
fi
grep -q "addnode node-b.example:19335 onetry" "${STATE_DIR}/addnode.log"

STATE_DIR="${TMPDIR}/state-default-bootstrap"
RESULTS_DIR="${TMPDIR}/results-default-bootstrap"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-bootstrap" \
BTX_MINING_USE_DEFAULT_BOOTSTRAP_PEERS=1 \
BTX_MINING_PEER_REMEDIATION_THRESHOLD=2 \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=999 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=99 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_MAX_LOOPS=4 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=3 succeeded=3 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "addnode node.btx.dev:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "addnode node.btxchain.org:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "addnode node.btx.tools:19335 onetry" "${STATE_DIR}/addnode.log"

STATE_DIR="${TMPDIR}/state-cached-peers"
RESULTS_DIR="${TMPDIR}/results-cached-peers"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-cached-peers" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|getpeerinfo|generatetoaddress|addnode|setnetworkactive)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    count=0
    if [[ -f "${STATE_DIR}/mininginfo-count" ]]; then
      count="$(cat "${STATE_DIR}/mininginfo-count")"
    fi
    count=$((count + 1))
    printf '%s\n' "${count}" > "${STATE_DIR}/mininginfo-count"
    if (( count == 1 )); then
      cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":4,"near_tip_peers":4}}
JSON
    else
      cat <<JSON
{"chain_guard":{"healthy":false,"should_pause_mining":false,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
JSON
    fi
    ;;
  getpeerinfo)
    cat <<JSON
[{"inbound":false,"addr":"100.85.221.75:19335","connection_type":"manual","minping":0.001,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"node.btx.tools:19335","connection_type":"manual","minping":0.050,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"221.240.90.124:19335","connection_type":"outbound-full-relay","minping":0.003,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"147.182.192.221:19335","connection_type":"outbound-full-relay","minping":0.108,"synced_headers":100,"synced_blocks":100}]
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  addnode)
    printf '%s\n' "$*" >> "${STATE_DIR}/addnode.log"
    echo null
    ;;
  setnetworkactive)
    printf '%s\n' "$*" >> "${STATE_DIR}/setnetworkactive.log"
    echo true
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-cached-peers"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-cached-peers" \
BTX_MINING_PEER_REMEDIATION_THRESHOLD=2 \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=999 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=99 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_MAX_LOOPS=5 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

test "$(sed -n '1p' "${RESULTS_DIR}/live-peer-cache.txt")" = "221.240.90.124:19335"
test "$(sed -n '2p' "${RESULTS_DIR}/live-peer-cache.txt")" = "147.182.192.221:19335"
grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=4 succeeded=4 failed=0" "${RESULTS_DIR}/live-mining-health.log"
test "$(sed -n '1p' "${STATE_DIR}/addnode.log")" = "addnode 221.240.90.124:19335 onetry"
test "$(sed -n '2p' "${STATE_DIR}/addnode.log")" = "addnode 147.182.192.221:19335 onetry"
grep -q "addnode node.btx.tools:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "addnode 100.85.221.75:19335 onetry" "${STATE_DIR}/addnode.log"

STATE_DIR="${TMPDIR}/state-peer-topoff"
RESULTS_DIR="${TMPDIR}/results-peer-topoff"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-peer-topoff" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|getpeerinfo|generatetoaddress|addnode|setnetworkactive)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":4,"near_tip_peers":4}}
JSON
    ;;
  getpeerinfo)
    cat <<JSON
[{"inbound":false,"addr":"100.85.221.75:19335","connection_type":"manual","minping":0.001,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"100.115.222.45:19335","connection_type":"manual","minping":0.002,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"100.123.243.104:19335","connection_type":"manual","minping":0.003,"synced_headers":100,"synced_blocks":100},{"inbound":false,"addr":"100.127.0.10:19335","connection_type":"manual","minping":0.004,"synced_headers":100,"synced_blocks":100}]
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  addnode)
    printf '%s\n' "$*" >> "${STATE_DIR}/addnode.log"
    echo null
    ;;
  setnetworkactive)
    printf '%s\n' "$*" >> "${STATE_DIR}/setnetworkactive.log"
    echo true
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-peer-topoff"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-peer-topoff" \
BTX_MINING_BOOTSTRAP_ADDNODES="node-a.example:19335,node-b.example:19335" \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=999 \
BTX_MINING_PEER_REFRESH_LIMIT=2 \
BTX_MINING_MAX_LOOPS=3 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "peer-topology-low public_outbound=0 synced_public_outbound=0 full_relay_outbound=0 private_outbound=4 manual_private_outbound=4" "${RESULTS_DIR}/live-mining-health.log"
grep -q "peer-bootstrap-refresh reason=healthy_topoff attempted=2 succeeded=2 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "addnode node-a.example:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "setnetworkactive true" "${STATE_DIR}/setnetworkactive.log"

STATE_DIR="${TMPDIR}/state-peer-stall"
RESULTS_DIR="${TMPDIR}/results-peer-stall"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"
NODE_PIDFILE="${STATE_DIR}/managed.pid"

cat > "${TMPDIR}/fake-cli-peer-stall" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
NODE_PIDFILE="${BTX_MINING_NODE_PIDFILE:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|getpeerinfo|addnode|setnetworkactive|disconnectnode|stop)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":false,"should_pause_mining":false,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
JSON
    ;;
  getpeerinfo)
    cat <<JSON
[{"inbound":false,"addr":"stale-a.example:19335","connection_type":"manual","synced_headers":-1,"synced_blocks":-1},{"inbound":false,"addr":"healthy-a.example:19335","connection_type":"manual","synced_headers":100,"synced_blocks":100}]
JSON
    ;;
  addnode)
    printf '%s\n' "$*" >> "${STATE_DIR}/addnode.log"
    echo null
    ;;
  setnetworkactive)
    printf '%s\n' "$*" >> "${STATE_DIR}/setnetworkactive.log"
    echo true
    ;;
  disconnectnode)
    printf '%s\n' "$*" >> "${STATE_DIR}/disconnect.log"
    echo null
    ;;
  stop)
    printf 'stop %s\n' "$*" >> "${STATE_DIR}/events.log"
    if [[ -f "${NODE_PIDFILE}" ]]; then
      pid="$(tr -d '\n' < "${NODE_PIDFILE}")"
      if [[ "${pid}" =~ ^[0-9]+$ ]]; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
    fi
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-peer-stall"

cat > "${TMPDIR}/fake-btxd-peer-stall" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
PIDFILE=""
for arg in "$@"; do
  case "${arg}" in
    -pid=*)
      PIDFILE="${arg#*=}"
      ;;
  esac
done
printf 'start %s\n' "$*" >> "${STATE_DIR}/events.log"
(
  trap 'exit 0' TERM INT
  while true; do
    sleep 1
  done
) &
child_pid=$!
if [[ -n "${PIDFILE}" ]]; then
  printf '%s\n' "${child_pid}" > "${PIDFILE}"
fi
exit 0
EOF
chmod +x "${TMPDIR}/fake-btxd-peer-stall"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-peer-stall" \
BTX_MINING_DAEMON="${TMPDIR}/fake-btxd-peer-stall" \
BTX_MINING_NODE_PIDFILE="${NODE_PIDFILE}" \
BTX_MINING_BOOTSTRAP_ADDNODES="node-a.example:19335,node-b.example:19335" \
BTX_MINING_PEER_REMEDIATION_THRESHOLD=1 \
BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS=0 \
BTX_MINING_HEALTH_RESTART_THRESHOLD=2 \
BTX_MINING_RESTART_COOLDOWN_SECS=0 \
BTX_MINING_WAIT_FOR_RPC_SECS=1 \
BTX_MINING_STARTUP_GRACE_SECS=0 \
BTX_MINING_SYNC_STALL_RESTART_SECS=0 \
BTX_MINING_MAX_LOOPS=5 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "peer-stale-disconnect reason=insufficient_peer_consensus attempted=1 disconnected=1 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "stale-a.example:19335 stale_manual_peer" "${RESULTS_DIR}/disabled-peer-mesh.txt"
grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=2 succeeded=2 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "chain-guard-advisory reason=insufficient_peer_consensus" "${RESULTS_DIR}/live-mining-health.log"
if grep -q "restarting-node reason=chain_guard" "${RESULTS_DIR}/live-mining-health.log"; then
  echo "peer remediation should not restart the node for chain guard advisory state" >&2
  exit 1
fi
grep -q "disconnectnode stale-a.example:19335" "${STATE_DIR}/disconnect.log"
grep -q "addnode node-a.example:19335 onetry" "${STATE_DIR}/addnode.log"
grep -q "setnetworkactive true" "${STATE_DIR}/setnetworkactive.log"
if grep -q "disconnectnode healthy-a.example:19335" "${STATE_DIR}/disconnect.log"; then
  echo "healthy peer should not have been disconnected during stale-peer remediation" >&2
  exit 1
fi

cleanup_pidfile "${NODE_PIDFILE}"

STATE_DIR="${TMPDIR}/state-idle"
RESULTS_DIR="${TMPDIR}/results-idle"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-idle" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    ;;
  generatetoaddress)
    echo "[]" >> "${STATE_DIR}/generate.log"
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-idle"

cat > "${TMPDIR}/should-mine" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
count=0
if [[ -f "${STATE_DIR}/should-mine-count" ]]; then
  count="$(cat "${STATE_DIR}/should-mine-count")"
fi
count=$((count + 1))
printf '%s\n' "${count}" > "${STATE_DIR}/should-mine-count"
if (( count <= 2 )); then
  exit 1
fi
exit 0
EOF
chmod +x "${TMPDIR}/should-mine"

should_mine_state_dir="${STATE_DIR}"
BTX_MINING_CLI="${TMPDIR}/fake-cli-idle" \
BTX_MINING_SHOULD_MINE_COMMAND="STATE_DIR=${should_mine_state_dir} ${TMPDIR}/should-mine" \
STATE_DIR="${should_mine_state_dir}" \
BTX_MINING_MAX_LOOPS=5 \
"${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "idle-gate-pause exit=1" "${RESULTS_DIR}/live-mining-health.log"
grep -q "idle-gate-open" "${RESULTS_DIR}/live-mining-health.log"
[[ "$(wc -l < "${STATE_DIR}/generate.log")" -eq 2 ]]

NOJQ_BIN="${TMPDIR}/nojq-bin"
mkdir -p "${NOJQ_BIN}"
for cmd in cat dirname mkdir nohup rm; do
  target="$(command -v "${cmd}")"
  ln -sf "${target}" "${NOJQ_BIN}/${cmd}"
done

NOJQ_STDERR="${TMPDIR}/start-nojq.err"
set +e
PATH="${NOJQ_BIN}" /bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --results-dir="${TMPDIR}/results-nojq" \
  --address-file="${TMPDIR}/address.txt" \
  >/dev/null 2>"${NOJQ_STDERR}"
status=$?
set -e

[[ "${status}" -ne 0 ]]
grep -q "Missing required command: jq" "${NOJQ_STDERR}"
[[ ! -f "${TMPDIR}/results-nojq/live-mining-loop.pid" ]]

START_FAIL_STDERR="${TMPDIR}/start-loop-fail.err"
set +e
/bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --results-dir="${TMPDIR}/results-start-fail" \
  --address-file="${TMPDIR}/address.txt" \
  --cli="${TMPDIR}/missing-cli" \
  >/dev/null 2>"${START_FAIL_STDERR}"
status=$?
set -e

[[ "${status}" -ne 0 ]]
grep -q "Live mining loop exited before startup verification completed" "${START_FAIL_STDERR}"
grep -q "Missing required command: ${TMPDIR}/missing-cli" "${START_FAIL_STDERR}"
[[ ! -f "${TMPDIR}/results-start-fail/live-mining-loop.pid" ]]

STATE_DIR="${TMPDIR}/state-foreground"
RESULTS_DIR="${TMPDIR}/results-foreground"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-foreground" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-foreground"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-foreground" \
BTX_MINING_MAX_LOOPS=2 \
/bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --foreground \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -q "loop-start datadir=default wallet=miner" "${RESULTS_DIR}/live-mining-health.log"
grep -q '\["deadbeef"\]' "${RESULTS_DIR}/live-mining-loop.log"
[[ ! -f "${RESULTS_DIR}/live-mining-loop.pid" ]]

STATE_DIR="${TMPDIR}/state-launch-cwd"
RESULTS_DIR="${TMPDIR}/results-launch-cwd"
LAUNCH_CWD="${TMPDIR}/stable-launch-cwd"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}" "${LAUNCH_CWD}"
EXPECTED_LAUNCH_CWD="$(cd "${LAUNCH_CWD}" && pwd -P)"

cat > "${TMPDIR}/fake-cli-launch-cwd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
pwd -P > "${STATE_DIR}/cwd.txt"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8}}
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-launch-cwd"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-launch-cwd" \
BTX_MINING_MAX_LOOPS=2 \
BTX_MINING_START_VERIFY_SECS=0 \
/bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 \
  --launch-cwd="${LAUNCH_CWD}" >/dev/null

for _ in 1 2 3 4 5; do
  [[ -f "${STATE_DIR}/cwd.txt" ]] && break
  sleep 1
done
grep -qx "${EXPECTED_LAUNCH_CWD}" "${STATE_DIR}/cwd.txt"

STATE_DIR="${TMPDIR}/state-backend-requirement"
RESULTS_DIR="${TMPDIR}/results-backend-requirement"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-backend-requirement" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8},"backend_runtime":{"requested_backend":"metal","active_backend":"cpu","backend_selection_reason":"metal_unavailable_fallback_to_cpu:test","required_backend_enabled":true,"required_backend":"metal","required_backend_valid":true,"required_backend_satisfied":false,"metal_fallbacks_to_cpu":0,"cuda_fallbacks_to_cpu":0}}
JSON
    ;;
  generatetoaddress)
    echo generate >> "${STATE_DIR}/generate.log"
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-backend-requirement"

set +e
STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-backend-requirement" \
/bin/bash "${SCRIPT_DIR}/live-mining-loop.sh" \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 \
  --require-backend=metal >/dev/null 2>&1
status=$?
set -e

[[ "${status}" -ne 0 ]]
grep -q "backend-requirement-failed required=metal active=cpu" "${RESULTS_DIR}/live-mining-health.log"
[[ ! -f "${STATE_DIR}/generate.log" ]]

STATE_DIR="${TMPDIR}/state-start-backend-env"
RESULTS_DIR="${TMPDIR}/results-start-backend-env"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-start-backend-env" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
printf '%s\n' "${BTX_MATMUL_BACKEND:-}" > "${STATE_DIR}/backend.env"
printf '%s\n' "${BTX_MATMUL_REQUIRE_BACKEND:-}" > "${STATE_DIR}/require.env"
printf '%s\n' "${BTX_MATMUL_GPU_INPUTS:-}" > "${STATE_DIR}/gpu-inputs.env"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8},"backend_runtime":{"requested_backend":"metal","active_backend":"metal","backend_selection_reason":"requested_backend_available","required_backend_enabled":true,"required_backend":"metal","required_backend_valid":true,"required_backend_satisfied":true,"metal_fallbacks_to_cpu":0,"cuda_fallbacks_to_cpu":0}}
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-start-backend-env"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-start-backend-env" \
BTX_MINING_MAX_LOOPS=2 \
/bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --foreground \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 \
  --backend=metal \
  --require-backend=metal \
  --gpu-inputs=1 >/dev/null 2>&1

grep -qx "metal" "${STATE_DIR}/backend.env"
grep -qx "metal" "${STATE_DIR}/require.env"
grep -qx "1" "${STATE_DIR}/gpu-inputs.env"
grep -q "backend=metal require_backend=metal" "${RESULTS_DIR}/live-mining-health.log"
grep -q "gpu_inputs=1" "${RESULTS_DIR}/live-mining-health.log"

STATE_DIR="${TMPDIR}/state-start-apple-defaults"
RESULTS_DIR="${TMPDIR}/results-start-apple-defaults"
mkdir -p "${STATE_DIR}" "${RESULTS_DIR}"

cat > "${TMPDIR}/fake-cli-start-apple-defaults" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${STATE_DIR:?}"
printf '%s\n' "${BTX_MATMUL_BACKEND:-}" > "${STATE_DIR}/backend.env"
printf '%s\n' "${BTX_MATMUL_REQUIRE_BACKEND:-}" > "${STATE_DIR}/require.env"
printf '%s\n' "${BTX_MATMUL_GPU_INPUTS:-}" > "${STATE_DIR}/gpu-inputs.env"
cmd=""
for arg in "$@"; do
  case "${arg}" in
    getblockcount|getmininginfo|generatetoaddress)
      cmd="${arg}"
      ;;
  esac
done

case "${cmd}" in
  getblockcount)
    echo 100
    ;;
  getmininginfo)
    cat <<JSON
{"chain_guard":{"healthy":true,"should_pause_mining":false,"reason":"ok","local_tip":100,"median_peer_tip":100,"peer_count":8,"near_tip_peers":8},"backend_runtime":{"requested_backend":"metal","active_backend":"metal","backend_selection_reason":"requested_backend_available","required_backend_enabled":true,"required_backend":"metal","required_backend_valid":true,"required_backend_satisfied":true,"metal_fallbacks_to_cpu":0,"metal_nonce_seed_scan_fallbacks_to_cpu":0,"cuda_fallbacks_to_cpu":0,"cuda_nonce_seed_scan_fallbacks_to_cpu":0}}
JSON
    ;;
  generatetoaddress)
    echo '["deadbeef"]'
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${TMPDIR}/fake-cli-start-apple-defaults"

STATE_DIR="${STATE_DIR}" \
BTX_MINING_HOST_OS_FOR_TEST=Darwin \
BTX_MINING_HOST_ARCH_FOR_TEST=arm64 \
BTX_MINING_CLI="${TMPDIR}/fake-cli-start-apple-defaults" \
BTX_MINING_MAX_LOOPS=2 \
/bin/bash "${SCRIPT_DIR}/start-live-mining.sh" \
  --foreground \
  --results-dir="${RESULTS_DIR}" \
  --address-file="${TMPDIR}/address.txt" \
  --sleep=0 >/dev/null 2>&1

grep -qx "metal" "${STATE_DIR}/backend.env"
grep -qx "metal" "${STATE_DIR}/require.env"
grep -qx "1" "${STATE_DIR}/gpu-inputs.env"
grep -q "daemonize=0 backend=metal require_backend=metal" "${RESULTS_DIR}/live-mining-health.log"
grep -q "gpu_inputs=1 apple_silicon_defaults=1" "${RESULTS_DIR}/live-mining-health.log"

RESULTS_DIR="${TMPDIR}/results-stop"
mkdir -p "${RESULTS_DIR}"

(
  trap 'exit 0' TERM INT
  while true; do
    sleep 1
  done
) &
managed_pid=$!
printf '%s\n' "${managed_pid}" > "${RESULTS_DIR}/live-mining-loop.pid"

cat > "${TMPDIR}/pattern-sleeper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
trap 'exit 0' TERM INT
while true; do
  sleep 1
done
EOF
chmod +x "${TMPDIR}/pattern-sleeper"
"${TMPDIR}/pattern-sleeper" fake-cli-pattern &
unrelated_pid=$!

BTX_MINING_CLI_PATTERN="fake-cli-pattern" /bin/bash "${SCRIPT_DIR}/stop-live-mining.sh" \
  --results-dir="${RESULTS_DIR}" >/dev/null

if kill -0 "${managed_pid}" >/dev/null 2>&1; then
  echo "managed live-mining loop pid still running after stop" >&2
  exit 1
fi
kill -0 "${unrelated_pid}" >/dev/null 2>&1
kill "${unrelated_pid}" >/dev/null 2>&1 || true

start_help="$("${SCRIPT_DIR}/start-live-mining.sh" --help)"
live_help="$("${SCRIPT_DIR}/live-mining-loop.sh" --help)"
stop_help="$("${SCRIPT_DIR}/stop-live-mining.sh" --help)"

grep -q "Usage: start-live-mining.sh" <<< "${start_help}"
grep -q -- "--cli=PATH" <<< "${start_help}"
grep -q -- "--foreground" <<< "${start_help}"
grep -q -- "--launch-cwd=PATH" <<< "${start_help}"
grep -q -- "--require-backend=NAME" <<< "${start_help}"
grep -q -- "--daemonize=0|1" <<< "${start_help}"
grep -q -- "--gpu-inputs=auto|0|1" <<< "${start_help}"
grep -q "Usage: live-mining-loop.sh" <<< "${live_help}"
grep -q -- "--should-mine-command=CMD" <<< "${live_help}"
grep -q -- "--require-backend=NAME" <<< "${live_help}"
grep -q -- "--daemonize=0|1" <<< "${live_help}"
grep -q -- "--gpu-inputs=auto|0|1" <<< "${live_help}"
grep -q "Usage: stop-live-mining.sh" <<< "${stop_help}"
grep -q -- "--results-dir=PATH" <<< "${stop_help}"

printf 'live-mining-loop health tests passed\n'
