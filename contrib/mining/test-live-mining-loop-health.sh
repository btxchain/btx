#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

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
NODE_PIDFILE="${NODE_PIDFILE:?}"
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
{"chain_guard":{"healthy":false,"should_pause_mining":true,"reason":"local_tip_ahead_of_peer_median","local_tip":100,"median_peer_tip":95,"peer_count":4,"near_tip_peers":1}}
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
NODE_PIDFILE="${NODE_PIDFILE}" \
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

grep -q "restarting-node reason=chain_guard_stalled_local_tip_ahead_of_peer_median" "${RESULTS_DIR}/live-mining-health.log"
grep -q -- '-maxconnections=32' "${STATE_DIR}/events.log"
grep -q -- "-pid=${NODE_PIDFILE}" "${STATE_DIR}/events.log"
grep -q '\["deadbeef"\]' "${RESULTS_DIR}/live-mining-loop.log"
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
{"chain_guard":{"healthy":false,"should_pause_mining":true,"reason":"local_tip_behind_peer_median","local_tip":$((100 + count)),"median_peer_tip":120,"peer_count":2,"near_tip_peers":0}}
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
{"chain_guard":{"healthy":false,"should_pause_mining":true,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
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
{"chain_guard":{"healthy":false,"should_pause_mining":true,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
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
NODE_PIDFILE="${NODE_PIDFILE:?}"
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
{"chain_guard":{"healthy":false,"should_pause_mining":true,"reason":"insufficient_peer_consensus","local_tip":100,"median_peer_tip":-1,"peer_count":0,"near_tip_peers":0}}
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
NODE_PIDFILE="${NODE_PIDFILE}" \
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
grep -q "peer-bootstrap-refresh reason=insufficient_peer_consensus attempted=2 succeeded=2 failed=0" "${RESULTS_DIR}/live-mining-health.log"
grep -q "restarting-node reason=chain_guard_insufficient_peer_consensus" "${RESULTS_DIR}/live-mining-health.log"
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

STATE_DIR="${STATE_DIR}" \
BTX_MINING_CLI="${TMPDIR}/fake-cli-idle" \
BTX_MINING_SHOULD_MINE_COMMAND="STATE_DIR=${STATE_DIR} ${TMPDIR}/should-mine" \
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
grep -q "Usage: live-mining-loop.sh" <<< "${live_help}"
grep -q -- "--should-mine-command=CMD" <<< "${live_help}"
grep -q "Usage: stop-live-mining.sh" <<< "${stop_help}"
grep -q -- "--results-dir=PATH" <<< "${stop_help}"

printf 'live-mining-loop health tests passed\n'
