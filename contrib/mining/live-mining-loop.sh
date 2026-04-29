#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DATADIR="${BTX_MINING_DATADIR:-}"
CONF="${BTX_MINING_CONF:-}"
CHAIN="${BTX_MINING_CHAIN:-}"
RPC_CONNECT="${BTX_MINING_RPCCONNECT:-}"
RPC_PORT="${BTX_MINING_RPCPORT:-}"
RPC_USER="${BTX_MINING_RPCUSER:-}"
RPC_PASSWORD="${BTX_MINING_RPCPASSWORD:-}"
RPC_COOKIEFILE="${BTX_MINING_RPCCOOKIEFILE:-}"
WALLET="${BTX_MINING_WALLET:-miner}"
ADDRESS=""
ADDRESS_FILE="${BTX_MINING_ADDRESS_FILE:-}"
SLEEP_SECS="${BTX_MINING_SLEEP_SECS:-1}"
RESULTS_DIR="${BTX_MINING_RESULTS_DIR:-}"
# Leave enough automatic peer slots available for normal discovery to widen
# beyond a tiny manual peer island during solo mining.
MAXCONNECTIONS="${BTX_MINING_MAXCONNECTIONS:-32}"
RPC_RESTART_THRESHOLD="${BTX_MINING_RPC_RESTART_THRESHOLD:-5}"
HEALTH_RESTART_THRESHOLD="${BTX_MINING_HEALTH_RESTART_THRESHOLD:-20}"
RESTART_COOLDOWN_SECS="${BTX_MINING_RESTART_COOLDOWN_SECS:-60}"
WAIT_FOR_RPC_SECS="${BTX_MINING_WAIT_FOR_RPC_SECS:-90}"
STARTUP_GRACE_SECS="${BTX_MINING_STARTUP_GRACE_SECS:-120}"
STOP_WAIT_SECS="${BTX_MINING_STOP_WAIT_SECS:-30}"
PEER_REMEDIATION_THRESHOLD="${BTX_MINING_PEER_REMEDIATION_THRESHOLD:-3}"
PEER_REMEDIATION_COOLDOWN_SECS="${BTX_MINING_PEER_REMEDIATION_COOLDOWN_SECS:-30}"
PEER_CACHE_LIMIT="${BTX_MINING_PEER_CACHE_LIMIT:-24}"
PEER_REFRESH_LIMIT="${BTX_MINING_PEER_REFRESH_LIMIT:-12}"
HEALTHY_PUBLIC_PEER_TARGET="${BTX_MINING_HEALTHY_PUBLIC_PEER_TARGET:-4}"
HEALTHY_FULL_RELAY_PEER_TARGET="${BTX_MINING_HEALTHY_FULL_RELAY_PEER_TARGET:-4}"
SYNC_STALL_RESTART_SECS="${BTX_MINING_SYNC_STALL_RESTART_SECS:-300}"
BOOTSTRAP_ADDNODES="${BTX_MINING_BOOTSTRAP_ADDNODES:-${BTX_MINING_BOOTSTRAP_PEERS:-}}"
MAX_LOOPS="${BTX_MINING_MAX_LOOPS:-0}"
SHOULD_MINE_COMMAND="${BTX_MINING_SHOULD_MINE_COMMAND:-}"
NODE_PIDFILE="${BTX_MINING_NODE_PIDFILE:-}"

CLI="${BTX_MINING_CLI:-btx-cli}"
DAEMON="${BTX_MINING_DAEMON:-btxd}"
START_CMD="${BTX_MINING_START_CMD:-}"
DAEMON_ARGS="${BTX_MINING_DAEMON_ARGS:-}"

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Continuously mine with local health checks, optional idleness gating, and
restart-safe supervision for a BTX node.

Options:
  --datadir=PATH            BTX datadir to supervise
  --conf=PATH               BTX config file used by the daemon/CLI
  --chain=NAME              BTX chain name (main, testnet4, regtest, ...)
  --rpcconnect=HOST         RPC host override
  --rpcport=PORT            RPC port override
  --rpcuser=USER            RPC username override
  --rpcpassword=PASS        RPC password override
  --rpccookiefile=PATH      RPC cookie file override
  --wallet=NAME             Wallet used for mining RPCs (default: miner)
  --address=ADDR            Explicit payout address
  --address-file=PATH       File containing the payout address
  --sleep=SECS              Seconds between loop iterations
  --results-dir=PATH        Directory for pid/log/health files
  --should-mine-command=CMD Idle gate command; mine only when it exits 0
  --node-pidfile=PATH       PID file for the supervised daemon
  --cli=PATH                Path to btx-cli (default: btx-cli)
  --daemon=PATH             Path to btxd (default: btxd)
  --help, -h                Show this help text
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --help|-h)
      print_usage
      exit 0
      ;;
    --datadir=*)
      DATADIR="${arg#*=}"
      ;;
    --conf=*)
      CONF="${arg#*=}"
      ;;
    --chain=*)
      CHAIN="${arg#*=}"
      ;;
    --rpcconnect=*)
      RPC_CONNECT="${arg#*=}"
      ;;
    --rpcport=*)
      RPC_PORT="${arg#*=}"
      ;;
    --rpcuser=*)
      RPC_USER="${arg#*=}"
      ;;
    --rpcpassword=*)
      RPC_PASSWORD="${arg#*=}"
      ;;
    --rpccookiefile=*)
      RPC_COOKIEFILE="${arg#*=}"
      ;;
    --wallet=*)
      WALLET="${arg#*=}"
      ;;
    --address=*)
      ADDRESS="${arg#*=}"
      ;;
    --address-file=*)
      ADDRESS_FILE="${arg#*=}"
      ;;
    --sleep=*)
      SLEEP_SECS="${arg#*=}"
      ;;
    --results-dir=*)
      RESULTS_DIR="${arg#*=}"
      ;;
    --should-mine-command=*)
      SHOULD_MINE_COMMAND="${arg#*=}"
      ;;
    --node-pidfile=*)
      NODE_PIDFILE="${arg#*=}"
      ;;
    --daemon=*)
      DAEMON="${arg#*=}"
      ;;
    --cli=*)
      CLI="${arg#*=}"
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${RESULTS_DIR}" ]]; then
  if [[ -n "${DATADIR}" ]]; then
    RESULTS_DIR="${DATADIR}/mining-ops"
  else
    RESULTS_DIR="${PWD}/mining-ops"
  fi
fi

mkdir -p "${RESULTS_DIR}"
LOG="${RESULTS_DIR}/live-mining-loop.log"
ERR="${RESULTS_DIR}/live-mining-loop.err"
HEALTH_LOG="${RESULTS_DIR}/live-mining-health.log"
PIDFILE="${RESULTS_DIR}/live-mining-loop.pid"
PEER_CACHE_FILE="${RESULTS_DIR}/live-peer-cache.txt"

if [[ -z "${NODE_PIDFILE}" ]]; then
  NODE_PIDFILE="${RESULTS_DIR}/btxd-supervised.pid"
fi

touch "${LOG}" "${ERR}" "${HEALTH_LOG}"

require_command() {
  local name="$1"
  if [[ "${name}" == */* ]]; then
    if [[ ! -x "${name}" ]]; then
      echo "Missing required command: ${name}" >&2
      exit 1
    fi
    return
  fi
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "Missing required command: ${name}" >&2
    exit 1
  fi
}

require_command jq
require_command "${CLI}"

if [[ -z "${ADDRESS}" ]]; then
  if [[ -z "${ADDRESS_FILE}" ]]; then
    echo "Either --address or --address-file must be provided" >&2
    exit 1
  fi
  if [[ ! -f "${ADDRESS_FILE}" ]]; then
    echo "Missing address file: ${ADDRESS_FILE}" >&2
    exit 1
  fi
  ADDRESS="$(tr -d '\n' < "${ADDRESS_FILE}")"
fi

if [[ -z "${ADDRESS}" ]]; then
  echo "Mining address is empty" >&2
  exit 1
fi

log_health() {
  local timestamp
  timestamp="$(date '+%Y-%m-%dT%H:%M:%S%z')"
  printf '%s %s\n' "${timestamp}" "$*" | tee -a "${HEALTH_LOG}"
}

default_datadir_pidfile() {
  if [[ -n "${DATADIR}" ]]; then
    printf '%s\n' "${DATADIR}/btxd.pid"
  fi
}

append_file_if_present() {
  local src="$1"
  local dst="$2"
  if [[ -s "${src}" ]]; then
    cat "${src}" >> "${dst}"
  fi
}

derive_recommended_action() {
  local reason="$1"
  case "${reason}" in
    disabled|healthy|ok)
      printf 'continue\n'
      ;;
    initial_block_download|local_tip_ahead_of_peer_median|local_tip_behind_peer_median)
      printf 'catch_up\n'
      ;;
    *)
      printf 'pause\n'
      ;;
  esac
}

supervised_node_running() {
  local pid
  pid="$(read_supervised_node_pid || true)"
  if [[ -z "${pid}" ]]; then
    return 1
  fi
  kill -0 "${pid}" >/dev/null 2>&1
}

rpc_cli() {
  local cmd=("${CLI}")
  if [[ -n "${DATADIR}" ]]; then
    cmd+=("-datadir=${DATADIR}")
  fi
  if [[ -n "${CONF}" ]]; then
    cmd+=("-conf=${CONF}")
  fi
  if [[ -n "${CHAIN}" ]]; then
    cmd+=("-chain=${CHAIN}")
  fi
  if [[ -n "${RPC_CONNECT}" ]]; then
    cmd+=("-rpcconnect=${RPC_CONNECT}")
  fi
  if [[ -n "${RPC_PORT}" ]]; then
    cmd+=("-rpcport=${RPC_PORT}")
  fi
  if [[ -n "${RPC_USER}" ]]; then
    cmd+=("-rpcuser=${RPC_USER}")
  fi
  if [[ -n "${RPC_PASSWORD}" ]]; then
    cmd+=("-rpcpassword=${RPC_PASSWORD}")
  fi
  if [[ -n "${RPC_COOKIEFILE}" ]]; then
    cmd+=("-rpccookiefile=${RPC_COOKIEFILE}")
  fi
  "${cmd[@]}" "$@"
}

rpc_wallet_cli() {
  local cmd=("${CLI}")
  if [[ -n "${DATADIR}" ]]; then
    cmd+=("-datadir=${DATADIR}")
  fi
  if [[ -n "${CONF}" ]]; then
    cmd+=("-conf=${CONF}")
  fi
  if [[ -n "${CHAIN}" ]]; then
    cmd+=("-chain=${CHAIN}")
  fi
  if [[ -n "${RPC_CONNECT}" ]]; then
    cmd+=("-rpcconnect=${RPC_CONNECT}")
  fi
  if [[ -n "${RPC_PORT}" ]]; then
    cmd+=("-rpcport=${RPC_PORT}")
  fi
  if [[ -n "${RPC_USER}" ]]; then
    cmd+=("-rpcuser=${RPC_USER}")
  fi
  if [[ -n "${RPC_PASSWORD}" ]]; then
    cmd+=("-rpcpassword=${RPC_PASSWORD}")
  fi
  if [[ -n "${RPC_COOKIEFILE}" ]]; then
    cmd+=("-rpccookiefile=${RPC_COOKIEFILE}")
  fi
  cmd+=("-rpcwallet=${WALLET}")
  "${cmd[@]}" "$@"
}

rpc_error_is_warmup_file() {
  local err_file="$1"
  [[ -f "${err_file}" ]] || return 1
  grep -Eiq '(^error code: -28$|error code: -28|rpc in warmup|loading block index|verifying blocks|loading wallet|rescanning|activating best chain|rewinding blocks)' "${err_file}"
}

note_rpc_ready() {
  if [[ "${last_rpc_fault_state}" == ready ]]; then
    return
  fi
  log_health "rpc-ready source=${last_rpc_fault_state}"
  last_rpc_fault_state="ready"
}

note_rpc_warmup() {
  local source="$1"
  local now
  local next_grace
  now="$(date +%s)"
  next_grace=$((now + STARTUP_GRACE_SECS))
  if (( next_grace > grace_until_epoch )); then
    grace_until_epoch="${next_grace}"
  fi
  rpc_failure_streak=0
  health_failure_streak=0
  if [[ "${last_rpc_fault_state}" != "warmup:${source}" ]]; then
    log_health "rpc-warmup source=${source} grace_until=${grace_until_epoch}"
  fi
  last_rpc_fault_state="warmup:${source}"
}

wait_for_rpc_ready() {
  local limit="$1"
  local i
  local saw_warmup=0
  local tmp_err
  for ((i = 0; i < limit; ++i)); do
    tmp_err="$(mktemp)"
    if rpc_cli getblockcount >/dev/null 2>"${tmp_err}"; then
      rm -f "${tmp_err}"
      note_rpc_ready
      return 0
    fi
    if rpc_error_is_warmup_file "${tmp_err}"; then
      saw_warmup=1
      note_rpc_warmup "getblockcount"
    fi
    rm -f "${tmp_err}"
    sleep 1
  done
  if (( saw_warmup )); then
    return 2
  fi
  return 1
}

start_node() {
  rm -f "${NODE_PIDFILE}"
  if [[ -n "${START_CMD}" ]]; then
    eval "${START_CMD}" >>"${LOG}" 2>>"${ERR}"
    return
  fi

  require_command "${DAEMON}"
  local cmd=("${DAEMON}" "-daemon" "-maxconnections=${MAXCONNECTIONS}" "-pid=${NODE_PIDFILE}")
  if [[ -n "${DATADIR}" ]]; then
    cmd+=("-datadir=${DATADIR}")
  fi
  if [[ -n "${CONF}" ]]; then
    cmd+=("-conf=${CONF}")
  fi
  if [[ -n "${CHAIN}" ]]; then
    cmd+=("-chain=${CHAIN}")
  fi
  if [[ -n "${RPC_PORT}" ]]; then
    cmd+=("-rpcport=${RPC_PORT}")
  fi
  if [[ -n "${RPC_USER}" ]]; then
    cmd+=("-rpcuser=${RPC_USER}")
  fi
  if [[ -n "${RPC_PASSWORD}" ]]; then
    cmd+=("-rpcpassword=${RPC_PASSWORD}")
  fi
  if [[ -n "${RPC_COOKIEFILE}" ]]; then
    cmd+=("-rpccookiefile=${RPC_COOKIEFILE}")
  fi
  if [[ -n "${DAEMON_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${DAEMON_ARGS} )
    cmd+=("${extra[@]}")
  fi
  "${cmd[@]}" >>"${LOG}" 2>>"${ERR}"
}

read_supervised_node_pid() {
  local pidfile
  local pid
  for pidfile in "${NODE_PIDFILE}" "$(default_datadir_pidfile)"; do
    [[ -n "${pidfile}" ]] || continue
    [[ -f "${pidfile}" ]] || continue
    pid="$(tr -d '\n' < "${pidfile}")"
    if [[ "${pid}" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "${pid}"
      return 0
    fi
  done
  return 1
}

wait_for_supervised_pid_exit() {
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

update_chain_progress() {
  local now="$1"
  local local_tip="$2"
  local peer_count="$3"

  if (( last_local_tip < 0 || local_tip > last_local_tip )); then
    last_local_tip="${local_tip}"
    last_tip_progress_epoch="${now}"
  fi

  if (( peer_count > 0 )); then
    last_peer_seen_epoch="${now}"
  fi
}

update_reason_streak() {
  local reason="$1"

  if [[ "${reason}" == "${last_health_reason}" ]]; then
    ((same_reason_streak += 1))
  else
    last_health_reason="${reason}"
    same_reason_streak=1
  fi
}

refresh_live_peer_cache_from_json() {
  local local_tip="${1:-0}"
  local tmp_cache

  tmp_cache="$(mktemp)"
  if jq -r --argjson local_tip "${local_tip}" --argjson cache_limit "${PEER_CACHE_LIMIT}" '
    def is_private_peer:
      (.addr // "") | test("^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|^127\\.|^169\\.254\\.|^localhost($|:)|^\\[?::1\\]?|^\\[?(fc|fd|fe80):"; "i");
    [
      .[]
      | select((.inbound // false) | not)
      | {
          addr: (.addr // ""),
          private: is_private_peer,
          synced: (((.synced_blocks // -1000000) >= ($local_tip - 1)) or ((.synced_headers // -1000000) >= ($local_tip - 1))),
          full_relay: ((.connection_type // "") == "outbound-full-relay"),
          manual: ((.connection_type // "") == "manual"),
          minping: (.minping // 999999),
          addr_sort: (.addr // "")
        }
      | select(.addr != "")
    ]
    | sort_by([.private, (.synced | not), (.full_relay | not), .manual, .minping, .addr_sort])
    | .[:$cache_limit]
    | .[].addr
  ' | awk 'NF && !seen[$0]++' > "${tmp_cache}"; then
    if [[ -s "${tmp_cache}" ]]; then
      mv "${tmp_cache}" "${PEER_CACHE_FILE}"
      return 0
    fi
  fi

  rm -f "${tmp_cache}"
  return 1
}

summarize_outbound_peer_mix_from_json() {
  local local_tip="${1:-0}"

  jq -c --argjson local_tip "${local_tip}" '
    def is_private_peer:
      (.addr // "") | test("^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|^127\\.|^169\\.254\\.|^localhost($|:)|^\\[?::1\\]?|^\\[?(fc|fd|fe80):"; "i");
    [
      .[]
      | select((.inbound // false) | not)
      | {
          private: is_private_peer,
          manual: ((.connection_type // "") == "manual"),
          full_relay: ((.connection_type // "") == "outbound-full-relay"),
          synced: (((.synced_blocks // -1000000) >= ($local_tip - 1)) or ((.synced_headers // -1000000) >= ($local_tip - 1)))
        }
    ] as $outbound
    | {
        outbound: ($outbound | length),
        public_outbound: ($outbound | map(select(.private | not)) | length),
        private_outbound: ($outbound | map(select(.private)) | length),
        full_relay_outbound: ($outbound | map(select(.full_relay)) | length),
        synced_public_outbound: ($outbound | map(select((.private | not) and .synced)) | length),
        manual_private_outbound: ($outbound | map(select(.manual and .private)) | length)
      }
  '
}

refresh_live_peer_cache() {
  local local_tip="${1:-${last_local_tip:-0}}"
  local tmp_err
  local peer_json

  tmp_err="$(mktemp)"
  if peer_json="$(rpc_cli getpeerinfo 2>"${tmp_err}")"; then
    rm -f "${tmp_err}"
    refresh_live_peer_cache_from_json "${local_tip}" <<<"${peer_json}"
    return $?
  fi

  append_file_if_present "${tmp_err}" "${ERR}"
  rm -f "${tmp_err}"
  return 1
}

is_private_peer_addr() {
  local node="${1:-}"

  [[ "${node}" =~ ^10\. ]] || \
  [[ "${node}" =~ ^192\.168\. ]] || \
  [[ "${node}" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
  [[ "${node}" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]] || \
  [[ "${node}" =~ ^127\. ]] || \
  [[ "${node}" =~ ^169\.254\. ]] || \
  [[ "${node}" =~ ^localhost(:|$) ]] || \
  [[ "${node}" =~ ^\[?::1\]? ]] || \
  [[ "${node}" =~ ^\[?(fc|fd|fe80): ]]
}

collect_bootstrap_nodes() {
  local node
  local bootstrap_nodes=()
  local public_cached=()
  local private_cached=()

  if [[ -f "${PEER_CACHE_FILE}" ]]; then
    while IFS= read -r node; do
      [[ -n "${node}" ]] || continue
      if is_private_peer_addr "${node}"; then
        private_cached+=("${node}")
      else
        public_cached+=("${node}")
      fi
    done < "${PEER_CACHE_FILE}"
  fi

  if [[ -n "${BOOTSTRAP_ADDNODES}" ]]; then
    IFS=',' read -r -a bootstrap_nodes <<< "${BOOTSTRAP_ADDNODES}"
  fi

  {
    if (( ${#public_cached[@]} > 0 )); then
      for node in "${public_cached[@]}"; do
        printf '%s\n' "${node}"
      done
    fi
    if (( ${#bootstrap_nodes[@]} > 0 )); then
      for node in "${bootstrap_nodes[@]}"; do
        printf '%s\n' "${node}"
      done
    fi
    if (( ${#private_cached[@]} > 0 )); then
      for node in "${private_cached[@]}"; do
        printf '%s\n' "${node}"
      done
    fi
  } | awk -v limit="${PEER_REFRESH_LIMIT}" '
    NF && !seen[$0]++ {
      print
      if (limit > 0 && ++count >= limit) {
        exit
      }
    }
  '
}

maybe_refresh_healthy_peer_topology() {
  local local_tip="${1:-${last_local_tip:-0}}"
  local tmp_err
  local peer_json
  local summary_json
  local public_outbound=0
  local private_outbound=0
  local full_relay_outbound=0
  local synced_public_outbound=0
  local manual_private_outbound=0

  tmp_err="$(mktemp)"
  if ! peer_json="$(rpc_cli getpeerinfo 2>"${tmp_err}")"; then
    append_file_if_present "${tmp_err}" "${ERR}"
    rm -f "${tmp_err}"
    return 1
  fi
  rm -f "${tmp_err}"

  refresh_live_peer_cache_from_json "${local_tip}" <<<"${peer_json}" || true
  if ! summary_json="$(summarize_outbound_peer_mix_from_json "${local_tip}" <<<"${peer_json}")"; then
    return 1
  fi

  public_outbound="$(jq -r '.public_outbound // 0' <<<"${summary_json}")"
  private_outbound="$(jq -r '.private_outbound // 0' <<<"${summary_json}")"
  full_relay_outbound="$(jq -r '.full_relay_outbound // 0' <<<"${summary_json}")"
  synced_public_outbound="$(jq -r '.synced_public_outbound // 0' <<<"${summary_json}")"
  manual_private_outbound="$(jq -r '.manual_private_outbound // 0' <<<"${summary_json}")"

  if (( public_outbound < HEALTHY_PUBLIC_PEER_TARGET )) || \
     (( synced_public_outbound < HEALTHY_PUBLIC_PEER_TARGET )) || \
     (( full_relay_outbound < HEALTHY_FULL_RELAY_PEER_TARGET )) || \
     (( public_outbound == 0 && manual_private_outbound > 0 )); then
    log_health "peer-topology-low public_outbound=${public_outbound} synced_public_outbound=${synced_public_outbound} full_relay_outbound=${full_relay_outbound} private_outbound=${private_outbound} manual_private_outbound=${manual_private_outbound}"
    refresh_peer_bootstrap "healthy_topoff" || true
  fi

  return 0
}

disconnect_stale_outbound_peers() {
  local reason="$1"
  local tmp_err
  local peer_json
  local attempted=0
  local disconnected=0
  local failed=0

  tmp_err="$(mktemp)"
  if ! peer_json="$(rpc_cli getpeerinfo 2>"${tmp_err}")"; then
    append_file_if_present "${tmp_err}" "${ERR}"
    rm -f "${tmp_err}"
    return 1
  fi
  rm -f "${tmp_err}"

  while IFS= read -r node; do
    [[ -n "${node}" ]] || continue
    ((attempted += 1))
    if rpc_cli disconnectnode "${node}" >>"${LOG}" 2>>"${ERR}"; then
      ((disconnected += 1))
    else
      ((failed += 1))
    fi
  done < <(
    jq -r '
      .[]
      | select((.inbound // false) | not)
      | select((.connection_type // "") == "manual")
      | select((.synced_headers // -1) < 0 and (.synced_blocks // -1) < 0)
      | .addr // empty
    ' <<<"${peer_json}" | awk 'NF && !seen[$0]++'
  )

  if (( attempted == 0 )); then
    return 1
  fi

  log_health "peer-stale-disconnect reason=${reason} attempted=${attempted} disconnected=${disconnected} failed=${failed}"
  (( disconnected > 0 ))
}

refresh_peer_bootstrap() {
  local reason="$1"
  local now
  local attempted=0
  local succeeded=0
  local failed=0

  if [[ -z "${BOOTSTRAP_ADDNODES}" && ! -f "${PEER_CACHE_FILE}" ]]; then
    return 1
  fi

  now="$(date +%s)"
  if (( last_peer_refresh_epoch > 0 && now - last_peer_refresh_epoch < PEER_REMEDIATION_COOLDOWN_SECS )); then
    return 1
  fi
  last_peer_refresh_epoch="${now}"

  rpc_cli setnetworkactive true >>"${LOG}" 2>>"${ERR}" || true

  local bootstrap_nodes=()
  while IFS= read -r node; do
    [[ -n "${node}" ]] || continue
    bootstrap_nodes+=("${node}")
  done < <(collect_bootstrap_nodes)
  for node in "${bootstrap_nodes[@]}"; do
    [[ -n "${node}" ]] || continue
    ((attempted += 1))
    if rpc_cli addnode "${node}" onetry >>"${LOG}" 2>>"${ERR}"; then
      ((succeeded += 1))
    else
      ((failed += 1))
    fi
  done

  log_health "peer-bootstrap-refresh reason=${reason} attempted=${attempted} succeeded=${succeeded} failed=${failed}"
  (( succeeded > 0 ))
}

should_defer_chain_guard_restart() {
  local reason="$1"
  local recommended_action="$2"
  local peer_count="$3"
  local now="$4"

  case "${reason}" in
    insufficient_peer_consensus)
      if (( peer_count < 2 )) && (( same_reason_streak >= PEER_REMEDIATION_THRESHOLD )); then
        disconnect_stale_outbound_peers "${reason}" || true
        refresh_peer_bootstrap "${reason}" || true
      fi
      if (( now - last_tip_progress_epoch < SYNC_STALL_RESTART_SECS )); then
        return 0
      fi
      return 1
      ;;
  esac

  if [[ "${recommended_action}" == "catch_up" ]]; then
    if (( peer_count < 2 )) && (( same_reason_streak >= PEER_REMEDIATION_THRESHOLD )); then
      refresh_peer_bootstrap "${reason}" || true
    fi
    if (( now - last_tip_progress_epoch < SYNC_STALL_RESTART_SECS )); then
      return 0
    fi
  fi

  return 1
}

maybe_start_node_for_rpc_failure() {
  local now
  local wait_status=0
  if (( rpc_failure_streak != 1 )); then
    return 1
  fi
  if supervised_node_running; then
    return 1
  fi

  now="$(date +%s)"
  last_restart_epoch="${now}"
  grace_until_epoch=$((now + STARTUP_GRACE_SECS))
  log_health "rpc-unavailable-start-attempt"
  if ! start_node; then
    log_health "rpc-unavailable-start-failed"
    return 1
  fi

  wait_for_rpc_ready "${WAIT_FOR_RPC_SECS}" || wait_status=$?
  if (( wait_status == 0 )); then
    now="$(date +%s)"
    grace_until_epoch=$((now + STARTUP_GRACE_SECS))
    rpc_failure_streak=0
    health_failure_streak=0
    note_rpc_ready
    log_health "rpc-unavailable-start-complete"
    return 0
  fi

  if (( wait_status == 2 )); then
    log_health "rpc-unavailable-start-warmup"
    return 0
  fi

  log_health "rpc-unavailable-start-timeout"
  return 0
}

should_mine_now() {
  if [[ -z "${SHOULD_MINE_COMMAND}" ]]; then
    return 0
  fi

  local exit_code=0
  if eval "${SHOULD_MINE_COMMAND}" >>"${LOG}" 2>>"${ERR}"; then
    if [[ "${last_should_mine_state}" != "allow" ]]; then
      log_health "idle-gate-open"
    fi
    last_should_mine_state="allow"
    return 0
  else
    exit_code=$?
  fi
  if [[ "${last_should_mine_state}" != "block:${exit_code}" ]]; then
    log_health "idle-gate-pause exit=${exit_code}"
  fi
  last_should_mine_state="block:${exit_code}"
  return 1
}

restart_node() {
  local reason="$1"
  local now
  local supervised_pid=""
  local wait_status=0
  now="$(date +%s)"
  if [[ "${reason}" != "node_missing" ]] && (( last_restart_epoch > 0 && now - last_restart_epoch < RESTART_COOLDOWN_SECS )); then
    log_health "restart-skipped cooldown reason=${reason} since_last=$((now - last_restart_epoch))s"
    return 1
  fi

  last_restart_epoch="${now}"
  grace_until_epoch=$((now + STARTUP_GRACE_SECS))
  log_health "restarting-node reason=${reason}"

  if supervised_node_running; then
    supervised_pid="$(read_supervised_node_pid || true)"
  fi
  rpc_cli stop >>"${LOG}" 2>>"${ERR}" || true
  if [[ -n "${supervised_pid}" ]]; then
    if ! wait_for_supervised_pid_exit "${supervised_pid}" "${STOP_WAIT_SECS}"; then
      kill "${supervised_pid}" >/dev/null 2>&1 || true
      if ! wait_for_supervised_pid_exit "${supervised_pid}" 5; then
        log_health "restart-timeout reason=${reason} phase=stop pid=${supervised_pid}"
        return 1
      fi
    fi
  else
    log_health "restart-no-node-pid reason=${reason} pidfile=${NODE_PIDFILE}"
  fi

  if ! start_node; then
    log_health "restart-launch-failed reason=${reason}"
    return 1
  fi

  wait_for_rpc_ready "${WAIT_FOR_RPC_SECS}" || wait_status=$?
  if (( wait_status == 0 )); then
    now="$(date +%s)"
    grace_until_epoch=$((now + STARTUP_GRACE_SECS))
    rpc_failure_streak=0
    health_failure_streak=0
    note_rpc_ready
    log_health "restart-complete reason=${reason}"
    return 0
  fi

  if (( wait_status == 2 )); then
    log_health "restart-warmup reason=${reason}"
    return 0
  fi

  log_health "restart-timeout reason=${reason}"
  return 1
}

refresh_mininginfo() {
  local tmp_err
  tmp_err="$(mktemp)"
  if LAST_MININGINFO_JSON="$(rpc_cli getmininginfo 2>"${tmp_err}")"; then
    rm -f "${tmp_err}"
    note_rpc_ready
    return 0
  fi
  if rpc_error_is_warmup_file "${tmp_err}"; then
    rm -f "${tmp_err}"
    note_rpc_warmup "getmininginfo"
    return 2
  fi
  append_file_if_present "${tmp_err}" "${ERR}"
  rm -f "${tmp_err}"
  last_rpc_fault_state="error:getmininginfo"
  return 1
}

check_runtime_health() {
  local healthy
  local pause
  local reason
  local recommended_action
  local local_tip
  local median_peer_tip
  local peer_count
  local near_tip_peers
  local now
  local refresh_status=0

  refresh_mininginfo || refresh_status=$?
  if (( refresh_status == 2 )); then
    return 1
  fi
  if (( refresh_status != 0 )); then
    ((rpc_failure_streak += 1))
    if maybe_start_node_for_rpc_failure; then
      return 1
    fi
    if (( $(date +%s) < grace_until_epoch )); then
      return 1
    fi
    log_health "rpc-failure streak=${rpc_failure_streak}/${RPC_RESTART_THRESHOLD}"
    if (( rpc_failure_streak >= RPC_RESTART_THRESHOLD )); then
      restart_node "rpc_unavailable" || true
    fi
    return 1
  fi

  rpc_failure_streak=0
  healthy="$(jq -r '.chain_guard.healthy // false' <<<"${LAST_MININGINFO_JSON}")"
  pause="$(jq -r '.chain_guard.should_pause_mining // false' <<<"${LAST_MININGINFO_JSON}")"
  reason="$(jq -r '.chain_guard.reason // "unknown"' <<<"${LAST_MININGINFO_JSON}")"
  recommended_action="$(jq -r '.chain_guard.recommended_action // empty' <<<"${LAST_MININGINFO_JSON}")"
  if [[ -z "${recommended_action}" ]]; then
    recommended_action="$(derive_recommended_action "${reason}")"
  fi
  local_tip="$(jq -r '.chain_guard.local_tip // 0' <<<"${LAST_MININGINFO_JSON}")"
  median_peer_tip="$(jq -r '.chain_guard.median_peer_tip // 0' <<<"${LAST_MININGINFO_JSON}")"
  peer_count="$(jq -r '.chain_guard.peer_count // 0' <<<"${LAST_MININGINFO_JSON}")"
  near_tip_peers="$(jq -r '.chain_guard.near_tip_peers // 0' <<<"${LAST_MININGINFO_JSON}")"
  now="$(date +%s)"
  update_chain_progress "${now}" "${local_tip}" "${peer_count}"

  if [[ "${healthy}" == "true" && "${pause}" == "false" ]]; then
    health_failure_streak=0
    last_health_reason="ok"
    same_reason_streak=0
    maybe_refresh_healthy_peer_topology "${local_tip}" || true
    return 0
  fi

  update_reason_streak "${reason}"
  ((health_failure_streak += 1))
  log_health "chain-guard-pause streak=${health_failure_streak}/${HEALTH_RESTART_THRESHOLD} reason=${reason} action=${recommended_action} reason_streak=${same_reason_streak} local_tip=${local_tip} peer_median=${median_peer_tip} peers=${peer_count} near_tip_peers=${near_tip_peers}"

  if (( now < grace_until_epoch )); then
    return 1
  fi

  if should_defer_chain_guard_restart "${reason}" "${recommended_action}" "${peer_count}" "${now}"; then
    return 1
  fi

  if (( health_failure_streak >= HEALTH_RESTART_THRESHOLD )); then
    if [[ "${recommended_action}" == "catch_up" ]]; then
      restart_node "chain_guard_stalled_${reason}" || true
    else
      restart_node "chain_guard_${reason}" || true
    fi
  fi
  return 1
}

rpc_failure_streak=0
health_failure_streak=0
last_restart_epoch=0
grace_until_epoch=$(( $(date +%s) + STARTUP_GRACE_SECS ))
loop_count=0
LAST_MININGINFO_JSON=''
last_should_mine_state="unknown"
last_rpc_fault_state="unknown"
last_health_reason="unknown"
same_reason_streak=0
last_local_tip=-1
last_tip_progress_epoch="$(date +%s)"
last_peer_seen_epoch="$(date +%s)"
last_peer_refresh_epoch=0

printf '%s\n' "$$" > "${PIDFILE}"
trap 'rm -f "${PIDFILE}"' EXIT

log_health "loop-start datadir=${DATADIR:-default} wallet=${WALLET} rpc_restart_threshold=${RPC_RESTART_THRESHOLD} health_restart_threshold=${HEALTH_RESTART_THRESHOLD} peer_remediation_threshold=${PEER_REMEDIATION_THRESHOLD} peer_cache_limit=${PEER_CACHE_LIMIT} peer_refresh_limit=${PEER_REFRESH_LIMIT} healthy_public_peer_target=${HEALTHY_PUBLIC_PEER_TARGET} healthy_full_relay_peer_target=${HEALTHY_FULL_RELAY_PEER_TARGET} sync_stall_restart_secs=${SYNC_STALL_RESTART_SECS} maxconnections=${MAXCONNECTIONS} startup_grace=${STARTUP_GRACE_SECS} node_pidfile=${NODE_PIDFILE}"

while true; do
  ((loop_count += 1))
  if (( MAX_LOOPS > 0 && loop_count >= MAX_LOOPS )); then
    log_health "max-loops-reached loops=${loop_count}"
    exit 0
  fi

  if ! check_runtime_health; then
    sleep "${SLEEP_SECS}"
    continue
  fi

  if ! should_mine_now; then
    sleep "${SLEEP_SECS}"
    continue
  fi

  tmp_out="$(mktemp)"
  tmp_err="$(mktemp)"
  if rpc_wallet_cli generatetoaddress 1 "${ADDRESS}" >"${tmp_out}" 2>"${tmp_err}"; then
    append_file_if_present "${tmp_out}" "${LOG}"
  else
    append_file_if_present "${tmp_out}" "${LOG}"
    append_file_if_present "${tmp_err}" "${ERR}"
    if grep -q "mining paused by chain guard" "${tmp_err}"; then
      ((health_failure_streak += 1))
      log_health "generate-paused streak=${health_failure_streak}/${HEALTH_RESTART_THRESHOLD}"
      if refresh_mininginfo; then
        reason="$(jq -r '.chain_guard.reason // "unknown"' <<<"${LAST_MININGINFO_JSON}")"
        recommended_action="$(jq -r '.chain_guard.recommended_action // empty' <<<"${LAST_MININGINFO_JSON}")"
        if [[ -z "${recommended_action}" ]]; then
          recommended_action="$(derive_recommended_action "${reason}")"
        fi
        peer_count="$(jq -r '.chain_guard.peer_count // 0' <<<"${LAST_MININGINFO_JSON}")"
        now="$(date +%s)"
        if should_defer_chain_guard_restart "${reason}" "${recommended_action}" "${peer_count}" "${now}"; then
          :
        elif (( health_failure_streak >= HEALTH_RESTART_THRESHOLD )); then
          restart_node "generate_chain_guard_pause" || true
        fi
      else
        refresh_status=$?
        if (( refresh_status == 2 )); then
          :
        elif (( health_failure_streak >= HEALTH_RESTART_THRESHOLD )); then
          restart_node "generate_chain_guard_pause" || true
        fi
      fi
    elif rpc_error_is_warmup_file "${tmp_err}"; then
      note_rpc_warmup "generatetoaddress"
    else
      last_rpc_fault_state="error:generatetoaddress"
      ((rpc_failure_streak += 1))
      log_health "generate-rpc-failure streak=${rpc_failure_streak}/${RPC_RESTART_THRESHOLD}"
      if (( rpc_failure_streak >= RPC_RESTART_THRESHOLD )); then
        restart_node "generate_rpc_failure" || true
      fi
    fi
  fi
  rm -f "${tmp_out}" "${tmp_err}"

  sleep "${SLEEP_SECS}"
done
