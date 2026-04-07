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
SHOULD_MINE_COMMAND="${BTX_MINING_SHOULD_MINE_COMMAND:-}"
NODE_PIDFILE="${BTX_MINING_NODE_PIDFILE:-}"
CLI="${BTX_MINING_CLI:-btx-cli}"
DAEMON="${BTX_MINING_DAEMON:-btxd}"
START_VERIFY_SECS="${BTX_MINING_START_VERIFY_SECS:-1}"

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Start the BTX live-mining supervisor in the background, auto-provisioning a
mining wallet/address when needed.

Options:
  --datadir=PATH            BTX datadir to supervise
  --conf=PATH               BTX config file used by the daemon/CLI
  --chain=NAME              BTX chain name (main, testnet4, regtest, ...)
  --rpcconnect=HOST         RPC host override
  --rpcport=PORT            RPC port override
  --rpcuser=USER            RPC username override
  --rpcpassword=PASS        RPC password override
  --rpccookiefile=PATH      RPC cookie file override
  --wallet=NAME             Wallet used for mining rewards (default: miner)
  --address=ADDR            Explicit payout address
  --address-file=PATH       File containing the payout address
  --sleep=SECS              Loop sleep interval passed to the supervisor
  --results-dir=PATH        Directory for pid/log/address files
  --should-mine-command=CMD Idle gate command; mine only when it exits 0
  --node-pidfile=PATH       PID file for the supervised daemon
  --cli=PATH                Path to btx-cli (default: btx-cli)
  --daemon=PATH             Path to btxd (default: btxd)
  --help, -h                Show this help text
EOF
}

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
    --cli=*)
      CLI="${arg#*=}"
      ;;
    --daemon=*)
      DAEMON="${arg#*=}"
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

require_command jq

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

ensure_wallet_loaded() {
  if rpc_wallet_cli getwalletinfo >/dev/null 2>&1; then
    return 0
  fi
  if rpc_cli -named loadwallet filename="${WALLET}" load_on_startup=true >/dev/null 2>&1; then
    return 0
  fi
  if rpc_cli -named createwallet wallet_name="${WALLET}" load_on_startup=true >/dev/null 2>&1; then
    return 0
  fi
  echo "Failed to load or create wallet: ${WALLET}" >&2
  return 1
}

provision_address_if_needed() {
  if [[ -n "${ADDRESS}" ]]; then
    return 0
  fi
  if [[ -n "${ADDRESS_FILE}" && -f "${ADDRESS_FILE}" ]]; then
    ADDRESS="$(tr -d '\n' < "${ADDRESS_FILE}")"
    if [[ -n "${ADDRESS}" ]]; then
      return 0
    fi
  fi

  require_command "${CLI}"
  ensure_wallet_loaded
  ADDRESS="$(rpc_wallet_cli getnewaddress | tr -d '\n')"
  if [[ -z "${ADDRESS_FILE}" ]]; then
    ADDRESS_FILE="${RESULTS_DIR}/${WALLET}-mining-address.txt"
  fi
  printf '%s\n' "${ADDRESS}" > "${ADDRESS_FILE}"
  printf 'Provisioned mining wallet/address; wallet: %s address_file: %s\n' "${WALLET}" "${ADDRESS_FILE}"
}

provision_address_if_needed

PIDFILE="${RESULTS_DIR}/live-mining-loop.pid"
OUT="${RESULTS_DIR}/live-mining-agent.out"
ERR="${RESULTS_DIR}/live-mining-agent.err"

if [[ -f "${PIDFILE}" ]]; then
  existing_pid="$(cat "${PIDFILE}")"
  if [[ "${existing_pid}" =~ ^[0-9]+$ ]] && kill -0 "${existing_pid}" >/dev/null 2>&1; then
    printf 'Live mining loop already running with PID %s\n' "${existing_pid}"
    exit 0
  fi
  rm -f "${PIDFILE}"
fi

cmd=("${SCRIPT_DIR}/live-mining-loop.sh")
if [[ -n "${DATADIR}" ]]; then
  cmd+=("--datadir=${DATADIR}")
fi
if [[ -n "${CONF}" ]]; then
  cmd+=("--conf=${CONF}")
fi
if [[ -n "${CHAIN}" ]]; then
  cmd+=("--chain=${CHAIN}")
fi
if [[ -n "${RPC_CONNECT}" ]]; then
  cmd+=("--rpcconnect=${RPC_CONNECT}")
fi
if [[ -n "${RPC_PORT}" ]]; then
  cmd+=("--rpcport=${RPC_PORT}")
fi
if [[ -n "${RPC_USER}" ]]; then
  cmd+=("--rpcuser=${RPC_USER}")
fi
if [[ -n "${RPC_PASSWORD}" ]]; then
  cmd+=("--rpcpassword=${RPC_PASSWORD}")
fi
if [[ -n "${RPC_COOKIEFILE}" ]]; then
  cmd+=("--rpccookiefile=${RPC_COOKIEFILE}")
fi
cmd+=("--wallet=${WALLET}" "--sleep=${SLEEP_SECS}" "--results-dir=${RESULTS_DIR}")
if [[ -n "${SHOULD_MINE_COMMAND}" ]]; then
  cmd+=("--should-mine-command=${SHOULD_MINE_COMMAND}")
fi
if [[ -n "${NODE_PIDFILE}" ]]; then
  cmd+=("--node-pidfile=${NODE_PIDFILE}")
fi
if [[ -n "${CLI}" ]]; then
  cmd+=("--cli=${CLI}")
fi
if [[ -n "${DAEMON}" ]]; then
  cmd+=("--daemon=${DAEMON}")
fi
if [[ -n "${ADDRESS}" ]]; then
  cmd+=("--address=${ADDRESS}")
fi
if [[ -n "${ADDRESS_FILE}" ]]; then
  cmd+=("--address-file=${ADDRESS_FILE}")
fi

nohup "${cmd[@]}" >>"${OUT}" 2>>"${ERR}" </dev/null &
loop_pid="$!"
printf '%s\n' "${loop_pid}" > "${PIDFILE}"

report_start_failure() {
  echo "Live mining loop exited before startup verification completed" >&2
  if [[ -s "${OUT}" ]]; then
    echo "--- ${OUT} ---" >&2
    tail -n 40 "${OUT}" >&2
  fi
  if [[ -s "${ERR}" ]]; then
    echo "--- ${ERR} ---" >&2
    tail -n 40 "${ERR}" >&2
  fi
}

verify_loop_started() {
  local pid="$1"
  local seconds="$2"
  local i
  if (( seconds <= 0 )); then
    return 0
  fi
  for ((i = 0; i < seconds; ++i)); do
    sleep 1
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      rm -f "${PIDFILE}"
      report_start_failure
      return 1
    fi
  done
}

verify_loop_started "${loop_pid}" "${START_VERIFY_SECS}"
printf 'Started live mining loop; pid file: %s\n' "${PIDFILE}"
