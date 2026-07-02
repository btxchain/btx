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
BOOTSTRAP_ADDNODES="${BTX_MINING_BOOTSTRAP_ADDNODES:-${BTX_MINING_BOOTSTRAP_PEERS:-}}"
NO_DEFAULT_BOOTSTRAP_PEERS=0
SLEEP_SECS="${BTX_MINING_SLEEP_SECS:-1}"
RESULTS_DIR="${BTX_MINING_RESULTS_DIR:-}"
SHOULD_MINE_COMMAND="${BTX_MINING_SHOULD_MINE_COMMAND:-}"
NODE_PIDFILE="${BTX_MINING_NODE_PIDFILE:-}"
MINING_BACKEND="${BTX_MINING_BACKEND:-${BTX_MATMUL_BACKEND:-}}"
REQUIRE_BACKEND="${BTX_MINING_REQUIRE_BACKEND:-${BTX_MATMUL_REQUIRE_BACKEND:-}}"
MAX_BACKEND_FALLBACKS="${BTX_MINING_MAX_BACKEND_FALLBACKS:-0}"
GPU_INPUTS="${BTX_MINING_GPU_INPUTS:-${BTX_MATMUL_GPU_INPUTS:-}}"
HOST_OS="${BTX_MINING_HOST_OS_FOR_TEST:-$(uname -s 2>/dev/null || true)}"
HOST_ARCH="${BTX_MINING_HOST_ARCH_FOR_TEST:-$(uname -m 2>/dev/null || true)}"
APPLE_SILICON_MINING_DEFAULTS=0
if [[ "${HOST_OS}" == "Darwin" && "${HOST_ARCH}" == "arm64" ]]; then
  APPLE_SILICON_MINING_DEFAULTS=1
  MINING_BACKEND="${MINING_BACKEND:-metal}"
  REQUIRE_BACKEND="${REQUIRE_BACKEND:-metal}"
  GPU_INPUTS="${GPU_INPUTS:-1}"
fi
CLI="${BTX_MINING_CLI:-btx-cli}"
DAEMON="${BTX_MINING_DAEMON:-btxd}"
if (( APPLE_SILICON_MINING_DEFAULTS )); then
  DAEMONIZE="${BTX_MINING_DAEMONIZE:-0}"
else
  DAEMONIZE="${BTX_MINING_DAEMONIZE:-1}"
fi
START_VERIFY_SECS="${BTX_MINING_START_VERIFY_SECS:-1}"
FOREGROUND="${BTX_MINING_FOREGROUND:-0}"
LAUNCH_CWD="${BTX_MINING_LAUNCH_CWD:-}"

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
  --bootstrap-peers=LIST    Comma-separated addnode host:port list for peer recovery
  --no-default-bootstrap-peers
                            Do not use the supervisor's built-in public BTX bootstrap mesh
  --sleep=SECS              Loop sleep interval passed to the supervisor
  --results-dir=PATH        Directory for pid/log/address files
  --should-mine-command=CMD Idle gate command; mine only when it exits 0
  --node-pidfile=PATH       PID file for the supervised daemon
  --backend=NAME            Set BTX_MATMUL_BACKEND for supervised daemon starts (Apple Silicon default: metal)
  --require-backend=NAME    Fail closed unless getmininginfo reports this backend active (Apple Silicon default: metal)
  --max-backend-fallbacks=N Maximum GPU-to-CPU fallbacks allowed when backend is required (default: 0)
  --gpu-inputs=auto|0|1     Set BTX_MATMUL_GPU_INPUTS for host-tuned GPU input generation (Apple Silicon default: 1)
  --cli=PATH                Path to btx-cli (default: btx-cli)
  --daemon=PATH             Path to btxd (default: btxd)
  --daemonize=0|1           Start btxd with -daemon (default: 1; Apple Silicon default: 0)
  --foreground              Exec the supervisor instead of detaching it
  --launch-cwd=PATH         Working directory for detached supervisor
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
    --bootstrap-peers=*)
      BOOTSTRAP_ADDNODES="${arg#*=}"
      ;;
    --no-default-bootstrap-peers)
      NO_DEFAULT_BOOTSTRAP_PEERS=1
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
    --backend=*)
      MINING_BACKEND="${arg#*=}"
      ;;
    --require-backend=*)
      REQUIRE_BACKEND="${arg#*=}"
      ;;
    --max-backend-fallbacks=*)
      MAX_BACKEND_FALLBACKS="${arg#*=}"
      ;;
    --gpu-inputs=*)
      GPU_INPUTS="${arg#*=}"
      ;;
    --cli=*)
      CLI="${arg#*=}"
      ;;
    --daemon=*)
      DAEMON="${arg#*=}"
      ;;
    --daemonize=*)
      DAEMONIZE="${arg#*=}"
      ;;
    --foreground)
      FOREGROUND="1"
      ;;
    --launch-cwd=*)
      LAUNCH_CWD="${arg#*=}"
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

if [[ "${FOREGROUND}" != "0" && "${FOREGROUND}" != "1" ]]; then
  echo "Invalid foreground flag: ${FOREGROUND}" >&2
  exit 1
fi
REQUIRE_BACKEND_NORMALIZED="$(printf '%s' "${REQUIRE_BACKEND}" | tr 'A-Z' 'a-z')"
if [[ -n "${REQUIRE_BACKEND}" && -z "${MINING_BACKEND}" ]]; then
  case "${REQUIRE_BACKEND_NORMALIZED}" in
    1|true|yes|on|0|false|no|off|none|disabled)
      ;;
    *)
      MINING_BACKEND="${REQUIRE_BACKEND}"
      ;;
  esac
fi
if [[ -n "${MINING_BACKEND}" ]]; then
  export BTX_MATMUL_BACKEND="${MINING_BACKEND}"
fi
if [[ -n "${REQUIRE_BACKEND}" ]]; then
  export BTX_MATMUL_REQUIRE_BACKEND="${REQUIRE_BACKEND}"
fi
if [[ -n "${GPU_INPUTS}" ]]; then
  export BTX_MATMUL_GPU_INPUTS="${GPU_INPUTS}"
fi
if ! [[ "${MAX_BACKEND_FALLBACKS}" =~ ^[0-9]+$ ]]; then
  echo "Invalid --max-backend-fallbacks value: ${MAX_BACKEND_FALLBACKS}" >&2
  exit 1
fi
if [[ -n "${GPU_INPUTS}" ]]; then
  gpu_inputs_normalized="$(printf '%s' "${GPU_INPUTS}" | tr 'A-Z' 'a-z')"
  case "${gpu_inputs_normalized}" in
    auto|1|true|yes|on|0|false|no|off)
      ;;
    *)
      echo "Invalid --gpu-inputs value: ${GPU_INPUTS}" >&2
      exit 1
      ;;
  esac
fi
if [[ "${DAEMONIZE}" != "0" && "${DAEMONIZE}" != "1" ]]; then
  echo "Invalid --daemonize value: ${DAEMONIZE}" >&2
  exit 1
fi

resolve_launch_cwd() {
  local candidate resolved
  for candidate in "${LAUNCH_CWD}" "${RESULTS_DIR}" "${DATADIR}" "/tmp"; do
    [[ -n "${candidate}" ]] || continue
    resolved="$(
      mkdir -p "${candidate}" >/dev/null 2>&1 &&
        cd "${candidate}" >/dev/null 2>&1 &&
        pwd -P
    )" || resolved=""
    if [[ -n "${resolved}" ]]; then
      printf '%s\n' "${resolved}"
      return 0
    fi
  done
  echo "Unable to resolve a usable launch working directory" >&2
  return 1
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
if [[ -n "${BOOTSTRAP_ADDNODES}" ]]; then
  cmd+=("--bootstrap-peers=${BOOTSTRAP_ADDNODES}")
fi
if (( NO_DEFAULT_BOOTSTRAP_PEERS )); then
  cmd+=("--no-default-bootstrap-peers")
fi
if [[ -n "${SHOULD_MINE_COMMAND}" ]]; then
  cmd+=("--should-mine-command=${SHOULD_MINE_COMMAND}")
fi
if [[ -n "${NODE_PIDFILE}" ]]; then
  cmd+=("--node-pidfile=${NODE_PIDFILE}")
fi
if [[ -n "${MINING_BACKEND}" ]]; then
  cmd+=("--backend=${MINING_BACKEND}")
fi
if [[ -n "${REQUIRE_BACKEND}" ]]; then
  cmd+=("--require-backend=${REQUIRE_BACKEND}")
fi
cmd+=("--max-backend-fallbacks=${MAX_BACKEND_FALLBACKS}")
if [[ -n "${GPU_INPUTS}" ]]; then
  cmd+=("--gpu-inputs=${GPU_INPUTS}")
fi
if [[ -n "${CLI}" ]]; then
  cmd+=("--cli=${CLI}")
fi
if [[ -n "${DAEMON}" ]]; then
  cmd+=("--daemon=${DAEMON}")
fi
cmd+=("--daemonize=${DAEMONIZE}")
if [[ -n "${ADDRESS}" ]]; then
  cmd+=("--address=${ADDRESS}")
fi
if [[ -n "${ADDRESS_FILE}" ]]; then
  cmd+=("--address-file=${ADDRESS_FILE}")
fi

if [[ "${FOREGROUND}" == "1" ]]; then
  exec "${cmd[@]}"
fi

LAUNCH_CWD="$(resolve_launch_cwd)"

launch_detached() {
  (
    cd "${LAUNCH_CWD}"
    nohup "${cmd[@]}" >>"${OUT}" 2>>"${ERR}" </dev/null &
    printf '%s\n' "$!"
  )
}

loop_pid="$(launch_detached)"

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
printf 'Started live mining loop; pid file: %s launch_cwd: %s\n' "${PIDFILE}" "${LAUNCH_CWD}"
