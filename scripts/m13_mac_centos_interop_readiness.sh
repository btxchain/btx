#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m13_mac_centos_interop_readiness.sh [options]

Run a live macOS <-> CentOS Docker regtest interoperability validation:
1) Start a macOS node and a CentOS container node with matching custom regtest identity
2) Validate peer connectivity and genesis alignment
3) Mine on macOS, sync to CentOS, transfer funds macOS -> CentOS
4) Transfer funds CentOS -> macOS and confirm both directions

Options:
  --mac-build-dir <path>      macOS build directory (default: build-btx)
  --centos-build-dir <path>   CentOS build directory under repo root
                              (default: build-btx-centos)
  --artifact <path>           JSON artifact output path
                              (default: .btx-validation/m13-mac-centos-interop.json)
  --timeout-seconds <n>       Wait timeout per phase (default: 240)
  --skip-centos-build         Reuse existing CentOS build directory if present
  --help                      Show this message

Environment overrides:
  BTX_M13_CONTAINER_IMAGE         Docker image (default: quay.io/centos/centos:stream10)
  BTX_M13_CONTAINER_PLATFORM      Docker --platform override (optional)
  BTX_M13_MATMUL_BACKEND          MatMul solve backend for both nodes (default: cpu)
  BTX_M13_V2_TRANSPORT            P2P v2 transport toggle for both nodes (0/1, default: 0)
  BTX_M13_GENESIS_TIME            Custom regtest genesis nTime (default: 1700001234)
  BTX_M13_GENESIS_NONCE           Custom regtest genesis nNonce (default: 42)
  BTX_M13_GENESIS_BITS            Custom regtest genesis nBits hex (default: 2070ffff)
  BTX_M13_GENESIS_VERSION         Custom regtest genesis nVersion (default: 4)
  BTX_M13_MSGSTART                Custom regtest message-start hex (default: random 8 hex chars)
  BTX_M13_REGTEST_PORT            Custom regtest default port override (default: 19444)
  BTX_M13_MATURITY_BLOCKS         Coinbase maturity setup blocks (default: 101)
  BTX_M13_SEND_AMOUNT_FORWARD     macOS -> CentOS amount (default: 1.25)
  BTX_M13_SEND_AMOUNT_REVERSE     CentOS -> macOS amount (default: 0.75)
  BTX_M13_KEEP_TMP                Preserve temp directories on exit (1/0, default: 0)
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAC_BUILD_DIR="${ROOT_DIR}/build-btx"
CENTOS_BUILD_DIR="${ROOT_DIR}/build-btx-centos"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m13-mac-centos-interop.json"
TIMEOUT_SECONDS=240
SKIP_CENTOS_BUILD=0

CONTAINER_IMAGE="${BTX_M13_CONTAINER_IMAGE:-quay.io/centos/centos:stream10}"
CONTAINER_PLATFORM="${BTX_M13_CONTAINER_PLATFORM:-}"
GENESIS_TIME="${BTX_M13_GENESIS_TIME:-1700001234}"
GENESIS_NONCE="${BTX_M13_GENESIS_NONCE:-42}"
GENESIS_BITS="${BTX_M13_GENESIS_BITS:-2070ffff}"
GENESIS_VERSION="${BTX_M13_GENESIS_VERSION:-4}"
MESSAGE_START="${BTX_M13_MSGSTART:-}"
REGTEST_PORT_OVERRIDE="${BTX_M13_REGTEST_PORT:-19444}"
MATURITY_BLOCKS="${BTX_M13_MATURITY_BLOCKS:-101}"
SEND_AMOUNT_FORWARD="${BTX_M13_SEND_AMOUNT_FORWARD:-1.25}"
SEND_AMOUNT_REVERSE="${BTX_M13_SEND_AMOUNT_REVERSE:-0.75}"
KEEP_TMP="${BTX_M13_KEEP_TMP:-0}"
MATMUL_BACKEND="${BTX_M13_MATMUL_BACKEND:-cpu}"
P2P_V2_TRANSPORT="${BTX_M13_V2_TRANSPORT:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mac-build-dir)
      MAC_BUILD_DIR="$2"
      shift 2
      ;;
    --centos-build-dir)
      CENTOS_BUILD_DIR="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --skip-centos-build)
      SKIP_CENTOS_BUILD=1
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

if ! [[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "error: --timeout-seconds must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MATURITY_BLOCKS}" =~ ^[0-9]+$ ]] || [[ "${MATURITY_BLOCKS}" -lt 101 ]]; then
  echo "error: BTX_M13_MATURITY_BLOCKS must be an integer >= 101" >&2
  exit 1
fi
if ! [[ "${GENESIS_TIME}" =~ ^[0-9]+$ ]]; then
  echo "error: BTX_M13_GENESIS_TIME must be a uint32 decimal" >&2
  exit 1
fi
if ! [[ "${GENESIS_NONCE}" =~ ^[0-9]+$ ]]; then
  echo "error: BTX_M13_GENESIS_NONCE must be a uint32 decimal" >&2
  exit 1
fi
if ! [[ "${GENESIS_VERSION}" =~ ^-?[0-9]+$ ]]; then
  echo "error: BTX_M13_GENESIS_VERSION must be an int32 decimal" >&2
  exit 1
fi
if ! [[ "${REGTEST_PORT_OVERRIDE}" =~ ^[0-9]+$ ]] || [[ "${REGTEST_PORT_OVERRIDE}" -lt 1 ]] || [[ "${REGTEST_PORT_OVERRIDE}" -gt 65535 ]]; then
  echo "error: BTX_M13_REGTEST_PORT must be an integer in [1,65535]" >&2
  exit 1
fi
if ! [[ "${P2P_V2_TRANSPORT}" =~ ^[01]$ ]]; then
  echo "error: BTX_M13_V2_TRANSPORT must be 0 or 1" >&2
  exit 1
fi
if ! [[ "${MATMUL_BACKEND}" =~ ^(cpu|metal|mlx|cuda|auto)$ ]]; then
  echo "error: BTX_M13_MATMUL_BACKEND must be one of: cpu, metal, mlx, cuda, auto" >&2
  exit 1
fi

if [[ ! "${MAC_BUILD_DIR}" = /* ]]; then
  MAC_BUILD_DIR="${ROOT_DIR}/${MAC_BUILD_DIR}"
fi
if [[ ! "${CENTOS_BUILD_DIR}" = /* ]]; then
  CENTOS_BUILD_DIR="${ROOT_DIR}/${CENTOS_BUILD_DIR}"
fi
if [[ ! "${ARTIFACT_PATH}" = /* ]]; then
  ARTIFACT_PATH="${ROOT_DIR}/${ARTIFACT_PATH}"
fi

if [[ -z "${MESSAGE_START}" ]]; then
  MESSAGE_START="$(python3 - <<'PY'
import random
print(f"{random.getrandbits(32):08x}")
PY
)"
fi

if ! [[ "${MESSAGE_START}" =~ ^(0x|0X)?[0-9a-fA-F]{8}$ ]]; then
  echo "error: BTX_M13_MSGSTART must be 8 hex chars (optionally prefixed with 0x)" >&2
  exit 1
fi

if ! [[ "${GENESIS_BITS}" =~ ^(0x|0X)?[0-9a-fA-F]{8}$ ]]; then
  echo "error: BTX_M13_GENESIS_BITS must be 8 hex chars (optionally prefixed with 0x)" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required for CentOS interoperability validation" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "error: docker daemon is not reachable" >&2
  exit 1
fi

resolve_btx_binary() {
  local canonical="$1"
  local legacy="$2"
  if [[ -x "${canonical}" ]]; then
    printf '%s\n' "${canonical}"
  elif [[ -x "${legacy}" ]]; then
    printf '%s\n' "${legacy}"
  else
    printf '%s\n' "${canonical}"
  fi
}

MAC_BITCOIND_BIN="$(resolve_btx_binary "${MAC_BUILD_DIR}/bin/btxd" "${MAC_BUILD_DIR}/bin/bitcoind")"
MAC_BITCOIN_CLI_BIN="$(resolve_btx_binary "${MAC_BUILD_DIR}/bin/btx-cli" "${MAC_BUILD_DIR}/bin/bitcoin-cli")"
if [[ ! -x "${MAC_BITCOIND_BIN}" || ! -x "${MAC_BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing macOS btxd/btx-cli (or legacy aliases) in ${MAC_BUILD_DIR}/bin" >&2
  exit 1
fi

CENTOS_BUILD_DIR_REAL="$(python3 - "$CENTOS_BUILD_DIR" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)"
ROOT_DIR_REAL="$(python3 - "$ROOT_DIR" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)"
if [[ "${CENTOS_BUILD_DIR_REAL}" != "${ROOT_DIR_REAL}"* ]]; then
  echo "error: --centos-build-dir must be under repository root (${ROOT_DIR_REAL})" >&2
  exit 1
fi
CENTOS_BUILD_DIR_REL="${CENTOS_BUILD_DIR_REAL#"${ROOT_DIR_REAL}"/}"

mkdir -p "$(dirname "${ARTIFACT_PATH}")"

CONTAINER_BTXD_BIN="/workspace/${CENTOS_BUILD_DIR_REL}/bin/btxd"
CONTAINER_BTX_CLI_BIN="/workspace/${CENTOS_BUILD_DIR_REL}/bin/btx-cli"
CONTAINER_LEGACY_BITCOIND_BIN="/workspace/${CENTOS_BUILD_DIR_REL}/bin/bitcoind"
CONTAINER_LEGACY_BITCOIN_CLI_BIN="/workspace/${CENTOS_BUILD_DIR_REL}/bin/bitcoin-cli"
CONTAINER_BITCOIND_BIN="${CONTAINER_BTXD_BIN}"
CONTAINER_BITCOIN_CLI_BIN="${CONTAINER_BTX_CLI_BIN}"

if [[ "${SKIP_CENTOS_BUILD}" -ne 1 ]]; then
  platform_args=()
  if [[ -n "${CONTAINER_PLATFORM}" ]]; then
    platform_args=(--platform "${CONTAINER_PLATFORM}")
  fi
  docker run --rm "${platform_args[@]}" \
    -v "${ROOT_DIR_REAL}:/workspace" \
    -w /workspace \
    "${CONTAINER_IMAGE}" \
    bash -lc '
      set -euo pipefail
      dnf -y install gcc-c++ glibc-devel libstdc++-devel make git python3 which patch xz procps-ng rsync bison e2fsprogs cmake sqlite-devel libevent-devel boost-devel >/tmp/m13-dnf.log
      scripts/build_btx.sh "'"${CENTOS_BUILD_DIR_REL}"'" -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DWITH_ZMQ=OFF
    '
fi

if docker run --rm \
  -v "${ROOT_DIR_REAL}:/workspace" \
  -w /workspace \
  "${CONTAINER_IMAGE}" \
  bash -lc "test -x '${CONTAINER_BTXD_BIN}' -a -x '${CONTAINER_BTX_CLI_BIN}'" >/dev/null; then
  CONTAINER_BITCOIND_BIN="${CONTAINER_BTXD_BIN}"
  CONTAINER_BITCOIN_CLI_BIN="${CONTAINER_BTX_CLI_BIN}"
elif docker run --rm \
  -v "${ROOT_DIR_REAL}:/workspace" \
  -w /workspace \
  "${CONTAINER_IMAGE}" \
  bash -lc "test -x '${CONTAINER_LEGACY_BITCOIND_BIN}' -a -x '${CONTAINER_LEGACY_BITCOIN_CLI_BIN}'" >/dev/null; then
  CONTAINER_BITCOIND_BIN="${CONTAINER_LEGACY_BITCOIND_BIN}"
  CONTAINER_BITCOIN_CLI_BIN="${CONTAINER_LEGACY_BITCOIN_CLI_BIN}"
else
  echo "error: missing CentOS btxd/btx-cli (or legacy aliases) in ${CENTOS_BUILD_DIR_REL}/bin" >&2
  exit 1
fi

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port_available() {
  python3 - "$1" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
sys.exit(0)
PY
}

choose_p2p_port() {
  for _ in $(seq 1 256); do
    local p
    p="$(find_free_port)"
    local p_aux=$((p + 1))
    if [[ "${p_aux}" -gt 65535 ]]; then
      continue
    fi
    local conflict=0
    if [[ "$#" -gt 0 ]]; then
      for r in "$@"; do
        if [[ -n "${r}" && ( "${p}" == "${r}" || "${p_aux}" == "${r}" ) ]]; then
          conflict=1
          break
        fi
      done
    fi
    if [[ "${conflict}" -eq 1 ]]; then
      continue
    fi
    if port_available "${p}" && port_available "${p_aux}"; then
      printf '%s\n' "${p}"
      return 0
    fi
  done
  return 1
}

choose_rpc_port() {
  for _ in $(seq 1 256); do
    local p
    p="$(find_free_port)"
    local conflict=0
    if [[ "$#" -gt 0 ]]; then
      for r in "$@"; do
        if [[ -n "${r}" && "${p}" == "${r}" ]]; then
          conflict=1
          break
        fi
      done
    fi
    if [[ "${conflict}" -eq 1 ]]; then
      continue
    fi
    if port_available "${p}"; then
      printf '%s\n' "${p}"
      return 0
    fi
  done
  return 1
}

assign_ports() {
  for _ in $(seq 1 32); do
    MAC_P2P_PORT="$(choose_p2p_port)" || continue
    local mac_aux=$((MAC_P2P_PORT + 1))
    CENTOS_P2P_PORT="$(choose_p2p_port "${MAC_P2P_PORT}" "${mac_aux}")" || continue
    local centos_aux=$((CENTOS_P2P_PORT + 1))
    MAC_RPC_PORT="$(choose_rpc_port "${MAC_P2P_PORT}" "${mac_aux}" "${CENTOS_P2P_PORT}" "${centos_aux}")" || continue
    CENTOS_RPC_PORT="$(choose_rpc_port "${MAC_P2P_PORT}" "${mac_aux}" "${CENTOS_P2P_PORT}" "${centos_aux}" "${MAC_RPC_PORT}")" || continue
    return 0
  done
  echo "error: failed to allocate conflict-free RPC/P2P ports" >&2
  return 1
}

MAC_P2P_PORT=""
MAC_RPC_PORT=""
CENTOS_P2P_PORT=""
CENTOS_RPC_PORT=""
assign_ports

BASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m13-mac-centos.XXXXXX")"
MAC_DATADIR="${BASE_DIR}/mac-node"
CENTOS_DATADIR="${BASE_DIR}/centos-node"
mkdir -p "${MAC_DATADIR}" "${CENTOS_DATADIR}"

CONTAINER_NAME="btx-m13-centos-$$"
MAC_NODE_PID=""

cleanup() {
  set +e
  if [[ -n "${CONTAINER_NAME}" ]]; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${MAC_NODE_PID}" ]]; then
    "${MAC_BITCOIN_CLI_BIN}" \
      -regtest \
      -regtestmsgstart="${MESSAGE_START}" \
      -regtestport="${REGTEST_PORT_OVERRIDE}" \
      -regtestgenesisntime="${GENESIS_TIME}" \
      -regtestgenesisnonce="${GENESIS_NONCE}" \
      -regtestgenesisbits="${GENESIS_BITS}" \
      -regtestgenesisversion="${GENESIS_VERSION}" \
      -datadir="${MAC_DATADIR}" \
      -rpcport="${MAC_RPC_PORT}" \
      stop >/dev/null 2>&1 || true
    wait "${MAC_NODE_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "M13 debug: preserved temp dir ${BASE_DIR}" >&2
  else
    rm -rf "${BASE_DIR}"
  fi
}
trap cleanup EXIT

mac_cli() {
  "${MAC_BITCOIN_CLI_BIN}" \
    -regtest \
    -regtestmsgstart="${MESSAGE_START}" \
    -regtestport="${REGTEST_PORT_OVERRIDE}" \
    -regtestgenesisntime="${GENESIS_TIME}" \
    -regtestgenesisnonce="${GENESIS_NONCE}" \
    -regtestgenesisbits="${GENESIS_BITS}" \
    -regtestgenesisversion="${GENESIS_VERSION}" \
    -datadir="${MAC_DATADIR}" \
    -rpcport="${MAC_RPC_PORT}" \
    "$@"
}

centos_cli() {
  docker exec "${CONTAINER_NAME}" \
    "${CONTAINER_BITCOIN_CLI_BIN}" \
    -regtest \
    -regtestmsgstart="${MESSAGE_START}" \
    -regtestport="${REGTEST_PORT_OVERRIDE}" \
    -regtestgenesisntime="${GENESIS_TIME}" \
    -regtestgenesisnonce="${GENESIS_NONCE}" \
    -regtestgenesisbits="${GENESIS_BITS}" \
    -regtestgenesisversion="${GENESIS_VERSION}" \
    -datadir=/data \
    -rpcport="${CENTOS_RPC_PORT}" \
    "$@"
}

wait_for_mac_rpc() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if mac_cli getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: timed out waiting for macOS RPC" >&2
  return 1
}

wait_for_centos_rpc() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if centos_cli getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: timed out waiting for CentOS RPC" >&2
  return 1
}

wait_for_height() {
  local cli_fn="$1"
  local expected="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local h
    h="$(${cli_fn} getblockcount)"
    if [[ "${h}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} did not reach height ${expected}" >&2
  return 1
}

wait_for_peer_connection() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local mac_conn centos_conn
    mac_conn="$(mac_cli getconnectioncount)"
    centos_conn="$(centos_cli getconnectioncount)"
    if [[ "${mac_conn}" -ge 1 && "${centos_conn}" -ge 1 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: peers did not connect" >&2
  return 1
}

wait_for_mempool_tx() {
  local txid="$1"
  local cli_fn="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if ${cli_fn} getmempoolentry "${txid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} did not observe tx ${txid} in mempool" >&2
  return 1
}

ensure_wallet() {
  local cli_fn="$1"
  local wallet="$2"
  if ! ${cli_fn} -rpcwallet="${wallet}" getwalletinfo >/dev/null 2>&1; then
    ${cli_fn} -named createwallet wallet_name="${wallet}" descriptors=true load_on_startup=false >/dev/null
  fi
}

BTX_MATMUL_BACKEND="${MATMUL_BACKEND}" "${MAC_BITCOIND_BIN}" \
  -regtest \
  -regtestmsgstart="${MESSAGE_START}" \
  -regtestport="${REGTEST_PORT_OVERRIDE}" \
  -regtestgenesisntime="${GENESIS_TIME}" \
  -regtestgenesisnonce="${GENESIS_NONCE}" \
  -regtestgenesisbits="${GENESIS_BITS}" \
  -regtestgenesisversion="${GENESIS_VERSION}" \
  -server=1 \
  -listen=1 \
  -listenonion=0 \
  -discover=0 \
  -dnsseed=0 \
  -fixedseeds=0 \
  -natpmp=0 \
  -upnp=0 \
  -v2transport="${P2P_V2_TRANSPORT}" \
  -fallbackfee=0.0001 \
  -datadir="${MAC_DATADIR}" \
  -port="${MAC_P2P_PORT}" \
  -rpcport="${MAC_RPC_PORT}" \
  -printtoconsole=0 \
  >"${MAC_DATADIR}/btxd.log" 2>&1 &
MAC_NODE_PID="$!"

platform_args=()
if [[ -n "${CONTAINER_PLATFORM}" ]]; then
  platform_args=(--platform "${CONTAINER_PLATFORM}")
fi
add_host_args=()
if [[ "$(uname -s)" == "Linux" ]]; then
  add_host_args=(--add-host host.docker.internal:host-gateway)
fi
docker run -d --rm \
  --name "${CONTAINER_NAME}" \
  "${platform_args[@]}" \
  "${add_host_args[@]}" \
  -v "${ROOT_DIR_REAL}:/workspace" \
  -v "${CENTOS_DATADIR}:/data" \
  -p "${CENTOS_P2P_PORT}:${CENTOS_P2P_PORT}" \
  "${CONTAINER_IMAGE}" \
  bash -lc '
    set -euo pipefail
    dnf -y install libevent >/tmp/m13-runtime-dnf.log
    export BTX_MATMUL_BACKEND="'"${MATMUL_BACKEND}"'"
    exec "'"${CONTAINER_BITCOIND_BIN}"'" \
      -regtest \
      -regtestmsgstart="'"${MESSAGE_START}"'" \
      -regtestport="'"${REGTEST_PORT_OVERRIDE}"'" \
      -regtestgenesisntime="'"${GENESIS_TIME}"'" \
      -regtestgenesisnonce="'"${GENESIS_NONCE}"'" \
      -regtestgenesisbits="'"${GENESIS_BITS}"'" \
      -regtestgenesisversion="'"${GENESIS_VERSION}"'" \
      -server=1 \
      -listen=1 \
      -listenonion=0 \
      -discover=0 \
      -dnsseed=0 \
      -fixedseeds=0 \
      -natpmp=0 \
      -upnp=0 \
      -v2transport="'"${P2P_V2_TRANSPORT}"'" \
      -fallbackfee=0.0001 \
      -datadir=/data \
      -port="'"${CENTOS_P2P_PORT}"'" \
      -rpcport="'"${CENTOS_RPC_PORT}"'" \
      -printtoconsole=0
  ' >/dev/null

wait_for_mac_rpc
wait_for_centos_rpc

mac_cli addnode "127.0.0.1:${CENTOS_P2P_PORT}" add >/dev/null 2>&1 || true
centos_cli addnode "host.docker.internal:${MAC_P2P_PORT}" add >/dev/null 2>&1 || true
wait_for_peer_connection

GENESIS_MAC="$(mac_cli getblockhash 0)"
GENESIS_CENTOS="$(centos_cli getblockhash 0)"
if [[ "${GENESIS_MAC}" != "${GENESIS_CENTOS}" ]]; then
  echo "error: genesis mismatch between macOS and CentOS nodes" >&2
  exit 1
fi

ensure_wallet mac_cli "macminer"
ensure_wallet centos_cli "centoswallet"

MAC_MINER_ADDR="$(mac_cli -rpcwallet=macminer getnewaddress)"
mac_cli generatetoaddress "${MATURITY_BLOCKS}" "${MAC_MINER_ADDR}" >/dev/null
wait_for_height centos_cli "${MATURITY_BLOCKS}" "CentOS node"

CENTOS_RECEIVE_ADDR="$(centos_cli -rpcwallet=centoswallet getnewaddress)"

# Build a spend from a matured macOS coinbase output directly. P2MR coinbase
# outputs are spendable with wallet signing even when trusted-balance accounting
# has not yet surfaced spendable balance through sendtoaddress.
MAC_SPEND_BLOCK_HASH="$(mac_cli getblockhash 1)"
MAC_COINBASE_TXID="$(mac_cli getblock "${MAC_SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["txid"])')"
MAC_COINBASE_VALUE="$(mac_cli getblock "${MAC_SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["vout"][0]["value"])')"
read -r MAC_RAW_INPUTS MAC_RAW_OUTPUTS <<<"$(python3 - "${MAC_COINBASE_TXID}" "${MAC_COINBASE_VALUE}" "${CENTOS_RECEIVE_ADDR}" "${MAC_MINER_ADDR}" "${SEND_AMOUNT_FORWARD}" <<'PY'
import json, sys
from decimal import Decimal, ROUND_DOWN

txid = sys.argv[1]
coinbase_value = Decimal(sys.argv[2])
receiver = sys.argv[3]
change_addr = sys.argv[4]
send_amount = Decimal(sys.argv[5])
fee = Decimal("0.0001")
change = (coinbase_value - send_amount - fee).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
if change <= 0:
    raise SystemExit("insufficient coinbase value for requested forward amount")
inputs = json.dumps([{"txid": txid, "vout": 0}], separators=(",", ":"))
outputs = json.dumps({receiver: float(send_amount), change_addr: float(change)}, separators=(",", ":"))
print(inputs, outputs)
PY
)"
MAC_RAW_TX="$(mac_cli -named createrawtransaction inputs="${MAC_RAW_INPUTS}" outputs="${MAC_RAW_OUTPUTS}")"
MAC_SIGNED_JSON="$(mac_cli -rpcwallet=macminer signrawtransactionwithwallet "${MAC_RAW_TX}")"
MAC_TX_COMPLETE="$(printf '%s' "${MAC_SIGNED_JSON}" | python3 -c 'import json,sys; print("true" if json.load(sys.stdin)["complete"] else "false")')"
if [[ "${MAC_TX_COMPLETE}" != "true" ]]; then
  echo "error: macOS forward transaction signing was incomplete" >&2
  exit 1
fi
MAC_TX_HEX="$(printf '%s' "${MAC_SIGNED_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"
TXID_FORWARD="$(mac_cli sendrawtransaction "${MAC_TX_HEX}")"
wait_for_mempool_tx "${TXID_FORWARD}" centos_cli "CentOS node"

mac_cli generatetoaddress 1 "${MAC_MINER_ADDR}" >/dev/null
POST_FORWARD_HEIGHT=$((MATURITY_BLOCKS + 1))
wait_for_height mac_cli "${POST_FORWARD_HEIGHT}" "macOS node"
wait_for_height centos_cli "${POST_FORWARD_HEIGHT}" "CentOS node"

FORWARD_CONFIRMATIONS="$(centos_cli -rpcwallet=centoswallet gettransaction "${TXID_FORWARD}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])')"
if [[ "${FORWARD_CONFIRMATIONS}" -lt 1 ]]; then
  echo "error: forward transfer ${TXID_FORWARD} was not confirmed on CentOS wallet" >&2
  exit 1
fi

MAC_RECEIVE_ADDR="$(mac_cli -rpcwallet=macminer getnewaddress)"
TXID_REVERSE="$(centos_cli -rpcwallet=centoswallet -named sendtoaddress address="${MAC_RECEIVE_ADDR}" amount="${SEND_AMOUNT_REVERSE}" fee_rate=30)"
wait_for_mempool_tx "${TXID_REVERSE}" mac_cli "macOS node"

CENTOS_MINER_ADDR="$(centos_cli -rpcwallet=centoswallet getnewaddress)"
centos_cli generatetoaddress 2 "${CENTOS_MINER_ADDR}" >/dev/null
FINAL_HEIGHT=$((POST_FORWARD_HEIGHT + 2))
wait_for_height mac_cli "${FINAL_HEIGHT}" "macOS node"
wait_for_height centos_cli "${FINAL_HEIGHT}" "CentOS node"

REVERSE_CONFIRMATIONS="$(mac_cli -rpcwallet=macminer gettransaction "${TXID_REVERSE}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])')"
if [[ "${REVERSE_CONFIRMATIONS}" -lt 1 ]]; then
  echo "error: reverse transfer ${TXID_REVERSE} was not confirmed on macOS wallet" >&2
  exit 1
fi

BEST_MAC="$(mac_cli getbestblockhash)"
BEST_CENTOS="$(centos_cli getbestblockhash)"
MAC_CONNECTIONS="$(mac_cli getconnectioncount)"
CENTOS_CONNECTIONS="$(centos_cli getconnectioncount)"

python3 - "${ARTIFACT_PATH}" <<PY
import json
from datetime import datetime, timezone

artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": "pass",
    "chain": "regtest-custom",
    "container_image": "${CONTAINER_IMAGE}",
    "matmul_backend": "${MATMUL_BACKEND}",
    "p2p_v2_transport": int("${P2P_V2_TRANSPORT}"),
    "message_start": "${MESSAGE_START}",
    "regtest_default_port": int("${REGTEST_PORT_OVERRIDE}"),
    "genesis": {
        "time": int("${GENESIS_TIME}"),
        "nonce": int("${GENESIS_NONCE}"),
        "bits": "${GENESIS_BITS}",
        "version": int("${GENESIS_VERSION}"),
        "hash": "${GENESIS_MAC}",
    },
    "mac_node": {
        "p2p_port": int("${MAC_P2P_PORT}"),
        "rpc_port": int("${MAC_RPC_PORT}"),
        "connections": int("${MAC_CONNECTIONS}"),
        "best_block": "${BEST_MAC}",
        "height": int("${FINAL_HEIGHT}"),
    },
    "centos_node": {
        "p2p_port": int("${CENTOS_P2P_PORT}"),
        "rpc_port": int("${CENTOS_RPC_PORT}"),
        "connections": int("${CENTOS_CONNECTIONS}"),
        "best_block": "${BEST_CENTOS}",
        "height": int("${FINAL_HEIGHT}"),
    },
    "transfers": {
        "forward_txid": "${TXID_FORWARD}",
        "forward_amount": "${SEND_AMOUNT_FORWARD}",
        "forward_confirmations": int("${FORWARD_CONFIRMATIONS}"),
        "reverse_txid": "${TXID_REVERSE}",
        "reverse_amount": "${SEND_AMOUNT_REVERSE}",
        "reverse_confirmations": int("${REVERSE_CONFIRMATIONS}"),
    },
}
with open("${ARTIFACT_PATH}", "w", encoding="utf-8") as handle:
    json.dump(artifact, handle, indent=2)
PY

echo "M13 macOS/CentOS interoperability checks passed:"
echo "- Shared custom regtest genesis ${GENESIS_MAC}"
echo "- Bi-directional P2P sync verified at height ${FINAL_HEIGHT}"
echo "- Forward transfer ${TXID_FORWARD} and reverse transfer ${TXID_REVERSE} confirmed"
echo "- Artifact: ${ARTIFACT_PATH}"
