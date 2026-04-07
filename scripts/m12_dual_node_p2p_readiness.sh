#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m12_dual_node_p2p_readiness.sh [options]

Run a live dual-node BTX regtest validation with:
1) Genesis alignment between canonical node A and peer node B
2) P2P connectivity and block synchronization
3) Wallet transaction relay from A to B
4) Confirmation and reverse-direction block sync (B -> A)

Options:
  --build-dir <path>        Build directory (default: build-btx)
  --artifact <path>         JSON artifact output path
                            (default: .btx-validation/m12-dual-node-p2p.json)
  --timeout-seconds <n>     Wait timeout per phase (default: 300)
  --help                    Show this message

Environment overrides:
  BTX_CANONICAL_HOST        Canonical node A bind host (default: 127.0.0.1)
  BTX_PEER_HOST             Peer node B bind host (default: 127.0.0.1)
  BTX_CANONICAL_RPC_PORT    Canonical node A RPC port (default: auto)
  BTX_CANONICAL_P2P_PORT    Canonical node A P2P port (default: auto)
  BTX_PEER_RPC_PORT         Peer node B RPC port (default: auto)
  BTX_PEER_P2P_PORT         Peer node B P2P port (default: auto)
  BTX_M12_TIMEOUT_SECONDS   Equivalent to --timeout-seconds
  BTX_M12_MATURITY_BLOCKS   Blocks mined on node A before spend (default: 101)
  BTX_M12_SEND_AMOUNT       Amount sent from node A wallet to node B wallet (default: 1.25)
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m12-dual-node-p2p.json"
TIMEOUT_SECONDS="${BTX_M12_TIMEOUT_SECONDS:-300}"
MATURITY_BLOCKS="${BTX_M12_MATURITY_BLOCKS:-101}"
SEND_AMOUNT="${BTX_M12_SEND_AMOUNT:-1.25}"
KEEP_TMP="${BTX_M12_KEEP_TMP:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
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
  echo "error: timeout must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MATURITY_BLOCKS}" =~ ^[0-9]+$ ]] || [[ "${MATURITY_BLOCKS}" -lt 101 ]]; then
  echo "error: BTX_M12_MATURITY_BLOCKS must be an integer >= 101" >&2
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

CANONICAL_HOST="${BTX_CANONICAL_HOST:-127.0.0.1}"
PEER_HOST="${BTX_PEER_HOST:-127.0.0.1}"
CANONICAL_RPC_PORT_OVERRIDE="${BTX_CANONICAL_RPC_PORT:-}"
CANONICAL_P2P_PORT_OVERRIDE="${BTX_CANONICAL_P2P_PORT:-}"
PEER_RPC_PORT_OVERRIDE="${BTX_PEER_RPC_PORT:-}"
PEER_P2P_PORT_OVERRIDE="${BTX_PEER_P2P_PORT:-}"
MAX_START_ATTEMPTS="${BTX_M12_MAX_START_ATTEMPTS:-5}"

CANONICAL_RPC_PORT=""
CANONICAL_P2P_PORT=""
PEER_RPC_PORT=""
PEER_P2P_PORT=""

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

BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
if [[ ! -x "${BITCOIND_BIN}" || ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing btxd/btx-cli (or legacy aliases) in ${BUILD_DIR}/bin" >&2
  exit 1
fi

BASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m12-dual-node.XXXXXX")"
NODE_A_DIR="${BASE_DIR}/node-a"
NODE_B_DIR="${BASE_DIR}/node-b"
mkdir -p "${NODE_A_DIR}" "${NODE_B_DIR}" "$(dirname "${ARTIFACT_PATH}")"

NODE_A_PID=""
NODE_B_PID=""

cli_a() {
  "${BITCOIN_CLI_BIN}" -regtest -datadir="${NODE_A_DIR}" -rpcport="${CANONICAL_RPC_PORT}" "$@"
}

cli_b() {
  "${BITCOIN_CLI_BIN}" -regtest -datadir="${NODE_B_DIR}" -rpcport="${PEER_RPC_PORT}" "$@"
}

stop_node() {
  local pid="$1"
  local cli_fn="$2"
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  "${cli_fn}" stop >/dev/null 2>&1 || true
  for _ in $(seq 1 10); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  stop_node "${NODE_B_PID}" cli_b
  stop_node "${NODE_A_PID}" cli_a
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "M12 debug: preserved temp dir ${BASE_DIR}" >&2
  else
    rm -rf "${BASE_DIR}"
  fi
}
trap cleanup EXIT

wait_for_rpc() {
  local pid="$1"
  local cli_fn="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "error: ${label} exited before RPC became available" >&2
      return 1
    fi
    if "${cli_fn}" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: timed out waiting for ${label} RPC" >&2
  return 1
}

wait_for_height() {
  local cli_fn="$1"
  local label="$2"
  local expected_height="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local height
    height="$("${cli_fn}" getblockcount)"
    if [[ "${height}" -ge "${expected_height}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} did not reach height ${expected_height}" >&2
  return 1
}

wait_for_peer_connection() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local ca cb
    ca="$(cli_a getconnectioncount)"
    cb="$(cli_b getconnectioncount)"
    if [[ "${ca}" -ge 1 && "${cb}" -ge 1 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: nodes did not establish a peer connection" >&2
  return 1
}

wait_for_mempool_tx() {
  local txid="$1"
  local cli_fn="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if "${cli_fn}" getmempoolentry "${txid}" >/dev/null 2>&1; then
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
  if ! "${cli_fn}" -rpcwallet="${wallet}" getwalletinfo >/dev/null 2>&1; then
    "${cli_fn}" -named createwallet wallet_name="${wallet}" descriptors=true load_on_startup=false >/dev/null
  fi
}

assign_ports() {
  local attempts=0
  local has_overrides=0
  if [[ -n "${CANONICAL_RPC_PORT_OVERRIDE}" || -n "${CANONICAL_P2P_PORT_OVERRIDE}" || -n "${PEER_RPC_PORT_OVERRIDE}" || -n "${PEER_P2P_PORT_OVERRIDE}" ]]; then
    has_overrides=1
  fi

  while (( attempts < 32 )); do
    attempts=$((attempts + 1))
    if [[ "${has_overrides}" -eq 1 ]]; then
      CANONICAL_RPC_PORT="${CANONICAL_RPC_PORT_OVERRIDE}"
      CANONICAL_P2P_PORT="${CANONICAL_P2P_PORT_OVERRIDE}"
      PEER_RPC_PORT="${PEER_RPC_PORT_OVERRIDE}"
      PEER_P2P_PORT="${PEER_P2P_PORT_OVERRIDE}"
    else
      CANONICAL_P2P_PORT="$(choose_p2p_port)" || continue
      local canonical_aux=$((CANONICAL_P2P_PORT + 1))
      PEER_P2P_PORT="$(choose_p2p_port "${CANONICAL_P2P_PORT}" "${canonical_aux}")" || continue
      local peer_aux=$((PEER_P2P_PORT + 1))
      CANONICAL_RPC_PORT="$(choose_rpc_port "${CANONICAL_P2P_PORT}" "${canonical_aux}" "${PEER_P2P_PORT}" "${peer_aux}")" || continue
      PEER_RPC_PORT="$(choose_rpc_port "${CANONICAL_P2P_PORT}" "${canonical_aux}" "${PEER_P2P_PORT}" "${peer_aux}" "${CANONICAL_RPC_PORT}")" || continue
    fi

    local a_aux_port b_aux_port
    a_aux_port=$((CANONICAL_P2P_PORT + 1))
    b_aux_port=$((PEER_P2P_PORT + 1))

    local numeric_ok=1
    for port in "${CANONICAL_RPC_PORT}" "${CANONICAL_P2P_PORT}" "${PEER_RPC_PORT}" "${PEER_P2P_PORT}" "${a_aux_port}" "${b_aux_port}"; do
      if ! [[ "${port}" =~ ^[0-9]+$ ]] || [[ "${port}" -lt 1 ]] || [[ "${port}" -gt 65535 ]]; then
        numeric_ok=0
        break
      fi
    done
    if [[ "${numeric_ok}" -ne 1 ]]; then
      if [[ "${has_overrides}" -eq 1 ]]; then
        echo "error: invalid overridden RPC/P2P port value(s)" >&2
        return 1
      fi
      continue
    fi

    local unique_count
    unique_count="$(printf '%s\n' "${CANONICAL_RPC_PORT}" "${CANONICAL_P2P_PORT}" "${a_aux_port}" "${PEER_RPC_PORT}" "${PEER_P2P_PORT}" "${b_aux_port}" | sort -n | uniq | wc -l | tr -d ' ')"
    if [[ "${unique_count}" -ne 6 ]]; then
      if [[ "${has_overrides}" -eq 1 ]]; then
        echo "error: RPC/P2P ports conflict with required p2p+1 bindings" >&2
        return 1
      fi
      continue
    fi

    if ! port_available "${CANONICAL_RPC_PORT}" || \
       ! port_available "${CANONICAL_P2P_PORT}" || \
       ! port_available "${a_aux_port}" || \
       ! port_available "${PEER_RPC_PORT}" || \
       ! port_available "${PEER_P2P_PORT}" || \
       ! port_available "${b_aux_port}"; then
      if [[ "${has_overrides}" -eq 1 ]]; then
        echo "error: overridden RPC/P2P ports are unavailable on localhost" >&2
        return 1
      fi
      continue
    fi

    return 0
  done

  echo "error: unable to allocate conflict-free port set for dual-node validation" >&2
  return 1
}

start_nodes() {
  "${BITCOIND_BIN}" \
    -regtest \
    -test=matmulstrict \
    -autoshieldcoinbase=0 \
    -server=1 \
    -listen=1 \
    -discover=0 \
    -dnsseed=0 \
    -fixedseeds=0 \
    -natpmp=0 \
    -upnp=0 \
    -fallbackfee=0.0001 \
    -datadir="${NODE_A_DIR}" \
    -port="${CANONICAL_P2P_PORT}" \
    -rpcport="${CANONICAL_RPC_PORT}" \
    -printtoconsole=0 \
    >"${NODE_A_DIR}/btxd.log" 2>&1 &
  NODE_A_PID="$!"

  "${BITCOIND_BIN}" \
    -regtest \
    -test=matmulstrict \
    -autoshieldcoinbase=0 \
    -server=1 \
    -listen=1 \
    -discover=0 \
    -dnsseed=0 \
    -fixedseeds=0 \
    -natpmp=0 \
    -upnp=0 \
    -fallbackfee=0.0001 \
    -datadir="${NODE_B_DIR}" \
    -port="${PEER_P2P_PORT}" \
    -rpcport="${PEER_RPC_PORT}" \
    -printtoconsole=0 \
    >"${NODE_B_DIR}/btxd.log" 2>&1 &
  NODE_B_PID="$!"
}

if ! [[ "${MAX_START_ATTEMPTS}" =~ ^[0-9]+$ ]] || [[ "${MAX_START_ATTEMPTS}" -lt 1 ]]; then
  echo "error: BTX_M12_MAX_START_ATTEMPTS must be a positive integer" >&2
  exit 1
fi

started=0
for _ in $(seq 1 "${MAX_START_ATTEMPTS}"); do
  assign_ports
  : > "${NODE_A_DIR}/btxd.log"
  : > "${NODE_B_DIR}/btxd.log"
  start_nodes
  if wait_for_rpc "${NODE_A_PID}" cli_a "node A" && wait_for_rpc "${NODE_B_PID}" cli_b "node B"; then
    started=1
    break
  fi
  stop_node "${NODE_B_PID}" cli_b
  stop_node "${NODE_A_PID}" cli_a
  NODE_A_PID=""
  NODE_B_PID=""
  if [[ -n "${CANONICAL_RPC_PORT_OVERRIDE}" || -n "${CANONICAL_P2P_PORT_OVERRIDE}" || -n "${PEER_RPC_PORT_OVERRIDE}" || -n "${PEER_P2P_PORT_OVERRIDE}" ]]; then
    break
  fi
  sleep 1
done

if [[ "${started}" -ne 1 ]]; then
  echo "error: failed to start both nodes and reach RPC after ${MAX_START_ATTEMPTS} attempt(s)" >&2
  exit 1
fi

cli_b addnode "${CANONICAL_HOST}:${CANONICAL_P2P_PORT}" add >/dev/null 2>&1 || true
wait_for_peer_connection

GENESIS_A="$(cli_a getblockhash 0)"
GENESIS_B="$(cli_b getblockhash 0)"
if [[ "${GENESIS_A}" != "${GENESIS_B}" ]]; then
  echo "error: genesis mismatch between node A and node B" >&2
  exit 1
fi

ensure_wallet cli_a "miner"
ensure_wallet cli_b "receiver"

MINER_ADDRESS="$(cli_a -rpcwallet=miner getnewaddress)"
cli_a generatetoaddress "${MATURITY_BLOCKS}" "${MINER_ADDRESS}" >/dev/null
wait_for_height cli_b "node B" "${MATURITY_BLOCKS}"

RECEIVER_ADDRESS="$(cli_b -rpcwallet=receiver getnewaddress)"

# Coinbase outputs are spendable under P2MR, but wallet trusted-balance
# accounting may lag for generated coinbase UTXOs. Build and sign a spend from
# a matured coinbase output directly to exercise real relay/confirmation flow.
SPEND_BLOCK_HASH="$(cli_a getblockhash 1)"
COINBASE_TXID="$(cli_a getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["txid"])')"
COINBASE_VALUE="$(cli_a getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["vout"][0]["value"])')"
read -r RAW_INPUTS RAW_OUTPUTS <<<"$(python3 - "${COINBASE_TXID}" "${COINBASE_VALUE}" "${RECEIVER_ADDRESS}" "${MINER_ADDRESS}" "${SEND_AMOUNT}" <<'PY'
import json, sys
from decimal import Decimal, ROUND_DOWN

txid = sys.argv[1]
coinbase_value = Decimal(sys.argv[2])
receiver = sys.argv[3]
miner_change = sys.argv[4]
send_amount = Decimal(sys.argv[5])
fee = Decimal("0.0001")
change = (coinbase_value - send_amount - fee).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
if change <= 0:
    raise SystemExit("insufficient coinbase value for requested send amount")
inputs = json.dumps([{"txid": txid, "vout": 0}], separators=(",", ":"))
outputs = json.dumps({receiver: float(send_amount), miner_change: float(change)}, separators=(",", ":"))
print(inputs, outputs)
PY
)"
RAW_TX="$(cli_a -named createrawtransaction inputs="${RAW_INPUTS}" outputs="${RAW_OUTPUTS}")"
SIGNED_JSON="$(cli_a -rpcwallet=miner signrawtransactionwithwallet "${RAW_TX}")"
TX_COMPLETE="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print("true" if json.load(sys.stdin)["complete"] else "false")')"
if [[ "${TX_COMPLETE}" != "true" ]]; then
  echo "error: signrawtransactionwithwallet did not produce a complete transaction" >&2
  exit 1
fi
TX_HEX="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"
TXID="$(cli_a sendrawtransaction "${TX_HEX}")"
wait_for_mempool_tx "${TXID}" cli_b "node B"

cli_a generatetoaddress 1 "${MINER_ADDRESS}" >/dev/null
POST_TX_HEIGHT=$((MATURITY_BLOCKS + 1))
wait_for_height cli_a "node A" "${POST_TX_HEIGHT}"
wait_for_height cli_b "node B" "${POST_TX_HEIGHT}"

CONFIRMATIONS="$(cli_b -rpcwallet=receiver gettransaction "${TXID}" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])')"
if [[ "${CONFIRMATIONS}" -lt 1 ]]; then
  echo "error: tx ${TXID} was not confirmed in node B wallet" >&2
  exit 1
fi

PEER_MINING_ADDRESS="$(cli_b -rpcwallet=receiver getnewaddress)"
cli_b generatetoaddress 2 "${PEER_MINING_ADDRESS}" >/dev/null
FINAL_HEIGHT=$((POST_TX_HEIGHT + 2))
wait_for_height cli_a "node A" "${FINAL_HEIGHT}"
wait_for_height cli_b "node B" "${FINAL_HEIGHT}"

CONNECTIONS_A="$(cli_a getconnectioncount)"
CONNECTIONS_B="$(cli_b getconnectioncount)"
BEST_A="$(cli_a getbestblockhash)"
BEST_B="$(cli_b getbestblockhash)"

python3 - "${ARTIFACT_PATH}" <<PY
import json
from datetime import datetime, timezone

artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": "pass",
    "chain": "regtest",
    "canonical_node": {
        "host": "${CANONICAL_HOST}",
        "p2p_port": int("${CANONICAL_P2P_PORT}"),
        "rpc_port": int("${CANONICAL_RPC_PORT}"),
    },
    "peer_node": {
        "host": "${PEER_HOST}",
        "p2p_port": int("${PEER_P2P_PORT}"),
        "rpc_port": int("${PEER_RPC_PORT}"),
    },
    "genesis_hash": "${GENESIS_A}",
    "txid": "${TXID}",
    "send_amount": "${SEND_AMOUNT}",
    "confirmations_on_peer_wallet": int("${CONFIRMATIONS}"),
    "connection_count_a": int("${CONNECTIONS_A}"),
    "connection_count_b": int("${CONNECTIONS_B}"),
    "final_height_a": int("${FINAL_HEIGHT}"),
    "final_height_b": int("${FINAL_HEIGHT}"),
    "best_block_a": "${BEST_A}",
    "best_block_b": "${BEST_B}",
}
with open("${ARTIFACT_PATH}", "w", encoding="utf-8") as f:
    json.dump(artifact, f, indent=2)
PY

echo "M12 dual-node P2P readiness checks passed:"
echo "- Nodes connected and shared genesis ${GENESIS_A}"
echo "- Node A mined ${MATURITY_BLOCKS} blocks, node B synchronized"
echo "- Wallet tx ${TXID} relayed from A -> B and confirmed"
echo "- Node B mined 2 blocks, node A synchronized at height ${FINAL_HEIGHT}"
echo "- Artifact: ${ARTIFACT_PATH}"
