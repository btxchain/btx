#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAC_BIN_DIR="${ROOT_DIR}/build-btx/bin"
CONTAINER_NAME="btx-centos-node"

MAC_PORT=19444
MAC_RPC_PORT=19443
CEN_PORT=29444
CEN_RPC_PORT=29443

MAC_RPC_USER="macuser"
MAC_RPC_PASS="macpass"
CEN_RPC_USER="cenuser"
CEN_RPC_PASS="cenpass"
CEN_BIN_DIR=""

MAC_DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-crossos-mac.XX""XX""XX")"
CEN_DATADIR="/tmp/btx-crossos-centos.$RANDOM$RANDOM"

MAC_NODE_STARTED=0
CEN_NODE_STARTED=0

cleanup() {
  set +e
  if [[ "${MAC_NODE_STARTED}" -eq 1 ]]; then
    "${MAC_BIN_DIR}/btx-cli" -regtest -rpcconnect=127.0.0.1 -rpcport="${MAC_RPC_PORT}" \
      -rpcuser="${MAC_RPC_USER}" -rpcpassword="${MAC_RPC_PASS}" stop >/dev/null 2>&1 || true
  fi
  if [[ "${CEN_NODE_STARTED}" -eq 1 ]]; then
    docker exec "${CONTAINER_NAME}" "${CEN_BIN_DIR}/btx-cli" -regtest \
      -rpcconnect=127.0.0.1 -rpcport="${CEN_RPC_PORT}" \
      -rpcuser="${CEN_RPC_USER}" -rpcpassword="${CEN_RPC_PASS}" stop >/dev/null 2>&1 || true
  fi
  docker exec "${CONTAINER_NAME}" bash -lc "rm -rf '${CEN_DATADIR}'" >/dev/null 2>&1 || true
  rm -rf "${MAC_DATADIR}"
}
trap cleanup EXIT

if [[ ! -x "${MAC_BIN_DIR}/btxd" || ! -x "${MAC_BIN_DIR}/btx-cli" ]]; then
  echo "error: macOS btxd/btx-cli not found in ${MAC_BIN_DIR}" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
  echo "error: required container '${CONTAINER_NAME}' is not running" >&2
  exit 1
fi

if docker exec "${CONTAINER_NAME}" bash -lc "/workspace/build-centos-run/bin/btxd --version >/dev/null 2>&1"; then
  CEN_BIN_DIR="/workspace/build-centos-run/bin"
elif docker exec "${CONTAINER_NAME}" bash -lc "/workspace/ci/scratch/out/bin/btxd --version >/dev/null 2>&1"; then
  CEN_BIN_DIR="/workspace/ci/scratch/out/bin"
elif docker exec "${CONTAINER_NAME}" bash -lc "/workspace/build/bin/btxd --version >/dev/null 2>&1"; then
  CEN_BIN_DIR="/workspace/build/bin"
else
  echo "error: no runnable linux btxd found in container (checked /workspace/build-centos-run/bin, /workspace/ci/scratch/out/bin, /workspace/build/bin)" >&2
  exit 1
fi

mac_cli() {
  "${MAC_BIN_DIR}/btx-cli" -regtest -rpcconnect=127.0.0.1 -rpcport="${MAC_RPC_PORT}" \
    -rpcuser="${MAC_RPC_USER}" -rpcpassword="${MAC_RPC_PASS}" "$@"
}

mac_wallet_cli() {
  "${MAC_BIN_DIR}/btx-cli" -regtest -rpcconnect=127.0.0.1 -rpcport="${MAC_RPC_PORT}" \
    -rpcuser="${MAC_RPC_USER}" -rpcpassword="${MAC_RPC_PASS}" -rpcwallet="$1" "${@:2}"
}

cen_cli() {
  docker exec "${CONTAINER_NAME}" "${CEN_BIN_DIR}/btx-cli" -regtest \
    -rpcconnect=127.0.0.1 -rpcport="${CEN_RPC_PORT}" \
    -rpcuser="${CEN_RPC_USER}" -rpcpassword="${CEN_RPC_PASS}" "$@"
}

cen_wallet_cli() {
  docker exec "${CONTAINER_NAME}" "${CEN_BIN_DIR}/btx-cli" -regtest \
    -rpcconnect=127.0.0.1 -rpcport="${CEN_RPC_PORT}" \
    -rpcuser="${CEN_RPC_USER}" -rpcpassword="${CEN_RPC_PASS}" -rpcwallet="$1" "${@:2}"
}

wait_for_connections() {
  local expected="$1"
  local attempts=0
  while [[ $attempts -lt 60 ]]; do
    local mac_count cen_count
    mac_count="$(mac_cli getconnectioncount)"
    cen_count="$(cen_cli getconnectioncount)"
    if [[ "${mac_count}" -ge "${expected}" && "${cen_count}" -ge "${expected}" ]]; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "error: peers did not connect (mac=$(mac_cli getconnectioncount), centos=$(cen_cli getconnectioncount))" >&2
  return 1
}

wait_for_block_sync() {
  local attempts=0
  while [[ $attempts -lt 60 ]]; do
    local mac_height cen_height
    mac_height="$(mac_cli getblockcount)"
    cen_height="$(cen_cli getblockcount)"
    if [[ "${mac_height}" == "${cen_height}" ]]; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "error: block heights diverged (mac=$(mac_cli getblockcount), centos=$(cen_cli getblockcount))" >&2
  return 1
}

wait_for_mempool_tx() {
  local node="$1"
  local txid="$2"
  local attempts=0
  while [[ $attempts -lt 30 ]]; do
    if [[ "${node}" == "mac" ]]; then
      if mac_cli getmempoolentry "${txid}" >/dev/null 2>&1; then
        return 0
      fi
    else
      if cen_cli getmempoolentry "${txid}" >/dev/null 2>&1; then
        return 0
      fi
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

echo "[1/8] Start macOS regtest node"
"${MAC_BIN_DIR}/btxd" -regtest -datadir="${MAC_DATADIR}" -server=1 -daemonwait=1 \
  -port="${MAC_PORT}" -rpcport="${MAC_RPC_PORT}" \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
  -rpcuser="${MAC_RPC_USER}" -rpcpassword="${MAC_RPC_PASS}" \
  -fallbackfee=0.0001 -keypool=100 -listen=1 -discover=0 >/dev/null
MAC_NODE_STARTED=1

echo "[2/8] Start CentOS regtest node in container"
docker exec "${CONTAINER_NAME}" bash -lc "mkdir -p '${CEN_DATADIR}' && '${CEN_BIN_DIR}/btxd' \
  -regtest -datadir='${CEN_DATADIR}' -server=1 -daemonwait=1 \
  -port='${CEN_PORT}' -rpcport='${CEN_RPC_PORT}' \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
  -rpcuser='${CEN_RPC_USER}' -rpcpassword='${CEN_RPC_PASS}' \
  -fallbackfee=0.0001 -keypool=100 -listen=1 -discover=0" >/dev/null
CEN_NODE_STARTED=1

echo "[3/8] Connect centos->mac peers"
HOST_GATEWAY_IP="$(docker exec "${CONTAINER_NAME}" bash -lc "getent hosts host.docker.internal 2>/dev/null | awk 'NR==1{print \$1}'")"
if [[ -z "${HOST_GATEWAY_IP}" ]]; then
  HOST_GATEWAY_IP="$(docker exec "${CONTAINER_NAME}" python3 - <<'PY'
import socket
import struct

gateway = ""
with open("/proc/net/route", "r", encoding="utf-8") as f:
    next(f)
    for line in f:
        fields = line.strip().split()
        if len(fields) < 3:
            continue
        destination, gw_hex = fields[1], fields[2]
        if destination == "00000000":
            gateway = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
            break
print(gateway)
PY
)"
fi
if [[ -z "${HOST_GATEWAY_IP}" ]]; then
  echo "error: could not determine host gateway IP from container" >&2
  exit 1
fi
cen_cli addnode "${HOST_GATEWAY_IP}:${MAC_PORT}" onetry
wait_for_connections 1

echo "[4/8] Create macOS wallet and addresses"
mac_cli -named createwallet wallet_name=macminer descriptors=true >/dev/null
SOURCE_ADDR="$(mac_wallet_cli macminer getnewaddress "" p2mr)"
DEST_ADDR="$(mac_wallet_cli macminer getnewaddress "" p2mr)"

echo "[5/8] Mine mature funds and select a spendable macOS UTXO"
mac_wallet_cli macminer generatetoaddress 110 "${SOURCE_ADDR}" >/dev/null
wait_for_block_sync
mac_cli syncwithvalidationinterfacequeue >/dev/null
cen_cli syncwithvalidationinterfacequeue >/dev/null
UTXO_JSON="$(mac_wallet_cli macminer listunspent 1 9999999 "[\"${SOURCE_ADDR}\"]" true)"
MS_TXID="$(printf '%s' "${UTXO_JSON}" | python3 -c 'import json,sys; u=json.load(sys.stdin); assert u, "empty UTXO set"; print(u[0]["txid"])')"
MS_VOUT="$(printf '%s' "${UTXO_JSON}" | python3 -c 'import json,sys; u=json.load(sys.stdin); assert u, "empty UTXO set"; print(u[0]["vout"])')"
MS_AMOUNT="$(printf '%s' "${UTXO_JSON}" | python3 -c 'import json,sys; u=json.load(sys.stdin); assert u, "empty UTXO set"; print(u[0]["amount"])')"
SPEND_AMOUNT="$(python3 - "${MS_AMOUNT}" <<'PY'
from decimal import Decimal, ROUND_DOWN
import sys

amount = Decimal(sys.argv[1])
fee = Decimal("0.001")
spend = (amount - fee).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
print(spend)
PY
)"
FUND_OUTPOINT="${MS_TXID}:${MS_VOUT}"

echo "[6/8] Build/sign/finalize PSBT on macOS"
INPUTS_JSON="[{\"txid\":\"${MS_TXID}\",\"vout\":${MS_VOUT}}]"
OUTPUTS_JSON="[{\"${DEST_ADDR}\":1.0}]"
OUTPUTS_JSON="[{\"${DEST_ADDR}\":${SPEND_AMOUNT}}]"
RAW_PSBT="$(mac_cli createpsbt "${INPUTS_JSON}" "${OUTPUTS_JSON}")"
PSBT_SIGNED="$(mac_wallet_cli macminer walletprocesspsbt "${RAW_PSBT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["psbt"])')"
FINAL_JSON="$(mac_cli finalizepsbt "${PSBT_SIGNED}")"
FINAL_HEX="$(printf '%s' "${FINAL_JSON}" | python3 -c 'import json,sys; j=json.load(sys.stdin); assert j.get("complete"); print(j["hex"])')"

echo "[7/8] Broadcast from CentOS node and verify relay on both nodes"
SPEND_TXID="$(cen_cli sendrawtransaction "${FINAL_HEX}")"
if ! wait_for_mempool_tx mac "${SPEND_TXID}"; then
  echo "error: broadcast tx not seen in mac mempool" >&2
  exit 1
fi
if ! wait_for_mempool_tx cen "${SPEND_TXID}"; then
  echo "error: broadcast tx not retained in centos mempool" >&2
  exit 1
fi

echo "[8/8] Confirm spend on macOS and verify both nodes are in sync"
mac_wallet_cli macminer generatetoaddress 1 "${SOURCE_ADDR}" >/dev/null
wait_for_block_sync
if [[ "$(mac_cli getrawmempool | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" != "0" ]]; then
  echo "error: mempool not empty after confirmation" >&2
  exit 1
fi
if [[ "$(cen_cli getrawmempool | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" != "0" ]]; then
  echo "error: centos mempool not empty after confirmation" >&2
  exit 1
fi
MAC_CONFS="$(mac_wallet_cli macminer gettransaction "${SPEND_TXID}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations", 0))')"
CEN_CONFS="$(cen_cli getrawtransaction "${SPEND_TXID}" 1 "$(cen_cli getbestblockhash)" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations", 0))')"
if [[ "${MAC_CONFS}" -lt 1 || "${CEN_CONFS}" -lt 1 ]]; then
  echo "error: confirmed spend not visible on both nodes (mac=${MAC_CONFS}, centos=${CEN_CONFS})" >&2
  exit 1
fi

echo "pq_cross_os_mac_centos_interop: PASS"
echo "  host_gateway=${HOST_GATEWAY_IP}"
echo "  funding_outpoint=${FUND_OUTPOINT}"
echo "  destination_address=${DEST_ADDR}"
echo "  spend_txid=${SPEND_TXID}"
