#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m12_docker_regtest_cluster.sh [options]

Run a live two-container BTX Docker regtest validation with:
1) Temporary Docker network, datadirs, and node configs
2) P2P connectivity, RPC availability, and genesis alignment checks
3) Wallet transaction relay from node A -> node B
4) Confirmation, then wallet transaction relay from node B -> node A
5) Bridge view-grant planning, settlement, chain retrieval, and operator decrypt
6) JSON artifact emission and cleanup of only resources created by this script

Options:
  --image <name>             Docker image to run (default: btxd)
  --artifact <path>          JSON artifact output path
                            (default: .btx-validation/m12-docker-regtest-cluster.json)
  --timeout-seconds <n>      Wait timeout per phase (default: 240)
  --build-image              Build --image from contrib/docker/Dockerfile before running
  --help                     Show this message

Environment overrides:
  BTX_M12_DOCKER_IMAGE             Docker image to run (default: btxd)
  BTX_M12_DOCKER_PLATFORM          Docker --platform override (optional)
  BTX_M12_DOCKER_TIMEOUT_SECONDS   Equivalent to --timeout-seconds
  BTX_M12_DOCKER_MATURITY_BLOCKS   Blocks mined on node A before spend (default: 101)
  BTX_M12_DOCKER_SEND_A_TO_B       Amount sent from node A wallet to node B wallet (default: 1.25)
  BTX_M12_DOCKER_SEND_B_TO_A       Amount sent from node B wallet to node A wallet (default: 0.75)
  BTX_M12_DOCKER_KEEP_TMP          Preserve temp directories on exit (1/0, default: 0)
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${BTX_M12_DOCKER_IMAGE:-btxd}"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m12-docker-regtest-cluster.json"
TIMEOUT_SECONDS="${BTX_M12_DOCKER_TIMEOUT_SECONDS:-240}"
MATURITY_BLOCKS="${BTX_M12_DOCKER_MATURITY_BLOCKS:-101}"
SEND_AMOUNT_A_TO_B="${BTX_M12_DOCKER_SEND_A_TO_B:-1.25}"
SEND_AMOUNT_B_TO_A="${BTX_M12_DOCKER_SEND_B_TO_A:-0.75}"
KEEP_TMP="${BTX_M12_DOCKER_KEEP_TMP:-0}"
CONTAINER_PLATFORM="${BTX_M12_DOCKER_PLATFORM:-}"
SHIELDED_WALLET_PASSPHRASE="${BTX_M12_DOCKER_WALLET_PASSPHRASE:-pass}"
SHIELDED_WALLET_UNLOCK_SECONDS="${BTX_M12_DOCKER_WALLET_UNLOCK_SECONDS:-}"
BUILD_IMAGE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE="$2"
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
    --build-image)
      BUILD_IMAGE=1
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
if [[ -z "${SHIELDED_WALLET_UNLOCK_SECONDS}" ]]; then
  SHIELDED_WALLET_UNLOCK_SECONDS=$((TIMEOUT_SECONDS * 3))
fi
if ! [[ "${SHIELDED_WALLET_UNLOCK_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${SHIELDED_WALLET_UNLOCK_SECONDS}" -lt 1 ]]; then
  echo "error: BTX_M12_DOCKER_WALLET_UNLOCK_SECONDS must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MATURITY_BLOCKS}" =~ ^[0-9]+$ ]] || [[ "${MATURITY_BLOCKS}" -lt 101 ]]; then
  echo "error: BTX_M12_DOCKER_MATURITY_BLOCKS must be an integer >= 101" >&2
  exit 1
fi
if ! [[ "${ARTIFACT_PATH}" = /* ]]; then
  ARTIFACT_PATH="${ROOT_DIR}/${ARTIFACT_PATH}"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required for Docker regtest cluster validation" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required for Docker regtest cluster validation" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "error: docker daemon is not reachable" >&2
  exit 1
fi

if [[ "${BUILD_IMAGE}" -eq 1 ]]; then
  if [[ -n "${CONTAINER_PLATFORM}" ]]; then
    docker build \
      --platform "${CONTAINER_PLATFORM}" \
      -f "${ROOT_DIR}/contrib/docker/Dockerfile" \
      -t "${IMAGE}" \
      "${ROOT_DIR}"
  else
    docker build \
      -f "${ROOT_DIR}/contrib/docker/Dockerfile" \
      -t "${IMAGE}" \
      "${ROOT_DIR}"
  fi
elif ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "error: Docker image '${IMAGE}' not found; build it with --build-image or contrib/docker/Dockerfile" >&2
  exit 1
fi

RUN_PARENT_DIR="${ROOT_DIR}/.btx-validation/tmp"
mkdir -p "${RUN_PARENT_DIR}" "$(dirname "${ARTIFACT_PATH}")"
BASE_DIR="$(mktemp -d "${RUN_PARENT_DIR}/m12-docker-regtest.XXXXXX")"
NODE_A_DIR="${BASE_DIR}/node-a"
NODE_B_DIR="${BASE_DIR}/node-b"
NODE_A_CONF="${BASE_DIR}/node-a.conf"
NODE_B_CONF="${BASE_DIR}/node-b.conf"
NETWORK_NAME="btx-m12-regtest-$$"
CONTAINER_A="btx-m12-node-a-$$"
CONTAINER_B="btx-m12-node-b-$$"
mkdir -p "${NODE_A_DIR}" "${NODE_B_DIR}"
chmod 0755 "${BASE_DIR}"
chmod 0777 "${NODE_A_DIR}" "${NODE_B_DIR}"

CURRENT_PHASE="initializing"
RUN_STATUS="running"

set_phase() {
  CURRENT_PHASE="$1"
}

write_status_artifact() {
  local status="$1"
  local error="${2:-}"
  BTX_ARTIFACT_PATH="${ARTIFACT_PATH}" \
  BTX_STATUS="${status}" \
  BTX_PHASE="${CURRENT_PHASE}" \
  BTX_ERROR="${error}" \
  BTX_BASE_DIR="${BASE_DIR}" \
  BTX_DOCKER_IMAGE="${IMAGE}" \
  BTX_DOCKER_NETWORK="${NETWORK_NAME}" \
  python3 <<'PY'
import json
import os
from datetime import datetime, timezone

artifact_path = os.environ["BTX_ARTIFACT_PATH"]
artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": os.environ["BTX_STATUS"],
    "phase": os.environ["BTX_PHASE"],
    "docker_image": os.environ["BTX_DOCKER_IMAGE"],
    "docker_network": os.environ["BTX_DOCKER_NETWORK"],
    "temp_dir": os.environ["BTX_BASE_DIR"],
}
if os.environ["BTX_ERROR"]:
    artifact["error"] = os.environ["BTX_ERROR"]
tmp_path = f"{artifact_path}.tmp"
with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(artifact, handle, indent=2)
os.replace(tmp_path, artifact_path)
PY
}

cleanup() {
  local exit_code=$?
  set +e
  if [[ "${RUN_STATUS}" != "pass" && "${exit_code}" -ne 0 ]]; then
    write_status_artifact "failed" "script exited with status ${exit_code}" || true
  fi
  docker rm -f "${CONTAINER_B}" >/dev/null 2>&1 || true
  docker rm -f "${CONTAINER_A}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "M12 Docker debug: preserved temp dir ${BASE_DIR}" >&2
  else
    rm -rf "${BASE_DIR}"
  fi
}
trap cleanup EXIT

write_status_artifact "running"

write_node_conf() {
  local path="$1"
  local p2p_port="$2"
  local rpc_port="$3"

  cat >"${path}" <<CONF
regtest=1
server=1
listen=1
listenonion=0
discover=0
dnsseed=0
fixedseeds=0
natpmp=0
upnp=0
test=matmulstrict
autoshieldcoinbase=0
fallbackfee=0.0001
regtestshieldedmatrictdisableheight=1

[regtest]
port=${p2p_port}
rpcport=${rpc_port}
rpcbind=0.0.0.0
rpcallowip=127.0.0.1
rpcallowip=172.16.0.0/12
rpcallowip=192.168.0.0/16
CONF
  chmod 0644 "${path}"
}

write_node_conf "${NODE_A_CONF}" 19444 19443
write_node_conf "${NODE_B_CONF}" 19544 19543

set_phase "start docker nodes"
docker network create "${NETWORK_NAME}" >/dev/null

if [[ -n "${CONTAINER_PLATFORM}" ]]; then
  docker run -d \
    --name "${CONTAINER_A}" \
    --network "${NETWORK_NAME}" \
    --network-alias node-a \
    --platform "${CONTAINER_PLATFORM}" \
    -v "${NODE_A_CONF}:/etc/btx/btx.conf:ro" \
    -v "${NODE_A_DIR}:/var/lib/btxd:rw" \
    "${IMAGE}" >/dev/null

  docker run -d \
    --name "${CONTAINER_B}" \
    --network "${NETWORK_NAME}" \
    --network-alias node-b \
    --platform "${CONTAINER_PLATFORM}" \
    -v "${NODE_B_CONF}:/etc/btx/btx.conf:ro" \
    -v "${NODE_B_DIR}:/var/lib/btxd:rw" \
    "${IMAGE}" >/dev/null
else
  docker run -d \
    --name "${CONTAINER_A}" \
    --network "${NETWORK_NAME}" \
    --network-alias node-a \
    -v "${NODE_A_CONF}:/etc/btx/btx.conf:ro" \
    -v "${NODE_A_DIR}:/var/lib/btxd:rw" \
    "${IMAGE}" >/dev/null

  docker run -d \
    --name "${CONTAINER_B}" \
    --network "${NETWORK_NAME}" \
    --network-alias node-b \
    -v "${NODE_B_CONF}:/etc/btx/btx.conf:ro" \
    -v "${NODE_B_DIR}:/var/lib/btxd:rw" \
    "${IMAGE}" >/dev/null
fi

cli_a() {
  docker exec "${CONTAINER_A}" btx-cli -conf=/etc/btx/btx.conf -datadir=/var/lib/btxd "$@"
}

cli_b() {
  docker exec "${CONTAINER_B}" btx-cli -conf=/etc/btx/btx.conf -datadir=/var/lib/btxd "$@"
}

wait_for_rpc() {
  local cli_fn="$1"
  local label="$2"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if ${cli_fn} getblockcount >/dev/null 2>&1; then
      return 0
    fi
    local running
    running="$(docker inspect -f '{{.State.Running}}' "${label}" 2>/dev/null || true)"
    if [[ "${running}" != "true" ]]; then
      echo "error: ${label} exited before RPC became available" >&2
      docker logs "${label}" >&2 || true
      return 1
    fi
    sleep 1
  done
  echo "error: timed out waiting for ${label} RPC" >&2
  docker logs "${label}" >&2 || true
  return 1
}

wait_for_height() {
  local cli_fn="$1"
  local expected="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local height
    height="$(${cli_fn} getblockcount 2>/dev/null || true)"
    if [[ "${height}" =~ ^[0-9]+$ && "${height}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} did not reach height ${expected}" >&2
  return 1
}

wait_for_block_hash() {
  local cli_fn="$1"
  local block_hash="$2"
  local label="$3"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if ${cli_fn} getblock "${block_hash}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} did not receive block ${block_hash}" >&2
  return 1
}

wait_for_peer_connection() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local a_conn b_conn
    a_conn="$(cli_a getconnectioncount)"
    b_conn="$(cli_b getconnectioncount)"
    if [[ "${a_conn}" -ge 1 && "${b_conn}" -ge 1 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "error: container nodes did not establish a peer connection" >&2
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

wait_for_shielded_total_balance() {
  local cli_fn="$1"
  local wallet="$2"
  local expected="$3"
  local label="$4"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    local balance
    balance="$(${cli_fn} -rpcwallet="${wallet}" z_getbalance 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_balance"])' 2>/dev/null || true)"
    if python3 - "${balance}" "${expected}" <<'PY'
import sys
from decimal import Decimal, InvalidOperation

try:
    current = Decimal(sys.argv[1])
    expected = Decimal(sys.argv[2])
except (InvalidOperation, IndexError):
    raise SystemExit(1)
raise SystemExit(0 if current == expected else 1)
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "error: ${label} shielded total balance did not reach ${expected}" >&2
  return 1
}

unlock_wallet() {
  local cli_fn="$1"
  local wallet="$2"
  ${cli_fn} -rpcwallet="${wallet}" walletpassphrase "${SHIELDED_WALLET_PASSPHRASE}" "${SHIELDED_WALLET_UNLOCK_SECONDS}" >/dev/null
}

ensure_wallet() {
  local cli_fn="$1"
  local wallet="$2"
  if ! ${cli_fn} -rpcwallet="${wallet}" getwalletinfo >/dev/null 2>&1; then
    ${cli_fn} -named createwallet wallet_name="${wallet}" descriptors=true load_on_startup=false >/dev/null
  fi
  local wallet_info encrypted
  wallet_info="$(${cli_fn} -rpcwallet="${wallet}" getwalletinfo)"
  encrypted="$(printf '%s' "${wallet_info}" | python3 -c 'import json,sys; print("true" if "unlocked_until" in json.load(sys.stdin) else "false")')"
  if [[ "${encrypted}" != "true" ]]; then
    ${cli_fn} -rpcwallet="${wallet}" encryptwallet "${SHIELDED_WALLET_PASSPHRASE}" >/dev/null
  fi
  unlock_wallet "${cli_fn}" "${wallet}"
}

set_phase "wait for RPC"
wait_for_rpc cli_a "${CONTAINER_A}"
wait_for_rpc cli_b "${CONTAINER_B}"

set_phase "connect peers"
cli_b addnode "node-a:19444" add >/dev/null 2>&1 || true
wait_for_peer_connection

set_phase "check genesis"
GENESIS_A="$(cli_a getblockhash 0)"
GENESIS_B="$(cli_b getblockhash 0)"
if [[ "${GENESIS_A}" != "${GENESIS_B}" ]]; then
  echo "error: genesis mismatch between node A and node B" >&2
  exit 1
fi

set_phase "create and unlock wallets"
ensure_wallet cli_a "node-a-wallet"
ensure_wallet cli_b "node-b-wallet"

set_phase "mine spendable funds"
NODE_A_MINER_ADDRESS="$(cli_a -rpcwallet=node-a-wallet getnewaddress)"
cli_a generatetoaddress "${MATURITY_BLOCKS}" "${NODE_A_MINER_ADDRESS}" >/dev/null
wait_for_height cli_b "${MATURITY_BLOCKS}" "node B"

set_phase "relay A to B transfer"
NODE_B_RECEIVE_ADDRESS="$(cli_b -rpcwallet=node-b-wallet getnewaddress)"

# Spend from a known matured coinbase output so the harness validates real
# relay and confirmation even if generated-balance accounting lags.
SPEND_BLOCK_HASH="$(cli_a getblockhash 1)"
COINBASE_TXID="$(cli_a getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["txid"])')"
COINBASE_VALUE="$(cli_a getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["vout"][0]["value"])')"
read -r RAW_INPUTS RAW_OUTPUTS <<<"$(python3 - "${COINBASE_TXID}" "${COINBASE_VALUE}" "${NODE_B_RECEIVE_ADDRESS}" "${NODE_A_MINER_ADDRESS}" "${SEND_AMOUNT_A_TO_B}" <<'PY'
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
    raise SystemExit("insufficient coinbase value for requested A -> B amount")
inputs = json.dumps([{"txid": txid, "vout": 0}], separators=(",", ":"))
outputs = json.dumps({receiver: str(send_amount), change_addr: format(change, "f")}, separators=(",", ":"))
print(inputs, outputs)
PY
)"
RAW_TX="$(cli_a -named createrawtransaction inputs="${RAW_INPUTS}" outputs="${RAW_OUTPUTS}")"
SIGNED_JSON="$(cli_a -rpcwallet=node-a-wallet signrawtransactionwithwallet "${RAW_TX}")"
TX_COMPLETE="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print("true" if json.load(sys.stdin)["complete"] else "false")')"
if [[ "${TX_COMPLETE}" != "true" ]]; then
  echo "error: node A transaction signing was incomplete" >&2
  exit 1
fi
TX_HEX="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"
TXID_A_TO_B="$(cli_a sendrawtransaction "${TX_HEX}")"
wait_for_mempool_tx "${TXID_A_TO_B}" cli_b "node B"

set_phase "confirm A to B transfer"
cli_a generatetoaddress 1 "${NODE_A_MINER_ADDRESS}" >/dev/null
POST_A_TO_B_HEIGHT=$((MATURITY_BLOCKS + 1))
wait_for_height cli_a "${POST_A_TO_B_HEIGHT}" "node A"
wait_for_height cli_b "${POST_A_TO_B_HEIGHT}" "node B"

CONFIRMATIONS_A_TO_B="$(cli_b -rpcwallet=node-b-wallet gettransaction "${TXID_A_TO_B}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])')"
if [[ "${CONFIRMATIONS_A_TO_B}" -lt 1 ]]; then
  echo "error: A -> B transfer ${TXID_A_TO_B} was not confirmed on node B wallet" >&2
  exit 1
fi

set_phase "relay B to A transfer"
NODE_A_RECEIVE_ADDRESS="$(cli_a -rpcwallet=node-a-wallet getnewaddress)"
TXID_B_TO_A="$(cli_b -rpcwallet=node-b-wallet -named sendtoaddress address="${NODE_A_RECEIVE_ADDRESS}" amount="${SEND_AMOUNT_B_TO_A}" fee_rate=30)"
wait_for_mempool_tx "${TXID_B_TO_A}" cli_a "node A"

set_phase "confirm B to A transfer"
NODE_B_MINER_ADDRESS="$(cli_b -rpcwallet=node-b-wallet getnewaddress)"
cli_b generatetoaddress 2 "${NODE_B_MINER_ADDRESS}" >/dev/null
FINAL_HEIGHT=$((POST_A_TO_B_HEIGHT + 2))
wait_for_height cli_a "${FINAL_HEIGHT}" "node A"
wait_for_height cli_b "${FINAL_HEIGHT}" "node B"

CONFIRMATIONS_B_TO_A="$(cli_a -rpcwallet=node-a-wallet gettransaction "${TXID_B_TO_A}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])')"
if [[ "${CONFIRMATIONS_B_TO_A}" -lt 1 ]]; then
  echo "error: B -> A transfer ${TXID_B_TO_A} was not confirmed on node A wallet" >&2
  exit 1
fi

BRIDGE_AMOUNT="1.50"
BRIDGE_MEMO="docker-view-grant"
BRIDGE_ID="000000000000000000000000000000000000000000000000000000000000c001"
BRIDGE_OPERATION_ID="000000000000000000000000000000000000000000000000000000000000c002"
set_phase "plan bridge view grant"
unlock_wallet cli_a "node-a-wallet"
unlock_wallet cli_b "node-b-wallet"
OPERATOR_ZADDR="$(cli_b -rpcwallet=node-b-wallet z_getnewaddress)"
OPERATOR_KEM_PUBKEY="$(cli_b -rpcwallet=node-b-wallet z_validateaddress "${OPERATOR_ZADDR}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["kem_public_key"])')"
BRIDGE_RECIPIENT="$(cli_a -rpcwallet=node-a-wallet z_getnewaddress)"
BRIDGE_RECIPIENT_HASH="$(cli_a -rpcwallet=node-a-wallet z_validateaddress "${BRIDGE_RECIPIENT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pk_hash"])')"
BRIDGE_OPERATOR_ADDR="$(cli_a -rpcwallet=node-a-wallet -named getnewaddress address_type=p2mr)"
BRIDGE_REFUND_ADDR="$(cli_a -rpcwallet=node-a-wallet -named getnewaddress address_type=p2mr)"
BRIDGE_OPERATOR_KEY="$(cli_a -rpcwallet=node-a-wallet exportpqkey "${BRIDGE_OPERATOR_ADDR}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')"
BRIDGE_REFUND_KEY="$(cli_a -rpcwallet=node-a-wallet exportpqkey "${BRIDGE_REFUND_ADDR}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')"
BRIDGE_OPTIONS="$(python3 - "${BRIDGE_ID}" "${BRIDGE_OPERATION_ID}" "${FINAL_HEIGHT}" "${BRIDGE_RECIPIENT}" "${BRIDGE_MEMO}" "${OPERATOR_KEM_PUBKEY}" <<'PY'
import json, sys

bridge_id, operation_id, current_height, recipient, memo, operator_pubkey = sys.argv[1:]
options = {
    "bridge_id": bridge_id,
    "operation_id": operation_id,
    "refund_lock_height": int(current_height) + 20,
    "recipient": recipient,
    "memo": memo,
    "operator_view_grants": [{
        "pubkey": operator_pubkey,
        "format": "structured_disclosure",
        "disclosure_fields": ["amount", "recipient", "memo", "sender"],
    }],
}
print(json.dumps(options, separators=(",", ":")))
PY
)"
BRIDGE_PLAN_FILE="${BASE_DIR}/bridge-plan.json"
cli_a -rpcwallet=node-a-wallet -named bridge_planin \
  operator_key="${BRIDGE_OPERATOR_KEY}" \
  refund_key="${BRIDGE_REFUND_KEY}" \
  amount="${BRIDGE_AMOUNT}" \
  options="${BRIDGE_OPTIONS}" >"${BRIDGE_PLAN_FILE}"

read -r BRIDGE_ADDRESS BRIDGE_PLAN_HEX BRIDGE_VIEW_GRANT_HEX BRIDGE_VIEW_GRANT_JSON <<<"$(python3 - "${BRIDGE_PLAN_FILE}" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as handle:
    plan = json.load(handle)
grant = plan["bundle"]["view_grants"][0]
print(plan["bridge_address"], plan["plan_hex"], grant["view_grant_hex"], json.dumps(grant, separators=(",", ":")))
PY
)"
BRIDGE_DECRYPT_PLAN_FILE="${BASE_DIR}/bridge-decrypt-plan.json"
set_phase "decrypt planned bridge view grant"
unlock_wallet cli_b "node-b-wallet"
cli_b -rpcwallet=node-b-wallet -named bridge_decryptviewgrant \
  view_grant="${BRIDGE_VIEW_GRANT_JSON}" \
  format=structured_disclosure >"${BRIDGE_DECRYPT_PLAN_FILE}"
read -r BRIDGE_DECRYPT_FORMAT BRIDGE_DECRYPT_AMOUNT BRIDGE_DECRYPT_MEMO BRIDGE_DECRYPT_BRIDGE_ID BRIDGE_DECRYPT_OPERATION_ID <<<"$(python3 - "${BRIDGE_DECRYPT_PLAN_FILE}" "${BRIDGE_AMOUNT}" "${BRIDGE_MEMO}" "${BRIDGE_RECIPIENT_HASH}" "${BRIDGE_ID}" "${BRIDGE_OPERATION_ID}" <<'PY'
import json, sys
from decimal import Decimal

path, amount, memo, recipient_hash, bridge_id, operation_id = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    decoded = json.load(handle)
payload = decoded["payload"]
assert decoded["format"] == "structured_disclosure", decoded
assert decoded["metadata_authenticated"] is True, decoded
assert decoded["metadata_verified"] is True, decoded
assert Decimal(str(payload["amount"])) == Decimal(amount), decoded
assert payload["memo"] == memo, decoded
assert payload["recipient_pk_hash"] == recipient_hash, decoded
assert payload["sender"]["bridge_id"] == bridge_id, decoded
assert payload["sender"]["operation_id"] == operation_id, decoded
print(decoded["format"], format(Decimal(str(payload["amount"])), "f"), payload["memo"], payload["sender"]["bridge_id"], payload["sender"]["operation_id"])
PY
)"

BRIDGE_FUNDING_AMOUNT="$(python3 - "${BRIDGE_AMOUNT}" <<'PY'
import sys
from decimal import Decimal

print(format(Decimal(sys.argv[1]) + Decimal("0.00020000"), "f"))
PY
)"
set_phase "fund bridge output"
unlock_wallet cli_a "node-a-wallet"
BRIDGE_FUNDING_TXID="$(cli_a -rpcwallet=node-a-wallet sendtoaddress "${BRIDGE_ADDRESS}" "${BRIDGE_FUNDING_AMOUNT}")"
cli_a generatetoaddress 1 "${NODE_A_MINER_ADDRESS}" >/dev/null
FINAL_HEIGHT=$((FINAL_HEIGHT + 1))
wait_for_height cli_a "${FINAL_HEIGHT}" "node A"
wait_for_height cli_b "${FINAL_HEIGHT}" "node B"

BRIDGE_FUNDING_TX_JSON="$(cli_a -rpcwallet=node-a-wallet gettransaction "${BRIDGE_FUNDING_TXID}")"
BRIDGE_FUNDING_HEX="$(printf '%s' "${BRIDGE_FUNDING_TX_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"
BRIDGE_FUNDING_DECODED_JSON="$(cli_a decoderawtransaction "${BRIDGE_FUNDING_HEX}")"
read -r BRIDGE_FUNDING_VOUT BRIDGE_FUNDING_VALUE <<<"$(BTX_FUNDING_TX_JSON="${BRIDGE_FUNDING_TX_JSON}" BTX_FUNDING_DECODED_JSON="${BRIDGE_FUNDING_DECODED_JSON}" python3 - "${BRIDGE_ADDRESS}" <<'PY'
import json
import os
import sys

address = sys.argv[1]
wallet_tx = json.loads(os.environ["BTX_FUNDING_TX_JSON"])
decoded_tx = json.loads(os.environ["BTX_FUNDING_DECODED_JSON"])

candidates = []
for detail in wallet_tx.get("details", []):
    if detail.get("address") == address and "vout" in detail:
        candidates.append(int(detail["vout"]))

for output in decoded_tx.get("vout", []):
    script = output.get("scriptPubKey", {})
    addresses = []
    if "address" in script:
        addresses.append(script["address"])
    if isinstance(script.get("addresses"), list):
        addresses.extend(script["addresses"])
    if address in addresses:
        candidates.append(int(output["n"]))

for n in dict.fromkeys(candidates):
    for output in decoded_tx.get("vout", []):
        if int(output["n"]) == n:
            print(n, str(output["value"]))
            raise SystemExit(0)

raise SystemExit(f"bridge funding output for {address} not found")
PY
)"
if [[ -z "${BRIDGE_FUNDING_VOUT}" || -z "${BRIDGE_FUNDING_VALUE}" ]]; then
  echo "error: bridge funding output lookup returned an empty vout or amount" >&2
  exit 1
fi
BRIDGE_SUBMIT_FILE="${BASE_DIR}/bridge-submit.json"
BRIDGE_SUBMIT_ERR_FILE="${BASE_DIR}/bridge-submit.err"
BRIDGE_SUBMIT_ATTACK_FILE="${BASE_DIR}/bridge-submit-no-accept.json"
BRIDGE_SUBMIT_ATTACK_ERR_FILE="${BASE_DIR}/bridge-submit-no-accept.err"
set_phase "reject bridge shield tx without view-grant acceptance"
if cli_a -rpcwallet=node-a-wallet -named bridge_submitshieldtx \
  plan_hex="${BRIDGE_PLAN_HEX}" \
  txid="${BRIDGE_FUNDING_TXID}" \
  vout="${BRIDGE_FUNDING_VOUT}" \
  amount="${BRIDGE_FUNDING_VALUE}" \
  options='{"track_pending":false,"enforce_fee_headroom":false}' >"${BRIDGE_SUBMIT_ATTACK_FILE}" 2>"${BRIDGE_SUBMIT_ATTACK_ERR_FILE}"; then
  echo "error: bridge_submitshieldtx unexpectedly accepted a grant-bearing plan without accept_plan_view_grants" >&2
  cat "${BRIDGE_SUBMIT_ATTACK_FILE}" >&2 || true
  exit 1
fi
if ! grep -q "accept_plan_view_grants=true" "${BRIDGE_SUBMIT_ATTACK_ERR_FILE}"; then
  echo "error: bridge_submitshieldtx rejected the attack for the wrong reason" >&2
  cat "${BRIDGE_SUBMIT_ATTACK_ERR_FILE}" >&2 || true
  exit 1
fi
BRIDGE_SUBMIT_NO_ACCEPT_REJECTED="true"

BRIDGE_IMPORT_ATTACK_FILE="${BASE_DIR}/bridge-import-no-accept.json"
BRIDGE_IMPORT_ATTACK_ERR_FILE="${BASE_DIR}/bridge-import-no-accept.err"
set_phase "reject bridge pending import without view-grant acceptance"
if cli_a -rpcwallet=node-a-wallet -named bridge_importpending \
  plan_hex="${BRIDGE_PLAN_HEX}" \
  txid="${BRIDGE_FUNDING_TXID}" \
  vout="${BRIDGE_FUNDING_VOUT}" \
  amount="${BRIDGE_FUNDING_VALUE}" \
  options='{"recover_now":false}' >"${BRIDGE_IMPORT_ATTACK_FILE}" 2>"${BRIDGE_IMPORT_ATTACK_ERR_FILE}"; then
  echo "error: bridge_importpending unexpectedly accepted a grant-bearing plan without accept_plan_view_grants" >&2
  cat "${BRIDGE_IMPORT_ATTACK_FILE}" >&2 || true
  exit 1
fi
if ! grep -q "accept_plan_view_grants=true" "${BRIDGE_IMPORT_ATTACK_ERR_FILE}"; then
  echo "error: bridge_importpending rejected the attack for the wrong reason" >&2
  cat "${BRIDGE_IMPORT_ATTACK_ERR_FILE}" >&2 || true
  exit 1
fi
BRIDGE_IMPORT_NO_ACCEPT_REJECTED="true"

set_phase "submit bridge shield tx"
unlock_wallet cli_a "node-a-wallet"
if ! cli_a -rpcwallet=node-a-wallet -named bridge_submitshieldtx \
  plan_hex="${BRIDGE_PLAN_HEX}" \
  txid="${BRIDGE_FUNDING_TXID}" \
  vout="${BRIDGE_FUNDING_VOUT}" \
  amount="${BRIDGE_FUNDING_VALUE}" \
  options='{"track_pending":false,"enforce_fee_headroom":false,"accept_plan_view_grants":true}' >"${BRIDGE_SUBMIT_FILE}" 2>"${BRIDGE_SUBMIT_ERR_FILE}"; then
  echo "error: bridge_submitshieldtx failed" >&2
  cat "${BRIDGE_SUBMIT_ERR_FILE}" >&2 || true
  exit 1
fi
BRIDGE_SETTLEMENT_TXID="$(python3 - "${BRIDGE_SUBMIT_FILE}" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["txid"])
PY
)"
wait_for_mempool_tx "${BRIDGE_SETTLEMENT_TXID}" cli_b "node B"
set_phase "mine bridge settlement"
SETTLEMENT_BLOCK_HASH="$(cli_a generatetoaddress 1 "${NODE_A_MINER_ADDRESS}" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')"
FINAL_HEIGHT=$((FINAL_HEIGHT + 1))
wait_for_height cli_a "${FINAL_HEIGHT}" "node A"
wait_for_height cli_b "${FINAL_HEIGHT}" "node B"
wait_for_block_hash cli_b "${SETTLEMENT_BLOCK_HASH}" "node B"

set_phase "retrieve mined bridge view grant"
BRIDGE_BEST_BLOCK_FILE="${BASE_DIR}/bridge-settlement-block.json"
cli_b getblock "${SETTLEMENT_BLOCK_HASH}" 2 >"${BRIDGE_BEST_BLOCK_FILE}"
BRIDGE_CHAIN_VIEW_GRANT_JSON="$(python3 - "${BRIDGE_SETTLEMENT_TXID}" "${BRIDGE_BEST_BLOCK_FILE}" <<'PY'
import json
import sys

txid, block_path = sys.argv[1:]
with open(block_path, encoding="utf-8") as handle:
    block = json.load(handle)
for tx in block["tx"]:
    if tx["txid"] == txid:
        grant = tx["shielded"]["view_grants"][0]
        print(json.dumps(grant, separators=(",", ":")))
        raise SystemExit(0)
raise SystemExit(f"settlement {txid} not found in best block")
PY
)"
BRIDGE_CHAIN_VIEW_GRANT_HEX="$(python3 - "${BRIDGE_CHAIN_VIEW_GRANT_JSON}" <<'PY'
import json, sys

print(json.loads(sys.argv[1])["view_grant_hex"])
PY
)"
if [[ "${BRIDGE_CHAIN_VIEW_GRANT_HEX}" != "${BRIDGE_VIEW_GRANT_HEX}" ]]; then
  echo "error: mined bridge view grant does not match planned grant" >&2
  exit 1
fi
BRIDGE_CHAIN_VIEW_GRANT_WITH_METADATA_JSON="$(python3 - "${BRIDGE_VIEW_GRANT_JSON}" "${BRIDGE_CHAIN_VIEW_GRANT_JSON}" <<'PY'
import json, sys

plan_grant = json.loads(sys.argv[1])
chain_grant = json.loads(sys.argv[2])
plan_grant.update(chain_grant)
print(json.dumps(plan_grant, separators=(",", ":")))
PY
)"
BRIDGE_EXPECTED_VIEW_GRANT_JSON="$(python3 - "${BRIDGE_AMOUNT}" "${BRIDGE_MEMO}" "${BRIDGE_RECIPIENT_HASH}" "${BRIDGE_ID}" "${BRIDGE_OPERATION_ID}" <<'PY'
import json, sys

amount, memo, recipient_hash, bridge_id, operation_id = sys.argv[1:]
print(json.dumps({
    "amount": amount,
    "memo": memo,
    "recipient_pk_hash": recipient_hash,
    "sender": {
        "bridge_id": bridge_id,
        "operation_id": operation_id,
    },
}, separators=(",", ":")))
PY
)"
BRIDGE_DECRYPT_CHAIN_FILE="${BASE_DIR}/bridge-decrypt-chain.json"
set_phase "decrypt mined bridge view grant"
unlock_wallet cli_b "node-b-wallet"
cli_b -rpcwallet=node-b-wallet -named bridge_decryptviewgrant \
  view_grant="${BRIDGE_CHAIN_VIEW_GRANT_WITH_METADATA_JSON}" \
  format=structured_disclosure \
  expected="${BRIDGE_EXPECTED_VIEW_GRANT_JSON}" >"${BRIDGE_DECRYPT_CHAIN_FILE}"
python3 - "${BRIDGE_DECRYPT_CHAIN_FILE}" "${BRIDGE_AMOUNT}" "${BRIDGE_MEMO}" <<'PY'
import json, sys
from decimal import Decimal

path, amount, memo = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    decoded = json.load(handle)
payload = decoded["payload"]
assert decoded["format"] == "structured_disclosure", decoded
assert decoded["metadata_authenticated"] is True, decoded
assert decoded["metadata_verified"] is True, decoded
assert decoded["expected_verified"] is True, decoded
assert Decimal(str(payload["amount"])) == Decimal(amount), decoded
assert payload["memo"] == memo, decoded
PY

set_phase "verify shielded recipient balance"
cli_a syncwithvalidationinterfacequeue >/dev/null
wait_for_shielded_total_balance cli_a "node-a-wallet" "${BRIDGE_AMOUNT}" "node A recipient"
BRIDGE_RECIPIENT_BALANCE="$(cli_a -rpcwallet=node-a-wallet z_getbalance | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_balance"])')"

CONNECTIONS_A="$(cli_a getconnectioncount)"
CONNECTIONS_B="$(cli_b getconnectioncount)"
BEST_A="$(cli_a getbestblockhash)"
BEST_B="$(cli_b getbestblockhash)"
if [[ "${BEST_A}" != "${BEST_B}" ]]; then
  echo "error: final best block mismatch between node A and node B" >&2
  exit 1
fi

set_phase "write success artifact"
BTX_ARTIFACT_PATH="${ARTIFACT_PATH}" \
BTX_DOCKER_IMAGE="${IMAGE}" \
BTX_DOCKER_NETWORK="${NETWORK_NAME}" \
BTX_GENESIS_HASH="${GENESIS_A}" \
BTX_CONTAINER_A="${CONTAINER_A}" \
BTX_CONTAINER_B="${CONTAINER_B}" \
BTX_CONNECTIONS_A="${CONNECTIONS_A}" \
BTX_CONNECTIONS_B="${CONNECTIONS_B}" \
BTX_FINAL_HEIGHT="${FINAL_HEIGHT}" \
BTX_BEST_A="${BEST_A}" \
BTX_BEST_B="${BEST_B}" \
BTX_TXID_A_TO_B="${TXID_A_TO_B}" \
BTX_TXID_B_TO_A="${TXID_B_TO_A}" \
BTX_SEND_AMOUNT_A_TO_B="${SEND_AMOUNT_A_TO_B}" \
BTX_SEND_AMOUNT_B_TO_A="${SEND_AMOUNT_B_TO_A}" \
BTX_CONFIRMATIONS_A_TO_B="${CONFIRMATIONS_A_TO_B}" \
BTX_CONFIRMATIONS_B_TO_A="${CONFIRMATIONS_B_TO_A}" \
BTX_BRIDGE_DECRYPT_FORMAT="${BRIDGE_DECRYPT_FORMAT}" \
BTX_BRIDGE_DECRYPT_AMOUNT="${BRIDGE_DECRYPT_AMOUNT}" \
BTX_BRIDGE_DECRYPT_MEMO="${BRIDGE_DECRYPT_MEMO}" \
BTX_BRIDGE_DECRYPT_BRIDGE_ID="${BRIDGE_DECRYPT_BRIDGE_ID}" \
BTX_BRIDGE_DECRYPT_OPERATION_ID="${BRIDGE_DECRYPT_OPERATION_ID}" \
BTX_BRIDGE_FUNDING_TXID="${BRIDGE_FUNDING_TXID}" \
BTX_BRIDGE_SETTLEMENT_TXID="${BRIDGE_SETTLEMENT_TXID}" \
BTX_SETTLEMENT_BLOCK_HASH="${SETTLEMENT_BLOCK_HASH}" \
BTX_BRIDGE_VIEW_GRANT_HEX="${BRIDGE_VIEW_GRANT_HEX}" \
BTX_BRIDGE_RECIPIENT_BALANCE="${BRIDGE_RECIPIENT_BALANCE}" \
BTX_BRIDGE_SUBMIT_NO_ACCEPT_REJECTED="${BRIDGE_SUBMIT_NO_ACCEPT_REJECTED}" \
BTX_BRIDGE_IMPORT_NO_ACCEPT_REJECTED="${BRIDGE_IMPORT_NO_ACCEPT_REJECTED}" \
python3 <<'PY'
import json
import os
from datetime import datetime, timezone

artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": "pass",
    "chain": "regtest",
    "docker_image": os.environ["BTX_DOCKER_IMAGE"],
    "docker_network": os.environ["BTX_DOCKER_NETWORK"],
    "genesis_hash": os.environ["BTX_GENESIS_HASH"],
    "node_a": {
        "container": os.environ["BTX_CONTAINER_A"],
        "p2p_port": 19444,
        "rpc_port": 19443,
        "connections": int(os.environ["BTX_CONNECTIONS_A"]),
        "height": int(os.environ["BTX_FINAL_HEIGHT"]),
        "best_block": os.environ["BTX_BEST_A"],
    },
    "node_b": {
        "container": os.environ["BTX_CONTAINER_B"],
        "p2p_port": 19544,
        "rpc_port": 19543,
        "connections": int(os.environ["BTX_CONNECTIONS_B"]),
        "height": int(os.environ["BTX_FINAL_HEIGHT"]),
        "best_block": os.environ["BTX_BEST_B"],
    },
    "transfers": {
        "a_to_b_txid": os.environ["BTX_TXID_A_TO_B"],
        "a_to_b_amount": os.environ["BTX_SEND_AMOUNT_A_TO_B"],
        "a_to_b_confirmations": int(os.environ["BTX_CONFIRMATIONS_A_TO_B"]),
        "b_to_a_txid": os.environ["BTX_TXID_B_TO_A"],
        "b_to_a_amount": os.environ["BTX_SEND_AMOUNT_B_TO_A"],
        "b_to_a_confirmations": int(os.environ["BTX_CONFIRMATIONS_B_TO_A"]),
    },
    "view_grants": {
        "status": "pass",
        "plan_decrypt_format": os.environ["BTX_BRIDGE_DECRYPT_FORMAT"],
        "amount": os.environ["BTX_BRIDGE_DECRYPT_AMOUNT"],
        "memo": os.environ["BTX_BRIDGE_DECRYPT_MEMO"],
        "bridge_id": os.environ["BTX_BRIDGE_DECRYPT_BRIDGE_ID"],
        "operation_id": os.environ["BTX_BRIDGE_DECRYPT_OPERATION_ID"],
        "funding_txid": os.environ["BTX_BRIDGE_FUNDING_TXID"],
        "settlement_txid": os.environ["BTX_BRIDGE_SETTLEMENT_TXID"],
        "settlement_block_hash": os.environ["BTX_SETTLEMENT_BLOCK_HASH"],
        "recipient_total_balance": os.environ["BTX_BRIDGE_RECIPIENT_BALANCE"],
        "view_grant_hex": os.environ["BTX_BRIDGE_VIEW_GRANT_HEX"],
        "adversarial_rejections": {
            "submit_without_accept": os.environ["BTX_BRIDGE_SUBMIT_NO_ACCEPT_REJECTED"] == "true",
            "import_without_accept": os.environ["BTX_BRIDGE_IMPORT_NO_ACCEPT_REJECTED"] == "true",
        },
    },
}
artifact_path = os.environ["BTX_ARTIFACT_PATH"]
tmp_path = f"{artifact_path}.tmp"
with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(artifact, handle, indent=2)
os.replace(tmp_path, artifact_path)
PY
RUN_STATUS="pass"

echo "M12 Docker regtest cluster checks passed:"
echo "- Containers connected on temporary network ${NETWORK_NAME}"
echo "- Shared regtest genesis ${GENESIS_A}"
echo "- A -> B transfer ${TXID_A_TO_B} confirmed on node B"
echo "- B -> A transfer ${TXID_B_TO_A} confirmed on node A"
echo "- Missing accept_plan_view_grants submit/import attacks rejected"
echo "- Bridge view grant ${BRIDGE_VIEW_GRANT_HEX} decrypted from plan and mined settlement ${BRIDGE_SETTLEMENT_TXID}"
echo "- Artifact: ${ARTIFACT_PATH}"
