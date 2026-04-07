#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m15_single_node_wallet_lifecycle.sh [options]

Run a strict single-node regtest lifecycle validation:
1) startup
2) wallet creation
3) mine blocks and earn spendable funds
4) verify transaction-containing block/header fields
5) enforce wallet lock/unlock behavior
6) send and receive between wallets

Options:
  --build-dir <path>       Build directory containing btxd/btx-cli (legacy aliases accepted) (default: build-btx)
  --artifact <path>        Output JSON artifact path
                           (default: .btx-validation/m15-single-node-lifecycle.json)
  --timeout-seconds <n>    RPC wait timeout seconds (default: 240)
  --node-label <text>      Label included in artifact/log output (default: host)
  --help                   Show this message

Environment overrides:
  BTX_M15_GENESIS_TIME        Regtest genesis nTime (default: 1700002234)
  BTX_M15_GENESIS_NONCE       Regtest genesis nNonce (default: 77)
  BTX_M15_GENESIS_BITS        Regtest genesis nBits (default: 2070ffff)
  BTX_M15_GENESIS_VERSION     Regtest genesis nVersion (default: 5)
  BTX_M15_MSGSTART            Regtest message-start bytes (default: random)
  BTX_M15_REGTEST_PORT        Regtest default P2P port (default: 19454)
  BTX_M15_MATURITY_BLOCKS     Coinbase maturity setup blocks (default: 101)
  BTX_M15_FUND_AMOUNT         Miner -> Alice amount (default: 1.25)
  BTX_M15_PAYMENT_AMOUNT      Alice -> Bob amount (default: 0.5)
  BTX_M15_ALICE_PASSPHRASE    Alice wallet passphrase (default: alice-pass)
  BTX_M15_BOB_PASSPHRASE      Bob wallet passphrase (default: bob-pass)
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m15-single-node-lifecycle.json"
TIMEOUT_SECONDS=240
NODE_LABEL="host"

GENESIS_TIME="${BTX_M15_GENESIS_TIME:-1700002234}"
GENESIS_NONCE="${BTX_M15_GENESIS_NONCE:-77}"
GENESIS_BITS="${BTX_M15_GENESIS_BITS:-2070ffff}"
GENESIS_VERSION="${BTX_M15_GENESIS_VERSION:-5}"
MESSAGE_START="${BTX_M15_MSGSTART:-}"
REGTEST_PORT_OVERRIDE="${BTX_M15_REGTEST_PORT:-19454}"
MATURITY_BLOCKS="${BTX_M15_MATURITY_BLOCKS:-101}"
FUND_AMOUNT="${BTX_M15_FUND_AMOUNT:-1.25}"
PAYMENT_AMOUNT="${BTX_M15_PAYMENT_AMOUNT:-0.5}"
ALICE_PASSPHRASE="${BTX_M15_ALICE_PASSPHRASE:-alice-pass}"
BOB_PASSPHRASE="${BTX_M15_BOB_PASSPHRASE:-bob-pass}"

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
    --node-label)
      NODE_LABEL="$2"
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
  echo "error: --timeout-seconds must be a positive integer" >&2
  exit 1
fi
if ! [[ "${MATURITY_BLOCKS}" =~ ^[0-9]+$ ]] || [[ "${MATURITY_BLOCKS}" -lt 101 ]]; then
  echo "error: BTX_M15_MATURITY_BLOCKS must be an integer >= 101" >&2
  exit 1
fi
if ! [[ "${GENESIS_TIME}" =~ ^[0-9]+$ ]]; then
  echo "error: BTX_M15_GENESIS_TIME must be uint32 decimal" >&2
  exit 1
fi
if ! [[ "${GENESIS_NONCE}" =~ ^[0-9]+$ ]]; then
  echo "error: BTX_M15_GENESIS_NONCE must be uint32 decimal" >&2
  exit 1
fi
if ! [[ "${GENESIS_VERSION}" =~ ^-?[0-9]+$ ]]; then
  echo "error: BTX_M15_GENESIS_VERSION must be int32 decimal" >&2
  exit 1
fi
if ! [[ "${REGTEST_PORT_OVERRIDE}" =~ ^[0-9]+$ ]] || [[ "${REGTEST_PORT_OVERRIDE}" -lt 1 ]] || [[ "${REGTEST_PORT_OVERRIDE}" -gt 65535 ]]; then
  echo "error: BTX_M15_REGTEST_PORT must be an integer in [1,65535]" >&2
  exit 1
fi
if ! [[ "${GENESIS_BITS}" =~ ^(0x|0X)?[0-9a-fA-F]{8}$ ]]; then
  echo "error: BTX_M15_GENESIS_BITS must be 8 hex chars (optionally 0x prefixed)" >&2
  exit 1
fi

if [[ ! "${BUILD_DIR}" = /* ]]; then
  BUILD_DIR="${ROOT_DIR}/${BUILD_DIR}"
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
  echo "error: BTX_M15_MSGSTART must be 8 hex chars (optionally 0x prefixed)" >&2
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

BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
if [[ ! -x "${BITCOIND_BIN}" || ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing btxd/btx-cli (or legacy aliases) in ${BUILD_DIR}/bin" >&2
  exit 1
fi

mkdir -p "$(dirname "${ARTIFACT_PATH}")"

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

RPC_PORT="$(find_free_port)"
P2P_PORT="$(find_free_port)"

BASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m15-single-node.XXXXXX")"
DATADIR="${BASE_DIR}/node"
mkdir -p "${DATADIR}"
NODE_PID=""

cleanup() {
  set +e
  if [[ -n "${NODE_PID}" ]]; then
    "${BITCOIN_CLI_BIN}" \
      -regtest \
      -regtestmsgstart="${MESSAGE_START}" \
      -regtestport="${REGTEST_PORT_OVERRIDE}" \
      -regtestgenesisntime="${GENESIS_TIME}" \
      -regtestgenesisnonce="${GENESIS_NONCE}" \
      -regtestgenesisbits="${GENESIS_BITS}" \
      -regtestgenesisversion="${GENESIS_VERSION}" \
      -datadir="${DATADIR}" \
      -rpcport="${RPC_PORT}" \
      stop >/dev/null 2>&1 || true
    wait "${NODE_PID}" 2>/dev/null || true
  fi
  rm -rf "${BASE_DIR}"
}
trap cleanup EXIT

cli() {
  "${BITCOIN_CLI_BIN}" \
    -regtest \
    -regtestmsgstart="${MESSAGE_START}" \
    -regtestport="${REGTEST_PORT_OVERRIDE}" \
    -regtestgenesisntime="${GENESIS_TIME}" \
    -regtestgenesisnonce="${GENESIS_NONCE}" \
    -regtestgenesisbits="${GENESIS_BITS}" \
    -regtestgenesisversion="${GENESIS_VERSION}" \
    -datadir="${DATADIR}" \
    -rpcport="${RPC_PORT}" \
    "$@"
}

wait_for_rpc() {
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if cli getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: timed out waiting for RPC" >&2
  return 1
}

wait_for_mempool_tx() {
  local txid="$1"
  for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
    if cli getmempoolentry "${txid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: tx ${txid} did not appear in mempool" >&2
  return 1
}

verify_block_contains_tx() {
  local blockhash="$1"
  local txid="$2"
  local block_json
  block_json="$(cli getblock "${blockhash}" 2)"
  python3 - "${txid}" "${block_json}" <<'PY'
import json
import sys

target = sys.argv[1]
block = json.loads(sys.argv[2])
txids = [entry.get("txid", "") for entry in block.get("tx", [])]
if target not in txids:
    raise SystemExit(f"txid {target} not found in block")
PY
}

verify_matmul_header_fields() {
  local blockhash="$1"
  local header_json
  header_json="$(cli getblockheader "${blockhash}")"
  python3 - "${header_json}" <<'PY'
import json
import re
import sys

header = json.loads(sys.argv[1])
required = ("nonce64", "matmul_digest", "matmul_dim", "seed_a", "seed_b")
for key in required:
    if key not in header:
        raise SystemExit(f"missing header field: {key}")

if not re.fullmatch(r"[0-9a-fA-F]{16}", str(header["nonce64"])):
    raise SystemExit("nonce64 must be 16 hex chars")
for key in ("matmul_digest", "seed_a", "seed_b"):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(header[key])):
        raise SystemExit(f"{key} must be 64 hex chars")
if int(header["matmul_dim"]) <= 0:
    raise SystemExit("matmul_dim must be positive")
PY
}

"${BITCOIND_BIN}" \
  -regtest \
  -regtestmsgstart="${MESSAGE_START}" \
  -regtestport="${REGTEST_PORT_OVERRIDE}" \
  -regtestgenesisntime="${GENESIS_TIME}" \
  -regtestgenesisnonce="${GENESIS_NONCE}" \
  -regtestgenesisbits="${GENESIS_BITS}" \
  -regtestgenesisversion="${GENESIS_VERSION}" \
  -autoshieldcoinbase=0 \
  -server=1 \
  -listen=0 \
  -dnsseed=0 \
  -discover=0 \
  -fallbackfee=0.0001 \
  -datadir="${DATADIR}" \
  -port="${P2P_PORT}" \
  -rpcport="${RPC_PORT}" \
  -printtoconsole=0 \
  >"${DATADIR}/btxd.log" 2>&1 &
NODE_PID="$!"

wait_for_rpc

cli -named createwallet wallet_name=miner descriptors=true load_on_startup=false >/dev/null
cli -named createwallet wallet_name=alice descriptors=true passphrase="${ALICE_PASSPHRASE}" load_on_startup=false >/dev/null
cli -named createwallet wallet_name=bob descriptors=true passphrase="${BOB_PASSPHRASE}" load_on_startup=false >/dev/null

MINER_ADDR="$(cli -rpcwallet=miner getnewaddress)"
ALICE_ADDR="$(cli -rpcwallet=alice getnewaddress)"
BOB_ADDR="$(cli -rpcwallet=bob getnewaddress)"

cli -rpcwallet=miner generatetoaddress "${MATURITY_BLOCKS}" "${MINER_ADDR}" >/dev/null

MINER_BALANCE_BEFORE="$(cli -rpcwallet=miner getbalance)"

# Mature coinbase outputs are spendable under P2MR, but wallet trusted-balance
# accounting for generated coinbase UTXOs can lag. Build/sign a direct mature
# coinbase spend for deterministic lifecycle funding.
SPEND_BLOCK_HASH="$(cli getblockhash 1)"
COINBASE_TXID="$(cli getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["txid"])')"
COINBASE_VALUE="$(cli getblock "${SPEND_BLOCK_HASH}" 2 | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["tx"][0]["vout"][0]["value"])')"
read -r RAW_INPUTS RAW_OUTPUTS <<<"$(python3 - "${COINBASE_TXID}" "${COINBASE_VALUE}" "${ALICE_ADDR}" "${MINER_ADDR}" "${FUND_AMOUNT}" <<'PY'
import json
import sys
from decimal import Decimal, ROUND_DOWN

txid = sys.argv[1]
coinbase_value = Decimal(sys.argv[2])
alice_addr = sys.argv[3]
miner_change = sys.argv[4]
fund_amount = Decimal(sys.argv[5])
fee = Decimal("0.0001")
change = (coinbase_value - fund_amount - fee).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
if change <= 0:
    raise SystemExit("insufficient coinbase value for requested fund amount")
inputs = json.dumps([{"txid": txid, "vout": 0}], separators=(",", ":"))
outputs = json.dumps({alice_addr: float(fund_amount), miner_change: float(change)}, separators=(",", ":"))
print(inputs, outputs)
PY
)"
RAW_TX="$(cli -named createrawtransaction inputs="${RAW_INPUTS}" outputs="${RAW_OUTPUTS}")"
SIGNED_JSON="$(cli -rpcwallet=miner signrawtransactionwithwallet "${RAW_TX}")"
TX_COMPLETE="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print("true" if json.load(sys.stdin)["complete"] else "false")')"
if [[ "${TX_COMPLETE}" != "true" ]]; then
  echo "error: signrawtransactionwithwallet did not produce a complete transaction" >&2
  exit 1
fi
TX_HEX="$(printf '%s' "${SIGNED_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])')"
TXID_FUND="$(cli sendrawtransaction "${TX_HEX}")"
wait_for_mempool_tx "${TXID_FUND}"
cli -rpcwallet=miner generatetoaddress 1 "${MINER_ADDR}" >/dev/null

FUND_CONFIRMATIONS="$(cli -rpcwallet=alice gettransaction "${TXID_FUND}" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["confirmations"]))')"
if [[ "${FUND_CONFIRMATIONS}" -lt 1 ]]; then
  echo "error: expected funded tx ${TXID_FUND} to be confirmed" >&2
  exit 1
fi
FUND_BLOCKHASH="$(cli -rpcwallet=alice gettransaction "${TXID_FUND}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')"
verify_block_contains_tx "${FUND_BLOCKHASH}" "${TXID_FUND}"
verify_matmul_header_fields "${FUND_BLOCKHASH}"

LOCKED_SEND_STDERR="${BASE_DIR}/alice-locked-send.err"
set +e
cli -rpcwallet=alice -named sendtoaddress address="${BOB_ADDR}" amount="${PAYMENT_AMOUNT}" fee_rate=30 >/dev/null 2>"${LOCKED_SEND_STDERR}"
LOCKED_SEND_RC=$?
set -e
if [[ "${LOCKED_SEND_RC}" -eq 0 ]]; then
  echo "error: expected locked Alice wallet sendtoaddress to fail" >&2
  exit 1
fi
if ! grep -q "walletpassphrase" "${LOCKED_SEND_STDERR}"; then
  echo "error: locked wallet failure did not mention walletpassphrase" >&2
  cat "${LOCKED_SEND_STDERR}" >&2
  exit 1
fi

cli -rpcwallet=alice walletpassphrase "${ALICE_PASSPHRASE}" 60 >/dev/null
TXID_PAYMENT="$(cli -rpcwallet=alice -named sendtoaddress address="${BOB_ADDR}" amount="${PAYMENT_AMOUNT}" fee_rate=30)"
cli -rpcwallet=alice walletlock >/dev/null

RELOCKED_SEND_STDERR="${BASE_DIR}/alice-relocked-send.err"
set +e
cli -rpcwallet=alice -named sendtoaddress address="${BOB_ADDR}" amount="0.01" fee_rate=30 >/dev/null 2>"${RELOCKED_SEND_STDERR}"
RELOCKED_SEND_RC=$?
set -e
if [[ "${RELOCKED_SEND_RC}" -eq 0 ]]; then
  echo "error: expected relocked Alice wallet sendtoaddress to fail" >&2
  exit 1
fi
if ! grep -q "walletpassphrase" "${RELOCKED_SEND_STDERR}"; then
  echo "error: relocked wallet failure did not mention walletpassphrase" >&2
  cat "${RELOCKED_SEND_STDERR}" >&2
  exit 1
fi

cli -rpcwallet=miner generatetoaddress 1 "${MINER_ADDR}" >/dev/null

PAYMENT_CONFIRMATIONS="$(cli -rpcwallet=bob gettransaction "${TXID_PAYMENT}" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["confirmations"]))')"
if [[ "${PAYMENT_CONFIRMATIONS}" -lt 1 ]]; then
  echo "error: expected Alice->Bob tx ${TXID_PAYMENT} to be confirmed" >&2
  exit 1
fi
PAYMENT_BLOCKHASH="$(cli -rpcwallet=bob gettransaction "${TXID_PAYMENT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')"
verify_block_contains_tx "${PAYMENT_BLOCKHASH}" "${TXID_PAYMENT}"
verify_matmul_header_fields "${PAYMENT_BLOCKHASH}"

FINAL_HEIGHT="$(cli getblockcount)"
BEST_BLOCK="$(cli getbestblockhash)"
ALICE_BALANCE="$(cli -rpcwallet=alice getbalance)"
BOB_BALANCE="$(cli -rpcwallet=bob getbalance)"
MINER_BALANCE_AFTER="$(cli -rpcwallet=miner getbalance)"

python3 - "${BOB_BALANCE}" "${PAYMENT_AMOUNT}" <<'PY'
import decimal
import sys

bob = decimal.Decimal(sys.argv[1])
minimum = decimal.Decimal(sys.argv[2])
if bob < minimum:
    raise SystemExit(f"bob balance {bob} below expected minimum {minimum}")
PY

python3 - "${ARTIFACT_PATH}" <<PY
import json
from datetime import datetime, timezone

artifact = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "overall_status": "pass",
    "node_label": "${NODE_LABEL}",
    "skipped_steps": [],
    "phase_coverage": {
        "startup": "pass",
        "wallet_creation": "pass",
        "mining_rewards": "pass",
        "funding_transfer": "pass",
        "funding_block_verification": "pass",
        "locked_send_rejection": "pass",
        "unlock_send_success": "pass",
        "relocked_send_rejection": "pass",
        "payment_block_verification": "pass",
    },
    "regtest": {
        "message_start": "${MESSAGE_START}",
        "default_port": int("${REGTEST_PORT_OVERRIDE}"),
        "genesis_time": int("${GENESIS_TIME}"),
        "genesis_nonce": int("${GENESIS_NONCE}"),
        "genesis_bits": "${GENESIS_BITS}",
        "genesis_version": int("${GENESIS_VERSION}"),
    },
    "node": {
        "p2p_port": int("${P2P_PORT}"),
        "rpc_port": int("${RPC_PORT}"),
        "height": int("${FINAL_HEIGHT}"),
        "best_block": "${BEST_BLOCK}",
    },
    "wallets": {
        "miner_balance_before_spend": "${MINER_BALANCE_BEFORE}",
        "miner_balance_after": "${MINER_BALANCE_AFTER}",
        "alice_balance": "${ALICE_BALANCE}",
        "bob_balance": "${BOB_BALANCE}",
    },
    "transactions": {
        "miner_to_alice": {
            "txid": "${TXID_FUND}",
            "amount": "${FUND_AMOUNT}",
            "confirmations": int("${FUND_CONFIRMATIONS}"),
            "blockhash": "${FUND_BLOCKHASH}",
        },
        "alice_to_bob": {
            "txid": "${TXID_PAYMENT}",
            "amount": "${PAYMENT_AMOUNT}",
            "confirmations": int("${PAYMENT_CONFIRMATIONS}"),
            "blockhash": "${PAYMENT_BLOCKHASH}",
        },
    },
    "locking_checks": {
        "locked_send_rc": int("${LOCKED_SEND_RC}"),
        "relocked_send_rc": int("${RELOCKED_SEND_RC}"),
    },
}
with open("${ARTIFACT_PATH}", "w", encoding="utf-8") as handle:
    json.dump(artifact, handle, indent=2)
PY

echo "M15 single-node lifecycle checks passed (${NODE_LABEL}):"
echo "- Startup/wallet creation/mining/send/receive/lock/unlock all validated"
echo "- Verified MatMul header fields and tx inclusion for mined blocks"
echo "- Artifact: ${ARTIFACT_PATH}"
