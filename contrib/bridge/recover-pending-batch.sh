#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash contrib/bridge/recover-pending-batch.sh [options]

Import a historical bridge batch into the wallet recovery journal and, by
default, immediately attempt recovery.

Required options:
  --wallet <name>              Wallet name that owns the bridge signing keys
  --plan-hex <hex>             Hex-encoded bridge plan
  --funding-txid <txid>        Funding transaction id
  --vout <n>                   Funding output index
  --amount <amount>            Funding output amount

Optional:
  --refund-destination <addr>  Explicit refund destination. If omitted, the
                               wallet will auto-generate one.
  --refund-fee <amount>        Refund fee for timeout fallback
                               (default: 0.00010000)
  --import-only                Import into the journal but do not attempt
                               immediate recovery
  --no-preflight               Skip the gettxout preflight check
  --no-list-after              Skip the bridge_listpending follow-up view
  --cli <path>                 Path to btx-cli (default: btx-cli)
  --datadir <path>             Optional datadir passed to every btx-cli call
  --rpc-arg <arg>              Extra argument passed to every btx-cli call
                               (repeatable)
  -h, --help                   Show this message

Environment overrides:
  BTX_BRIDGE_RECOVER_CLI
  BTX_BRIDGE_RECOVER_DATADIR
USAGE
}

CLI="${BTX_BRIDGE_RECOVER_CLI:-btx-cli}"
DATADIR="${BTX_BRIDGE_RECOVER_DATADIR:-}"
WALLET=""
PLAN_HEX=""
FUNDING_TXID=""
VOUT=""
AMOUNT=""
REFUND_DESTINATION=""
REFUND_FEE="0.00010000"
RECOVER_NOW=1
PREFLIGHT=1
LIST_AFTER=1
RPC_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wallet)
      WALLET="$2"
      shift 2
      ;;
    --plan-hex)
      PLAN_HEX="$2"
      shift 2
      ;;
    --funding-txid)
      FUNDING_TXID="$2"
      shift 2
      ;;
    --vout)
      VOUT="$2"
      shift 2
      ;;
    --amount)
      AMOUNT="$2"
      shift 2
      ;;
    --refund-destination)
      REFUND_DESTINATION="$2"
      shift 2
      ;;
    --refund-fee)
      REFUND_FEE="$2"
      shift 2
      ;;
    --import-only)
      RECOVER_NOW=0
      shift
      ;;
    --no-preflight)
      PREFLIGHT=0
      shift
      ;;
    --no-list-after)
      LIST_AFTER=0
      shift
      ;;
    --cli)
      CLI="$2"
      shift 2
      ;;
    --datadir)
      DATADIR="$2"
      shift 2
      ;;
    --rpc-arg)
      RPC_ARGS+=("$2")
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

require_arg() {
  local name="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    echo "error: missing required option ${name}" >&2
    usage >&2
    exit 1
  fi
}

require_arg --wallet "${WALLET}"
require_arg --plan-hex "${PLAN_HEX}"
require_arg --funding-txid "${FUNDING_TXID}"
require_arg --vout "${VOUT}"
require_arg --amount "${AMOUNT}"

COMMON_ARGS=()
if [[ -n "${DATADIR}" ]]; then
  COMMON_ARGS+=("-datadir=${DATADIR}")
fi
for rpc_arg in "${RPC_ARGS[@]}"; do
  COMMON_ARGS+=("${rpc_arg}")
done

node_cli() {
  "${CLI}" "${COMMON_ARGS[@]}" "$@"
}

wallet_cli() {
  "${CLI}" "${COMMON_ARGS[@]}" "-rpcwallet=${WALLET}" "$@"
}

json_pretty() {
  python3 -m json.tool
}

if [[ "${PREFLIGHT}" -eq 1 ]]; then
  preflight_json="$(node_cli gettxout "${FUNDING_TXID}" "${VOUT}" 2>/dev/null || true)"
  if [[ -z "${preflight_json}" || "${preflight_json}" == "null" ]]; then
    echo "warning: gettxout returned null for ${FUNDING_TXID}:${VOUT}" >&2
    echo "warning: the funding outpoint is not currently unspent on this node" >&2
    echo "warning: recovery may report spent_elsewhere, or you may need manual historical review" >&2
  else
    python3 - <<'PY' "${preflight_json}" "${AMOUNT}"
import decimal
import json
import sys

txout = json.loads(sys.argv[1])
requested = decimal.Decimal(sys.argv[2])
value = decimal.Decimal(str(txout["value"]))
confirmations = txout.get("confirmations")
script = txout.get("scriptPubKey", {})
address = script.get("address")
if address is None:
    addresses = script.get("addresses") or []
    if addresses:
        address = addresses[0]

print(f"preflight: funding outpoint is currently unspent on this node")
print(f"preflight: value={value} confirmations={confirmations}")
if address:
    print(f"preflight: script address={address}")
if value != requested:
    print(f"warning: requested amount {requested} does not match gettxout value {value}", file=sys.stderr)
PY
  fi
fi

OPTIONS_JSON="$(
  python3 - <<'PY' "${REFUND_DESTINATION}" "${REFUND_FEE}" "${RECOVER_NOW}"
import json
import sys

refund_destination = sys.argv[1]
refund_fee = sys.argv[2]
recover_now = sys.argv[3] == "1"

parts = [
    f'"refund_fee": {refund_fee}',
    f'"recover_now": {"true" if recover_now else "false"}',
]
if refund_destination:
    parts.insert(0, '"refund_destination": ' + json.dumps(refund_destination))

print('{' + ', '.join(parts) + '}')
PY
)"

echo "import: attaching ${FUNDING_TXID}:${VOUT} to wallet journal ${WALLET}"
IMPORT_RESULT="$(wallet_cli bridge_importpending "${PLAN_HEX}" "${FUNDING_TXID}" "${VOUT}" "${AMOUNT}" "${OPTIONS_JSON}")"
printf '%s\n' "${IMPORT_RESULT}" | json_pretty

python3 - <<'PY' "${IMPORT_RESULT}"
import json
import sys

result = json.loads(sys.argv[1])
refund_destination = result.get("refund_destination")
status = result.get("status")
current_status = result.get("current_status")
current = result.get("current")

if refund_destination:
    print(f"summary: refund_destination={refund_destination}")
if current_status:
    print(f"summary: current_status={current_status}")
elif isinstance(current, dict) and current.get("status"):
    print(f"summary: current_status={current['status']}")
elif status:
    print(f"summary: status={status}")
PY

if [[ "${LIST_AFTER}" -eq 1 ]]; then
  LIST_RESULT="$(wallet_cli bridge_listpending)"
  echo "list: unresolved journal entry for ${FUNDING_TXID}:${VOUT}"
  python3 - <<'PY' "${LIST_RESULT}" "${FUNDING_TXID}" "${VOUT}"
import json
import sys

rows = json.loads(sys.argv[1])
txid = sys.argv[2]
vout = int(sys.argv[3])
matches = [
    row for row in rows
    if row.get("funding_txid") == txid and int(row.get("funding_vout", -1)) == vout
]
print(json.dumps(matches, indent=2, sort_keys=True))
if not matches:
    print("note: no unresolved pending entry remains for this outpoint")
PY
fi
