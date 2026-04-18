#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  local_pq_multisig_setup.sh --coordinator <wallet> --threshold <m> [options] <signer_wallet>...

Build a deterministic PQ multisig keyset from signer wallets and import it into
the coordinator wallet via addpqmultisigaddress.

Options:
  --coordinator <wallet>    Coordinator wallet name (required)
  --threshold <m>           Required signatures (required)
  --label <text>            Address book label on coordinator (default: pq-team-safe)
  --algorithms <csv>        Comma-separated per-signer algorithms
                            (ml-dsa-44 or slh-dsa-shake-128s). If omitted, all
                            signers use ml-dsa-44.
  --no-sort                 Do not lexicographically sort keys (default: sort=true)
  --help                    Show this help

Environment:
  BTX_CLI                   bitcoin-cli path (default: bitcoin-cli)
  BTX_CLI_ARGS              Extra bitcoin-cli args, e.g. "-datadir=/tmp/btx -rpcport=19332"

Example:
  BTX_CLI=./build/bin/bitcoin-cli \
  BTX_CLI_ARGS="-regtest" \
  ./contrib/pq-multisig/local_pq_multisig_setup.sh \
    --coordinator coordinator \
    --threshold 2 \
    signerA signerB signerC
EOF
}

CLI="${BTX_CLI:-bitcoin-cli}"
CLI_ARGS=()
if [[ -n "${BTX_CLI_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  CLI_ARGS=(${BTX_CLI_ARGS})
fi

COORDINATOR=""
THRESHOLD=""
LABEL="pq-team-safe"
ALGORITHMS_CSV=""
SORT_KEYS=true

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --coordinator)
      COORDINATOR="${2:-}"
      shift 2
      ;;
    --threshold)
      THRESHOLD="${2:-}"
      shift 2
      ;;
    --label)
      LABEL="${2:-}"
      shift 2
      ;;
    --algorithms)
      ALGORITHMS_CSV="${2:-}"
      shift 2
      ;;
    --no-sort)
      SORT_KEYS=false
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ -z "${COORDINATOR}" ]]; then
  echo "error: --coordinator is required" >&2
  exit 1
fi
if [[ -z "${THRESHOLD}" ]]; then
  echo "error: --threshold is required" >&2
  exit 1
fi
if ! [[ "${THRESHOLD}" =~ ^[0-9]+$ ]]; then
  echo "error: --threshold must be a positive integer" >&2
  exit 1
fi
if (( THRESHOLD < 1 )); then
  echo "error: --threshold must be >= 1" >&2
  exit 1
fi
if (( ${#POSITIONAL[@]} < 2 )); then
  echo "error: at least two signer wallets are required" >&2
  exit 1
fi
if (( THRESHOLD > ${#POSITIONAL[@]} )); then
  echo "error: threshold cannot exceed signer count" >&2
  exit 1
fi

SIGNERS=("${POSITIONAL[@]}")
ALGORITHMS=()
if [[ -n "${ALGORITHMS_CSV}" ]]; then
  IFS=',' read -r -a ALGORITHMS <<< "${ALGORITHMS_CSV}"
  if (( ${#ALGORITHMS[@]} != ${#SIGNERS[@]} )); then
    echo "error: --algorithms count (${#ALGORITHMS[@]}) must match signer count (${#SIGNERS[@]})" >&2
    exit 1
  fi
else
  for _ in "${SIGNERS[@]}"; do
    ALGORITHMS+=("ml-dsa-44")
  done
fi

call_cli() {
  "${CLI}" "${CLI_ARGS[@]}" "$@"
}

echo "Collecting deterministic PQ keys from signer wallets..."
KEYS=()
for i in "${!SIGNERS[@]}"; do
  signer="${SIGNERS[$i]}"
  algo="${ALGORITHMS[$i]}"
  src_addr="$(call_cli -rpcwallet="${signer}" getnewaddress)"
  exported="$(call_cli -rpcwallet="${signer}" exportpqkey "${src_addr}" "${algo}")"
  key="$(jq -r '.key' <<< "${exported}")"
  exported_algo="$(jq -r '.algorithm' <<< "${exported}")"
  echo "  signer=${signer} address=${src_addr} algorithm=${exported_algo}"
  KEYS+=("${key}")
done

KEYS_JSON="$(printf '%s\n' "${KEYS[@]}" | jq -R . | jq -s .)"
echo "Importing ${THRESHOLD}-of-${#KEYS[@]} descriptor into coordinator wallet '${COORDINATOR}'..."

RESULT="$(call_cli -rpcwallet="${COORDINATOR}" addpqmultisigaddress "${THRESHOLD}" "${KEYS_JSON}" "${LABEL}" "${SORT_KEYS}")"
echo "${RESULT}" | jq .
