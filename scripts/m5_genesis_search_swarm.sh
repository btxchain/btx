#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/m5_genesis_search_swarm.sh [options]

Run parallel, resumable KAWPOW genesis nonce64 search rounds using btx-genesis.

Options:
  --build-dir <path>      Build directory containing bin/btx-genesis (default: build-btx)
  --genesis-bin <path>    Explicit btx-genesis binary path (overrides --build-dir)
  --workers <n>           Parallel workers per round (default: 4)
  --chunk-tries <n>       Tries per worker per round (default: 200000)
  --max-rounds <n>        Stop after n rounds (default: 0, unlimited)
  --start-nonce64 <n>     Initial nonce64 search start (default: 0)
  --state-file <path>     Progress file storing next nonce64 start
  --artifact <path>       Output file written when a solution is found
  --reset-state           Ignore existing state-file and restart from --start-nonce64
  --network <name>        Label for progress/artifact naming (default: main)
  --timestamp <text>      Coinbase timestamp message
  --script-hex <hex>      Coinbase output script hex
  --time <uint32>         Block time
  --bits <hex>            Compact difficulty bits
  --version <int32>       Block version
  --nonce <uint32>        Legacy nonce value
  --height <uint32>       KAWPOW height argument
  --reward-sats <int64>   Coinbase reward in satoshis
  --dry-run               Print worker ranges without executing
  -h, --help              Show this message
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
GENESIS_BIN=""
WORKERS=4
CHUNK_TRIES=200000
MAX_ROUNDS=0
START_NONCE64=0
RESET_STATE=0
NETWORK="main"
TIMESTAMP="BTX 06/Feb/2026 KAWPOW+BIP110 genesis"
SCRIPT_HEX="76a914000000000000000000000000000000000000000088ac"
BLOCK_TIME=1231006505
BITS="0x1d00ffff"
VERSION=1
NONCE=2083236893
HEIGHT=0
REWARD_SATS=5000000000
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --genesis-bin)
      GENESIS_BIN="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --chunk-tries)
      CHUNK_TRIES="$2"
      shift 2
      ;;
    --max-rounds)
      MAX_ROUNDS="$2"
      shift 2
      ;;
    --start-nonce64)
      START_NONCE64="$2"
      shift 2
      ;;
    --state-file)
      STATE_FILE="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --reset-state)
      RESET_STATE=1
      shift
      ;;
    --network)
      NETWORK="$2"
      shift 2
      ;;
    --timestamp)
      TIMESTAMP="$2"
      shift 2
      ;;
    --script-hex)
      SCRIPT_HEX="$2"
      shift 2
      ;;
    --time)
      BLOCK_TIME="$2"
      shift 2
      ;;
    --bits)
      BITS="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --nonce)
      NONCE="$2"
      shift 2
      ;;
    --height)
      HEIGHT="$2"
      shift 2
      ;;
    --reward-sats)
      REWARD_SATS="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
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

if [[ -z "${GENESIS_BIN}" ]]; then
  GENESIS_BIN="${BUILD_DIR}/bin/btx-genesis"
fi

if [[ -z "${STATE_FILE:-}" ]]; then
  STATE_FILE="${ROOT_DIR}/.btx-swarm/m5-genesis-${NETWORK}.state"
fi

if [[ -z "${ARTIFACT_PATH:-}" ]]; then
  ARTIFACT_PATH="${ROOT_DIR}/.btx-swarm/m5-genesis-${NETWORK}-found.txt"
fi

if ! [[ "${WORKERS}" =~ ^[0-9]+$ ]] || (( WORKERS < 1 )); then
  echo "error: --workers must be a positive integer" >&2
  exit 1
fi

if ! [[ "${CHUNK_TRIES}" =~ ^[0-9]+$ ]] || (( CHUNK_TRIES < 1 )); then
  echo "error: --chunk-tries must be a positive integer" >&2
  exit 1
fi

if ! [[ "${MAX_ROUNDS}" =~ ^[0-9]+$ ]]; then
  echo "error: --max-rounds must be a non-negative integer" >&2
  exit 1
fi

if ! [[ "${START_NONCE64}" =~ ^[0-9]+$ ]]; then
  echo "error: --start-nonce64 must be a non-negative integer" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 0 ]] && [[ ! -x "${GENESIS_BIN}" ]]; then
  echo "error: missing executable btx-genesis: ${GENESIS_BIN}" >&2
  exit 1
fi

mkdir -p "$(dirname "${STATE_FILE}")" "$(dirname "${ARTIFACT_PATH}")"
LOG_ROOT="${ROOT_DIR}/.btx-swarm/logs/m5-genesis-${NETWORK}"
mkdir -p "${LOG_ROOT}"

next_nonce64="${START_NONCE64}"
if [[ "${RESET_STATE}" -eq 0 && -f "${STATE_FILE}" ]]; then
  read -r stored < "${STATE_FILE}"
  if [[ "${stored}" =~ ^[0-9]+$ ]]; then
    next_nonce64="${stored}"
  else
    echo "error: invalid state file contents in ${STATE_FILE}" >&2
    exit 1
  fi
fi

round=0
while true; do
  ((round += 1))
  round_base="${next_nonce64}"

  echo "round=${round} base_nonce64=${round_base} workers=${WORKERS} chunk_tries=${CHUNK_TRIES}"

  declare -a pids=()
  declare -a logs=()
  for ((i = 0; i < WORKERS; ++i)); do
    worker_start=$((round_base + (i * CHUNK_TRIES)))
    worker_log="${LOG_ROOT}/round-${round}-worker-${i}.log"
    logs+=("${worker_log}")

    if [[ "${DRY_RUN}" -eq 1 ]]; then
      echo "[dry-run] worker=${i} start_nonce64=${worker_start} max_tries=${CHUNK_TRIES}"
      continue
    fi

    (
      set -euo pipefail
      "${GENESIS_BIN}" \
        --timestamp "${TIMESTAMP}" \
        --script-hex "${SCRIPT_HEX}" \
        --time "${BLOCK_TIME}" \
        --bits "${BITS}" \
        --version "${VERSION}" \
        --nonce "${NONCE}" \
        --height "${HEIGHT}" \
        --nonce64-start "${worker_start}" \
        --max-tries "${CHUNK_TRIES}" \
        --reward-sats "${REWARD_SATS}"
    ) >"${worker_log}" 2>&1 &
    pids+=("$!")
  done

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    next_nonce64=$((round_base + (WORKERS * CHUNK_TRIES)))
    echo "${next_nonce64}" > "${STATE_FILE}"
    if (( MAX_ROUNDS > 0 && round >= MAX_ROUNDS )); then
      break
    fi
    continue
  fi

  found_log=""
  expected_miss_count=0
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      found_log="${logs[$i]}"
    else
      if rg -q "no valid nonce found within max tries" "${logs[$i]}"; then
        ((expected_miss_count += 1))
      else
        echo "error: worker ${i} failed unexpectedly (see ${logs[$i]})" >&2
        exit 1
      fi
    fi
  done

  if [[ -n "${found_log}" ]]; then
    cp "${found_log}" "${ARTIFACT_PATH}"
    echo "found=true artifact=${ARTIFACT_PATH}"
    exit 0
  fi

  if (( expected_miss_count != WORKERS )); then
    echo "error: inconsistent worker outcomes in round ${round}" >&2
    exit 1
  fi

  next_nonce64=$((round_base + (WORKERS * CHUNK_TRIES)))
  echo "${next_nonce64}" > "${STATE_FILE}"
  echo "round=${round} no solution; next_nonce64=${next_nonce64}"

  if (( MAX_ROUNDS > 0 && round >= MAX_ROUNDS )); then
    echo "status=exhausted rounds=${round} next_nonce64=${next_nonce64}"
    exit 2
  fi
done

exit 0
