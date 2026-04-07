#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m11_metal_mining_validation.sh [options]

Run repeated mining validations across:
1) Standard BTX strict-regtest block mining flow.
2) Optional Apple Silicon Metal-assisted nonce search via btx-genesis.

Options:
  --build-dir <path>        Build directory (default: build-btx)
  --rounds <n>              Number of validation rounds (default: 3)
  --cpu-blocks <n>          Standard regtest blocks to mine per round (default: 3)
  --metal-max-tries <n>     Max tries for btx-genesis Metal search (default: 200000)
  --require-metal           Fail if Metal acceleration is unavailable
  --artifact <path>         Output JSON artifact path
  -h, --help                Show this message

Environment overrides:
  BTX_M11_BTXD_BIN
  BTX_M11_BTX_CLI_BIN
  BTX_M11_BITCOIND_BIN
  BTX_M11_BITCOIN_CLI_BIN
  BTX_M11_GENESIS_BIN
  BTX_M11_STOP_TIMEOUT_SECONDS
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
ROUNDS=3
CPU_BLOCKS=3
METAL_MAX_TRIES=200000
REQUIRE_METAL=0
ARTIFACT="${ROOT_DIR}/.btx-metal/m11-validation.json"
STOP_TIMEOUT_SECONDS="${BTX_M11_STOP_TIMEOUT_SECONDS:-5}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --rounds)
      ROUNDS="$2"
      shift 2
      ;;
    --cpu-blocks)
      CPU_BLOCKS="$2"
      shift 2
      ;;
    --metal-max-tries)
      METAL_MAX_TRIES="$2"
      shift 2
      ;;
    --require-metal)
      REQUIRE_METAL=1
      shift
      ;;
    --artifact)
      ARTIFACT="$2"
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

for n in "${ROUNDS}" "${CPU_BLOCKS}" "${METAL_MAX_TRIES}"; do
  if ! [[ "${n}" =~ ^[0-9]+$ ]] || [[ "${n}" -lt 1 ]]; then
    echo "error: numeric options must be positive integers" >&2
    exit 1
  fi
done
if ! [[ "${STOP_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${STOP_TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "error: BTX_M11_STOP_TIMEOUT_SECONDS must be a positive integer" >&2
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

BITCOIND_BIN="${BTX_M11_BTXD_BIN:-${BTX_M11_BITCOIND_BIN:-}}"
BITCOIN_CLI_BIN="${BTX_M11_BTX_CLI_BIN:-${BTX_M11_BITCOIN_CLI_BIN:-}}"
if [[ -z "${BITCOIND_BIN}" ]]; then
  BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
fi
if [[ -z "${BITCOIN_CLI_BIN}" ]]; then
  BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
fi
GENESIS_BIN="${BTX_M11_GENESIS_BIN:-${BUILD_DIR}/bin/btx-genesis}"

for bin in "${BITCOIND_BIN}" "${BITCOIN_CLI_BIN}" "${GENESIS_BIN}"; do
  if [[ ! -x "${bin}" ]]; then
    echo "error: missing executable ${bin}" >&2
    exit 1
  fi
done

find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

mkdir -p "$(dirname "${ARTIFACT}")"
ROUND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-rounds.XXXXXX")"

cleanup() {
  rm -rf "${ROUND_DIR}"
}
trap cleanup EXIT

overall_status="pass"

for round in $(seq 1 "${ROUNDS}"); do
  datadir="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-node.${round}.XXXXXX")"
  rpcport="$(find_free_port)"
  node_pid=""

  cli() {
    "${BITCOIN_CLI_BIN}" -regtest -rpcport="${rpcport}" -datadir="${datadir}" "$@"
  }

  stop_node() {
    if [[ -n "${node_pid}" ]]; then
      cli stop >/dev/null 2>&1 || true
      for _ in $(seq 1 "${STOP_TIMEOUT_SECONDS}"); do
        if ! kill -0 "${node_pid}" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
      if kill -0 "${node_pid}" >/dev/null 2>&1; then
        kill -TERM "${node_pid}" >/dev/null 2>&1 || true
      fi
      for _ in $(seq 1 2); do
        if ! kill -0 "${node_pid}" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
      if kill -0 "${node_pid}" >/dev/null 2>&1; then
        kill -KILL "${node_pid}" >/dev/null 2>&1 || true
      fi
      wait "${node_pid}" 2>/dev/null || true
    fi
    rm -rf "${datadir}"
  }

  "${BITCOIND_BIN}" -regtest -test=matmulstrict -rpcport="${rpcport}" -datadir="${datadir}" -listen=0 -fallbackfee=0.0001 -printtoconsole=0 >/dev/null 2>&1 &
  node_pid="$!"

  rpc_ready=0
  for _ in $(seq 1 60); do
    if ! kill -0 "${node_pid}" >/dev/null 2>&1; then
      break
    fi
    if cli getblockcount >/dev/null 2>&1; then
      rpc_ready=1
      break
    fi
    sleep 1
  done

  if [[ "${rpc_ready}" -ne 1 ]]; then
    echo "error: round ${round}: node RPC did not become ready" >&2
    stop_node
    exit 1
  fi

  cpu_height_before="$(cli getblockcount)"
  cli generatetodescriptor "${CPU_BLOCKS}" "raw(51)" >/dev/null
  cpu_height_after="$(cli getblockcount)"
  stop_node

  timestamp="BTX M11 round ${round} $(date +%s)"
  genesis_log="${ROUND_DIR}/round-${round}-genesis.log"
  genesis_cmd=(
    "${GENESIS_BIN}"
    --timestamp "${timestamp}"
    --time "$((1231006505 + round))"
    --bits 0x207fffff
    --max-tries "${METAL_MAX_TRIES}"
    --metal
  )
  if [[ "${REQUIRE_METAL}" -eq 1 ]]; then
    genesis_cmd+=(--metal-require)
  fi

  set +e
  "${genesis_cmd[@]}" >"${genesis_log}" 2>&1
  genesis_rc=$?
  set -e

  if [[ "${genesis_rc}" -ne 0 ]]; then
    overall_status="fail"
  fi

  status_line="$(rg '^status=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"
  metal_available="$(rg '^metal_available=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"
  metal_used="$(rg '^metal_used=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"
  nonce64="$(rg '^nonce64=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"
  powhash="$(rg '^(powhash|matmul_digest)=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"
  blockhash="$(rg '^blockhash=' "${genesis_log}" -N | tail -n1 | cut -d= -f2- || true)"

  if [[ "${status_line}" != "found" ]]; then
    overall_status="fail"
  fi

  if [[ "${REQUIRE_METAL}" -eq 1 && ( "${metal_available}" != "1" || "${metal_used}" != "1" ) ]]; then
    overall_status="fail"
  fi

  cat > "${ROUND_DIR}/round-${round}.json" <<JSON
{
  "round": ${round},
  "cpu_height_before": ${cpu_height_before},
  "cpu_height_after": ${cpu_height_after},
  "cpu_blocks_mined": $((cpu_height_after - cpu_height_before)),
  "genesis_exit_code": ${genesis_rc},
  "genesis_status": "${status_line}",
  "metal_available": "${metal_available}",
  "metal_used": "${metal_used}",
  "nonce64": "${nonce64}",
  "powhash": "${powhash}",
  "blockhash": "${blockhash}",
  "genesis_log": "${genesis_log}"
}
JSON

done

python3 - <<'PY' "${ROUND_DIR}" "${ARTIFACT}" "${overall_status}" "${ROUNDS}" "${REQUIRE_METAL}"
import json
import pathlib
import sys
from datetime import datetime, timezone

round_dir = pathlib.Path(sys.argv[1])
artifact = pathlib.Path(sys.argv[2])
overall_status = sys.argv[3]
rounds = int(sys.argv[4])
require_metal = int(sys.argv[5])

entries = []
for i in range(1, rounds + 1):
    path = round_dir / f"round-{i}.json"
    entries.append(json.loads(path.read_text(encoding="utf-8")))

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "overall_status": overall_status,
    "require_metal": bool(require_metal),
    "rounds": entries,
}
artifact.parent.mkdir(parents=True, exist_ok=True)
artifact.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"artifact: {artifact}")
print(f"overall_status: {overall_status}")
PY

if [[ "${overall_status}" != "pass" ]]; then
  exit 1
fi

echo "M11 metal mining validation completed successfully (${ROUNDS} rounds)."
