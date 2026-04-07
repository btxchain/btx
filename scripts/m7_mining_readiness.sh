#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-btx}"
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
if [[ $# -gt 0 ]]; then
  shift
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

DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m7.XXXXXX")"
RPC_READY_TIMEOUT_SECONDS="${BTX_M7_RPC_READY_TIMEOUT_SECONDS:-60}"
find_free_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

RPC_PORT="$(find_free_port)"

cli() {
  "${BITCOIN_CLI_BIN}" -regtest -datadir="${DATADIR}" -rpcport="${RPC_PORT}" "$@"
}

cleanup() {
  if [[ -n "${NODE_PID:-}" ]]; then
    cli stop >/dev/null 2>&1 || true
    for _ in $(seq 1 5); do
      if ! kill -0 "${NODE_PID}" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    if kill -0 "${NODE_PID}" >/dev/null 2>&1; then
      kill "${NODE_PID}" >/dev/null 2>&1 || true
      for _ in $(seq 1 5); do
        if ! kill -0 "${NODE_PID}" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
    fi
    if kill -0 "${NODE_PID}" >/dev/null 2>&1; then
      kill -9 "${NODE_PID}" >/dev/null 2>&1 || true
    fi
    wait "${NODE_PID}" 2>/dev/null || true
  fi
  rm -rf "${DATADIR}"
}
trap cleanup EXIT

if [[ ! -x "${BITCOIND_BIN}" || ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing BTX binaries in ${BUILD_DIR}/bin" >&2
  exit 1
fi

if ! [[ "${RPC_READY_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${RPC_READY_TIMEOUT_SECONDS}" -lt 1 ]]; then
  echo "error: BTX_M7_RPC_READY_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 1
fi

"${BITCOIND_BIN}" -regtest -test=matmulstrict -fallbackfee=0.0001 -datadir="${DATADIR}" -rpcport="${RPC_PORT}" -listen=0 -daemonwait=0 -printtoconsole=0 >/dev/null 2>&1 &
NODE_PID=$!

rpc_ready=0
for _ in $(seq 1 "${RPC_READY_TIMEOUT_SECONDS}"); do
  if ! kill -0 "${NODE_PID}" >/dev/null 2>&1; then
    echo "error: btxd exited before RPC became available" >&2
    exit 1
  fi
  if cli getblockcount >/dev/null 2>&1; then
    rpc_ready=1
    break
  fi
  sleep 1
done

if [[ "${rpc_ready}" -ne 1 ]]; then
  echo "error: timed out waiting for btxd RPC availability" >&2
  exit 1
fi

cli generatetodescriptor 3 "raw(51)" >/dev/null

GBT="$(cli getblocktemplate '{"rules":["segwit"]}')"
echo "${GBT}" | rg -q '"height"'
echo "${GBT}" | rg -q '"target"'
echo "${GBT}" | rg -q '"bits"'
echo "${GBT}" | rg -q '"noncerange"[[:space:]]*:[[:space:]]*"0000000000000000ffffffffffffffff"'

echo "M7 readiness checks passed:"
echo "- BTX regtest node booted with strict MatMul validation"
echo "- getblocktemplate exposes MatMul mining fields including 64-bit noncerange"
