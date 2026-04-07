#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m5_verify_genesis_freeze.sh [options]

Verify that frozen BTX genesis tuples (main/testnet/regtest) match the active
node's genesis header fields.

Options:
  --build-dir <path>      Build directory containing btxd/btx-cli (legacy aliases accepted)
                          (default: build-btx)
  --tuples <path>         Genesis tuples JSON (default: doc/btx-genesis-tuples.json)
  --artifact <path>       Output JSON artifact path
                          (default: .btx-validation/m5-genesis-freeze.json)
  --networks <csv>        Networks to verify (default: main,testnet,regtest)
  -h, --help              Show this message

Environment overrides:
  BTX_M5_VERIFY_BTXD_BIN
  BTX_M5_VERIFY_BTX_CLI_BIN
  BTX_M5_VERIFY_BITCOIND_BIN
  BTX_M5_VERIFY_BITCOIN_CLI_BIN
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
TUPLES_PATH="${ROOT_DIR}/doc/btx-genesis-tuples.json"
ARTIFACT_PATH="${ROOT_DIR}/.btx-validation/m5-genesis-freeze.json"
NETWORKS_CSV="main,testnet,regtest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --tuples)
      TUPLES_PATH="$2"
      shift 2
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --networks)
      NETWORKS_CSV="$2"
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

BITCOIND_BIN="${BTX_M5_VERIFY_BTXD_BIN:-${BTX_M5_VERIFY_BITCOIND_BIN:-}}"
BITCOIN_CLI_BIN="${BTX_M5_VERIFY_BTX_CLI_BIN:-${BTX_M5_VERIFY_BITCOIN_CLI_BIN:-}}"
if [[ -z "${BITCOIND_BIN}" ]]; then
  BITCOIND_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btxd" "${BUILD_DIR}/bin/bitcoind")"
fi
if [[ -z "${BITCOIN_CLI_BIN}" ]]; then
  BITCOIN_CLI_BIN="$(resolve_btx_binary "${BUILD_DIR}/bin/btx-cli" "${BUILD_DIR}/bin/bitcoin-cli")"
fi

if [[ ! -x "${BITCOIND_BIN}" || ! -x "${BITCOIN_CLI_BIN}" ]]; then
  echo "error: missing btxd/btx-cli executables (or legacy aliases)" >&2
  exit 1
fi

if [[ ! -f "${TUPLES_PATH}" ]]; then
  echo "error: missing tuples file: ${TUPLES_PATH}" >&2
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

IFS=',' read -r -a NETWORKS <<< "${NETWORKS_CSV}"
if [[ "${#NETWORKS[@]}" -eq 0 ]]; then
  echo "error: --networks cannot be empty" >&2
  exit 1
fi
for network in "${NETWORKS[@]}"; do
  case "${network}" in
    main|testnet|regtest)
      ;;
    *)
      echo "error: unsupported network in --networks: ${network}" >&2
      exit 1
      ;;
  esac
done

OBSERVED_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m5-freeze-observed.XXXXXX")"
cleanup() {
  rm -rf "${OBSERVED_DIR}"
}
trap cleanup EXIT

for network in "${NETWORKS[@]}"; do
  datadir="$(mktemp -d "${TMPDIR:-/tmp}/btx-m5-freeze-${network}.XXXXXX")"
  rpcport="$(find_free_port)"
  pid=""

  case "${network}" in
    main)
      daemon_chain_arg=""
      cli_chain_arg=""
      ;;
    testnet)
      daemon_chain_arg="-testnet"
      cli_chain_arg="-testnet"
      ;;
    regtest)
      daemon_chain_arg="-regtest"
      cli_chain_arg="-regtest"
      ;;
  esac

  cli() {
    if [[ -n "${cli_chain_arg}" ]]; then
      "${BITCOIN_CLI_BIN}" "${cli_chain_arg}" -datadir="${datadir}" -rpcport="${rpcport}" "$@"
    else
      "${BITCOIN_CLI_BIN}" -datadir="${datadir}" -rpcport="${rpcport}" "$@"
    fi
  }

  stop_node() {
    if [[ -n "${pid}" ]]; then
      cli stop >/dev/null 2>&1 || true
      for _ in $(seq 1 10); do
        if ! kill -0 "${pid}" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
      if kill -0 "${pid}" >/dev/null 2>&1; then
        kill "${pid}" >/dev/null 2>&1 || true
        for _ in $(seq 1 5); do
          if ! kill -0 "${pid}" >/dev/null 2>&1; then
            break
          fi
          sleep 1
        done
      fi
      if kill -0 "${pid}" >/dev/null 2>&1; then
        kill -9 "${pid}" >/dev/null 2>&1 || true
      fi
      wait "${pid}" 2>/dev/null || true
      pid=""
    fi
    rm -rf "${datadir}"
  }

  if [[ -n "${daemon_chain_arg}" ]]; then
    "${BITCOIND_BIN}" "${daemon_chain_arg}" -datadir="${datadir}" -rpcport="${rpcport}" -listen=0 -server=1 -fallbackfee=0.0001 -printtoconsole=0 >/dev/null 2>&1 &
  else
    "${BITCOIND_BIN}" -datadir="${datadir}" -rpcport="${rpcport}" -listen=0 -server=1 -fallbackfee=0.0001 -printtoconsole=0 >/dev/null 2>&1 &
  fi
  pid="$!"

  rpc_ready=0
  for _ in $(seq 1 60); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "error: ${network} node exited before RPC became ready" >&2
      stop_node
      exit 1
    fi
    if cli getblockcount >/dev/null 2>&1; then
      rpc_ready=1
      break
    fi
    sleep 1
  done
  if [[ "${rpc_ready}" -ne 1 ]]; then
    echo "error: timed out waiting for ${network} RPC" >&2
    stop_node
    exit 1
  fi

  blockhash="$(cli getblockhash 0)"
  header_json="$(cli getblockheader "${blockhash}")"
  header_hex="$(cli getblockheader "${blockhash}" false)"

  python3 - <<'PY' "${network}" "${blockhash}" "${header_json}" "${header_hex}" "${OBSERVED_DIR}"
import json
import pathlib
import sys

network = sys.argv[1]
blockhash = sys.argv[2]
header = json.loads(sys.argv[3])
header_hex = sys.argv[4].strip()
out_dir = pathlib.Path(sys.argv[5])
header_raw = bytes.fromhex(header_hex)

if len(header_raw) != 182:
    raise ValueError(f"unexpected BTX header size for {network}: {len(header_raw)} bytes")

nonce64 = int.from_bytes(header_raw[76:84], "little")
matmul_digest = header_raw[84:116][::-1].hex()
matmul_dim = int.from_bytes(header_raw[116:118], "little")
seed_a = header_raw[118:150][::-1].hex()
seed_b = header_raw[150:182][::-1].hex()

out = {
    "blockhash": blockhash,
    "time": header.get("time"),
    "bits": str(header.get("bits", "")).lower(),
    "nonce": header.get("nonce"),
    "nonce64": nonce64,
    "matmul_digest": matmul_digest,
    "matmul_dim": matmul_dim,
    "seed_a": seed_a,
    "seed_b": seed_b,
    "merkleroot": header.get("merkleroot"),
}
(out_dir / f"{network}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
PY

  stop_node
done

mkdir -p "$(dirname "${ARTIFACT_PATH}")"
python3 - <<'PY' "${TUPLES_PATH}" "${OBSERVED_DIR}" "${ARTIFACT_PATH}" "${NETWORKS_CSV}"
import json
import pathlib
import sys
from datetime import datetime, timezone

tuples_path = pathlib.Path(sys.argv[1])
observed_dir = pathlib.Path(sys.argv[2])
artifact_path = pathlib.Path(sys.argv[3])
networks = [n for n in sys.argv[4].split(",") if n]

tuples = json.loads(tuples_path.read_text(encoding="utf-8"))
results = []
overall = "pass"

for network in networks:
    expected = tuples.get(network)
    observed_path = observed_dir / f"{network}.json"
    observed = json.loads(observed_path.read_text(encoding="utf-8"))

    if expected is None:
        results.append({
            "network": network,
            "status": "fail",
            "reason": f"missing network in tuples file: {network}",
        })
        overall = "fail"
        continue

    checks = {
        "blockhash": str(expected.get("blockhash", "")).lower(),
        "time": int(expected.get("time")),
        "bits": str(expected.get("bits", "")).lower().removeprefix("0x"),
        "nonce": int(expected.get("nonce")),
        "nonce64": int(expected.get("nonce64")),
        "matmul_digest": str(expected.get("matmul_digest", "")).lower(),
        "matmul_dim": int(expected.get("matmul_dim")),
        "seed_a": str(expected.get("seed_a", "")).lower(),
        "seed_b": str(expected.get("seed_b", "")).lower(),
        "merkleroot": str(expected.get("merkleroot", "")).lower(),
    }
    observed_norm = {
        "blockhash": str(observed.get("blockhash", "")).lower(),
        "time": int(observed.get("time")),
        "bits": str(observed.get("bits", "")).lower().removeprefix("0x"),
        "nonce": int(observed.get("nonce")),
        "nonce64": int(observed.get("nonce64")),
        "matmul_digest": str(observed.get("matmul_digest", "")).lower(),
        "matmul_dim": int(observed.get("matmul_dim")),
        "seed_a": str(observed.get("seed_a", "")).lower(),
        "seed_b": str(observed.get("seed_b", "")).lower(),
        "merkleroot": str(observed.get("merkleroot", "")).lower(),
    }

    mismatches = {}
    for field, value in checks.items():
        if observed_norm[field] != value:
            mismatches[field] = {
                "expected": value,
                "observed": observed_norm[field],
            }

    if mismatches:
        status = "fail"
        overall = "fail"
    else:
        status = "pass"

    results.append({
        "network": network,
        "status": status,
        "mismatches": mismatches,
        "observed": observed_norm,
    })

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "tuples_file": str(tuples_path),
    "overall_status": overall,
    "results": results,
}
artifact_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"artifact: {artifact_path}")
print(f"overall_status: {overall}")

if overall != "pass":
    sys.exit(1)
PY

echo "m5_genesis_freeze_verification: PASS"
