#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m7_external_kawpowminer_validation.sh [options]

Validate external kawpowminer integration readiness across:
1) Regtest end-to-end BTX miner/pool submission path.
2) Testnet template-only mining job compatibility checks.

Options:
  --build-dir <path>         BTX build directory (default: build-btx)
  --kawpowminer-dir <path>   External kawpowminer repo path
                             (default: ../upstream/kawpowminer)
  --regtest-artifact <path>  Output artifact path for regtest validation
  --testnet-artifact <path>  Output artifact path for testnet validation
  --skip-testnet             Skip testnet template-only validation
  -h, --help                 Show this message

Environment overrides:
  BTX_M7_E2E_SCRIPT          Path to m7_miner_pool_e2e.py-compatible runner
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-btx"
KAWPOWMINER_DIR="${ROOT_DIR}/../upstream/kawpowminer"
REGTEST_ARTIFACT="${ROOT_DIR}/.btx-validation/m7-regtest-readiness.json"
TESTNET_ARTIFACT="${ROOT_DIR}/.btx-validation/m7-testnet-template.json"
SKIP_TESTNET=0
E2E_SCRIPT="${BTX_M7_E2E_SCRIPT:-${ROOT_DIR}/scripts/m7_miner_pool_e2e.py}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --kawpowminer-dir)
      KAWPOWMINER_DIR="$2"
      shift 2
      ;;
    --regtest-artifact)
      REGTEST_ARTIFACT="$2"
      shift 2
      ;;
    --testnet-artifact)
      TESTNET_ARTIFACT="$2"
      shift 2
      ;;
    --skip-testnet)
      SKIP_TESTNET=1
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
  echo "error: missing BTX binaries in ${BUILD_DIR}/bin" >&2
  exit 1
fi

if [[ ! -f "${E2E_SCRIPT}" ]]; then
  echo "error: missing M7 e2e runner script: ${E2E_SCRIPT}" >&2
  exit 1
fi

if [[ ! -d "${KAWPOWMINER_DIR}" ]]; then
  echo "error: missing external kawpowminer repo: ${KAWPOWMINER_DIR}" >&2
  exit 1
fi

for required in CMakeLists.txt kawpowminer libpoolprotocols libprogpow; do
  if [[ ! -e "${KAWPOWMINER_DIR}/${required}" ]]; then
    echo "error: kawpowminer repo missing required path: ${KAWPOWMINER_DIR}/${required}" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "${REGTEST_ARTIFACT}")" "$(dirname "${TESTNET_ARTIFACT}")"

python3 "${E2E_SCRIPT}" "${BUILD_DIR}" --chain regtest --artifact "${REGTEST_ARTIFACT}"
if [[ "${SKIP_TESTNET}" -eq 0 ]]; then
  python3 "${E2E_SCRIPT}" "${BUILD_DIR}" --chain testnet --template-only --artifact "${TESTNET_ARTIFACT}"
fi

python3 - <<'PY' "${REGTEST_ARTIFACT}" "${TESTNET_ARTIFACT}" "${SKIP_TESTNET}"
import json
import pathlib
import sys

regtest_path = pathlib.Path(sys.argv[1])
testnet_path = pathlib.Path(sys.argv[2])
skip_testnet = sys.argv[3] == "1"

reg = json.loads(regtest_path.read_text(encoding="utf-8"))
if reg.get("chain") != "regtest":
    raise SystemExit(f"unexpected regtest chain value: {reg.get('chain')}")
if reg.get("template_only"):
    raise SystemExit("regtest artifact unexpectedly in template_only mode")
if reg.get("submission") is None:
    raise SystemExit("regtest artifact missing submission payload")
if reg.get("stratum_job", {}).get("noncerange") != "0000000000000000ffffffffffffffff":
    raise SystemExit("regtest artifact missing expected noncerange")

if not skip_testnet:
    testnet = json.loads(testnet_path.read_text(encoding="utf-8"))
    if testnet.get("chain") != "testnet":
        raise SystemExit(f"unexpected testnet chain value: {testnet.get('chain')}")
    if not testnet.get("template_only"):
        raise SystemExit("testnet artifact must be template_only")
    if testnet.get("submission") is not None:
        raise SystemExit("testnet artifact unexpectedly contains submission payload")
    if testnet.get("stratum_job", {}).get("noncerange") != "0000000000000000ffffffffffffffff":
        raise SystemExit("testnet artifact missing expected noncerange")

print("m7_external_kawpowminer_validation: artifact checks passed")
PY

echo "M7 external kawpowminer validation passed:"
echo "- External repo structure present at ${KAWPOWMINER_DIR}"
echo "- Regtest submission artifact: ${REGTEST_ARTIFACT}"
if [[ "${SKIP_TESTNET}" -eq 0 ]]; then
  echo "- Testnet template artifact: ${TESTNET_ARTIFACT}"
else
  echo "- Testnet template validation skipped"
fi
