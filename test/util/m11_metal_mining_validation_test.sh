#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m11_metal_mining_validation.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-metal-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

BITCOIND_STUB="${TMP_DIR}/btxd-stub.sh"
BITCOIN_CLI_STUB="${TMP_DIR}/btx-cli-stub.sh"
GENESIS_STUB="${TMP_DIR}/btx-genesis-stub.sh"

cat > "${BITCOIND_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
sleep 300
EOS
chmod +x "${BITCOIND_STUB}"

cat > "${BITCOIN_CLI_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

datadir=""
args=()
for arg in "$@"; do
  if [[ "${arg}" == -datadir=* ]]; then
    datadir="${arg#-datadir=}"
  elif [[ "${arg}" == -regtest || "${arg}" == -rpcport=* ]]; then
    continue
  else
    args+=("${arg}")
  fi
done

if [[ -z "${datadir}" ]]; then
  echo "missing datadir" >&2
  exit 2
fi
mkdir -p "${datadir}"
state_file="${datadir}/height"
if [[ ! -f "${state_file}" ]]; then
  echo 0 > "${state_file}"
fi

cmd="${args[0]:-}"
case "${cmd}" in
  getblockcount)
    cat "${state_file}"
    ;;
  generatetodescriptor)
    blocks="${args[1]}"
    current="$(cat "${state_file}")"
    echo $((current + blocks)) > "${state_file}"
    echo "[]"
    ;;
  stop)
    echo "stopped"
    ;;
  *)
    echo "unsupported command: ${cmd}" >&2
    exit 3
    ;;
esac
EOS
chmod +x "${BITCOIN_CLI_STUB}"

cat > "${GENESIS_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${M11_GENESIS_FORCE_FAIL:-0}" == "1" ]]; then
  echo "error: forced failure" >&2
  exit 1
fi

metal_available="1"
if [[ "${M11_GENESIS_NO_METAL:-0}" == "1" ]]; then
  metal_available="0"
fi

if [[ "${metal_available}" == "0" ]]; then
  for arg in "$@"; do
    if [[ "${arg}" == "--metal-require" ]]; then
      echo "error: Metal required but unavailable" >&2
      exit 1
    fi
  done
fi

cat <<OUT
status=found
tries=12
tested_nonces=12
nonce64=42
matmul_digest=00abcd
blockhash=00beef
metal_requested=1
metal_available=${metal_available}
metal_used=${metal_available}
metal_batches=1
metal_candidates_tested=12
OUT
EOS
chmod +x "${GENESIS_STUB}"

ARTIFACT_PASS="${TMP_DIR}/pass.json"
BTX_M11_BITCOIND_BIN="${BITCOIND_STUB}" \
BTX_M11_BITCOIN_CLI_BIN="${BITCOIN_CLI_STUB}" \
BTX_M11_GENESIS_BIN="${GENESIS_STUB}" \
"${SCRIPT}" --rounds 2 --cpu-blocks 2 --artifact "${ARTIFACT_PASS}"

python3 - <<'PY' "${ARTIFACT_PASS}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert len(data["rounds"]) == 2, data
for entry in data["rounds"]:
    assert entry["cpu_blocks_mined"] == 2, entry
    assert entry["genesis_status"] == "found", entry
PY

ARTIFACT_FAIL="${TMP_DIR}/fail.json"
set +e
BTX_M11_BITCOIND_BIN="${BITCOIND_STUB}" \
BTX_M11_BITCOIN_CLI_BIN="${BITCOIN_CLI_STUB}" \
BTX_M11_GENESIS_BIN="${GENESIS_STUB}" \
M11_GENESIS_NO_METAL=1 \
"${SCRIPT}" --rounds 1 --require-metal --artifact "${ARTIFACT_FAIL}"
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected failure when metal is required but unavailable" >&2
  exit 1
fi

python3 - <<'PY' "${ARTIFACT_FAIL}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
PY

echo "m11_metal_mining_validation_test: PASS"
