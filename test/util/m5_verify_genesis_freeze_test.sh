#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m5_verify_genesis_freeze.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m5-freeze-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

BITCOIND_STUB="${TMP_DIR}/btxd-stub.sh"
BITCOIN_CLI_STUB="${TMP_DIR}/btx-cli-stub.sh"

cat > "${BITCOIND_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
sleep 300
EOS
chmod +x "${BITCOIND_STUB}"

cat > "${BITCOIN_CLI_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

network="main"
args=()
for arg in "$@"; do
  case "${arg}" in
    -testnet)
      network="testnet"
      ;;
    -regtest)
      network="regtest"
      ;;
    -datadir=*|-rpcport=*)
      ;;
    *)
      args+=("${arg}")
      ;;
  esac
done

cmd="${args[0]:-}"
case "${cmd}" in
  getblockcount)
    echo "0"
    ;;
  getblockhash)
    case "${network}" in
      main)
        echo "6db39cd6aa03d259232d301776550df7caa9a25da237b52c6ea74f2f5a0fbf1c"
        ;;
      testnet)
        echo "f1dde19eaa71533c46fd5892799e7e034500bf305a63f5cb60ee613d51cf0289"
        ;;
      regtest)
        echo "bbc501af18e6b3a69a43c6f134d4b9710bd96dff17ee07fa648c297438495247"
        ;;
    esac
    ;;
  getblockheader)
    header_mode="${args[2]:-true}"
    case "${network}" in
      main)
        nonce="0"
        nonce64="9"
        bits="20147ae1"
        time="1772582400"
        matmul_dim="512"
        matmul_digest="14551a9264a117521ebfaa2b4e17853b5dc1c2bdd4b2bfbe93ba71b16ec31023"
        seed_a="a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"
        seed_b="f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"
        blockhash="6db39cd6aa03d259232d301776550df7caa9a25da237b52c6ea74f2f5a0fbf1c"
        ;;
      testnet)
        nonce="0"
        nonce64="238"
        bits="20027525"
        time="1772582400"
        matmul_dim="256"
        matmul_digest="010bc73b4dab4871b55ad56e6e16b44aa69f64b2dae7725d19e85c81977232d2"
        seed_a="a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"
        seed_b="f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"
        blockhash="f1dde19eaa71533c46fd5892799e7e034500bf305a63f5cb60ee613d51cf0289"
        ;;
      regtest)
        nonce="2"
        nonce64="2"
        bits="207fffff"
        time="1296688602"
        matmul_dim="64"
        matmul_digest="6e7004077d6bb961cfe2d82977d0cad1f7e3843cc6c9ceb981fd3c059c78d27c"
        seed_a="a8a82ec830e8346550cad66c4cf43985dddd6a056d4bed2a5dcace445fa924ab"
        seed_b="f9aaa742cdbfb26be3d22d743b548740ff0a9e00f9cc977c1fb03df85fdf978d"
        blockhash="bbc501af18e6b3a69a43c6f134d4b9710bd96dff17ee07fa648c297438495247"
        ;;
    esac

    if [[ "${M5_STUB_BAD_NONCE:-0}" == "1" && "${network}" == "main" ]]; then
      nonce="7"
      nonce64="7"
    fi

    if [[ "${header_mode}" == "false" ]]; then
      python3 - <<'PY' "${time}" "${bits}" "${nonce64}" "${matmul_dim}" "${matmul_digest}" "${seed_a}" "${seed_b}"
import sys

time_v = int(sys.argv[1])
bits_v = int(sys.argv[2], 16)
nonce64_v = int(sys.argv[3])
dim_v = int(sys.argv[4])
matmul_digest = bytes.fromhex(sys.argv[5])
seed_a = bytes.fromhex(sys.argv[6])
seed_b = bytes.fromhex(sys.argv[7])
merkle = bytes.fromhex("4b33106f07de6b56e6358304f44fae90f8698d81137497433a381848c9807951")
header = (
    (1).to_bytes(4, "little")
    + bytes(32)  # prev block hash (null)
    + merkle[::-1]
    + time_v.to_bytes(4, "little")
    + bits_v.to_bytes(4, "little")
    + nonce64_v.to_bytes(8, "little")
    + matmul_digest[::-1]
    + dim_v.to_bytes(2, "little")
    + seed_a[::-1]
    + seed_b[::-1]
)
print(header.hex())
PY
      exit 0
    fi

    cat <<JSON
{"hash":"${blockhash}","time":${time},"bits":"${bits}","nonce":${nonce},"merkleroot":"4b33106f07de6b56e6358304f44fae90f8698d81137497433a381848c9807951"}
JSON
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

ARTIFACT_PASS="${TMP_DIR}/pass.json"
BTX_M5_VERIFY_BITCOIND_BIN="${BITCOIND_STUB}" \
BTX_M5_VERIFY_BITCOIN_CLI_BIN="${BITCOIN_CLI_STUB}" \
"${SCRIPT}" --artifact "${ARTIFACT_PASS}"

python3 - <<'PY' "${ARTIFACT_PASS}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert len(data["results"]) == 3, data
PY

ARTIFACT_FAIL="${TMP_DIR}/fail.json"
set +e
M5_STUB_BAD_NONCE=1 \
BTX_M5_VERIFY_BITCOIND_BIN="${BITCOIND_STUB}" \
BTX_M5_VERIFY_BITCOIN_CLI_BIN="${BITCOIN_CLI_STUB}" \
"${SCRIPT}" --artifact "${ARTIFACT_FAIL}"
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected mismatch scenario to fail" >&2
  exit 1
fi

python3 - <<'PY' "${ARTIFACT_FAIL}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
main = [entry for entry in data["results"] if entry["network"] == "main"][0]
assert "nonce" in main["mismatches"], main
PY

echo "m5_verify_genesis_freeze_test: PASS"
