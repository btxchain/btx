#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/update_chain_hardening_manifest.py"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-chain-hardening-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_CLI_OK="${TMP_DIR}/fake-btx-cli-ok.sh"
cat > "${FAKE_CLI_OK}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

command_name=""
command_args=()
for arg in "$@"; do
  case "${arg}" in
    -chain=*|-rpc*|-datadir=*|-conf=*|-debug=*|-stdinrpcpass)
      continue
      ;;
    *)
      if [[ -z "${command_name}" ]]; then
        command_name="${arg}"
      else
        command_args+=("${arg}")
      fi
      ;;
  esac
done

case "${command_name}" in
  getblockcount)
    echo "50042"
    ;;
  getbestblockhash)
    echo "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ;;
  getblockhash)
    case "${command_args[0]:-}" in
      0)
        echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ;;
      50040)
        echo "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ;;
      *)
        echo "unexpected getblockhash height: ${command_args[*]-}" >&2
        exit 2
        ;;
    esac
    ;;
  getblockheader)
    cat <<'JSON'
{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","height":50040,"chainwork":"0000000000000000000000000000000000000000000000000000000000abc123"}
JSON
    ;;
  getchaintxstats)
    cat <<'JSON'
{"time":1739999999,"txcount":7654321,"txrate":7.25}
JSON
    ;;
  *)
    echo "unexpected command: ${command_name}" >&2
    exit 2
    ;;
esac
EOS
chmod +x "${FAKE_CLI_OK}"

OUT_JSON_OK="${TMP_DIR}/manifest-ok.json"
python3 "${SCRIPT}" \
  --btx-cli "${FAKE_CLI_OK}" \
  --chain main \
  --output "${OUT_JSON_OK}" \
  --window-blocks 4096

python3 - <<'PY' "${OUT_JSON_OK}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["chain"] == "main"
assert data["tip_height"] == 50042
assert data["anchor_height"] == 50040
assert data["genesis_hash"] == "a" * 64
assert data["anchor_hash"] == "b" * 64
assert data["bestblockhash"] == "c" * 64
assert data["nMinimumChainWork"] == "0000000000000000000000000000000000000000000000000000000000abc123"
assert data["defaultAssumeValid"] == "b" * 64
assert data["chainTxData"]["nTime"] == 1739999999
assert data["chainTxData"]["tx_count"] == 7654321
assert abs(data["chainTxData"]["dTxRate"] - 7.25) < 1e-12
assert "{50040, uint256{\"" + "b" * 64 + "\"}}" in data["cpp_snippet"]
assert "consensus.nMinimumChainWork = uint256{\"0000000000000000000000000000000000000000000000000000000000abc123\"};" in data["cpp_snippet"]
PY

FAKE_CLI_LOW="${TMP_DIR}/fake-btx-cli-low.sh"
cat > "${FAKE_CLI_LOW}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${*: -1}" == "getblockcount" ]]; then
  echo "1000"
  exit 0
fi
if [[ "$*" == *"getblockcount"* ]]; then
  echo "1000"
  exit 0
fi
echo "not expected in low-height path: $*" >&2
exit 2
EOS
chmod +x "${FAKE_CLI_LOW}"

set +e
python3 "${SCRIPT}" \
  --btx-cli "${FAKE_CLI_LOW}" \
  --chain main \
  --window-blocks 4096 >/dev/null 2>"${TMP_DIR}/low.err"
rc=$?
set -e
if (( rc == 0 )); then
  echo "error: expected low-height mainnet guard to fail" >&2
  exit 1
fi
if ! rg -q "below required minimum" "${TMP_DIR}/low.err"; then
  echo "error: expected minimum-height failure message" >&2
  cat "${TMP_DIR}/low.err" >&2
  exit 1
fi

FAKE_CLI_SMALL="${TMP_DIR}/fake-btx-cli-small.sh"
cat > "${FAKE_CLI_SMALL}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

command_name=""
command_args=()
for arg in "$@"; do
  case "${arg}" in
    -chain=*|-rpc*|-datadir=*|-conf=*|-debug=*|-stdinrpcpass)
      continue
      ;;
    *)
      if [[ -z "${command_name}" ]]; then
        command_name="${arg}"
      else
        command_args+=("${arg}")
      fi
      ;;
  esac
done

case "${command_name}" in
  getblockcount)
    echo "1"
    ;;
  getbestblockhash)
    echo "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ;;
  getblockhash)
    case "${command_args[0]:-}" in
      0)
        echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ;;
      1)
        echo "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ;;
      *)
        echo "unexpected getblockhash height: ${command_args[*]-}" >&2
        exit 2
        ;;
    esac
    ;;
  getblockheader)
    cat <<'JSON'
{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","height":0,"chainwork":"1"}
JSON
    ;;
  getchaintxstats)
    if [[ "${command_args[0]:-}" != "0" ]]; then
      echo "expected nBlocks=0 for low-height chain, got: ${command_args[*]-}" >&2
      exit 2
    fi
    cat <<'JSON'
{"time":1771726946,"txcount":1,"txrate":0}
JSON
    ;;
  *)
    echo "unexpected command: ${command_name}" >&2
    exit 2
    ;;
esac
EOS
chmod +x "${FAKE_CLI_SMALL}"

OUT_JSON_SMALL="${TMP_DIR}/manifest-small.json"
python3 "${SCRIPT}" \
  --btx-cli "${FAKE_CLI_SMALL}" \
  --chain main \
  --allow-low-anchor-height \
  --output "${OUT_JSON_SMALL}"

python3 - <<'PY' "${OUT_JSON_SMALL}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["tip_height"] == 1
assert data["anchor_height"] == 0
assert data["chainTxData"]["tx_count"] == 1
assert data["nMinimumChainWork"] == "0" * 63 + "1"
PY

# Legacy alias compatibility: --bitcoin-cli should still work.
python3 "${SCRIPT}" \
  --bitcoin-cli "${FAKE_CLI_SMALL}" \
  --chain main \
  --allow-low-anchor-height >/dev/null

echo "update_chain_hardening_manifest_test: PASS"
