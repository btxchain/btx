#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/apply_chain_hardening_manifest.py"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-apply-chain-hardening-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

CHAINPARAMS_COPY="${TMP_DIR}/chainparams.cpp"
cp "${ROOT_DIR}/src/kernel/chainparams.cpp" "${CHAINPARAMS_COPY}"

MAINNET_GENESIS="$(
  python3 - <<'PY' "${CHAINPARAMS_COPY}"
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
main_block = re.search(r"class CMainParams : public CChainParams \{.*?\n\};\n", text, re.S)
if not main_block:
    raise SystemExit("missing CMainParams block")
match = re.search(
    r'assert\(consensus\.hashGenesisBlock == uint256\{"([0-9a-f]{64})"\}\);',
    main_block.group(0),
)
if not match:
    raise SystemExit("missing mainnet genesis assertion")
print(match.group(1))
PY
)"

MANIFEST_OK="${TMP_DIR}/mainnet-manifest.json"
cat > "${MANIFEST_OK}" <<JSON
{
  "chain": "main",
  "tip_height": 50042,
  "anchor_height": 50040,
  "genesis_hash": "${MAINNET_GENESIS}",
  "anchor_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "nMinimumChainWork": "0000000000000000000000000000000000000000000000000000000000abc123",
  "chainTxData": {
    "nTime": 1739999999,
    "tx_count": 7654321,
    "dTxRate": 7.25
  }
}
JSON

python3 "${SCRIPT}" \
  --manifest "${MANIFEST_OK}" \
  --chainparams "${CHAINPARAMS_COPY}" \
  --chain main

python3 - <<'PY' "${CHAINPARAMS_COPY}"
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
main_block = re.search(r"class CMainParams : public CChainParams \{.*?\n\};\n", text, re.S)
assert main_block, "missing main block"
block = main_block.group(0)

assert (
    'consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000000000abc123"};'
    in block
)
assert (
    'consensus.defaultAssumeValid = uint256{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};'
    in block
)
assert '{50040, uint256{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}' in block
assert ".nTime = 1739999999," in block
assert ".tx_count = 7654321," in block
assert ".dTxRate = 7.25," in block
PY

python3 "${SCRIPT}" \
  --manifest "${MANIFEST_OK}" \
  --chainparams "${CHAINPARAMS_COPY}" \
  --chain main \
  --check

MANIFEST_GENESIS_ANCHOR="${TMP_DIR}/mainnet-manifest-genesis-anchor.json"
cat > "${MANIFEST_GENESIS_ANCHOR}" <<JSON
{
  "chain": "main",
  "tip_height": 0,
  "anchor_height": 0,
  "genesis_hash": "${MAINNET_GENESIS}",
  "anchor_hash": "${MAINNET_GENESIS}",
  "nMinimumChainWork": "000000000000000000000000000000000000000000000000000000000000000c",
  "chainTxData": {
    "nTime": 1771726946,
    "tx_count": 1,
    "dTxRate": 0.0
  }
}
JSON

python3 "${SCRIPT}" \
  --manifest "${MANIFEST_GENESIS_ANCHOR}" \
  --chainparams "${CHAINPARAMS_COPY}" \
  --chain main

python3 - <<'PY' "${CHAINPARAMS_COPY}"
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
main_block = re.search(r"class CMainParams : public CChainParams \{.*?\n\};\n", text, re.S)
assert main_block, "missing main block"
block = main_block.group(0)

genesis_match = re.search(
    r'assert\(consensus\.hashGenesisBlock == uint256\{"([0-9a-f]{64})"\}\);',
    block,
)
assert genesis_match, "missing mainnet genesis assertion"
genesis_checkpoint = '{0, uint256{"' + genesis_match.group(1) + '"}}'
assert block.count(genesis_checkpoint) == 1, "genesis checkpoint should not be duplicated"
PY

MANIFEST_BAD="${TMP_DIR}/mainnet-manifest-bad-genesis.json"
cp "${MANIFEST_OK}" "${MANIFEST_BAD}"
python3 - <<'PY' "${MANIFEST_BAD}"
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["genesis_hash"] = "0" * 64
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

set +e
python3 "${SCRIPT}" \
  --manifest "${MANIFEST_BAD}" \
  --chainparams "${CHAINPARAMS_COPY}" \
  --chain main >/dev/null 2>"${TMP_DIR}/bad.err"
rc=$?
set -e
if (( rc == 0 )); then
  echo "error: expected genesis mismatch to fail" >&2
  exit 1
fi
rg -q "does not match chainparams genesis" "${TMP_DIR}/bad.err"

echo "apply_chain_hardening_manifest_test: PASS"
