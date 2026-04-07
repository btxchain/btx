#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m7_external_kawpowminer_validation.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m7-external-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_BUILD="${TMP_DIR}/build"
mkdir -p "${FAKE_BUILD}/bin"
for bin in btxd btx-cli; do
  cat > "${FAKE_BUILD}/bin/${bin}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOS
  chmod +x "${FAKE_BUILD}/bin/${bin}"
done

FAKE_KAWPOW="${TMP_DIR}/kawpowminer"
mkdir -p "${FAKE_KAWPOW}/kawpowminer" "${FAKE_KAWPOW}/libpoolprotocols" "${FAKE_KAWPOW}/libprogpow"
cat > "${FAKE_KAWPOW}/CMakeLists.txt" <<'EOS'
cmake_minimum_required(VERSION 3.16)
EOS

FAKE_E2E="${TMP_DIR}/fake-m7-e2e.py"
cat > "${FAKE_E2E}" <<'EOS'
#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("build_dir")
parser.add_argument("--artifact", required=True)
parser.add_argument("--chain", choices=["regtest", "testnet"], default="regtest")
parser.add_argument("--template-only", action="store_true")
args = parser.parse_args()

payload = {
    "chain": args.chain,
    "template_only": args.template_only,
    "stratum_job": {
        "noncerange": "0000000000000000ffffffffffffffff"
    },
    "submission": None if args.template_only else {"block_hash": "00abc"},
}

artifact = Path(args.artifact)
artifact.parent.mkdir(parents=True, exist_ok=True)
artifact.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
EOS
chmod +x "${FAKE_E2E}"

REGTEST_ART="${TMP_DIR}/regtest.json"
TESTNET_ART="${TMP_DIR}/testnet.json"
BTX_M7_E2E_SCRIPT="${FAKE_E2E}" "${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --kawpowminer-dir "${FAKE_KAWPOW}" \
  --regtest-artifact "${REGTEST_ART}" \
  --testnet-artifact "${TESTNET_ART}"

python3 - <<'PY' "${REGTEST_ART}" "${TESTNET_ART}"
import json
import sys
reg = json.load(open(sys.argv[1], encoding="utf-8"))
test = json.load(open(sys.argv[2], encoding="utf-8"))
assert reg["chain"] == "regtest", reg
assert reg["submission"] is not None, reg
assert reg["template_only"] is False, reg
assert test["chain"] == "testnet", test
assert test["submission"] is None, test
assert test["template_only"] is True, test
PY

set +e
BTX_M7_E2E_SCRIPT="${FAKE_E2E}" "${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --kawpowminer-dir "${TMP_DIR}/missing-kawpow" \
  --regtest-artifact "${REGTEST_ART}" \
  --testnet-artifact "${TESTNET_ART}" >"${TMP_DIR}/missing.log" 2>&1
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected failure for missing external kawpowminer repo" >&2
  exit 1
fi

rg -q 'missing external kawpowminer repo' "${TMP_DIR}/missing.log"

echo "m7_external_kawpowminer_validation_test: PASS"
