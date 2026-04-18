#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m15_single_node_wallet_lifecycle.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m15-single-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

ARTIFACT="${TMP_DIR}/single-node.json"
"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --artifact "${ARTIFACT}" \
  --node-label "test-host" \
  --timeout-seconds 240

python3 - <<'PY' "${ARTIFACT}"
import json
import re
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert data["node_label"] == "test-host", data
assert data["node"]["height"] >= 103, data["node"]
assert data["skipped_steps"] == [], data
phase_coverage = data["phase_coverage"]
required_phases = {
    "startup",
    "wallet_creation",
    "mining_rewards",
    "funding_transfer",
    "funding_block_verification",
    "locked_send_rejection",
    "unlock_send_success",
    "relocked_send_rejection",
    "payment_block_verification",
}
assert set(phase_coverage) == required_phases, phase_coverage
assert all(phase_coverage[name] == "pass" for name in required_phases), phase_coverage

miner_to_alice = data["transactions"]["miner_to_alice"]
alice_to_bob = data["transactions"]["alice_to_bob"]

assert re.fullmatch(r"[0-9a-f]{64}", miner_to_alice["txid"]), miner_to_alice
assert re.fullmatch(r"[0-9a-f]{64}", alice_to_bob["txid"]), alice_to_bob
assert miner_to_alice["confirmations"] >= 1, miner_to_alice
assert alice_to_bob["confirmations"] >= 1, alice_to_bob

locking = data["locking_checks"]
assert locking["locked_send_rc"] != 0, locking
assert locking["relocked_send_rc"] != 0, locking
PY

echo "m15_single_node_wallet_lifecycle_test: PASS"
