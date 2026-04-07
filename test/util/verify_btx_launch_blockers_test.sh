#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/verify_btx_launch_blockers.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-launch-blockers-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PASS_ARTIFACT="${TMP_DIR}/pass.json"
BTX_LAUNCH_OVERRIDE_BLOCK_HASH_SEMANTICS='echo block-hash-semantics-pass' \
BTX_LAUNCH_OVERRIDE_GENESIS_FREEZE='echo genesis-freeze-pass' \
BTX_LAUNCH_OVERRIDE_MINER_POOL_PATH='echo miner-pool-path-pass' \
BTX_LAUNCH_OVERRIDE_CLOSURE_CHECKS='echo closure-checks-pass' \
"${SCRIPT}" --artifact "${PASS_ARTIFACT}" --check-timeout-seconds 10

python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert len(data["checks"]) == 4, data
assert all(item["status"] == "pass" for item in data["checks"]), data
PY

FAIL_ARTIFACT="${TMP_DIR}/fail.json"
set +e
BTX_LAUNCH_OVERRIDE_BLOCK_HASH_SEMANTICS='echo block-hash-semantics-pass' \
BTX_LAUNCH_OVERRIDE_GENESIS_FREEZE='echo genesis-freeze-pass' \
BTX_LAUNCH_OVERRIDE_MINER_POOL_PATH='echo forced failure >&2; exit 9' \
BTX_LAUNCH_OVERRIDE_CLOSURE_CHECKS='echo closure-checks-pass' \
"${SCRIPT}" --artifact "${FAIL_ARTIFACT}" --check-timeout-seconds 10
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected failure scenario to fail" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
statuses = {item["id"]: item["status"] for item in data["checks"]}
assert statuses["miner_pool_path"] == "fail", statuses
assert statuses["block_hash_semantics"] == "pass", statuses
assert statuses["closure_checks"] == "pass", statuses
PY

echo "verify_btx_launch_blockers_test: PASS"
