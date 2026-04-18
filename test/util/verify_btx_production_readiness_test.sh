#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/verify_btx_production_readiness.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-prod-readiness-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

ARTIFACT="${TMP_DIR}/report.json"
LOG_DIR="${TMP_DIR}/logs"

"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --artifact "${ARTIFACT}" \
  --log-dir "${LOG_DIR}" \
  --skip-m7-external-kawpow \
  --skip-launch-blockers \
  --skip-parallel-gate

test -f "${ARTIFACT}"
python3 - <<'PY' "${ARTIFACT}"
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
ids = {entry["id"] for entry in data["checks"]}
required = {
    "binaries",
    "lint",
    "m7_readiness",
    "m7_pool_e2e",
    "m5_genesis_freeze",
    "benchmark_suite",
    "pow_scaling_suite",
    "m7_timeout_guard",
    "m7_parallel_isolation",
    "parallel_timeout_guard",
    "production_loop_guard",
    "live_dual_node_p2p",
    "live_strict_mining",
}
missing = required - ids
assert not missing, missing
for entry in data["checks"]:
    assert entry["status"] == "pass", entry
PY

echo "verify_btx_production_readiness_test: PASS"
