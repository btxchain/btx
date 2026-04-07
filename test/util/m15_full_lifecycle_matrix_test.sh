#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m15_full_lifecycle_matrix.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m15-matrix-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PASS_ARTIFACT="${TMP_DIR}/pass.json"
PASS_LOG_DIR="${TMP_DIR}/pass-logs"

BTX_M15_OVERRIDE_MAC_HOST_LIFECYCLE='echo mac-pass' \
BTX_M15_OVERRIDE_CENTOS_CONTAINER_LIFECYCLE='echo centos-pass' \
BTX_M15_OVERRIDE_MAC_CENTOS_BRIDGE_LIFECYCLE='echo bridge-pass' \
"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --centos-build-dir "${ROOT_DIR}/build-btx-centos" \
  --artifact "${PASS_ARTIFACT}" \
  --log-dir "${PASS_LOG_DIR}" \
  --timeout-seconds 30

python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
checks = {item["id"]: item for item in data["checks"]}
required = {
    "mac_host_lifecycle",
    "centos_container_lifecycle",
    "mac_centos_bridge_lifecycle",
}
assert required == set(checks), checks
assert all(item["status"] == "pass" for item in checks.values()), checks
assert data["skipped_phases"] == [], data
phase_coverage = data["phase_coverage"]
assert set(phase_coverage) == required, phase_coverage
assert all(phase_coverage[name] == "pass" for name in required), phase_coverage
PY

FAIL_ARTIFACT="${TMP_DIR}/fail.json"
FAIL_LOG_DIR="${TMP_DIR}/fail-logs"
set +e
BTX_M15_OVERRIDE_MAC_HOST_LIFECYCLE='echo mac-pass' \
BTX_M15_OVERRIDE_CENTOS_CONTAINER_LIFECYCLE='echo centos-pass' \
BTX_M15_OVERRIDE_MAC_CENTOS_BRIDGE_LIFECYCLE='echo forced fail >&2; exit 9' \
"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --centos-build-dir "${ROOT_DIR}/build-btx-centos" \
  --artifact "${FAIL_ARTIFACT}" \
  --log-dir "${FAIL_LOG_DIR}" \
  --timeout-seconds 30
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected fail scenario to fail" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
checks = {item["id"]: item["status"] for item in data["checks"]}
assert checks["mac_host_lifecycle"] == "pass", checks
assert checks["centos_container_lifecycle"] == "pass", checks
assert checks["mac_centos_bridge_lifecycle"] == "fail", checks
assert data["skipped_phases"] == [], data
phase_coverage = data["phase_coverage"]
assert phase_coverage["mac_host_lifecycle"] == "pass", phase_coverage
assert phase_coverage["centos_container_lifecycle"] == "pass", phase_coverage
assert phase_coverage["mac_centos_bridge_lifecycle"] == "fail", phase_coverage
PY

echo "m15_full_lifecycle_matrix_test: PASS"
