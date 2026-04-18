#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE_SCRIPT="${ROOT_DIR}/scripts/m8_pow_scaling_suite.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m8-pow-suite-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_BUILD="${TMP_DIR}/build"
mkdir -p "${FAKE_BUILD}/bin"
CALL_LOG="${TMP_DIR}/calls.log"

cat > "${FAKE_BUILD}/bin/test_btx" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

: "${FAKE_TEST_CALL_LOG:?missing FAKE_TEST_CALL_LOG}"
run_test_arg=""
for arg in "$@"; do
  if [[ "${arg}" == --run_test=* ]]; then
    run_test_arg="${arg#--run_test=}"
    break
  fi
done

echo "${run_test_arg}" >> "${FAKE_TEST_CALL_LOG}"

if [[ -n "${FAKE_FAIL_TEST:-}" && "${run_test_arg}" == "pow_tests/${FAKE_FAIL_TEST}" ]]; then
  echo "simulated failure for ${run_test_arg}" >&2
  exit 99
fi

echo "simulated pass for ${run_test_arg}"
exit 0
EOS
chmod +x "${FAKE_BUILD}/bin/test_btx"

PASS_ARTIFACT="${TMP_DIR}/pass.json"
PASS_LOG_DIR="${TMP_DIR}/logs-pass"
: > "${CALL_LOG}"

FAKE_TEST_CALL_LOG="${CALL_LOG}" \
  "${SUITE_SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${PASS_ARTIFACT}" \
  --log-dir "${PASS_LOG_DIR}"

test -f "${PASS_ARTIFACT}"
python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
ids = [entry["id"] for entry in data["scenarios"]]
assert ids == [
    "GetNextWorkRequired_matmul_dgw_steady_state",
    "GetNextWorkRequired_matmul_dgw_long_horizon_scaling",
    "GetNextWorkRequired_matmul_dgw_oscillation_resilience",
    "GetNextWorkRequired_matmul_dgw_timestamp_drift_recovery",
], ids
for entry in data["scenarios"]:
    assert entry["status"] == "pass", entry
PY

test "$(wc -l < "${CALL_LOG}" | tr -d '[:space:]')" -eq 4

FAIL_ARTIFACT="${TMP_DIR}/fail.json"
FAIL_LOG_DIR="${TMP_DIR}/logs-fail"
: > "${CALL_LOG}"
set +e
FAKE_TEST_CALL_LOG="${CALL_LOG}" FAKE_FAIL_TEST="GetNextWorkRequired_matmul_dgw_oscillation_resilience" \
  "${SUITE_SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${FAIL_ARTIFACT}" \
  --log-dir "${FAIL_LOG_DIR}"
rc=$?
set -e

if (( rc == 0 )); then
  echo "error: failure scenario unexpectedly succeeded" >&2
  exit 1
fi

test -f "${FAIL_ARTIFACT}"
python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
statuses = {entry["id"]: entry["status"] for entry in data["scenarios"]}
assert statuses["GetNextWorkRequired_matmul_dgw_oscillation_resilience"] == "fail", statuses
assert statuses["GetNextWorkRequired_matmul_dgw_steady_state"] == "pass", statuses
assert statuses["GetNextWorkRequired_matmul_dgw_long_horizon_scaling"] == "pass", statuses
assert statuses["GetNextWorkRequired_matmul_dgw_timestamp_drift_recovery"] == "pass", statuses
PY

test "$(wc -l < "${CALL_LOG}" | tr -d '[:space:]')" -eq 4

echo "m8_pow_scaling_suite_test: PASS"
