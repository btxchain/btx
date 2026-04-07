#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/generate_validation_checklist.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-checklist-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

SUCCESS_STUB="${TMP_DIR}/success_stub.sh"
FAIL_STUB="${TMP_DIR}/fail_stub.sh"
HANG_STUB="${TMP_DIR}/hang_stub.sh"
TRANSCRIPT="${TMP_DIR}/transcript.log"

cat > "${SUCCESS_STUB}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sleep 0.01
echo "success:$0:$*" >> "${TRANSCRIPT}"
EOF
chmod +x "${SUCCESS_STUB}"

cat > "${FAIL_STUB}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "fail:$0:$*" >> "${TRANSCRIPT}"
exit 1
EOF
chmod +x "${FAIL_STUB}"

cat > "${HANG_STUB}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sleep 30
EOF
chmod +x "${HANG_STUB}"

FAKE_BUILD="${TMP_DIR}/fake-build"
mkdir -p "${FAKE_BUILD}"

ARTIFACT_PASS="${TMP_DIR}/report-pass.json"
LOG_DIR_PASS="${TMP_DIR}/logs-pass"
BTX_CHECKLIST_OVERRIDE_CONSENSUS="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_PARALLEL="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_BENCHMARK="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_PRODUCTION="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_SCALING="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_MINING="${SUCCESS_STUB}" \
TRANSCRIPT="${TRANSCRIPT}" \
"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${ARTIFACT_PASS}" \
  --log-dir "${LOG_DIR_PASS}"

python3 - <<'PY' "${ARTIFACT_PASS}"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
assert data["overall_status"] == "pass", data
ids = [entry["id"] for entry in data["checks"]]
expected = ["consensus", "parallel", "benchmark", "production", "scaling", "mining"]
assert ids == expected, ids
for entry in data["checks"]:
    assert entry["status"] == "pass", entry
    assert Path(entry["log"]).exists(), entry
PY

ARTIFACT_FAIL="${TMP_DIR}/report-fail.json"
LOG_DIR_FAIL="${TMP_DIR}/logs-fail"
set +e
BTX_CHECKLIST_OVERRIDE_CONSENSUS="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_PARALLEL="${FAIL_STUB}" \
BTX_CHECKLIST_OVERRIDE_BENCHMARK="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_PRODUCTION="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_SCALING="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_MINING="${SUCCESS_STUB}" \
TRANSCRIPT="${TRANSCRIPT}" \
"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${ARTIFACT_FAIL}" \
  --log-dir "${LOG_DIR_FAIL}"
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "error: checklist script should fail when a check fails" >&2
  exit 1
fi

python3 - <<'PY' "${ARTIFACT_FAIL}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
statuses = {entry["id"]: entry["status"] for entry in data["checks"]}
assert statuses["parallel"] == "fail", statuses
for check in ("consensus", "benchmark", "production", "scaling", "mining"):
    assert statuses[check] == "pass", statuses
PY

ARTIFACT_TIMEOUT="${TMP_DIR}/report-timeout.json"
LOG_DIR_TIMEOUT="${TMP_DIR}/logs-timeout"
set +e
BTX_CHECKLIST_OVERRIDE_CONSENSUS="${HANG_STUB}" \
BTX_CHECKLIST_OVERRIDE_PARALLEL="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_BENCHMARK="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_PRODUCTION="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_SCALING="${SUCCESS_STUB}" \
BTX_CHECKLIST_OVERRIDE_MINING="${SUCCESS_STUB}" \
TRANSCRIPT="${TRANSCRIPT}" \
"${SCRIPT}" \
  --build-dir "${FAKE_BUILD}" \
  --artifact "${ARTIFACT_TIMEOUT}" \
  --log-dir "${LOG_DIR_TIMEOUT}" \
  --check-timeout-seconds 1
timeout_status=$?
set -e

if [[ "${timeout_status}" -eq 0 ]]; then
  echo "error: checklist script should fail when a check times out" >&2
  exit 1
fi

python3 - <<'PY' "${ARTIFACT_TIMEOUT}"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
statuses = {entry["id"]: entry["status"] for entry in data["checks"]}
assert statuses["consensus"] == "fail", statuses
for check in ("parallel", "benchmark", "production", "scaling", "mining"):
    assert statuses[check] == "pass", statuses
PY

rg -q 'timeout after 1s' "${LOG_DIR_TIMEOUT}/consensus.log"

echo "generate_validation_checklist_test: PASS"
