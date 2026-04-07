#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m10_validation_checklist.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m10-checklist-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FAKE_VERIFY="${TMP_DIR}/fake-verify.sh"
cat > "${FAKE_VERIFY}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

artifact=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      artifact="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "${artifact}" ]]; then
  echo "missing --artifact" >&2
  exit 2
fi

mkdir -p "$(dirname "${artifact}")"
if [[ "${FAKE_VERIFY_FAIL:-0}" == "1" ]]; then
  cat > "${artifact}" <<'JSON'
{
  "overall_status": "fail",
  "checks": [
    {"id": "alpha", "status": "pass", "seconds": 1, "description": "alpha check", "log": "/tmp/alpha.log"},
    {"id": "beta", "status": "fail", "seconds": 2, "description": "beta check", "log": "/tmp/beta.log"}
  ]
}
JSON
  exit 9
fi

cat > "${artifact}" <<'JSON'
{
  "overall_status": "pass",
  "checks": [
    {"id": "alpha", "status": "pass", "seconds": 1, "description": "alpha check", "log": "/tmp/alpha.log"},
    {"id": "beta", "status": "pass", "seconds": 2, "description": "beta check", "log": "/tmp/beta.log"}
  ]
}
JSON
EOS
chmod +x "${FAKE_VERIFY}"

FAKE_VERIFY_HANG="${TMP_DIR}/fake-verify-hang.sh"
cat > "${FAKE_VERIFY_HANG}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
sleep 30
EOS
chmod +x "${FAKE_VERIFY_HANG}"

PASS_JSON="${TMP_DIR}/checklist-pass.json"
PASS_MD="${TMP_DIR}/checklist-pass.md"
PASS_VERIFY_ARTIFACT="${TMP_DIR}/verify-pass.json"

"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --verify-script "${FAKE_VERIFY}" \
  --verify-artifact "${PASS_VERIFY_ARTIFACT}" \
  --artifact-json "${PASS_JSON}" \
  --checklist-md "${PASS_MD}"

test -f "${PASS_JSON}"
test -f "${PASS_MD}"
python3 - <<'PY' "${PASS_JSON}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
assert data["verify_exit_code"] == 0, data
assert data["check_count"] == 2, data
PY
rg -q '\[x\] `alpha`' "${PASS_MD}"
rg -q '\[x\] `beta`' "${PASS_MD}"

FAIL_JSON="${TMP_DIR}/checklist-fail.json"
FAIL_MD="${TMP_DIR}/checklist-fail.md"
FAIL_VERIFY_ARTIFACT="${TMP_DIR}/verify-fail.json"

set +e
FAKE_VERIFY_FAIL=1 "${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --verify-script "${FAKE_VERIFY}" \
  --verify-artifact "${FAIL_VERIFY_ARTIFACT}" \
  --artifact-json "${FAIL_JSON}" \
  --checklist-md "${FAIL_MD}"
rc=$?
set -e

if (( rc == 0 )); then
  echo "error: failure scenario unexpectedly succeeded" >&2
  exit 1
fi

test -f "${FAIL_JSON}"
test -f "${FAIL_MD}"
python3 - <<'PY' "${FAIL_JSON}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
assert data["verify_exit_code"] == 9, data
PY
rg -q '\[x\] `alpha`' "${FAIL_MD}"
rg -q '\[ \] `beta`' "${FAIL_MD}"

TIMEOUT_JSON="${TMP_DIR}/checklist-timeout.json"
TIMEOUT_MD="${TMP_DIR}/checklist-timeout.md"
TIMEOUT_VERIFY_ARTIFACT="${TMP_DIR}/verify-timeout.json"

set +e
"${SCRIPT}" \
  --build-dir "${ROOT_DIR}/build-btx" \
  --verify-script "${FAKE_VERIFY_HANG}" \
  --verify-artifact "${TIMEOUT_VERIFY_ARTIFACT}" \
  --verify-timeout-seconds 1 \
  --artifact-json "${TIMEOUT_JSON}" \
  --checklist-md "${TIMEOUT_MD}"
timeout_rc=$?
set -e

if (( timeout_rc == 0 )); then
  echo "error: timeout scenario unexpectedly succeeded" >&2
  exit 1
fi

if (( timeout_rc != 1 )); then
  echo "error: expected timeout scenario to fail with artifact-missing rc=1, got ${timeout_rc}" >&2
  exit 1
fi

if [[ -f "${TIMEOUT_JSON}" || -f "${TIMEOUT_MD}" ]]; then
  echo "error: timeout scenario should not emit checklist artifacts without verify artifact" >&2
  exit 1
fi

echo "m10_validation_checklist_test: PASS"
