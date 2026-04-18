#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m11_codex_feedback_loop.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-feedback-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

VALIDATE_PASS="${TMP_DIR}/validate-pass.sh"
VALIDATE_FLAKY="${TMP_DIR}/validate-flaky.sh"
CODEX_STUB="${TMP_DIR}/codex-stub.sh"
STATE_FILE="${TMP_DIR}/state"
TRANSCRIPT="${TMP_DIR}/transcript.log"

cat > "${VALIDATE_PASS}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "validation pass"
EOS
chmod +x "${VALIDATE_PASS}"

cat > "${VALIDATE_FLAKY}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
state_file="$1"
count=0
if [[ -f "${state_file}" ]]; then
  count="$(cat "${state_file}")"
fi
count=$((count + 1))
echo "${count}" > "${state_file}"
if [[ "${count}" -eq 1 ]]; then
  echo "validation fail cycle" >&2
  exit 2
fi
echo "validation pass cycle"
EOS
chmod +x "${VALIDATE_FLAKY}"

cat > "${CODEX_STUB}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "codex-invoked" >> "$1"
EOS
chmod +x "${CODEX_STUB}"

PASS_DIR="${TMP_DIR}/pass"
"${SCRIPT}" \
  --repo "${ROOT_DIR}" \
  --cycles 2 \
  --delay-seconds 0 \
  --artifact-dir "${PASS_DIR}" \
  --validation-cmd "${VALIDATE_PASS}" \
  --codex-on-pass \
  --codex-cmd "${CODEX_STUB} ${TRANSCRIPT}"

python3 - <<'PY' "${PASS_DIR}/summary.json"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert len(data["cycles"]) == 2, data
PY

if [[ "$(wc -l < "${TRANSCRIPT}")" -lt 2 ]]; then
  echo "error: expected codex stub to be called on pass cycles" >&2
  exit 1
fi

FAIL_DIR="${TMP_DIR}/fail"
set +e
"${SCRIPT}" \
  --repo "${ROOT_DIR}" \
  --cycles 2 \
  --delay-seconds 0 \
  --artifact-dir "${FAIL_DIR}" \
  --validation-cmd "${VALIDATE_FLAKY} ${STATE_FILE}" \
  --codex-cmd "${CODEX_STUB} ${TRANSCRIPT}"
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected failure when a validation cycle fails" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_DIR}/summary.json"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
assert len(data["cycles"]) == 2, data
PY

echo "m11_codex_feedback_loop_test: PASS"
