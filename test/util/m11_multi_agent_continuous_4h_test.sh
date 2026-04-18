#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/m11_multi_agent_continuous_4h.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-m11-multi-agent-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

SWARM_PASS="${TMP_DIR}/swarm-pass.sh"
VALIDATION_PASS="${TMP_DIR}/validation-pass.sh"
FEEDBACK_PASS="${TMP_DIR}/feedback-pass.sh"
VALIDATION_FAIL="${TMP_DIR}/validation-fail.sh"

cat > "${SWARM_PASS}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "swarm pass"
EOS
chmod +x "${SWARM_PASS}"

cat > "${VALIDATION_PASS}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "validation pass"
EOS
chmod +x "${VALIDATION_PASS}"

cat > "${FEEDBACK_PASS}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "feedback pass"
EOS
chmod +x "${FEEDBACK_PASS}"

cat > "${VALIDATION_FAIL}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
echo "validation fail" >&2
exit 9
EOS
chmod +x "${VALIDATION_FAIL}"

PASS_DIR="${TMP_DIR}/pass"
"${SCRIPT}" \
  --repo "${ROOT_DIR}" \
  --duration-seconds 2 \
  --round-delay-seconds 0 \
  --artifact-dir "${PASS_DIR}" \
  --swarm-cmd "${SWARM_PASS}" \
  --validation-cmd "${VALIDATION_PASS}" \
  --feedback-cmd "${FEEDBACK_PASS}"

python3 - <<'PY' "${PASS_DIR}/summary.json"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "pass", data
assert data["round_count"] >= 1, data
PY

FAIL_DIR="${TMP_DIR}/fail"
set +e
"${SCRIPT}" \
  --repo "${ROOT_DIR}" \
  --duration-seconds 2 \
  --round-delay-seconds 0 \
  --artifact-dir "${FAIL_DIR}" \
  --swarm-cmd "${SWARM_PASS}" \
  --validation-cmd "${VALIDATION_FAIL}" \
  --feedback-cmd "${FEEDBACK_PASS}"
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
  echo "error: expected failure when validation command fails" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_DIR}/summary.json"
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["overall_status"] == "fail", data
assert data["round_count"] >= 1, data
PY

echo "m11_multi_agent_continuous_4h_test: PASS"
