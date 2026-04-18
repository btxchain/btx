#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/verify_btx_production_readiness.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-prod-timeout-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

SUCCESS_STUB="${TMP_DIR}/success.sh"
HANG_STUB="${TMP_DIR}/hang.sh"

cat > "${SUCCESS_STUB}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
chmod +x "${SUCCESS_STUB}"

cat > "${HANG_STUB}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sleep 30
EOF
chmod +x "${HANG_STUB}"

common_args=(
  --build-dir "${ROOT_DIR}/build-btx"
  --log-dir "${TMP_DIR}/logs"
  --skip-parallel-gate
  --skip-lint
  --skip-m7-readiness
  --skip-m7-pool-e2e
  --skip-m5-genesis-freeze
  --skip-m7-external-kawpow
  --skip-launch-blockers
  --skip-benchmark-suite
  --skip-pow-scaling-suite
  --skip-m7-timeout-check
  --skip-m7-parallel-check
  --skip-parallel-timeout-check
  --skip-production-loop-guard
  --skip-live-p2p
  --skip-live-mining
)

PASS_ARTIFACT="${TMP_DIR}/pass.json"
BTX_PROD_OVERRIDE_BINARIES="${SUCCESS_STUB}" "${SCRIPT}" "${common_args[@]}" --check-timeout-seconds 0 --artifact "${PASS_ARTIFACT}"
python3 - <<'PY' "${PASS_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "pass", data
checks = data["checks"]
assert len(checks) == 1, checks
assert checks[0]["id"] == "binaries", checks
assert checks[0]["status"] == "pass", checks
PY

FAIL_ARTIFACT="${TMP_DIR}/fail.json"
set +e
BTX_PROD_OVERRIDE_BINARIES="${HANG_STUB}" "${SCRIPT}" "${common_args[@]}" --check-timeout-seconds 3 --artifact "${FAIL_ARTIFACT}"
rc=$?
set -e

if (( rc == 0 )); then
  echo "error: timeout scenario unexpectedly succeeded" >&2
  exit 1
fi

python3 - <<'PY' "${FAIL_ARTIFACT}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

assert data["overall_status"] == "fail", data
checks = data["checks"]
assert len(checks) == 1, checks
assert checks[0]["id"] == "binaries", checks
assert checks[0]["status"] == "fail", checks
PY

rg -q 'timeout after 3s' "${TMP_DIR}/logs/binaries.log"

echo "verify_btx_production_readiness_timeout_guard_test: PASS"
