#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOOP_SCRIPT="${ROOT_DIR}/scripts/verify_btx_production_loop.sh"

if [[ ! -x "${LOOP_SCRIPT}" ]]; then
  echo "error: missing loop script at ${LOOP_SCRIPT}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-prod-loop-test.XX""XX""XX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

FLAKY_SCRIPT="${TMP_DIR}/flaky-readiness.sh"
cat <<'EOS' > "${FLAKY_SCRIPT}"
#!/usr/bin/env bash
set -euo pipefail

: "${FAKE_VERIFY_STATE_FILE:?FAKE_VERIFY_STATE_FILE must be set}"
STATE_FILE="${FAKE_VERIFY_STATE_FILE}"

attempt=0
if [[ -f "${STATE_FILE}" ]]; then
  attempt="$(< "${STATE_FILE}")"
fi
attempt=$((attempt + 1))
printf '%s\n' "${attempt}" > "${STATE_FILE}"

if (( attempt < 3 )); then
  echo "flaky readiness still failing (attempt ${attempt})" >&2
  exit 42
fi

round_dir="${BTX_PRODUCTION_LOOP_ROUND_DIR:-}"
if [[ -n "${round_dir}" ]]; then
  printf 'round_dir=%s\n' "${round_dir}"
fi
echo "flaky readiness passed on attempt ${attempt}"
EOS
chmod +x "${FLAKY_SCRIPT}"

FAILING_SCRIPT="${TMP_DIR}/always-fail-readiness.sh"
cat <<'EOS' > "${FAILING_SCRIPT}"
#!/usr/bin/env bash
set -euo pipefail
echo "always failing readiness" >&2
exit 86
EOS
chmod +x "${FAILING_SCRIPT}"

ARTIFACT_SUCCESS="${TMP_DIR}/artifacts-success"
STATE_FILE="${TMP_DIR}/flaky-state"

FAKE_VERIFY_STATE_FILE="${STATE_FILE}" \
  "${LOOP_SCRIPT}" \
  --verify-script "${FLAKY_SCRIPT}" \
  --artifact-dir "${ARTIFACT_SUCCESS}" \
  --max-rounds 5 \
  --round-delay 0

test -f "${STATE_FILE}"
test "$(cat "${STATE_FILE}")" -eq 3

round1=( "${ARTIFACT_SUCCESS}"/round-001_* )
round2=( "${ARTIFACT_SUCCESS}"/round-002_* )
round3=( "${ARTIFACT_SUCCESS}"/round-003_* )

test -d "${round1[0]}"
test -d "${round2[0]}"
test -d "${round3[0]}"

test "$(cat "${round1[0]}/exit_code")" -eq 42
test "$(cat "${round2[0]}/exit_code")" -eq 42
test "$(cat "${round3[0]}/exit_code")" -eq 0

rg -q '^flaky readiness still failing' "${round1[0]}/stderr.log"
rg -q '^flaky readiness passed on attempt 3' "${round3[0]}/stdout.log"
rg -q "^round_dir=${round3[0]}" "${round3[0]}/stdout.log"

FAIL_ARTIFACTS="${TMP_DIR}/artifacts-fail"
set +e
"${LOOP_SCRIPT}" \
  --verify-script "${FAILING_SCRIPT}" \
  --artifact-dir "${FAIL_ARTIFACTS}" \
  --max-rounds 2 \
  --round-delay 0
rc=$?
set -e

test "${rc}" -eq 86
fail_rounds=( "${FAIL_ARTIFACTS}"/round-001_* )
test -d "${fail_rounds[0]}"
test "$(cat "${fail_rounds[0]}/exit_code")" -eq 86

fail_rounds2=( "${FAIL_ARTIFACTS}"/round-002_* )
test -d "${fail_rounds2[0]}"
test "$(cat "${fail_rounds2[0]}/exit_code")" -eq 86

echo "verify_btx_production_loop_test: PASS"
