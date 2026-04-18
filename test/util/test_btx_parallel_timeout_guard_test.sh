#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/test_btx_parallel.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-parallel-timeout-test.XX""XX""XX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PASS_LOG_DIR="${TMP_DIR}/pass-logs"
PASS_STDOUT="${TMP_DIR}/pass-stdout.log"
PASS_STDERR="${TMP_DIR}/pass-stderr.log"

set +e
BTX_PARALLEL_SKIP_DEFAULT_JOBS=1 \
BTX_PARALLEL_TEST_COMMAND="sleep 1" \
BTX_PARALLEL_JOB_TIMEOUT_SECONDS=20 \
BTX_PARALLEL_LOG_DIR="${PASS_LOG_DIR}" \
BTX_PARALLEL_LOCK_DIR="${TMP_DIR}/pass-lock" \
"${SCRIPT}" >"${PASS_STDOUT}" 2>"${PASS_STDERR}"
pass_rc=$?
set -e

if (( pass_rc != 0 )); then
  echo "error: expected pass scenario to succeed" >&2
  cat "${PASS_STDOUT}" >&2
  cat "${PASS_STDERR}" >&2
  exit 1
fi

test -f "${PASS_LOG_DIR}/selftest.log"
if rg -q "warning: setlocale" "${PASS_LOG_DIR}/selftest.log"; then
  echo "error: pass scenario leaked locale warning into job log" >&2
  cat "${PASS_LOG_DIR}/selftest.log" >&2
  exit 1
fi

STALE_LOCK_DIR="${TMP_DIR}/stale-lock"
STALE_LOG_DIR="${TMP_DIR}/stale-lock-logs"
STALE_STDOUT="${TMP_DIR}/stale-lock-stdout.log"
STALE_STDERR="${TMP_DIR}/stale-lock-stderr.log"

mkdir -p "${STALE_LOCK_DIR}"
printf '999999\n' > "${STALE_LOCK_DIR}/owner.pid"
printf 'scripts/test_btx_parallel.sh\n' > "${STALE_LOCK_DIR}/owner.cmd"

set +e
BTX_PARALLEL_SKIP_DEFAULT_JOBS=1 \
BTX_PARALLEL_TEST_COMMAND="sleep 1" \
BTX_PARALLEL_JOB_TIMEOUT_SECONDS=20 \
BTX_PARALLEL_LOG_DIR="${STALE_LOG_DIR}" \
BTX_PARALLEL_LOCK_DIR="${STALE_LOCK_DIR}" \
"${SCRIPT}" >"${STALE_STDOUT}" 2>"${STALE_STDERR}"
stale_lock_rc=$?
set -e

if (( stale_lock_rc != 0 )); then
  echo "error: stale lock recovery scenario failed" >&2
  cat "${STALE_STDOUT}" >&2
  cat "${STALE_STDERR}" >&2
  exit 1
fi
rg -q "warning: removing stale parallel test lock" "${STALE_STDERR}"
test -f "${STALE_LOG_DIR}/selftest.log"

NESTED_STDOUT="${TMP_DIR}/nested-stdout.log"
NESTED_STDERR="${TMP_DIR}/nested-stderr.log"
set +e
BTX_PARALLEL_ACTIVE=1 BTX_PARALLEL_LOG_DIR="${TMP_DIR}/nested-logs" "${SCRIPT}" >"${NESTED_STDOUT}" 2>"${NESTED_STDERR}"
nested_rc=$?
set -e
if (( nested_rc == 0 )); then
  echo "error: nested default invocation unexpectedly succeeded" >&2
  cat "${NESTED_STDOUT}" >&2
  cat "${NESTED_STDERR}" >&2
  exit 1
fi
rg -q "nested default test_btx_parallel invocation is not allowed" "${NESTED_STDERR}"

FAIL_LOG_DIR="${TMP_DIR}/fail-logs"
FAIL_STDOUT="${TMP_DIR}/fail-stdout.log"
FAIL_STDERR="${TMP_DIR}/fail-stderr.log"

start_ts="$(date +%s)"
set +e
BTX_PARALLEL_SKIP_DEFAULT_JOBS=1 \
BTX_PARALLEL_TEST_COMMAND="sleep 30" \
BTX_PARALLEL_JOB_TIMEOUT_SECONDS=2 \
BTX_PARALLEL_LOG_DIR="${FAIL_LOG_DIR}" \
BTX_PARALLEL_LOCK_DIR="${TMP_DIR}/fail-lock" \
"${SCRIPT}" >"${FAIL_STDOUT}" 2>"${FAIL_STDERR}"
fail_rc=$?
set -e
end_ts="$(date +%s)"
elapsed=$((end_ts - start_ts))

if (( fail_rc == 0 )); then
  echo "error: expected timeout scenario to fail" >&2
  cat "${FAIL_STDOUT}" >&2
  cat "${FAIL_STDERR}" >&2
  exit 1
fi

if (( elapsed > 12 )); then
  echo "error: timeout scenario took too long (${elapsed}s)" >&2
  cat "${FAIL_STDOUT}" >&2
  cat "${FAIL_STDERR}" >&2
  exit 1
fi

rg -q "error: selftest failed" "${FAIL_STDERR}"
rg -q "timeout after 2s" "${FAIL_LOG_DIR}/selftest.log"
if rg -q "warning: setlocale" "${FAIL_LOG_DIR}/selftest.log"; then
  echo "error: timeout scenario leaked locale warning into job log" >&2
  cat "${FAIL_LOG_DIR}/selftest.log" >&2
  exit 1
fi

echo "test_btx_parallel_timeout_guard_test: PASS"
