#!/usr/bin/env bash
# Two-host + CUDA + Chrome + mutual inspect. Fail-fast per job; wait all.
# Set FETCHER_HOST / SEEDER_HOST / CUDA_HOST and production PID env vars.
# Never SIGKILL production.
export LC_ALL=C
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$ROOT/e2e-scratch/parallel-hosts"
rm -rf "$LOG"; mkdir -p "$LOG"

run() {
  local name="$1"; shift
  echo "START $name"
  ( "$@" ) >"$LOG/$name.log" 2>&1
  local rc=$?
  echo "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) $name rc=$rc"
  echo "$rc" >"$LOG/$name.rc"
  return $rc
}

fail=0
jobs=()
run cuda "$ROOT/contrib/modelnet/cuda-isolated-e2e.sh" &
jobs+=($!)
run regtest_two "$ROOT/contrib/modelnet/e2e-regtest-two-host.sh" &
jobs+=($!)
run chrome "$ROOT/contrib/modelnet/e2e-bridge-optional.sh" &
jobs+=($!)
run inspect_start "$ROOT/contrib/modelnet/e2e-cross-host-inspect.sh" &
jobs+=($!)
run watch "$ROOT/contrib/modelnet/e2e-prod-watch.sh" "$LOG" &
watch_pid=$!

for p in "${jobs[@]}"; do
  if ! wait "$p"; then fail=1; fi
done
touch "$LOG/stop-watch"
if ! wait "$watch_pid"; then fail=1; fi
run inspect_end "$ROOT/contrib/modelnet/e2e-cross-host-inspect.sh" || fail=1

if [[ $fail -ne 0 ]]; then
  echo "E2E_PARALLEL_HOSTS FAIL — see $LOG" >&2
  grep -H 'FAIL\|Traceback' "$LOG"/*.log | head -40 >&2 || true
  exit 1
fi
echo "E2E_PARALLEL_HOSTS PASS"
exit 0
