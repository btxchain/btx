#!/usr/bin/env bash
# Production remaining wave: parallel fail-fast jobs. One test_runner is
# started by the caller (not here) so functional tests stay single-runner.
export LC_ALL=C
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$ROOT/e2e-scratch/parallel-prod"
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
run openssl358 "$ROOT/contrib/modelnet/e2e-openssl-358.sh" &
jobs+=($!)
run bench "$ROOT/contrib/modelnet/e2e-bench-12-3.sh" &
jobs+=($!)
run disc "$ROOT/contrib/modelnet/e2e-disc-failure.sh" &
jobs+=($!)
run tls512 "$ROOT/contrib/modelnet/e2e-tls-fragment.sh" &
jobs+=($!)
run cuda_fit "$ROOT/contrib/modelnet/e2e-cuda-granite-fit.sh" &
jobs+=($!)
run gui_uri "$ROOT/contrib/modelnet/e2e-gui-uri.sh" &
jobs+=($!)
run webpki "$ROOT/contrib/modelnet/e2e-webpki-tls.sh" &
jobs+=($!)
run inspect "$ROOT/contrib/modelnet/e2e-cross-host-inspect.sh" &
jobs+=($!)
run watch "$ROOT/contrib/modelnet/e2e-prod-watch.sh" "$LOG" &
watch_pid=$!
run two_wan "$ROOT/contrib/modelnet/e2e-two-wan.sh" &
jobs+=($!)
run recip "$ROOT/contrib/modelnet/e2e-reciprocity-wan.sh" &
jobs+=($!)

for p in "${jobs[@]}"; do
  if ! wait "$p"; then fail=1; fi
done
touch "$LOG/stop-watch"
wait "$watch_pid" || fail=1
run evidence "$ROOT/contrib/modelnet/e2e-production-evidence.sh" || fail=1
if [[ $fail -ne 0 ]]; then
  echo "E2E_PARALLEL_PROD FAIL — $LOG" >&2
  grep -H 'FAIL\|Traceback' "$LOG"/*.log | head -60 >&2 || true
  exit 1
fi
echo "E2E_PARALLEL_PROD PASS"
exit 0
