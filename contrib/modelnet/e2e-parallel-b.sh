#!/usr/bin/env bash
# Helper-using e2e jobs. Sequential inside this script only if they share
# nothing; they use random ports so they run concurrently.
export LC_ALL=C
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  :
elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}" && -x "${BIN_DIR}/btxd" ]]; then
  BIN="$BIN_DIR"
else
  BIN="$ROOT/build-gcc13/bin"
fi
export MODELD="${MODELD:-$BIN/btx-modeld}"
[[ -x "$BIN/btxd" ]] || { echo "e2e-parallel-b: missing $BIN/btxd" >&2; exit 1; }
[[ -x "$BIN/btx-cli" ]] || { echo "e2e-parallel-b: missing $BIN/btx-cli" >&2; exit 1; }
LOG="$ROOT/e2e-scratch/parallel-b"
rm -rf "$LOG"; mkdir -p "$LOG"
run() {
  local name="$1"; shift
  echo "START $name"
  ( "$@" ) >"$LOG/$name.log" 2>&1
  local rc=$?
  echo "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) $name rc=$rc"
  return $rc
}
jobs=()
run two_helper "$ROOT/contrib/modelnet/e2e-two-helper-pq1.sh" &
jobs+=($!)
run local_helper "$ROOT/contrib/modelnet/e2e-local-helper.sh" &
jobs+=($!)
run resolve "$ROOT/contrib/modelnet/e2e-resolve-8-4.sh" &
jobs+=($!)
run nat "$ROOT/contrib/modelnet/e2e-nat-congested.sh" &
jobs+=($!)
run preserve "$ROOT/contrib/modelnet/e2e-preserve-rare.sh" &
jobs+=($!)
run follow "$ROOT/contrib/modelnet/e2e-peer-follow.sh" &
jobs+=($!)
run two_source "$ROOT/contrib/modelnet/e2e-two-source.sh" &
jobs+=($!)
run firstrun "$ROOT/contrib/modelnet/e2e-firstrun-cli.sh" &
jobs+=($!)
run disc "$ROOT/contrib/modelnet/e2e-disc-failure.sh" &
jobs+=($!)
run bench "$ROOT/contrib/modelnet/e2e-bench-12-3.sh" &
jobs+=($!)
fail=0
for p in "${jobs[@]}"; do
  if ! wait "$p"; then fail=1; fi
done
if [[ $fail -ne 0 ]]; then
  echo "E2E_PARALLEL_B FAIL" >&2
  grep -H 'FAIL\|Traceback\|not ok' "$LOG"/*.log | head -50 >&2 || true
  tail -20 "$LOG"/*.log >&2 || true
  exit 1
fi
echo "E2E_PARALLEL_B PASS"
exit 0
