#!/usr/bin/env bash
# Run independent modelnet e2e jobs concurrently. First FAIL prints and we
# still wait for others (each job is fail-fast internally). Coordinator only.
# Does not cmake. Does not touch production btxd.
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
[[ -x "$BIN/btxd" ]] || { echo "e2e-parallel-a: missing $BIN/btxd" >&2; exit 1; }
[[ -x "$BIN/btx-cli" ]] || { echo "e2e-parallel-a: missing $BIN/btx-cli" >&2; exit 1; }
LOG="$ROOT/e2e-scratch/parallel-logs"
rm -rf "$LOG"; mkdir -p "$LOG"

jobs=()
run() {
  local name="$1"; shift
  echo "START $name" | tee "$LOG/$name.log"
  ( "$@" ) >>"$LOG/$name.log" 2>&1
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "PASS $name" | tee -a "$LOG/$name.log"
  else
    echo "FAIL $name rc=$rc" | tee -a "$LOG/$name.log"
  fi
  return $rc
}

# Independent jobs (own scratch dirs / ports).
run units "$BIN/test_btx" --run_test=modelnet_* &
jobs+=($!)
run reference bash -c "cd '$ROOT/contrib/modelnet/reference' && python3 -m unittest -q test_v11" &
jobs+=($!)
run os_handler "$ROOT/contrib/modelnet/e2e-os-handler.sh" &
jobs+=($!)
run webpki_tls "$ROOT/contrib/modelnet/e2e-webpki-tls.sh" &
jobs+=($!)
run webpki_kit "$ROOT/contrib/modelnet/e2e-public-webpki-kit.sh" &
jobs+=($!)
run bridge_matrix "$ROOT/contrib/modelnet/e2e-bridge-matrix.sh" &
jobs+=($!)
run doc_examples env BIN_DIR="$BIN" "$ROOT/contrib/modelnet/validate-doc-examples.sh" &
jobs+=($!)

fail=0
for p in "${jobs[@]}"; do
  if ! wait "$p"; then fail=1; fi
done
if [[ $fail -ne 0 ]]; then
  echo "E2E_PARALLEL_A FAIL — see $LOG" >&2
  grep -H 'FAIL' "$LOG"/*.log | head -40 >&2 || true
  exit 1
fi
echo "E2E_PARALLEL_A PASS (no helper overlap)"
exit 0
