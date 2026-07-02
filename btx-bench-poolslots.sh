#!/usr/bin/env bash
# Final lever: CUDA pool-slots (GPU pipeline depth) vs the ~3.62M baseline.
set -u
BENCH="/home/eldian/.local/bin/dexbtx-miner benchmark --gbt-solve /home/eldian/.dexbtx-miner/bin/btx-gbt-solve --duration 18 --threads 8 --batches 128 --prefetch 8 --workers 12"
run() {
  local label="$1"; shift
  pkill -f '[b]tx-gbt-solve' 2>/dev/null || true; sleep 1
  local nps
  nps=$(env "$@" DEXBTX_NO_SOLVER_AUTOUPDATE=1 $BENCH 2>/dev/null | grep -oE '[0-9,]+ N/s' | head -1)
  printf '%-32s %s\n' "$label" "${nps:-FAILED}"
}
echo "=== CUDA pool-slots sweep ==="
run "control (default)"
run "CUDA_POOL_SLOTS=4"  BTX_MATMUL_CUDA_POOL_SLOTS=4
run "CUDA_POOL_SLOTS=8"  BTX_MATMUL_CUDA_POOL_SLOTS=8
run "CUDA_POOL_SLOTS=16" BTX_MATMUL_CUDA_POOL_SLOTS=16
