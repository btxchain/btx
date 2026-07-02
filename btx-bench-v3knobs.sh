#!/usr/bin/env bash
# Test the V3 nonce-seed GPU-offload knobs against the standard-config ceiling
# (~3.65M N/s) using the official benchmark at a single fixed config.
set -u
BENCH="/home/eldian/.local/bin/dexbtx-miner benchmark --gbt-solve /home/eldian/.dexbtx-miner/bin/btx-gbt-solve --duration 18 --threads 8 --batches 128 --prefetch 8 --workers 12"
run() {
  local label="$1"; shift
  pkill -f '[b]tx-gbt-solve' 2>/dev/null || true; sleep 1
  local nps
  nps=$(env "$@" DEXBTX_NO_SOLVER_AUTOUPDATE=1 $BENCH 2>/dev/null | grep -oE '[0-9,]+ N/s' | head -1)
  printf '%-52s %s\n' "$label" "${nps:-FAILED}"
}
echo "=== V3 nonce-seed knob sweep (single config 8/128/12) ==="
run "control (defaults)"
run "NONCE_SEED_BATCH_SIZE=1024"          BTX_MATMUL_NONCE_SEED_BATCH_SIZE=1024
run "NONCE_SEED_BATCH_SIZE=4096"          BTX_MATMUL_NONCE_SEED_BATCH_SIZE=4096
run "NONCE_SEED_MEMORY_PERCENT=75"        BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=75
run "DEVICE_PREPARED_INPUTS=1"            BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1
run "SEED_BATCH=4096 + MEM=75 + DEVPREP=1" BTX_MATMUL_NONCE_SEED_BATCH_SIZE=4096 BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=75 BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1
