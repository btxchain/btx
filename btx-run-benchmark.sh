#!/usr/bin/env bash
# Run the official dexbtx-miner benchmark (raw nonce-throughput sweep) with
# exclusive GPU, write the winner to config. Sweeps the CUDA prep-pipeline
# levers + thread counts (i7-10700KF has more cores than the current 8).
set -u
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
echo "=== baseline GPU (idle) ==="
nvidia-smi --query-gpu=power.draw --format=csv,noheader | head -1
echo "=== running benchmark (this takes several minutes) ==="
DEXBTX_NO_SOLVER_AUTOUPDATE=1 /home/eldian/.local/bin/dexbtx-miner benchmark \
  --gbt-solve /home/eldian/.dexbtx-miner/bin/btx-gbt-solve \
  --duration "${DURATION:-20}" \
  --threads "${THREADS:-8,12}" \
  --batches "${BATCHES:-128,512}" \
  --prefetch "${PREFETCH:-8}" \
  --workers "${WORKERS:-8,12}" \
  --write-config 2>&1
echo "=== resulting config ==="
grep -E '^(gpu_inputs|solver_threads|solver_batch_size|solver_prefetch_depth|solver_prepare_workers|solver_pipeline_async):' /home/eldian/.dexbtx-miner/config.yaml
