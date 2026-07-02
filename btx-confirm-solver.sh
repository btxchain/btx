#!/usr/bin/env bash
# Wait for the gbt-solve daemon to come up, then report its live args + GPU.
for i in $(seq 1 30); do
  pgrep -f '[b]tx-gbt-solve' >/dev/null && break
  sleep 2
done
echo "=== live solver args ==="
pgrep -af '[b]tx-gbt-solve' | grep -oE 'solver-threads [0-9]+|batch-size [0-9]+' || echo "solver not up"
echo "=== latest spawn line ==="
grep 'spawning solver daemon' /mnt/d/BTX/dexbtx-miner.log | tail -1
echo "=== GPU (after warmup) ==="
sleep 6
nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw,memory.used --format=csv,noheader | head -1
