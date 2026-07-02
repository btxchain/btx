#!/usr/bin/env bash
# Wait for the miner to (re)connect and confirm it gets past connect → authorize
# → solver working, then show GPU.
for i in $(seq 1 40); do
  grep -q 'authorized as' <(tail -30 /mnt/d/BTX/dexbtx-miner.log) && break
  sleep 3
done
echo "=== recent miner log (connect/auth/solver) ==="
tail -30 /mnt/d/BTX/dexbtx-miner.log | grep -iE 'connecting|subscribed|authorized|solver: working|share OK|session ended|error' | tail -10
echo "=== gbt-solve up? ==="
pgrep -af '[b]tx-gbt-solve' | grep -oE 'solver-threads [0-9]+|batch-size [0-9]+' || echo "solver not up"
echo "=== GPU (after warmup) ==="
sleep 8
nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw --format=csv,noheader | head -1
echo "=== latest share counter ==="
grep 'share OK' /mnt/d/BTX/dexbtx-miner.log | tail -1
