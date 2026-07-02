#!/usr/bin/env bash
# Unambiguous current state (the miner log is dateless/multi-day, so use raw tail).
echo "=== NOW ==="; date '+%Y-%m-%d %H:%M:%S'
echo "=== processes ==="
pgrep -af '[d]exbtx-miner' | grep -v pgrep | head -1 || echo "MINER DOWN"
pgrep -af '[b]tx-gbt-solve' | grep -v pgrep | head -1 || echo "SOLVER DOWN"
pgrep -af '[b]tx-pool-guard' | grep -v pgrep | head -1 || echo "GUARD DOWN"
echo "=== GPU ==="
nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader | head -1
echo "=== raw miner log tail (last 15 lines, real recent) ==="
tail -15 /mnt/d/BTX/dexbtx-miner.log
echo "=== guard log tail (restart activity) ==="
tail -6 /mnt/d/BTX/btx-pool-guard.log
echo "=== miner log mtime ==="
stat -c '%y' /mnt/d/BTX/dexbtx-miner.log
