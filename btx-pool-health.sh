#!/usr/bin/env bash
# Snapshot pool-mining health: GPU, processes, guard, recent miner log.
echo "=== GPU ==="
nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw --format=csv,noheader | head -1
echo "=== processes ==="
echo "pool guard : $(pgrep -af '[b]tx-pool-guard.sh' | grep -v pgrep || echo DOWN)"
echo "dexbtx     : $(pgrep -af '[d]exbtx-miner' | grep -v pgrep | head -1 || echo DOWN)"
echo "gbt-solve  : $(pgrep -af '[b]tx-gbt-solve' | grep -v pgrep | head -1 || echo DOWN)"
echo "=== pool guard log tail ==="
tail -6 /mnt/d/BTX/btx-pool-guard.log 2>/dev/null
echo "=== miner log tail (last 12) ==="
tail -12 /mnt/d/BTX/dexbtx-miner.log 2>/dev/null
echo "=== miner log mtime ==="
stat -c '%y' /mnt/d/BTX/dexbtx-miner.log 2>/dev/null
date '+%Y-%m-%d %H:%M:%S%z (now)'
