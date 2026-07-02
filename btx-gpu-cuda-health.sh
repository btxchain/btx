#!/usr/bin/env bash
echo "=== solver binary: mtime + sha (did it auto-update near 02:32?) ==="
ls -la --time-style=full-iso /home/eldian/.dexbtx-miner/bin/btx-gbt-solve 2>/dev/null
sha256sum /home/eldian/.dexbtx-miner/bin/btx-gbt-solve 2>/dev/null | cut -c1-16
echo "=== solver backups present (rollback options) ==="
ls -la --time-style=full-iso /home/eldian/.dexbtx-miner/bin/ 2>/dev/null | grep -iE 'bak|solve'
echo "=== nvidia-smi full health ==="
nvidia-smi --query-gpu=name,driver_version,utilization.gpu,clocks.sm,power.draw,temperature.gpu,memory.used --format=csv,noheader 2>&1 | head -2
echo "=== nvidia-smi error state? ==="
nvidia-smi 2>&1 | grep -iE 'err|fail|fallen|unknown|not found' || echo "nvidia-smi nominal"
echo "=== last solver-update + last few non-working miner log lines ==="
grep 'solver auto-update' /mnt/d/BTX/dexbtx-miner.log 2>/dev/null | tail -2
tail -300 /mnt/d/BTX/dexbtx-miner.log | grep -ivE 'solver: working|notify job' | tail -12
