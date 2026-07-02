#!/usr/bin/env bash
LOG=/mnt/d/BTX/dexbtx-miner.log
echo "=== dexbtx-miner parent proc (start time) ==="
ps -o pid,lstart,args -C python3 2>/dev/null | grep -i dexbtx | grep -v grep
echo "=== gbt-solve daemon full cmdline ==="
pgrep -af 'gbt-solve' | grep -v pgrep
echo "=== latest 'spawning solver daemon' log line ==="
grep 'spawning solver daemon' "$LOG" | tail -1
echo "=== latest 'solver=' main config line ==="
grep -E 'solver=.*batch=' "$LOG" | tail -1
echo "=== VRAM now ==="
nvidia-smi --query-gpu=memory.used,utilization.gpu,power.draw --format=csv,noheader | head -1
echo "=== rejects in last 100 log lines (recent) ==="
tail -100 "$LOG" | grep -c 'submit raised'
echo "=== last 3 reject timestamps (if any) ==="
grep 'submit raised' "$LOG" | tail -3
echo "=== last 3 share OK timestamps ==="
grep 'share OK' "$LOG" | tail -3
