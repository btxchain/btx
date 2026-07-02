#!/usr/bin/env bash
# Forcibly stop pool guard + dexbtx-miner + solver daemon for exclusive-GPU work.
# Uses bracketed patterns so pkill does not match itself.
touch /tmp/btx-pool-guard.stop 2>/dev/null || true
pkill -f '[b]tx-pool-guard.sh' 2>/dev/null || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
left=$(pgrep -af 'dexbtx|gbt-solve|pool-guard' | grep -v pgrep)
if [ -n "$left" ]; then echo "STILL RUNNING:"; echo "$left"; else echo "all miner procs stopped"; fi
nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw --format=csv,noheader
