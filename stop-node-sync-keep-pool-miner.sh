#!/usr/bin/env bash
# Stop only the slow local-node faststart/sync, leaving pool miner guard and dexbtx-miner running.
set -u
for pat in 'btx-faststart.py' '/home/eldian/btx-node/bin/btxd'; do
  pids=$(pgrep -f "$pat" || true)
  if [ -n "$pids" ]; then
    echo "stopping $pat: $pids"
    kill $pids 2>/dev/null || true
  fi
done
sleep 3
for pat in 'btx-faststart.py' '/home/eldian/btx-node/bin/btxd'; do
  pids=$(pgrep -f "$pat" || true)
  if [ -n "$pids" ]; then
    echo "force stopping $pat: $pids"
    kill -9 $pids 2>/dev/null || true
  fi
done
echo remaining relevant processes:
ps -ef | grep -E 'dexbtx|btx-gbt|btx-pool-guard|btx-faststart|btxd' | grep -v grep || true
