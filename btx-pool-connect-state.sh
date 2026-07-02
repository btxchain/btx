#!/usr/bin/env bash
LOG=/mnt/d/BTX/dexbtx-miner.log
echo "=== which host is the live miner using? (config) ==="
grep -E '^pool_(host|port):' /home/eldian/.dexbtx-miner/config.yaml
echo "=== miner running? ==="
pgrep -af '[d]exbtx-miner' | grep -v pgrep | head -1 || echo "MINER DOWN"
pgrep -af '[b]tx-gbt-solve' >/dev/null && echo "solver up" || echo "solver DOWN"
echo "=== last connect / subscribe / authorize / canonical-name ==="
grep -iE 'connecting to pool|subscribed;|authorized as|Canonical name|extranonce' "$LOG" | tail -8
echo "=== last 5 share results (accepted vs reject) ==="
grep -iE 'share OK|submit raised|reject' "$LOG" | tail -5
echo "=== share counter (a/r/b) most recent ==="
grep -oE 'a/r/b=[0-9]+/[0-9]+/[0-9]+' "$LOG" | tail -1
echo "=== last 3 log lines (whatever they are) ==="
tail -3 "$LOG"
echo "=== log mtime vs now ==="
stat -c '%y' "$LOG"; date '+%Y-%m-%d %H:%M:%S (now)'
echo "=== GPU ==="
nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader | head -1
