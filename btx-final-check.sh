#!/usr/bin/env bash
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd
DATADIR=/home/eldian/.btx
echo "=== sync log tail ==="
tail -8 /mnt/d/BTX/btx-sync-fast.log
echo "=== btxd version ==="
"$BTXD" --version 2>/dev/null | head -1
echo "=== chain state ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getblockchaininfo 2>&1 | grep -E '"(blocks|headers|initialblockdownload|verificationprogress|pruned)"'
echo "=== node version via RPC ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getnetworkinfo 2>/dev/null | grep -E '"(subversion)"'
echo "=== faststart/btxd procs ==="
pgrep -af '[b]tx-faststart.py|[/]bin/btxd' | grep -v pgrep || echo "none"
echo "=== pool health ==="
pgrep -f '[g]bt-solve' >/dev/null && echo "solver running" || echo "solver DOWN"
echo "shares accepted: $(grep -c 'share OK' /mnt/d/BTX/dexbtx-miner.log)"
nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader | head -1
