#!/usr/bin/env bash
# One-shot status probe for the GUI: process flags, racer state, sync/log signals,
# node RPC snapshot. Output: KEY=VALUE lines, then ===LOG=== and the sync log tail.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx

echo "P_NODE=$(pgrep -f '[b]txd' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_SYNCF=$(pgrep -f '[b]tx-sync-fast.sh' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_FASTS=$(pgrep -f '[f]aststart.py' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_SGUARD=$(pgrep -f '[b]tx-solo-guard.sh' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_PGUARD=$(pgrep -f '[b]tx-pool-guard.sh' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_PMINER=$(pgrep -f '[d]exbtx-miner' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_SMINER=$(pgrep -f '[b]tx-mine.sh' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "P_RACER=$(pgrep -f '[r]acer -a btx' >/dev/null 2>&1 && echo 1 || echo 0)"
echo "RMODE=$(cat /mnt/d/BTX/btx-racer.mode 2>/dev/null || echo none)"
echo "RHS=$(grep -oE 'effective_rate=[0-9.]+' /mnt/d/BTX/racer.log 2>/dev/null | tail -1 | cut -d= -f2)"
echo "RAGE=$(( $(date +%s) - $(stat -c %Y /mnt/d/BTX/racer.log 2>/dev/null || date +%s) ))"
echo "LOCK=$([ -d /tmp/btx-sync-fast.lock ] && echo 1 || echo 0)"
echo "SNAPSZ=$(stat -c %s /home/eldian/.btx/faststart/snapshot.dat 2>/dev/null || echo 0)"
DL=/mnt/d/BTX/btx-faststart-debug.log
[ /home/eldian/.btx/debug.log -nt "$DL" ] 2>/dev/null && DL=/home/eldian/.btx/debug.log
echo "TIPH=$(grep -oE 'height=[0-9]+' "$DL" 2>/dev/null | tail -1 | cut -d= -f2)"
echo "TAGE=$(( $(date +%s) - $(stat -c %Y "$DL" 2>/dev/null || date +%s) ))"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null
echo '===LOG==='
tail -n 25 /mnt/d/BTX/btx-sync-fast.log 2>/dev/null
