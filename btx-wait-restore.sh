#!/usr/bin/env bash
# Wait for the snapshot restore to finish and report final state.
set -u
LOG=/mnt/d/BTX/btx-restore-snapshot.log
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx

for i in $(seq 1 36); do
    if grep -q "Fast snapshot restore complete" "$LOG" 2>/dev/null; then
        echo "RESTORE COMPLETE"
        break
    fi
    if ! pgrep -f btx-restore-snapshot.sh >/dev/null 2>&1; then
        echo "restore script exited (check log below)"
        break
    fi
    sleep 10
done
echo "=== restore log tail ==="
tail -8 "$LOG"
echo "=== node ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo 2>&1 | grep -E '"blocks"|"headers"|initialblockdownload'
