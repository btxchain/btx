#!/usr/bin/env bash
# Quick sync status: height, peers, recent log activity.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getblockchaininfo 2>&1 | grep -E '"(blocks|headers|initialblockdownload|verificationprogress)"'
echo "--- peers: $("$CLI" -datadir="$DATADIR" getconnectioncount 2>&1) ---"
"$CLI" -datadir="$DATADIR" getpeerinfo 2>/dev/null | grep -cE '"id"' | xargs -I{} echo "peer entries: {}"
echo "--- last btxd debug lines ---"
tail -6 /mnt/d/BTX/btx-faststart-debug.log
echo "--- sync log tail ---"
tail -4 /mnt/d/BTX/btx-sync-fast.log
