#!/usr/bin/env bash
# Wait for btx-sync-fast to finish (lock removed), then print node status.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
for i in $(seq 1 19); do
  if [ ! -d /tmp/btx-sync-fast.lock ]; then
    echo "SYNC DONE"
    break
  fi
  sleep 30
done
[ -d /tmp/btx-sync-fast.lock ] && echo "SYNC STILL RUNNING"
echo "--- sync log tail ---"
tail -4 /mnt/d/BTX/btx-sync-fast.log
echo "--- node ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getblockchaininfo 2>&1 | grep -E '"(blocks|headers|initialblockdownload)"' || echo "RPC not ready"
