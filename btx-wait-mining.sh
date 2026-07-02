#!/usr/bin/env bash
# Wait until the solo miner is running again (or ~9.5 min), then print status.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
for i in $(seq 1 19); do
  if pgrep -f 'btx-mine.sh' >/dev/null 2>&1; then
    echo "MINING RESUMED"
    break
  fi
  sleep 30
done
pgrep -f 'btx-mine.sh' >/dev/null 2>&1 || echo "MINER STILL DOWN"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getblockchaininfo 2>/dev/null | grep -E '"(blocks|headers|initialblockdownload)"' || echo "RPC not ready"
tail -3 /mnt/d/BTX/btx-solo-guard.log
echo "--- connections ---"
"$CLI" -datadir="$DATADIR" getnetworkinfo 2>/dev/null > /tmp/btx-netinfo.json && \
  python3 -c 'import json; d=json.load(open("/tmp/btx-netinfo.json")); print("in:", d.get("connections_in"), "out:", d.get("connections_out"))' || echo "netinfo unavailable"
