#!/usr/bin/env bash
# Wait until the node reports initialblockdownload=false (snapshot loaded, at tip).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
for i in $(seq 1 120); do
  ibd=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("0" if not d.get("initialblockdownload", True) else "1")' 2>/dev/null || echo 1)
  if [ "$ibd" = "0" ]; then
    echo "AT TIP"
    "$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getblockchaininfo 2>/dev/null | grep -E '"(blocks|headers|initialblockdownload)"'
    exit 0
  fi
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null | grep -E '"(blocks|headers)"' | tr -d '\n '
  echo " ibd=$ibd"
  sleep 15
done
echo "TIMEOUT waiting for tip"
exit 1
