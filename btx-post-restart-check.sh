#!/usr/bin/env bash
# Post-restart check: guard log, chainstate merge, btxd memory, WSL memory.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
tail -4 /mnt/d/BTX/btx-solo-guard.log
echo "--- chainstates ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getchainstates 2>&1 | grep -E '"(blocks|validated)"|snapshot_blockhash' || echo "RPC not up yet"
echo "--- wallet ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 listwallets 2>&1
echo "--- btxd memory ---"
ps -C btxd -o rss= | awk '{printf "%d MiB btxd RSS\n", $1/1024}'
free -h | head -2
echo "--- miner ---"
pgrep -f 'btx-mine.sh' >/dev/null && echo "solo miner running" || echo "solo miner not running"
echo "--- p2p ---"
ss -tln | grep 19335 || echo "not listening on 19335"
"$CLI" -datadir="$DATADIR" getnetworkinfo 2>/dev/null > /tmp/btx-netinfo.json && \
  python3 -c 'import json; d=json.load(open("/tmp/btx-netinfo.json")); print("connections in:", d.get("connections_in"), "out:", d.get("connections_out"))' || echo "netinfo unavailable"
