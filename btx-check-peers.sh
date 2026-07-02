#!/usr/bin/env bash
# Show peer summary: direction, sync height, address.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli

"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getpeerinfo | python3 -c '
import json, sys
peers = json.load(sys.stdin)
print(f"total peers: {len(peers)}")
for p in peers:
    direction = "inbound " if p.get("inbound") else "outbound"
    addr = p.get("addr")
    sh = p.get("synced_headers")
    sb = p.get("synced_blocks")
    sub = p.get("subver")
    print(f"  {direction} addr={addr} synced_headers={sh} synced_blocks={sb} subver={sub}")
'
