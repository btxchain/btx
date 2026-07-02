#!/usr/bin/env bash
# Diagnose inbound P2P reachability for solo-block propagation.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
echo "=== connections ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=15 getnetworkinfo 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("total:", d.get("connections"), "in:", d.get("connections_in"), "out:", d.get("connections_out"))
print("networkactive:", d.get("networkactive"))
for n in d.get("localaddresses", []):
    print("  localaddress:", n.get("address"), "port", n.get("port"), "score", n.get("score"))
'
echo "=== peer block-relay latency (outbound, near-tip) ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=15 getpeerinfo 2>/dev/null | python3 -c '
import json,sys,time
ps=json.load(sys.stdin); now=time.time()
for p in ps:
    if p.get("inbound"): continue
    sh=p.get("synced_headers",-1)
    if sh < 0: continue
    pr=p.get("pingtime")
    lb=p.get("last_block",0)
    print("  %-26s synced_h=%s ping=%sms last_block=%s" % (
        p.get("addr",""), sh, ("%.0f"%(pr*1000)) if pr else "?", ("%.0fs"%(now-lb)) if lb else "never"))
'
echo "=== host LAN IP (from WSL view of mirrored stack) ==="
ip -4 addr show 2>/dev/null | grep -E 'inet ' | grep -v '127.0.0.1'
