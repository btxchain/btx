#!/usr/bin/env bash
# Per-peer view of what the mining chain guard sees: outbound peers' synced_headers/common height + block signals.
/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=15 getpeerinfo 2>/dev/null | python3 -c '
import json, sys, time
peers = json.load(sys.stdin)
now = time.time()
print("%d peers" % len(peers))
for p in peers:
    inb = "in " if p.get("inbound") else "out"
    sh = p.get("synced_headers", -1)
    sb = p.get("synced_blocks", -1)
    lb = p.get("last_block", 0)
    age = ("%.0fs ago" % (now - lb)) if lb else "never"
    print("id=%3s %s %-28s synced_h=%7s synced_b=%7s last_block=%10s %s" % (
        p.get("id"), inb, p.get("addr", ""), sh, sb, age, p.get("subver", "")))'
