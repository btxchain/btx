#!/usr/bin/env bash
# Show per-peer heights and block-serving status.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
TMP=/tmp/btx-peerinfo.json
"$CLI" -datadir="$DATADIR" getpeerinfo > "$TMP" 2>/dev/null || { echo "getpeerinfo failed"; exit 1; }
python3 - "$TMP" <<'PY'
import json, sys
peers = json.load(open(sys.argv[1]))
for p in peers:
    svc = ",".join(p.get("servicesnames", []))
    print("id=%3s addr=%-28s start_h=%s synced_h=%s synced_b=%s type=%s svc=%s" % (
        p.get("id"), p.get("addr"), p.get("startingheight"),
        p.get("synced_headers"), p.get("synced_blocks"),
        p.get("connection_type"), svc))
PY
