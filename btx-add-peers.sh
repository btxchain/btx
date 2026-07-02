#!/usr/bin/env bash
# Persist the known-stable BTX peers as addnodes (live + btx.conf) so blocks
# propagate to/from this node as fast as possible.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
PEERS="13.140.162.63 46.101.113.132 84.32.49.226 114.198.53.149 91.199.137.209 173.249.29.226"
for p in $PEERS; do
  "$CLI" -datadir="$DATADIR" addnode "$p:19335" add 2>/dev/null || true
  grep -qx "addnode=$p" "$DATADIR/btx.conf" 2>/dev/null || echo "addnode=$p" >> "$DATADIR/btx.conf"
done
echo "connections: $("$CLI" -datadir="$DATADIR" getconnectioncount 2>/dev/null)"
"$CLI" -datadir="$DATADIR" getnetworkinfo 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print("in:", d.get("connections_in"), "out:", d.get("connections_out"))'
