#!/usr/bin/env bash
# Pin low-latency near-tip relay peers as persistent addnodes so a won block
# always has fast outbound propagation paths (minimises orphan-by-slow-relay).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
CONF="$DATADIR/btx.conf"
# Fast (<=75ms), near-tip, standard-port peers observed in getpeerinfo.
FAST="88.147.5.121 20.71.211.116 206.189.253.106 178.128.156.73"
for p in $FAST; do
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 addnode "$p:19335" add 2>/dev/null && echo "added $p"
  grep -qx "addnode=$p" "$CONF" 2>/dev/null || echo "addnode=$p" >> "$CONF"
done
echo "--- addnode lines in btx.conf ---"
grep -c '^addnode=' "$CONF"
echo "connections: $("$CLI" -datadir="$DATADIR" -rpcclienttimeout=8 getconnectioncount 2>/dev/null)"
