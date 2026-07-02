#!/usr/bin/env bash
# Ban peers stuck on the stale pre-recovery-exit fork (~height 122.5k) so the
# mining chain guard's peer-median reflects the live chain.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
for ip in 58.164.17.122 211.251.31.192; do
  "$CLI" -datadir="$DATADIR" setban "$ip" add 86400 2>&1 && echo "banned $ip (24h)"
done
"$CLI" -datadir="$DATADIR" listbanned | python3 -c 'import json,sys; print("banlist:", [b.get("address") for b in json.load(sys.stdin)])'
