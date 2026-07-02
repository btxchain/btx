#!/usr/bin/env bash
# Check recent blocks' coinbase payout addresses to confirm our miner is
# winning blocks.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
ADDR=btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35

TIP=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockcount)
echo "tip: $TIP   our address: $ADDR"
OURS=0
for h in $(seq $((TIP - 9)) "$TIP"); do
    HASH=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockhash "$h")
    PAYOUT=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblock "$HASH" 2 | python3 -c '
import json, sys
b = json.load(sys.stdin)
cb = b["tx"][0]
addrs = []
for v in cb.get("vout", []):
    a = v.get("scriptPubKey", {}).get("address")
    if a:
        addrs.append(a)
print(addrs[0] if addrs else "none")
')
    MARK=""
    if [ "$PAYOUT" = "$ADDR" ]; then
        MARK="  <-- OURS"
        OURS=$((OURS + 1))
    fi
    echo "block $h -> $PAYOUT$MARK"
done
echo "We mined $OURS of the last 10 blocks."
