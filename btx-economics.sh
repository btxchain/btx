#!/usr/bin/env bash
# Gather pool-payout economics: network hashrate, block reward, block spacing.
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
echo "=== getmininginfo (network hashps + backend) ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo 2>/dev/null | grep -E '"(blocks|networkhashps|difficulty)"'
echo "=== block reward (coinbasevalue, satoshis) ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=15 getblocktemplate '{"rules":["segwit"]}' 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print("coinbasevalue:", d.get("coinbasevalue"), "=", d.get("coinbasevalue",0)/1e8, "BTX"); print("height:", d.get("height"))'
echo "=== recent block spacing (last 10 intervals, seconds) ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo >/dev/null 2>&1
tip=$("$CLI" -datadir="$DATADIR" getbestblockhash 2>/dev/null)
prev_t=0; n=0
for i in $(seq 1 11); do
  t=$("$CLI" -datadir="$DATADIR" getblockheader "$tip" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["time"], d.get("previousblockhash",""))')
  bt=$(echo "$t" | cut -d' ' -f1); tip=$(echo "$t" | cut -d' ' -f2)
  if [ "$prev_t" -ne 0 ]; then echo "  interval: $((prev_t - bt))s"; fi
  prev_t=$bt; n=$((n+1))
  [ -z "$tip" ] && break
done
