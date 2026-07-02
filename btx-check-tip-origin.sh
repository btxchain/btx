#!/usr/bin/env bash
# Where did our recent tip blocks come from, and are we on the same chain as peers?
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
echo "--- chaintips ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=15 getchaintips 2>/dev/null | python3 -c 'import json,sys; ts=json.load(sys.stdin); [print(t["height"], t["status"], t["hash"][:16], "branchlen", t["branchlen"]) for t in ts[:8]]'
echo "--- last 6 block times ---"
tip=$("$CLI" -datadir="$DATADIR" getbestblockhash 2>/dev/null)
for _ in 1 2 3 4 5 6; do
  "$CLI" -datadir="$DATADIR" getblockheader "$tip" 2>/dev/null | python3 -c 'import json,sys,datetime; d=json.load(sys.stdin); print(d["height"], datetime.datetime.utcfromtimestamp(d["time"]).isoformat()+"Z")'
  tip=$("$CLI" -datadir="$DATADIR" getblockheader "$tip" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["previousblockhash"])')
done
echo "--- recent block receptions in debug log ---"
grep -E "UpdateTip|Saw new header" /mnt/d/BTX/btx-faststart-debug.log 2>/dev/null | tail -6
