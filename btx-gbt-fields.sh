#!/usr/bin/env bash
# Extract solver input fields from the node's getblocktemplate (BTX matmul GBT).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=20 getblocktemplate '{"rules":["segwit"]}' 2>&1 | python3 -c '
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print("GBT_ERROR:", raw[:300]); sys.exit(1)
keys=["version","previousblockhash","bits","height","curtime","target"]
for k in keys:
    print(k, "=", d.get(k))
# matmul seeds may be under different key names
for k in d:
    if "seed" in k.lower() or "matmul" in k.lower():
        print("MATMUL_KEY", k, "=", d[k])
print("ALL_KEYS=", sorted(d.keys()))
'
