#!/usr/bin/env bash
# Show the coinbase outputs of a block height (default 128091).
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx
H=${1:-128091}
HASH=$("$CLI" -datadir="$DATADIR" getblockhash "$H")
"$CLI" -datadir="$DATADIR" getblock "$HASH" 2 > /tmp/btx-block.json
python3 - /tmp/btx-block.json <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
cb = b["tx"][0]
print("block height:", b["height"])
print("coinbase txid:", cb["txid"])
for v in cb["vout"]:
    spk = v.get("scriptPubKey", {})
    print("  value=%.8f addr=%s type=%s" % (v.get("value", 0), spk.get("address", "?"), spk.get("type", "?")))
PY
