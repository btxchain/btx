#!/usr/bin/env bash
# Probe: sample backend_runtime counters 30s apart and print the deltas, to
# identify which counter tracks nonce attempts during solo mining.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx

A=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo)
sleep 30
B=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo)

python3 - <<PY
import json
a = json.loads('''$A''')["backend_runtime"]
b = json.loads('''$B''')["backend_runtime"]
for k in sorted(a):
    va, vb = a[k], b[k]
    if isinstance(va, (int, float)) and isinstance(vb, (int, float)) and vb != va:
        print(f"{k}: {va} -> {vb}  (delta {vb - va}, rate {(vb - va) / 30:.1f}/s)")
PY
