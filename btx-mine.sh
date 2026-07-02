#!/usr/bin/env bash
# Simple local-node solo loop using btx-cli generatetoaddress.
# This is a compatibility/fallback solo path; practical GPU solo requires a
# getblocktemplate + btx-gbt-solve + submitblock loop that can serialize the
# solved MatMul block.
set -u
CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
DATADIR=${DATADIR:-/home/eldian/.btx}
ADDR=${ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}

echo "Waiting for sync to complete..."
while true; do
    info=$($CLI -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo 2>/dev/null || true)
    if [ -z "$info" ]; then
        echo "[$(date)] RPC unavailable; retrying in 20s..."
        sleep 20
        continue
    fi
    IBD=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("1" if d.get("initialblockdownload", True) else "0")' 2>/dev/null || echo 1)
    BLOCKS=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("blocks", "?"))' 2>/dev/null || echo '?')
    HEADERS=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("headers", "?"))' 2>/dev/null || echo '?')
    if [ "$IBD" = "0" ]; then
        echo "SYNC COMPLETE at block $BLOCKS - starting solo generate loop."
        break
    fi
    echo "Syncing: block $BLOCKS / $HEADERS ..."
    sleep 20
done

echo "Starting solo mining loop to $ADDR..."
while true; do
    $CLI -datadir="$DATADIR" generatetoaddress 1 "$ADDR" 2>&1
    RESULT=$?
    if [ $RESULT -ne 0 ]; then
        echo "[$(date)] Mining error, retrying in 30s..."
        sleep 30
    else
        echo "[$(date)] Block attempt completed."
    fi
done
