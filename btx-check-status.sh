#!/usr/bin/env bash
# Wait for RPC and report node + chain guard status.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli

for i in $(seq 1 90); do
    if "$CLI" -datadir="$DATADIR" -rpcclienttimeout=3 getblockcount >/dev/null 2>&1; then
        echo "RPC ready"
        break
    fi
    if ! pgrep -x btxd >/dev/null 2>&1; then
        echo "btxd EXITED. Last debug.log lines:"
        tail -25 "$DATADIR/debug.log" 2>/dev/null
        exit 1
    fi
    sleep 2
done

"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo | grep -E '"blocks"|"headers"|initialblockdownload'
echo "--- connections ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getconnectioncount
echo "--- chain guard + backend ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("chain_guard"), indent=2)); print("active_backend:", d.get("backend_runtime", {}).get("active_backend"))'
