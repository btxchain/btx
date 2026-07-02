#!/usr/bin/env bash
# Prepare btx.conf with peer config, restart btxd with CUDA backend, and start
# the solo mining guard.
set -u

DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd

echo "=== Step 1: write merged btx.conf ==="
if [ -f "$DATADIR/faststart/faststart.conf" ]; then
    cp -f "$DATADIR/faststart/faststart.conf" "$DATADIR/btx.conf"
fi
touch "$DATADIR/btx.conf"
for kv in server=1 listen=1 dnsseed=1 maxconnections=96 fastshieldedstartup=1 shieldedstartupaudit=0; do
    key=${kv%%=*}
    grep -q "^${key}=" "$DATADIR/btx.conf" || echo "$kv" >> "$DATADIR/btx.conf"
done
for node in node.btx.tools peers.minebtx.com 164.90.246.229 146.190.179.86 143.198.155.4; do
    grep -qx "addnode=$node" "$DATADIR/btx.conf" || echo "addnode=$node" >> "$DATADIR/btx.conf"
done
cat "$DATADIR/btx.conf"

echo "=== Step 2: restart btxd with CUDA backend ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 stop 2>/dev/null || true
for _ in $(seq 1 60); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
pkill -x btxd 2>/dev/null || true
sleep 2
rm -f "$DATADIR/.lock"

export BTX_MATMUL_BACKEND=cuda
"$BTXD" -datadir="$DATADIR" -daemon
echo "btxd starting..."

echo "=== Step 3: wait for RPC ==="
for i in $(seq 1 90); do
    if "$CLI" -datadir="$DATADIR" -rpcclienttimeout=3 getblockcount >/dev/null 2>&1; then
        echo "RPC ready after ~${i}x2s"
        break
    fi
    if ! pgrep -x btxd >/dev/null 2>&1; then
        echo "btxd exited during startup! Last debug.log lines:"
        tail -25 "$DATADIR/debug.log" 2>/dev/null
        exit 1
    fi
    sleep 2
done

echo "=== Step 4: status ==="
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo | grep -E '"blocks"|"headers"|initialblockdownload'
echo "--- connections ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getconnectioncount
echo "--- chain guard ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("chain_guard"), indent=2)); print("backend:", d.get("backend_runtime", {}).get("active_backend"))'
