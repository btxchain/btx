#!/usr/bin/env bash
# Tune the mining chain guard for the small BTX network: require only 1
# consensus peer (the guard still pauses on isolation and tip divergence).
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd

# Persist in btx.conf
grep -q "^miningchainguardminpeers=" "$DATADIR/btx.conf" 2>/dev/null \
    && sed -i 's/^miningchainguardminpeers=.*/miningchainguardminpeers=1/' "$DATADIR/btx.conf" \
    || echo "miningchainguardminpeers=1" >> "$DATADIR/btx.conf"
echo "btx.conf guard settings:"
grep -E "miningchainguard|mining" "$DATADIR/btx.conf"

# Restart btxd to apply
echo "Restarting btxd..."
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 stop 2>/dev/null || true
for _ in $(seq 1 60); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
sleep 3
rm -f "$DATADIR/.lock"

export BTX_MATMUL_BACKEND=cuda
"$BTXD" -datadir="$DATADIR" -daemon
echo "btxd starting..."

for i in $(seq 1 90); do
    if "$CLI" -datadir="$DATADIR" -rpcclienttimeout=3 getblockcount >/dev/null 2>&1; then
        echo "RPC ready"
        break
    fi
    if ! pgrep -x btxd >/dev/null 2>&1; then
        echo "btxd exited during startup! Last debug.log lines:"
        tail -25 "$DATADIR/debug.log" 2>/dev/null
        exit 1
    fi
    sleep 2
done

echo "Waiting 30s for peers..."
sleep 30
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo | grep -E '"blocks"|"headers"|initialblockdownload'
echo "--- connections ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getconnectioncount
echo "--- chain guard ---"
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getmininginfo | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("chain_guard"), indent=2)); print("active_backend:", d.get("backend_runtime", {}).get("active_backend"))'
