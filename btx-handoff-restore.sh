#!/usr/bin/env bash
# Hand off from the still-running restore monitor: write the tuned btx.conf,
# stop the faststart-managed btxd, and let the solo guard restart it with the
# right settings. Background validation persists across the restart.
set -u
DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
LOG=/mnt/d/BTX/btx-restore-snapshot.log

echo "[handoff] Snapshot restore monitoring handed off to solo guard; node restarting with tuned btx.conf. Background validation continues." >> "$LOG"

# Stop the restore monitor + faststart first so their ERR traps don't race us.
pkill -f btx-restore-snapshot.sh 2>/dev/null
pkill -f btx-faststart.py 2>/dev/null
sleep 1

# Write btx.conf: faststart preset + peer + guard tuning.
if [ -f "$DATADIR/faststart/faststart.conf" ]; then
    cp -f "$DATADIR/faststart/faststart.conf" "$DATADIR/btx.conf"
fi
touch "$DATADIR/btx.conf"
for kv in server=1 listen=1 dnsseed=1 maxconnections=96 fastshieldedstartup=1 shieldedstartupaudit=0 miningchainguardminpeers=1; do
    key=${kv%%=*}
    if grep -q "^${key}=" "$DATADIR/btx.conf"; then
        sed -i "s/^${key}=.*/${kv}/" "$DATADIR/btx.conf"
    else
        echo "$kv" >> "$DATADIR/btx.conf"
    fi
done
for node in node.btx.tools peers.minebtx.com 164.90.246.229 146.190.179.86 143.198.155.4; do
    grep -qx "addnode=$node" "$DATADIR/btx.conf" || echo "addnode=$node" >> "$DATADIR/btx.conf"
done
echo "=== btx.conf written ==="

# Stop btxd; the running solo guard will restart it with btx.conf + CUDA.
"$CLI" -datadir="$DATADIR" -conf="$DATADIR/faststart/faststart.conf" -rpcclienttimeout=10 stop 2>/dev/null \
    || "$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 stop 2>/dev/null || true
for _ in $(seq 1 90); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
pgrep -x btxd >/dev/null 2>&1 && echo "btxd still shutting down" || echo "btxd stopped; solo guard will restart it"
