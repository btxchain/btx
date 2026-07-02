#!/usr/bin/env bash
# Finish a stuck btx-sync-fast: stop the zombie faststart monitor (validation
# already complete), merge faststart.conf into btx.conf, and restart btxd so
# the snapshot chainstate merges and memory bloat is released. The solo guard
# restarts btxd/miner automatically afterwards.
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx

echo "--- stopping zombie faststart monitor ---"
pkill -f 'btx-faststart\.py miner' 2>/dev/null || echo "no faststart monitor running"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ ! -d /tmp/btx-sync-fast.lock ] && break
  sleep 1
done
if [ -d /tmp/btx-sync-fast.lock ]; then
  echo "lock still present; removing stale lock"
  rmdir /tmp/btx-sync-fast.lock 2>/dev/null || true
fi
echo "lock state: $(ls -d /tmp/btx-sync-fast.lock 2>/dev/null || echo released)"

echo "--- merging faststart.conf into btx.conf ---"
if [ -f "$DATADIR/faststart/faststart.conf" ]; then
  cp -f "$DATADIR/faststart/faststart.conf" "$DATADIR/btx.conf"
fi
touch "$DATADIR/btx.conf"
for kv in prune=4096 dnsseed=1 listen=1 maxconnections=96 blockfilterindex=0 fastshieldedstartup=1 shieldedstartupaudit=0 miningchainguardminpeers=1 miningchainguardmaxmediangap=30 dbcache=300 maxmempool=100; do
  key=${kv%%=*}
  if grep -q "^${key}=" "$DATADIR/btx.conf" 2>/dev/null; then
    sed -i "s/^${key}=.*/${kv}/" "$DATADIR/btx.conf"
  else
    echo "$kv" >> "$DATADIR/btx.conf"
  fi
done
for node in node.btx.tools peers.minebtx.com 164.90.246.229 146.190.179.86 143.198.155.4; do
  grep -qx "addnode=$node" "$DATADIR/btx.conf" 2>/dev/null || echo "addnode=$node" >> "$DATADIR/btx.conf"
done
echo "btx.conf ready"

if [ "${NORESTART:-0}" = "1" ]; then
  echo "NORESTART=1: leaving btxd running (chainstate merge + RAM cleanup happen on its next natural restart)."
else
  echo "--- restarting btxd (guard will relaunch it) ---"
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 stop 2>&1 || true
  for _ in $(seq 1 60); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
  echo "btxd stopped: $(pgrep -x btxd >/dev/null 2>&1 && echo no || echo yes)"
fi
