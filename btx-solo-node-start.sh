#!/usr/bin/env bash
# Start btxd (node only) for solo mining prep and report sync status.
set -u
export BTX_MATMUL_BACKEND=${BTX_MATMUL_BACKEND:-cuda}
BTXD=/home/eldian/btx-node/bin/btxd
CLI=/home/eldian/btx-node/bin/btx-cli
DATADIR=/home/eldian/.btx

if ! pgrep -x btxd >/dev/null 2>&1; then
  rm -f "$DATADIR/.lock" 2>/dev/null || true
  echo "--- starting btxd v0.32.12 (node-only, daemon) ---"
  "$BTXD" -datadir="$DATADIR" -blockfilterindex=0 -miningminoutboundpeers=0 \
          -miningminsyncedoutboundpeers=0 -fastshieldedstartup=1 -daemon 2>&1 | tail -3
else
  echo "btxd already running"
fi

echo "--- waiting for RPC (up to ~90s) ---"
info=""
for i in $(seq 1 30); do
  info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null) && [ -n "$info" ] && break
  sleep 3
done

if [ -n "$info" ]; then
  printf '%s' "$info" | python3 - <<'PY'
import json,sys
d=json.load(sys.stdin)
print("blocks   =", d.get("blocks"))
print("headers  =", d.get("headers"))
print("ibd      =", d.get("initialblockdownload"))
print("progress = %.5f" % d.get("verificationprogress",0))
print("chain    =", d.get("chain"))
PY
  echo "peers    = $("$CLI" -datadir="$DATADIR" getconnectioncount 2>/dev/null)"
else
  echo "RPC not up yet (shielded-state init can take a while). debug.log tail:"
  tail -6 "$DATADIR/debug.log" 2>/dev/null
fi
echo "btxd_running = $(pgrep -x btxd >/dev/null && echo yes || echo no)"
