#!/usr/bin/env bash
# Start btxd v0.32.8 on the existing datadir and verify it operates (RPC + tip).
# Pool-safe: does not touch the pool guard/miner.
set -u
export BTX_MATMUL_BACKEND=cuda
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd
DATADIR=/home/eldian/.btx

pkill -x btxd 2>/dev/null || true; sleep 2
rm -f "$DATADIR/.lock"
echo "=== starting btxd v0.32.8 ==="
"$BTXD" -datadir="$DATADIR" -blockfilterindex=0 -fastshieldedstartup=1 -daemon 2>&1 | head -3
echo "waiting for RPC..."
ok=0
for i in $(seq 1 40); do
  info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
  if [ -n "$info" ]; then ok=1; break; fi
  sleep 3
done
if [ "$ok" = 1 ]; then
  echo "=== RPC up ==="
  printf '%s' "$info" | grep -E '"(chain|blocks|headers|initialblockdownload|verificationprogress)"'
  echo "=== version ==="
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getnetworkinfo 2>/dev/null | grep -E '"(version|subversion)"'
else
  echo "=== RPC did NOT come up; last debug.log lines ==="
  tail -25 "$DATADIR/debug.log" 2>/dev/null
fi
