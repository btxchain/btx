#!/usr/bin/env bash
# Resume BTX under the guard on v0.4.19, with solver auto-update ENABLED (user opted in).
set -u
GUARD=/mnt/d/btx/btx-pool-guard.sh
echo "=== enable auto-update in guard ==="
sed -i 's/DEXBTX_NO_SOLVER_AUTOUPDATE:-1/DEXBTX_NO_SOLVER_AUTOUPDATE:-0/' "$GUARD"
grep -nE 'DEXBTX_NO_SOLVER_AUTOUPDATE' "$GUARD" | head -1
echo "=== launch guard (auto-update ON) ==="
rm -f /tmp/btx-pool-guard.stop; rmdir /tmp/btx-pool-guard.lock 2>/dev/null || true
: > /mnt/d/BTX/dexbtx-miner.log
DEXBTX_NO_SOLVER_AUTOUPDATE=0 nohup bash "$GUARD" run >>/mnt/d/BTX/btx-pool-guard.log 2>&1 &
disown
echo "launched; warming up ~45s..."
sleep 45
echo "=== verify ==="
pgrep -af '[d]exbtx-miner|[b]tx-gbt-solve|[b]tx-pool-guard' | sed 's#--config.*##' | head
echo "--- GPU ---"; for i in 1 2 3; do nvidia-smi --query-gpu=power.draw,utilization.gpu --format=csv,noheader; sleep 3; done
echo "--- shares ---"; grep -aoE 'a/r/b=[0-9]+/[0-9]+/[0-9]+' /mnt/d/BTX/dexbtx-miner.log 2>/dev/null | tail -1
echo "--- pkg/solver ---"; echo "pkg=$(pip show dexbtx-miner 2>/dev/null | awk '/^Version/{print $2}')  solver=$(sha256sum /home/eldian/.dexbtx-miner/bin/btx-gbt-solve | cut -c1-16)"
