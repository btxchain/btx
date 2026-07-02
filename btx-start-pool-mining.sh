#!/usr/bin/env bash
# Hand BTX from the manual test miner to the managed pool guard (new solver stays deployed).
set -u
echo "=== stop manual test miner + solver ==="
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
echo "deployed solver: $(sha256sum /home/eldian/.dexbtx-miner/bin/btx-gbt-solve | cut -c1-16)  (want 3fbc9d71)"

echo "=== truncate runaway 7.5GB miner log ==="
: > /mnt/d/BTX/dexbtx-miner.log

echo "=== launch pool guard (auto-update OFF; manages miner + idle watchdog) ==="
rm -f /tmp/btx-pool-guard.stop; rmdir /tmp/btx-pool-guard.lock 2>/dev/null || true
DEXBTX_NO_SOLVER_AUTOUPDATE=1 nohup bash /mnt/d/btx/btx-pool-guard.sh run >>/mnt/d/BTX/btx-pool-guard.log 2>&1 &
disown
echo "guard launched (pid $!)"
sleep 50

echo "=== guard miner up? + GPU + pool activity ==="
pgrep -af '[d]exbtx-miner|[b]tx-gbt-solve' | sed 's/--config.*//' | head
for i in 1 2 3; do nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader; sleep 3; done
echo "--- pool log (shares/work) ---"; grep -aiE 'share OK|accepted|reject|difficulty set|subscribe|authorize|working' /mnt/d/BTX/dexbtx-miner.log 2>/dev/null | tail -6
echo "--- guard log ---"; tail -3 /mnt/d/BTX/btx-pool-guard.log 2>/dev/null
