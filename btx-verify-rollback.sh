#!/usr/bin/env bash
# Wait for the miner to come up on 0.4.14 and confirm GPU active + auto-update stayed off.
for i in $(seq 1 30); do pgrep -f '[b]tx-gbt-solve' >/dev/null && break; sleep 2; done
echo "=== running solver sha (must be 2c93d27 = 0.4.14, NOT re-updated) ==="
pid=$(pgrep -f '[b]tx-gbt-solve' | head -1)
[ -n "$pid" ] && sha256sum "/proc/$pid/exe" 2>/dev/null | cut -c1-16 || echo "solver not up"
sha256sum /home/eldian/.dexbtx-miner/bin/btx-gbt-solve | cut -c1-16
echo "=== auto-update check: did it try to update? (should be skipped) ==="
grep -E 'solver auto-update|NO_SOLVER_AUTOUPDATE|skipping' /mnt/d/BTX/dexbtx-miner.log | tail -2
echo "=== GPU after warmup (expect ~50W working, not 37W idle) ==="
sleep 20
for i in 1 2 3 4; do nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader | head -1; sleep 4; done
echo "=== recent shares ==="
grep -E 'share OK|submit raised' /mnt/d/BTX/dexbtx-miner.log | tail -3
