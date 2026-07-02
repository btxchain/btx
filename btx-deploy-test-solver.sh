#!/usr/bin/env bash
# Deploy the v0.32.11 solver and TEST it uninterrupted (no guard) to see if the
# GPU scan engages on this sm_86 RTX 3090. Rollback binary stays at .0.4.14-good-bak.
set -u
BIN=/home/eldian/.dexbtx-miner/bin
SRC=/mnt/d/BTX/v032.11-solver/btx-gbt-solve
CFG=/home/eldian/.dexbtx-miner/config.yaml
TESTLOG=/mnt/d/BTX/btx-solver-test.log

echo "=== config (gpu_inputs etc.) ==="
grep -nE 'gpu_inputs|solver_batch|solver_threads|prepare_workers|pipeline|pool_host|pool_port|address|worker' "$CFG" 2>/dev/null

echo ""; echo "=== stop guard + miner + solver ==="
bash /mnt/d/btx/btx-pool-guard.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3

echo "=== backup current solver, deploy v0.32.11 ==="
cp -f "$BIN/btx-gbt-solve" "$BIN/btx-gbt-solve.0.4.14-good-bak"
echo "was: $(sha256sum "$BIN/btx-gbt-solve" | cut -c1-16)"
cp -f "$SRC" "$BIN/btx-gbt-solve"; chmod +x "$BIN/btx-gbt-solve"
echo "now: $(sha256sum "$BIN/btx-gbt-solve" | cut -c1-16)  (v0.32.11 fix = 3f7bd3f7)"

echo ""; echo "=== start miner manually (auto-update OFF), uninterrupted ==="
: > "$TESTLOG"
DEXBTX_NO_SOLVER_AUTOUPDATE=1 nohup /home/eldian/.local/bin/dexbtx-miner --config "$CFG" >>"$TESTLOG" 2>&1 &
MPID=$!
echo "miner pid $MPID"

echo "=== warm up 30s, then sample GPU 10x (4s) ==="
sleep 30
peak=0
for i in $(seq 1 10); do
  line=$(nvidia-smi --query-gpu=utilization.gpu,power.draw,clocks.sm --format=csv,noheader 2>/dev/null)
  echo "$line"
  w=$(echo "$line" | sed -E 's/.*, ([0-9]+)\.[0-9]+ W.*/\1/')
  [ -n "$w" ] && [ "$w" -gt "$peak" ] 2>/dev/null && peak=$w
  sleep 4
done
echo "PEAK_POWER_W=$peak"

echo ""; echo "=== shares / scan / errors in test log ==="
grep -iE 'share OK|accepted|reject|code 23|>= share_target|error|scan|cuda|fail|seed' "$TESTLOG" | tail -15
echo "--- last 4 raw lines ---"; tail -4 "$TESTLOG"
echo ""; echo "VERDICT: peak GPU power = ${peak}W (>150W = scan engaged/working; ~32-40W = still CPU-fallback/idle)"
