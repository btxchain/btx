#!/usr/bin/env bash
# Deploy the NEW static-CUDA solver (3fbc9d71) and test GPU engagement on sm_86.
set -u
BIN=/home/eldian/.dexbtx-miner/bin
SRC=/mnt/d/BTX/v032.11-solver-new/btx-gbt-solve
CFG=/home/eldian/.dexbtx-miner/config.yaml
TESTLOG=/mnt/d/BTX/btx-newsolver-test.log

echo "=== stop any guard/miner/solver ==="
bash /mnt/d/btx/btx-pool-guard.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3

echo "=== deploy NEW solver (static CUDA, runs on 12+13) ==="
cp -f "$BIN/btx-gbt-solve" "$BIN/btx-gbt-solve.prev-bak" 2>/dev/null || true
cp -f "$SRC" "$BIN/btx-gbt-solve"; chmod +x "$BIN/btx-gbt-solve"
echo "deployed sha: $(sha256sum "$BIN/btx-gbt-solve" | cut -c1-16)  (new=3fbc9d71)"
echo "ldd cuda: $(ldd "$BIN/btx-gbt-solve" 2>&1 | grep -ciE 'libcudart') dynamic-cudart refs (0 = statically linked = good)"

echo "=== run miner manually (auto-update OFF), watch GPU ~80s ==="
: > "$TESTLOG"
DEXBTX_NO_SOLVER_AUTOUPDATE=1 nohup /home/eldian/.local/bin/dexbtx-miner --config "$CFG" >>"$TESTLOG" 2>&1 &
echo "miner pid $!"
sleep 30
peak=0
for i in $(seq 1 12); do
  line=$(nvidia-smi --query-gpu=utilization.gpu,power.draw,clocks.sm --format=csv,noheader 2>/dev/null)
  echo "$line"
  w=$(echo "$line" | sed -E 's/.*, ([0-9]+)\.[0-9]+ W.*/\1/')
  [ -n "$w" ] && [ "$w" -gt "$peak" ] 2>/dev/null && peak=$w
  sleep 4
done
echo "PEAK_POWER_W=$peak"
echo "=== pool / shares / errors ==="
grep -iE 'share OK|accepted|reject|code 23|error|connecting to pool|subscribe|authorize|difficulty set|pool closed' "$TESTLOG" | tail -15
echo "--- last 3 raw lines ---"; tail -3 "$TESTLOG"
echo "VERDICT: peak GPU = ${peak}W  (>150W = WORKING; ~30-50W = still idle)"
