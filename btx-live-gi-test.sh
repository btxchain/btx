#!/usr/bin/env bash
# Test a gpu_inputs value against the LIVE pool (no btxd needed). Sets config,
# runs the miner directly (no guard, so no restart-loop interference), waits for
# steady state, samples GPU, and reports recent share accept/reject.
set -u
CFG=/home/eldian/.dexbtx-miner/config.yaml
MINER=/home/eldian/.local/bin/dexbtx-miner
LOG=/mnt/d/BTX/dexbtx-miner.log
GI=${GI:-1}; BATCH=${BATCH:-128}; TH=${TH:-8}

pkill -f '[d]exbtx-miner' 2>/dev/null; pkill -f '[b]tx-gbt-solve' 2>/dev/null; sleep 2
sed -i "s/^gpu_inputs:.*/gpu_inputs: $GI/" "$CFG"
sed -i "s/^solver_batch_size:.*/solver_batch_size: $BATCH/" "$CFG"
sed -i "s/^solver_threads:.*/solver_threads: $TH/" "$CFG"
echo "config: gpu_inputs=$GI batch=$BATCH threads=$TH"

nohup env BTX_MATMUL_BACKEND=cuda "$MINER" --config "$CFG" >>"$LOG" 2>&1 &
echo "miner started pid $!; waiting for solver + steady state..."
for i in $(seq 1 30); do pgrep -f '[b]tx-gbt-solve' >/dev/null && break; sleep 2; done
sleep 25  # let it connect, get jobs, ramp
echo "=== GPU samples (6 over ~18s) ==="
mx=0
for i in $(seq 1 6); do
  line=$(nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw --format=csv,noheader,nounits | head -1)
  echo "  $line"
  u=$(echo "$line" | awk -F',' '{gsub(/ /,"",$1);print $1}')
  [ "$u" -gt "$mx" ] 2>/dev/null && mx=$u
  sleep 3
done
echo "peak_util=${mx}%"
echo "=== recent share results ==="
grep -E 'share OK|submit raised' "$LOG" | tail -4
