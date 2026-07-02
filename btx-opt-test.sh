#!/usr/bin/env bash
# Launch the pool miner with EXTRA_ENV solver knobs (no guard), measure GPU
# power/util + solver CPU% + share accept over a window. Reports averages.
set -u
CFG=/home/eldian/.dexbtx-miner/config.yaml
MINER=/home/eldian/.local/bin/dexbtx-miner
LOG=/mnt/d/BTX/dexbtx-miner.log
EXTRA_ENV=${EXTRA_ENV:-}
WARMUP=${WARMUP:-30}
SAMPLES=${SAMPLES:-8}

pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
ok_before=$(grep -c 'share OK' "$LOG")
# shellcheck disable=SC2086
nohup env BTX_MATMUL_BACKEND=cuda $EXTRA_ENV "$MINER" --config "$CFG" >>"$LOG" 2>&1 &
disown
echo "EXTRA_ENV: ${EXTRA_ENV:-<none>}"
echo "warming up ${WARMUP}s..."
for i in $(seq 1 30); do pgrep -f '[b]tx-gbt-solve' >/dev/null && break; sleep 1; done
sleep "$WARMUP"
pw_sum=0; ut_sum=0; pw_max=0; n=0
solver_pid=$(pgrep -f '[b]tx-gbt-solve' | head -1)
cpu_sum=0
for i in $(seq 1 "$SAMPLES"); do
  read ut pw <<<"$(nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader,nounits | head -1 | awk -F',' '{gsub(/ /,"");print $1, $2}')"
  cpu=$(ps -o %cpu= -p "$solver_pid" 2>/dev/null | tr -d ' '); cpu=${cpu:-0}
  echo "  util=${ut}% power=${pw}W solverCPU=${cpu}%"
  pw_sum=$(awk "BEGIN{print $pw_sum+$pw}"); ut_sum=$((ut_sum+${ut%.*})); n=$((n+1))
  awk "BEGIN{exit !($pw>$pw_max)}" && pw_max=$pw
  cpu_sum=$(awk "BEGIN{print $cpu_sum+$cpu}")
  sleep 3
done
ok_after=$(grep -c 'share OK' "$LOG")
echo "=== RESULT ==="
awk "BEGIN{printf \"avg_power=%.0fW peak_power=%.0fW avg_util=%.0f%% avg_solverCPU=%.0f%% accepts_in_window=%d\n\", $pw_sum/$n, $pw_max, $ut_sum/$n, $cpu_sum/$n, $ok_after-$ok_before}"
