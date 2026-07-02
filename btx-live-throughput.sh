#!/usr/bin/env bash
# Measure the LIVE pool miner: slice-dispatch cadence + GPU saturation over a window.
# "solver: working ... slice=N" lines mark each dispatched nonce slice.
set -u
LOG=/mnt/d/BTX/dexbtx-miner.log
WINDOW=${WINDOW:-60}
SLICE=$(grep -oE 'slice=[0-9]+' "$LOG" | tail -1 | cut -d= -f2); SLICE=${SLICE:-2000000}

start_slices=$(grep -c 'solver: working' "$LOG")
# GPU samples during the window
gpu_acc=0; gpu_n=0; gpu_max=0
end=$((SECONDS+WINDOW))
while [ $SECONDS -lt $end ]; do
  u=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -1)
  [ -n "$u" ] && { gpu_acc=$((gpu_acc+u)); gpu_n=$((gpu_n+1)); [ "$u" -gt "$gpu_max" ] && gpu_max=$u; }
  sleep 3
done
end_slices=$(grep -c 'solver: working' "$LOG")

ds=$((end_slices-start_slices))
rate=$(python3 -c "print(int($ds*$SLICE/$WINDOW))")
echo "slices_dispatched=$ds over ${WINDOW}s (slice_size=$SLICE)"
echo "nonce_rate=$rate H/s ($(python3 -c "print('%.1f'%($rate/1000))") kH/s)"
[ "$gpu_n" -gt 0 ] && echo "gpu_util avg=$((gpu_acc/gpu_n))% max=${gpu_max}%"
echo "recent notify cadence:"; grep -E 'solver: working|notify job' "$LOG" | tail -6
