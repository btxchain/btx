#!/usr/bin/env bash
# Sample GPU util/clock/power N times; report min/avg/max util.
N=${1:-10}; IVAL=${2:-2}
vals=()
for i in $(seq 1 "$N"); do
  line=$(nvidia-smi --query-gpu=utilization.gpu,clocks.sm,power.draw,memory.used --format=csv,noheader,nounits)
  echo "$line"
  u=$(echo "$line" | awk -F',' '{gsub(/ /,"",$1); print $1}')
  vals+=("$u")
  sleep "$IVAL"
done
printf '%s\n' "${vals[@]}" | awk 'BEGIN{mn=999;mx=0} {s+=$1; n++; if($1<mn)mn=$1; if($1>mx)mx=$1} END{printf "util: min=%d avg=%.1f max=%d over %d samples\n", mn, s/n, mx, n}'
