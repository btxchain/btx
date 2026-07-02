#!/usr/bin/env bash
# Run luckypool SOLO mining with the racer miner (no local node needed).
# The pool runs the node; a found block pays the full reward minus 1% to ADDR.
# Stop: pkill -f "racer -a btx"     Log: /mnt/d/BTX/racer.log
set -u
ADDR=${ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}
WORKER=${WORKER:-$(hostname)}
POOL=${POOL:-btx-eu.lproute.com:8660}
BIN=${BIN:-/home/eldian/racer/racer/racer}
LOG=${LOG:-/mnt/d/BTX/racer.log}
export LD_LIBRARY_PATH=/usr/lib/wsl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

case "${1:-run}" in
  stop) pkill -f "[r]acer -a btx" 2>/dev/null; echo "racer stopped"; exit 0 ;;
  status)
    pgrep -f "[r]acer -a btx" >/dev/null && echo "racer_running=yes" || echo "racer_running=no"
    tail -3 "$LOG" 2>/dev/null; exit 0 ;;
  run|start) ;;
  *) echo "Usage: $0 [run|stop|status]"; exit 2 ;;
esac

pgrep -f "[r]acer -a btx" >/dev/null && { echo "racer already running"; exit 0; }
echo "[$(date '+%F %T')] starting racer SOLO -> $POOL (addr=$ADDR worker=$WORKER)" >> "$LOG"
# Call this script SYNCHRONOUSLY (it returns in ~2s); racer detaches as its nohup child.
nohup "$BIN" -a btx -o "stratum+tcp://$POOL" -u "solo:$ADDR.$WORKER" -p x >> "$LOG" 2>&1 </dev/null &
sleep 2
pgrep -f "[r]acer -a btx" >/dev/null && echo "racer started (log: $LOG)" || { echo "racer FAILED to start; see $LOG"; exit 1; }
