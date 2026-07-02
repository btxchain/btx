#!/usr/bin/env bash
# luckypool miner control (racer). Modes: solo (no node, full block reward -1%)
# or pool (PPLNS 1%). Call SYNCHRONOUSLY: it returns in ~2s, racer self-detaches.
#   bash btx-racer.sh run solo|pool     bash btx-racer.sh stop     bash btx-racer.sh status
set -u
ADDR=${ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}
WORKER=${WORKER:-$(hostname)}
POOL=${POOL:-btx-eu.lproute.com:8660}
BIN=${BIN:-/home/eldian/racer/racer/racer}
LOG=${LOG:-/mnt/d/BTX/racer.log}
MODEFILE=/mnt/d/BTX/btx-racer.mode
export LD_LIBRARY_PATH=/usr/lib/wsl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

case "${1:-status}" in
  stop)
    pkill -f "[r]acer -a btx" 2>/dev/null
    rm -f "$MODEFILE"
    echo "racer stopped"
    exit 0
    ;;
  status)
    if pgrep -f "[r]acer -a btx" >/dev/null; then
      echo "racer_running=yes"
      echo "racer_mode=$(cat "$MODEFILE" 2>/dev/null || echo unknown)"
    else
      echo "racer_running=no"
    fi
    exit 0
    ;;
  run|start)
    mode=${2:-solo}
    case "$mode" in solo|pool) ;; *) echo "mode must be solo or pool"; exit 2 ;; esac
    ;;
  *) echo "Usage: $0 [run solo|run pool|stop|status]"; exit 2 ;;
esac

if [ ! -x "$BIN" ]; then echo "racer binary missing: $BIN"; exit 1; fi
pkill -f "[r]acer -a btx" 2>/dev/null && sleep 2
user="$ADDR.$WORKER"
[ "$mode" = "solo" ] && user="solo:$ADDR.$WORKER"
printf '%s\n' "$mode" > "$MODEFILE"
echo "[$(date '+%F %T')] starting racer $mode -> $POOL user=$user" >> "$LOG"
nohup "$BIN" -a btx -o "stratum+tcp://$POOL" -u "$user" -p x >> "$LOG" 2>&1 </dev/null &
sleep 2
if pgrep -f "[r]acer -a btx" >/dev/null; then
  echo "racer started: mode=$mode pool=$POOL"
else
  echo "racer FAILED to start; see $LOG"
  exit 1
fi
