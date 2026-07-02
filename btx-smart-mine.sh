#!/usr/bin/env bash
# BTX smart-mine launcher (thin, exits in seconds — no long-lived watcher needed).
# Starts the node fast-sync if the node is behind, then the solo guard. The solo guard
# itself pool-mines on the GPU while the node syncs and hands the GPU to solo at tip.
set -u
SYNC_FAST=${SYNC_FAST:-/mnt/d/BTX/btx-sync-fast.sh}
SOLO_GUARD=${SOLO_GUARD:-/mnt/d/BTX/btx-solo-guard.sh}
SYNC_LOCK=${SYNC_LOCK:-/tmp/btx-sync-fast.lock}
LOG=${LOG:-/mnt/d/BTX/btx-smart-mine.log}

log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

case "${1:-run}" in
  stop)
    bash /mnt/d/BTX/btx-pool-guard.sh stop >/dev/null 2>&1 || true
    bash "$SOLO_GUARD" stop >/dev/null 2>&1 || true
    log "smart-mine stop: guards stopped."
    exit 0
    ;;
  run|start) ;;
  *) echo "Usage: $0 [run|stop]"; exit 2 ;;
esac

log "=== smart-mine launch: sync (if needed) + solo guard (pool-mines during sync, solo at tip) ==="
printf 'BTX_MINING_MODE=solo\n' > /mnt/d/BTX/btx-mining-mode.conf

if [ ! -d "$SYNC_LOCK" ]; then
  chmod +x "$SYNC_FAST" 2>/dev/null || true
  nohup bash "$SYNC_FAST" >>/mnt/d/BTX/btx-smart-sync-launch.log 2>&1 </dev/null &
  log "fast-sync launched (it decides on its own whether a snapshot is actually needed)."
else
  log "fast-sync already running; leaving it alone."
fi

chmod +x "$SOLO_GUARD" /mnt/d/BTX/btx-pool-guard.sh 2>/dev/null || true
nohup bash "$SOLO_GUARD" run >>/mnt/d/BTX/btx-smart-solo-launch.log 2>&1 </dev/null &
log "solo guard launched. Done — everything else is automatic."
