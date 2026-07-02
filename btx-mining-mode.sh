#!/usr/bin/env bash
# Switch BTX mining mode between pool and solo from Windows/WSL.
set -u
MODE_FILE=${MODE_FILE:-/mnt/d/BTX/btx-mining-mode.conf}
POOL_GUARD=${POOL_GUARD:-/mnt/d/BTX/btx-pool-guard.sh}
SOLO_GUARD=${SOLO_GUARD:-/mnt/d/BTX/btx-solo-guard.sh}
HASHRATE=${HASHRATE:-/mnt/d/BTX/btx-hashrate.sh}
SOLO_HASHRATE=${SOLO_HASHRATE:-/mnt/d/BTX/btx-solo-hashrate.sh}
SOLO_STATS=${SOLO_STATS:-/mnt/d/BTX/btx-solo-stats.sh}
SYNC_FAST=${SYNC_FAST:-/mnt/d/BTX/btx-sync-fast.sh}
LAUNCH_LOG=${LAUNCH_LOG:-/mnt/d/BTX/btx-mode-switch.log}

get_mode() {
  if [ -f "$MODE_FILE" ]; then
    . "$MODE_FILE" 2>/dev/null || true
  fi
  case "${BTX_MINING_MODE:-pool}" in solo) echo solo ;; *) echo pool ;; esac
}
set_mode_file() {
  umask 077
  printf 'BTX_MINING_MODE=%s\n' "$1" > "$MODE_FILE"
}
start_detached() {
  nohup bash "$1" run >>"$LAUNCH_LOG" 2>&1 < /dev/null &
}

case "${1:-status}" in
  pool)
    chmod +x "$POOL_GUARD" "$SOLO_GUARD" "$HASHRATE" 2>/dev/null || true
    bash "$SOLO_GUARD" stop >/dev/null 2>&1 || true
    set_mode_file pool
    start_detached "$POOL_GUARD"
    sleep 2
    echo "mode=pool"
    bash "$POOL_GUARD" status 2>&1 || true
    bash "$HASHRATE" 2>&1 || true
    ;;
  solo)
    chmod +x "$POOL_GUARD" "$SOLO_GUARD" "$HASHRATE" 2>/dev/null || true
    bash "$POOL_GUARD" stop >/dev/null 2>&1 || true
    set_mode_file solo
    start_detached "$SOLO_GUARD"
    sleep 2
    echo "mode=solo"
    bash "$SOLO_GUARD" status 2>&1 || true
    echo "solo_note=solo mining requires local btxd RPC, synced chain, healthy shielded state, wallet/address, and a submit-capable mining loop; see btx-solo-guard.log"
    ;;
  stop)
    bash "$POOL_GUARD" stop 2>&1 || true
    bash "$SOLO_GUARD" stop 2>&1 || true
    echo "mode=$(get_mode)"
    echo "stopped=yes"
    ;;
  status)
    mode=$(get_mode)
    echo "mode=$mode"
    echo "--- pool ---"
    bash "$POOL_GUARD" status 2>&1 || true
    echo "--- solo ---"
    bash "$SOLO_GUARD" status 2>&1 || true
    echo "--- sync ---"
    if [ -d /tmp/btx-sync-fast.lock ]; then echo "sync_running=yes"; else echo "sync_running=no"; fi
    echo "sync_pid=$(cat /tmp/btx-sync-fast.pid 2>/dev/null || true)"
    echo "--- hashrate ---"
    bash "$HASHRATE" 2>&1 || true
    echo "--- solo hashrate ---"
    bash "$SOLO_HASHRATE" 2>&1 || true
    echo "--- solo stats ---"
    bash "$SOLO_STATS" 2>&1 || true
    ;;
  sync)
    chmod +x "$SYNC_FAST" 2>/dev/null || true
    nohup bash "$SYNC_FAST" >>"$LAUNCH_LOG" 2>&1 < /dev/null &
    sleep 2
    echo "sync=started"
    echo "log=/mnt/d/BTX/btx-sync-fast.log"
    ;;
  *)
    echo "Usage: $0 [pool|solo|sync|stop|status]" >&2
    exit 2
    ;;
esac
