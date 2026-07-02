#!/usr/bin/env bash
# BTX solo-mining guard. This is intentionally node-gated: solo mining needs a
# local btxd that can serve getblocktemplate and accept mined blocks.
set -u
export BTX_MATMUL_BACKEND=${BTX_MATMUL_BACKEND:-cuda}
CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
BTXD=${BTXD:-/home/eldian/btx-node/bin/btxd}
DATADIR=${DATADIR:-/home/eldian/.btx}
WALLET=${WALLET:-my-wallet}
ADDR=${SOLO_ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}
LOG=${LOG:-/mnt/d/BTX/btx-solo-guard.log}
SOLO_LOG=${SOLO_LOG:-/mnt/d/BTX/btx-solo-miner.log}
SYNC_SCRIPT=${SYNC_SCRIPT:-/mnt/d/BTX/btx-sync-fast.sh}
SYNC_LOCK=${SYNC_LOCK:-/tmp/btx-sync-fast.lock}
STOP=${STOP:-/tmp/btx-solo-guard.stop}
PIDFILE=${PIDFILE:-/tmp/btx-solo-guard.pid}
LOCKDIR=${LOCKDIR:-/tmp/btx-solo-guard.lock}
# Solo needs local templates. The min-peer guards prevent isolated/stale mining;
# keep the defaults at 0 here so the local test/switch is usable, then raise them
# later if you want stricter production solo policy.
BTXD_ARGS=${BTXD_ARGS:--blockfilterindex=0 -miningminoutboundpeers=0 -miningminsyncedoutboundpeers=0 -fastshieldedstartup=1 -dbcache=1500}

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
solo_running() { pgrep -f '^bash /mnt/d/BTX/btx-mine\.sh$|^/usr/bin/env bash /mnt/d/BTX/btx-mine\.sh$|^/bin/bash /mnt/d/BTX/btx-mine\.sh$' >/dev/null 2>&1; }
kill_solo() { pkill -f '/mnt/d/BTX/btx-mine.sh' 2>/dev/null || true; }

case "${1:-run}" in
  stop)
    touch "$STOP"
    if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; fi
    kill_solo
    rm -f "$PIDFILE"
    rmdir "$LOCKDIR" 2>/dev/null || true
    log "Stop requested; solo guard stopped. btxd left running for wallet/RPC safety."
    exit 0
    ;;
  status)
    echo "solo_guard_pid=$(cat "$PIDFILE" 2>/dev/null || true)"
    echo "solo_guard_running=$(if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then echo yes; else echo no; fi)"
    echo "solo_miner_running=$(if solo_running; then echo yes; else echo no; fi)"
    "$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null | tr -d '\n' || true
    echo
    exit 0
    ;;
  run|start) ;;
  *) echo "Usage: $0 [run|start|stop|status]"; exit 2 ;;
esac

if ! mkdir "$LOCKDIR" 2>/dev/null; then
  oldpid=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    log "Solo guard already running (pid $oldpid)."
    exit 0
  fi
  # Lock left behind by a hard-killed guard (traps don't run on kill -9): reclaim it.
  log "Stale solo-guard lock (owner ${oldpid:-unknown} is dead); reclaiming."
  rmdir "$LOCKDIR" 2>/dev/null || true
  mkdir "$LOCKDIR" 2>/dev/null || { log "Lock reclaim lost a race; exiting."; exit 0; }
fi
trap 'rm -f "$PIDFILE"; rmdir "$LOCKDIR" 2>/dev/null || true' EXIT
echo $$ > "$PIDFILE"
rm -f "$STOP"
mkdir -p "$(dirname "$LOG")" "$(dirname "$SOLO_LOG")"
log "=== BTX solo guard started (backend=$BTX_MATMUL_BACKEND, addr=$ADDR) ==="
FAST_SYNC_FAILURES=0
MAX_FAST_SYNC_RETRIES=3
# Consecutive btxd launches with no successful RPC in between. Three in a row
# means a startup crash loop (e.g. stale shielded mutation marker forcing a
# genesis replay that pruned/assumeutxo nodes cannot complete) — restarting
# btxd again will never fix it, only a fresh datadir + snapshot reload does.
NODE_STARTS=0

while [ ! -e "$STOP" ]; do
  if [ ! -x "$BTXD" ] || [ ! -x "$CLI" ]; then
    log "Missing BTX binaries. Run /mnt/d/BTX/btx-update-latest.sh first."
    sleep 30
    continue
  fi

  if [ -d "$SYNC_LOCK" ]; then
    # The sync flow holds the lock through background snapshot validation,
    # during which it only polls read-only RPC. Once the node reports it is
    # out of IBD the destructive phases (datadir wipe, loadtxoutset) are
    # over, so mining can start without waiting for validation to finish.
    sync_ibd=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print("0" if not d.get("initialblockdownload", True) else "1")' 2>/dev/null || echo '1')
    if [ "$sync_ibd" = "0" ]; then
      if ! solo_running; then
        log "Fast sync lock present but node is at tip (background validation only); proceeding with solo mining."
      fi
      # Zombie monitor: btx-faststart.py waits for the snapshot chainstate to
      # lose its snapshot_blockhash tag, which only happens on a btxd restart,
      # so after validation completes it polls forever and the lock never
      # releases. Detect "everything validated but lock still held" and finish
      # the sync (kill monitor, merge conf, release lock) without a restart.
      all_validated=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getchainstates 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); cs=d.get("chainstates",[]); print("1" if cs and all(c.get("validated") for c in cs) else "0")' 2>/dev/null || echo '0')
      if [ "$all_validated" = "1" ]; then
        log "Background validation complete but the sync monitor still holds the lock; finishing sync (conf merge + lock release)."
        NORESTART=1 bash /mnt/d/BTX/btx-finish-sync.sh >>"$LOG" 2>&1 || true
      fi
    else
      log "Fast sync is running; solo mining waits for local node sync. See /mnt/d/BTX/btx-sync-fast.log."
      kill_solo
      # GPU must not idle during the header/snapshot phase either.
      if ! pgrep -f "[d]exbtx-miner" >/dev/null 2>&1; then
        log "GPU idle during fast-sync; starting pool mining meanwhile (auto-stops at tip)."
        nohup bash /mnt/d/BTX/btx-pool-guard.sh run >>/mnt/d/BTX/btx-smart-pool-launch.log 2>&1 </dev/null &
      fi
      sleep 30
      continue
    fi
  fi

  if ! pgrep -f btxd >/dev/null 2>&1; then
    # Escalate fast only on the known-unrecoverable signature (stale shielded
    # mutation marker forcing a genesis replay). Unknown crash causes are often
    # transient (e.g. CUDA not ready right after WSL boot), so give btxd many
    # more retries before paying for a datadir wipe + snapshot reload.
    ESCALATE_AT=10
    if tail -50 "$DATADIR/debug.log" /mnt/d/BTX/btx-faststart-debug.log 2>/dev/null \
        | grep -q 'RebuildShieldedState: replaying.*genesis\|Refusing the destructive rebuild'; then
      ESCALATE_AT=3
    fi
    if [ "$NODE_STARTS" -ge "$ESCALATE_AT" ]; then
      log "btxd crashed $NODE_STARTS times without RPC ever coming up (threshold $ESCALATE_AT) — startup crash loop. Escalating to fresh snapshot sync instead of restarting btxd."
      if [ -x "$SYNC_SCRIPT" ] && [ ! -d "$SYNC_LOCK" ] && [ "$FAST_SYNC_FAILURES" -lt "$MAX_FAST_SYNC_RETRIES" ]; then
        NODE_STARTS=0
        nohup bash "$SYNC_SCRIPT" >>/mnt/d/BTX/btx-sync-fast-launch.log 2>&1 < /dev/null &
        log "Fast sync launched to replace crash-looping node. See /mnt/d/BTX/btx-sync-fast.log."
        sleep 60
        continue
      fi
      log "Fast sync unavailable (missing, already running, or retry budget spent); will keep retrying btxd."
      NODE_STARTS=0
    fi
    log "btxd is not running; starting node for solo mining ($BTXD_ARGS)."
    rm -f "$DATADIR/.lock"
    NODE_STARTS=$((NODE_STARTS + 1))
    BTX_MATMUL_BACKEND="$BTX_MATMUL_BACKEND" "$BTXD" -datadir="$DATADIR" $BTXD_ARGS -daemon >>"$LOG" 2>&1 || true
  fi

  info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
  if [ -z "$info" ]; then
    # GPU should not idle while the node warms up / loads its index either.
    if ! pgrep -f "[d]exbtx-miner" >/dev/null 2>&1; then
      log "GPU idle while node RPC warms up; starting pool mining meanwhile (auto-stops at tip)."
      nohup bash /mnt/d/BTX/btx-pool-guard.sh run >>/mnt/d/BTX/btx-smart-pool-launch.log 2>&1 </dev/null &
    fi
    log "RPC not ready; solo mining blocked. Last debug.log lines:"
    python3 - "$DATADIR/debug.log" >>"$LOG" 2>/dev/null <<'PY' || true
import pathlib, sys
p=pathlib.Path(sys.argv[1])
if p.exists():
    print('\n'.join(p.read_text(errors='replace').splitlines()[-20:]))
PY
    if ! pgrep -f btxd >/dev/null 2>&1; then
      if tail -30 "$DATADIR/debug.log" 2>/dev/null | grep -q 'Failed to initialize shielded state\|RebuildShieldedState.*failed'; then
        log "Shielded state rebuild failure detected. Removing corrupt shielded_state and retrying."
        rm -rf "$DATADIR/shielded_state"
      fi
    fi
    sleep 30
    continue
  fi

  NODE_STARTS=0
  blocks=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("blocks","?"))' 2>/dev/null || echo '?')
  headers=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("headers","?"))' 2>/dev/null || echo '?')
  ibd=$(printf '%s' "$info" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("1" if d.get("initialblockdownload", True) else "0")' 2>/dev/null || echo '1')
  if [ "$ibd" = "1" ]; then
    log "Node still syncing: $blocks/$headers; solo miner paused. Starting fast snapshot sync if far behind and not already running."
    kill_solo
    # Smart-mine: never let the GPU idle — pool-mine on minebtx while the node syncs.
    # (Bracketed pgrep so the pattern cannot match this script's own command line.)
    if ! pgrep -f "[d]exbtx-miner" >/dev/null 2>&1; then
      log "GPU idle during sync; starting pool mining meanwhile (auto-stops at tip)."
      nohup bash /mnt/d/BTX/btx-pool-guard.sh run >>/mnt/d/BTX/btx-smart-pool-launch.log 2>&1 </dev/null &
    fi
    if [ "${blocks:-0}" -lt 100000 ] && [ -x "$SYNC_SCRIPT" ] && [ ! -d "$SYNC_LOCK" ] && [ "$FAST_SYNC_FAILURES" -lt "$MAX_FAST_SYNC_RETRIES" ]; then
      nohup bash "$SYNC_SCRIPT" >>/mnt/d/BTX/btx-sync-fast-launch.log 2>&1 < /dev/null &
      log "Fast sync launched (attempt $((FAST_SYNC_FAILURES + 1))/$MAX_FAST_SYNC_RETRIES). See /mnt/d/BTX/btx-sync-fast.log."
      sleep 60
      if [ ! -d "$SYNC_LOCK" ]; then
        FAST_SYNC_FAILURES=$((FAST_SYNC_FAILURES + 1))
        log "Fast sync exited quickly (failure $FAST_SYNC_FAILURES/$MAX_FAST_SYNC_RETRIES)."
      fi
    elif [ "$FAST_SYNC_FAILURES" -ge "$MAX_FAST_SYNC_RETRIES" ]; then
      log "Fast sync failed $FAST_SYNC_FAILURES times; waiting for normal peer catch-up instead."
    else
      log "Fast snapshot already loaded or node is close enough; waiting for normal peer catch-up."
    fi
    sleep 30
    continue
  fi

  FAST_SYNC_FAILURES=0
  mining_info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getmininginfo 2>/dev/null || true)
  if printf '%s' "$mining_info" | grep -q '"should_pause_mining"[[:space:]]*:[[:space:]]*true'; then
    log "Chain guard says pause mining; solo miner paused."
    kill_solo
    sleep 30
    continue
  fi

  if ! solo_running; then
    # Node is at tip: hand the GPU from pool mining to solo before starting the loop.
    if pgrep -f "[d]exbtx-miner" >/dev/null 2>&1 || pgrep -f "[b]tx-pool-guard.sh" >/dev/null 2>&1; then
      log "Node synced; stopping pool mining and handing the GPU to solo."
      bash /mnt/d/BTX/btx-pool-guard.sh stop >>"$LOG" 2>&1 || true
      sleep 2
    fi
    log "Starting solo generate loop: /mnt/d/BTX/btx-mine.sh (addr=$ADDR)."
    nohup env CLI="$CLI" DATADIR="$DATADIR" ADDR="$ADDR" /mnt/d/BTX/btx-mine.sh >>"$SOLO_LOG" 2>&1 &
  fi
  sleep 20
done

log "Stop flag seen; stopping solo miner and exiting guard."
kill_solo
rm -f "$STOP" "$PIDFILE"
