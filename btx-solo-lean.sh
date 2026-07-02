#!/usr/bin/env bash
# Lean BTX solo miner — saturates the GPU with a tight high-maxtries generatetoaddress
# loop, self-heals the node, and SAFELY coexists with snapshot re-syncs.
#
# State machine each iteration (one cheap getblockchaininfo):
#   ok       (RPC up, ibd=false)  -> mine one tight generatetoaddress batch (GPU-saturating)
#   syncing  (RPC up, ibd=true)   -> a sync is happening; wait, never interfere
#   down     (RPC dead)           -> if a re-sync is running, wait; else after a sustained
#                                    down-streak, (re)start btxd; if it can't init its shielded
#                                    state on this pruned node, escalate to a v9 snapshot re-sync.
# Single instance is enforced at launch by the supervisor via `flock -n /tmp/btx-solo-lean.lock`.
set -u
export BTX_MATMUL_BACKEND=cuda
export BTX_MATMUL_GPU_INPUTS=${BTX_MATMUL_GPU_INPUTS:-1}
export BTX_MATMUL_SOLVE_BATCH_SIZE=${BTX_MATMUL_SOLVE_BATCH_SIZE:-128}
export BTX_MATMUL_SOLVER_THREADS=${BTX_MATMUL_SOLVER_THREADS:-8}
export BTX_MATMUL_PREPARE_WORKERS=${BTX_MATMUL_PREPARE_WORKERS:-12}
C=/home/eldian/btx-node/bin/btx-cli
B=/home/eldian/btx-node/bin/btxd
D=/home/eldian/.btx
A=${SOLO_ADDR:-btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35}
MAXTRIES=${BTX_MINING_MAXTRIES:-100000000}
LOG=${LOG:-/mnt/d/BTX/btx-solo-lean.log}
echo $$ > /tmp/btx-solo-lean.pid

log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }

resync_running(){
  pgrep -f "[b]tx-faststart" >/dev/null 2>&1 && return 0
  pgrep -f "[b]tx-sync-fast" >/dev/null 2>&1 && return 0
  [ -d /tmp/btx-sync-fast.lock ] && return 0
  return 1
}

node_state(){
  local info
  info=$("$C" -datadir="$D" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null) || { echo down; return; }
  if printf '%s' "$info" | grep -q '"initialblockdownload"[[:space:]]*:[[:space:]]*false'; then echo ok; else echo syncing; fi
}

start_or_heal(){
  if resync_running; then log "re-sync active; not touching btxd"; return; fi
  pkill -x btxd.real 2>/dev/null; sleep 2; rm -f "$D/.lock" 2>/dev/null
  log "(re)starting btxd"
  "$B" -datadir="$D" -prune=4096 -dbcache=200 -maxmempool=100 -blockfilterindex=0 \
       -fastshieldedstartup=1 -shieldedstartupaudit=0 -miningchainguardminpeers=1 \
       -dnsseed=1 -listen=1 -maxconnections=96 -addnode=node.btx.tools -addnode=peers.minebtx.com \
       -daemon >>"$LOG" 2>&1
  local i
  for i in $(seq 1 40); do "$C" -datadir="$D" -rpcclienttimeout=4 getblockchaininfo >/dev/null 2>&1 && return; sleep 3; done
  # Couldn't init. On a pruned node a corrupted shielded state forces a genesis replay
  # that fails (blocks pruned) -> a fresh v9 snapshot sync is the only fix.
  if tail -40 "$D/debug.log" 2>/dev/null | grep -qE 'RebuildShieldedState: replaying.*genesis|Failed to initialize shielded state'; then
    log "shielded state broken on pruned node -> escalating to v9 snapshot re-sync (~30 min)"
    pkill -x btxd.real 2>/dev/null; sleep 3
    BTX_MATMUL_BACKEND=cuda RELEASE_TAG=v0.32.12 bash /mnt/d/BTX/btx-sync-fast.sh >>"$LOG" 2>&1
  fi
}

log "lean solo miner start (addr=$A maxtries=$MAXTRIES)"
down_streak=0
while true; do
  case "$(node_state)" in
    ok)
      down_streak=0
      out=$("$C" -datadir="$D" -rpcclienttimeout=180 generatetoaddress 1 "$A" "$MAXTRIES" 2>/dev/null)
      if printf '%s' "$out" | grep -qiE '[0-9a-f]{64}'; then
        log "*** BLOCK FOUND *** $(printf '%s' "$out" | tr -d '\n ')"
      fi
      ;;
    syncing)
      down_streak=0; sleep 15
      ;;
    down)
      if resync_running; then down_streak=0; sleep 15; continue; fi
      down_streak=$((down_streak + 1))
      if [ "$down_streak" -ge 4 ]; then start_or_heal; down_streak=0; else sleep 8; fi
      ;;
  esac
done
