#!/usr/bin/env bash
# BTX pool miner guard — starts/stops guarded WSL pool mining from D:\BTX.
# Stop by creating /tmp/btx-pool-guard.stop or running: /mnt/d/BTX/btx-pool-guard.sh stop
set -u

export BTX_MATMUL_BACKEND=${BTX_MATMUL_BACKEND:-cuda}
# Pin the solver: auto-update has broken mining repeatedly (0.4.15 stopped using
# the GPU entirely — idle 37W, 0 shares for 5h). Disable it and update manually
# after verifying a new version works. Re-enable by unsetting this.
export DEXBTX_NO_SOLVER_AUTOUPDATE=${DEXBTX_NO_SOLVER_AUTOUPDATE:-0}
CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
BTXD=${BTXD:-/home/eldian/btx-node/bin/btxd}
DATADIR=${DATADIR:-/home/eldian/.btx}
# Disable block filter index at runtime. Existing WSL datadir has shown:
# "basic block filter index: best block of the index not found. Please rebuild the index."
# Pool mining does not need that index, and disabling it avoids a btxd startup loop.
BTXD_ARGS=${BTXD_ARGS:--blockfilterindex=0 -fastshieldedstartup=1}
WALLET=${WALLET:-my-wallet}
MINER_BIN=${MINER_BIN:-/home/eldian/.local/bin/dexbtx-miner}
MINER_CFG=${MINER_CFG:-/home/eldian/.dexbtx-miner/config.yaml}
LOG=${LOG:-/mnt/d/BTX/btx-pool-guard.log}
STOP=${STOP:-/tmp/btx-pool-guard.stop}
PIDFILE=${PIDFILE:-/tmp/btx-pool-guard.pid}
LOCKDIR=${LOCKDIR:-/tmp/btx-pool-guard.lock}
MINER_LOG=${MINER_LOG:-/mnt/d/BTX/dexbtx-miner.log}
SNAPSHOT=${SNAPSHOT:-/mnt/d/BTX/snapshot.dat}
# Pool mining via dexbtx-miner is a Stratum/pool client and should not wait days
# for a local full node. Keep this off by default: the guard starts/guards the
# pool miner immediately. Set REQUIRE_NODE_SYNC=1 only if you intentionally want
# local-node-gated mining.
REQUIRE_NODE_SYNC=${REQUIRE_NODE_SYNC:-0}
# Watchdog tuning. A healthy gpu_inputs=1 miner holds the GPU at 200W+; idle is
# ~40-50W. Restart if the miner log goes stale OR the GPU stays idle across
# several consecutive checks (catches a hung solver while the parent process is
# alive and still logging pool reconnects). ~90s staleness ≈ 3x faster than the
# old 300s. GPU check requires consecutive idle reads so a between-job power dip
# or a 1s reconnect cannot false-trigger.
STALE_SECS=${STALE_SECS:-90}
# Solver 0.4.14 (network V3, height>=130500) runs the GPU much lighter — ~50W
# (true idle ~38-40W) vs the old 0.4.13 gpu_inputs=1 ~250W. The idle threshold
# must sit just above true idle, with more consecutive reads to avoid misfiring.
GPU_IDLE_W=${GPU_IDLE_W:-42}
GPU_IDLE_LOOPS=${GPU_IDLE_LOOPS:-6}
# Reject-storm watchdog: a network hard-fork (e.g. V2->V3) makes the running
# solver submit 100% invalid shares ("digest >= share_target") until it pulls a
# new build, which only happens on miner restart. If recent results are all
# rejects with zero accepts, restart to auto-update the solver. (This is what
# silently cost a mining day on 2026-06-14.)
REJECT_WINDOW=${REJECT_WINDOW:-40}
REJECT_MIN=${REJECT_MIN:-12}

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
miner_running() { pgrep -f "$MINER_BIN" >/dev/null 2>&1 || pgrep -f 'dexbtx-miner' >/dev/null 2>&1; }
kill_miner() { pkill -f "$MINER_BIN" 2>/dev/null || true; pkill -f dexbtx-miner 2>/dev/null || true; pkill -f btx-gbt-solve 2>/dev/null || true; }

case "${1:-run}" in
  stop)
    touch "$STOP"
    if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; fi
    kill_miner
    rm -f "$PIDFILE"
    rmdir "$LOCKDIR" 2>/dev/null || true
    log "Stop requested; guard and miner stopped."
    exit 0
    ;;
  status)
    echo "guard_pid=$(cat "$PIDFILE" 2>/dev/null || true)"
    echo "guard_running=$(if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then echo yes; else echo no; fi)"
    echo "miner_running=$(if miner_running; then echo yes; else echo no; fi)"
    if [ -x /mnt/d/BTX/btx-hashrate.sh ]; then /mnt/d/BTX/btx-hashrate.sh 2>/dev/null || true; fi
    "$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null | tr -d '\n' || true
    echo
    exit 0
    ;;
  run|start) ;;
  *) echo "Usage: $0 [run|start|stop|status]"; exit 2 ;;
esac

if ! mkdir "$LOCKDIR" 2>/dev/null; then
  log "Guard already running (lock: $LOCKDIR)."
  exit 0
fi
trap 'rm -f "$PIDFILE"; rmdir "$LOCKDIR" 2>/dev/null || true' EXIT
echo $$ > "$PIDFILE"
rm -f "$STOP"
mkdir -p "$(dirname "$LOG")" "$(dirname "$MINER_LOG")"
log "=== BTX pool guard started (backend=$BTX_MATMUL_BACKEND, stale=${STALE_SECS}s, gpu_idle<${GPU_IDLE_W}W x${GPU_IDLE_LOOPS}) ==="
gpu_idle_count=0
last_reject_restart=0

while [ ! -e "$STOP" ]; do
  if [ ! -x "$BTXD" ] || [ ! -x "$CLI" ]; then
    log "Missing BTX binaries. Run /mnt/d/BTX/btx-update-latest.sh first."
    sleep 30
    continue
  fi
  if [ ! -x "$MINER_BIN" ]; then
    log "Missing pool miner: $MINER_BIN"
    sleep 30
    continue
  fi

  if [ "$REQUIRE_NODE_SYNC" != "1" ]; then
    if ! miner_running; then
      log "Pool-only mode: starting dexbtx-miner immediately (not waiting for local node sync)."
      log "Starting pool miner: $MINER_BIN --config $MINER_CFG"
      nohup env BTX_MATMUL_BACKEND="$BTX_MATMUL_BACKEND" "$MINER_BIN" --config "$MINER_CFG" >>"$MINER_LOG" 2>&1 &
      sleep 10
    fi

    # A healthy miner writes job/solver lines every few seconds. A stale log is
    # a far more reliable hang signal than GPU power draw, which dips below
    # any fixed threshold between work batches even while mining.
    if miner_running; then
      log_age=$(( $(date +%s) - $(stat -c %Y "$MINER_LOG" 2>/dev/null || date +%s) ))
      if [ "$log_age" -gt "$STALE_SECS" ]; then
        log "Miner log stale for ${log_age}s (>${STALE_SECS}s); restarting miner."
        kill_miner
        sleep 3
        gpu_idle_count=0
      else
        # GPU-idle watchdog: catches a hung/idle solver even while the parent
        # process is alive and logging (e.g. stuck after a pool reconnect).
        pw=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits 2>/dev/null | head -1 | cut -d. -f1)
        if [ -n "$pw" ] && [ "$pw" -lt "$GPU_IDLE_W" ]; then
          gpu_idle_count=$((gpu_idle_count + 1))
        else
          gpu_idle_count=0
        fi
        if [ "$gpu_idle_count" -ge "$GPU_IDLE_LOOPS" ]; then
          log "GPU idle (<${GPU_IDLE_W}W) for $gpu_idle_count consecutive checks; solver stalled, restarting miner."
          kill_miner
          sleep 3
          gpu_idle_count=0
        fi
        # Reject-storm watchdog: all-rejects/no-accepts over the recent window
        # means a stale solver vs a network upgrade — restart to pull the fix.
        recent=$(grep -E 'share OK|submit raised' "$MINER_LOG" 2>/dev/null | tail -n "$REJECT_WINDOW")
        rejs=$(printf '%s\n' "$recent" | grep -c 'submit raised')
        oks=$(printf '%s\n' "$recent" | grep -c 'share OK')
        now=$(date +%s)
        if [ "$rejs" -ge "$REJECT_MIN" ] && [ "$oks" -eq 0 ] && [ $((now - last_reject_restart)) -gt 180 ]; then
          log "Reject storm: last ${REJECT_WINDOW} results = ${rejs} rejects / 0 accepts; restarting miner to auto-update the solver (likely network upgrade)."
          kill_miner
          sleep 3
          gpu_idle_count=0
          last_reject_restart=$now
        fi
      fi
    fi
    sleep 15
    continue
  fi

  if ! pgrep -f btxd >/dev/null 2>&1; then
    log "btxd is not running; starting latest BTX node ($BTXD_ARGS)."
    rm -f "$DATADIR/.lock"
    BTX_MATMUL_BACKEND="$BTX_MATMUL_BACKEND" "$BTXD" -datadir="$DATADIR" $BTXD_ARGS -daemon >>"$LOG" 2>&1 || true

    rpc_ready=false
    for _ in $(seq 1 60); do
      [ -e "$STOP" ] && break
      info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=3 getblockchaininfo 2>/dev/null || true)
      if [ -n "$info" ]; then
        rpc_ready=true
        break
      fi
      if ! pgrep -f btxd >/dev/null 2>&1; then
        log "btxd exited before RPC became ready. Last debug.log lines:"
        tail -20 "$DATADIR/debug.log" >>"$LOG" 2>/dev/null || true
        if tail -30 "$DATADIR/debug.log" 2>/dev/null | grep -q 'Failed to initialize shielded state\|RebuildShieldedState.*failed'; then
          log "Shielded state rebuild failure detected. Removing corrupt shielded_state and retrying."
          rm -rf "$DATADIR/shielded_state"
        fi
        break
      fi
      sleep 2
    done

    if [ "$rpc_ready" != "true" ]; then
      log "RPC not ready yet; will retry node start/check."
      sleep 10
      continue
    fi
    "$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 loadwallet "$WALLET" >>"$LOG" 2>&1 || true
  fi

  info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
  if [ -z "$info" ]; then
    log "RPC not ready; waiting."
    sleep 10
    continue
  fi

  blocks=$(printf '%s' "$info" | sed -n 's/.*"blocks"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
  headers=$(printf '%s' "$info" | sed -n 's/.*"headers"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
  ibd=$(printf '%s' "$info" | grep -c '"initialblockdownload"[[:space:]]*:[[:space:]]*true' || true)
  if [ "$ibd" = "1" ]; then
    log "Node syncing: ${blocks:-?}/${headers:-?}; miner paused."
    sleep 30
    continue
  fi

  mining_info=$("$CLI" -datadir="$DATADIR" getmininginfo 2>/dev/null || true)
  pause=$(printf '%s' "$mining_info" | grep -c '"should_pause_mining"[[:space:]]*:[[:space:]]*true' || true)
  if [ "$pause" = "1" ]; then
    log "Chain guard says pause mining at block ${blocks:-?}; waiting."
    if miner_running; then kill_miner; fi
    sleep 20
    continue
  fi

  if ! miner_running; then
    log "Starting pool miner: $MINER_BIN --config $MINER_CFG"
    nohup env BTX_MATMUL_BACKEND="$BTX_MATMUL_BACKEND" "$MINER_BIN" --config "$MINER_CFG" >>"$MINER_LOG" 2>&1 &
    sleep 10
  fi

  if miner_running; then
    log_age=$(( $(date +%s) - $(stat -c %Y "$MINER_LOG" 2>/dev/null || date +%s) ))
    if [ "$log_age" -gt "$STALE_SECS" ]; then
      log "Miner log stale for ${log_age}s (>${STALE_SECS}s); restarting miner."
      kill_miner
      sleep 3
    fi
  fi

  sleep 15
done

log "Stop flag seen; stopping miner and exiting guard."
kill_miner
rm -f "$STOP" "$PIDFILE"
