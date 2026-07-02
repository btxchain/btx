#!/usr/bin/env bash
# BTX auto-tune: maximize pool-miner hashrate by sweeping the two "key levers"
# (solver_threads + solver_prepare_workers), measuring each on a clean window,
# and applying the best. Method = empirical ladder search: the miner --help
# says these are the levers to bump together when GPU util is sub-95%, and the
# real optimum depends on the CPU/GPU pair, so we measure instead of guess.
#
# Progress -> btx-autotune.log   Winner -> btx-autotune.result.json
# Stop early: touch /tmp/btx-autotune.stop  (or run: btx-autotune.sh stop)
set -u

CFG=${CFG:-/home/eldian/.dexbtx-miner/config.yaml}
HASH=${HASH:-/mnt/d/BTX/btx-hashrate.sh}
MODE_SWITCH=${MODE_SWITCH:-/mnt/d/BTX/btx-mining-mode.sh}
MINER_LOG=${MINER_LOG:-/mnt/d/BTX/dexbtx-miner.log}
LOG=${LOG:-/mnt/d/BTX/btx-autotune.log}
RESULT=${RESULT:-/mnt/d/BTX/btx-autotune.result.json}
STOP=${STOP:-/tmp/btx-autotune.stop}

# Clean-measurement window: only slices from the last WINDOW seconds count, so a
# candidate is never scored on the previous candidate's leftover log lines.
WINDOW=${WINDOW:-60}
FILL=${FILL:-66}          # let a full clean window accumulate before scoring
SAMPLES=${SAMPLES:-4}     # averaged hashrate samples per candidate
SAMPLE_GAP=${SAMPLE_GAP:-8}

# threads:prepare_workers ladder (canonical is 8:16; climb from there)
CANDIDATES=${CANDIDATES:-"6:12 8:16 10:20 12:24 16:32 20:40"}

if [ "${1:-run}" = "stop" ]; then touch "$STOP"; echo "stop flag set"; exit 0; fi

log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
cfg_get(){ grep -E "^\s*$1\s*:" "$CFG" 2>/dev/null | head -1 | sed -E "s/^\s*$1\s*:\s*//"; }
cfg_set(){
  if grep -qE "^\s*$1\s*:" "$CFG" 2>/dev/null; then
    sed -i -E "s|^\s*$1\s*:.*|$1: $2|" "$CFG"
  else
    printf '%s: %s\n' "$1" "$2" >> "$CFG"
  fi
}
miner_up(){ pgrep -f dexbtx-miner >/dev/null 2>&1; }
gpu_util(){ nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -1; }

# Kill the miner so the pool guard respawns it reading the new config; wait until
# it is back and actively logging before we start timing.
apply_and_wait(){
  pkill -f dexbtx-miner 2>/dev/null || true
  pkill -f btx-gbt-solve 2>/dev/null || true
  # make sure a guard exists to respawn it
  if ! pgrep -f 'btx-pool-guard.sh' >/dev/null 2>&1; then
    chmod +x "$MODE_SWITCH" 2>/dev/null || true
    bash "$MODE_SWITCH" pool >/dev/null 2>&1 || true
  fi
  local deadline=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ -e "$STOP" ] && return 1
    if miner_up; then
      local age=$(( $(date +%s) - $(stat -c %Y "$MINER_LOG" 2>/dev/null || echo 0) ))
      [ "$age" -lt 20 ] && return 0
    fi
    sleep 3
  done
  return 0
}

measure(){
  # average SAMPLES readings of hashrate_hs over a WINDOW-second trailing window
  local sum=0 n=0 i hs
  for ((i=0; i<SAMPLES; i++)); do
    [ -e "$STOP" ] && break
    hs=$(WINDOW="$WINDOW" bash "$HASH" 2>/dev/null | grep -E '^hashrate_hs=' | cut -d= -f2)
    if [ -n "$hs" ] && awk "BEGIN{exit !($hs>0)}"; then
      sum=$(awk "BEGIN{print $sum+$hs}"); n=$((n+1))
    fi
    sleep "$SAMPLE_GAP"
  done
  if [ "$n" -gt 0 ]; then awk "BEGIN{print $sum/$n}"; else echo 0; fi
}

rm -f "$STOP" "$RESULT"; : > "$LOG"
orig_t=$(cfg_get solver_threads); orig_p=$(cfg_get solver_prepare_workers)
log "=== BTX auto-tune start ==="
log "Baseline: threads=$orig_t prepare_workers=$orig_p. Ladder: $CANDIDATES"
log "Each rung: apply -> respawn -> fill ${WINDOW}s window -> average ${SAMPLES} samples. ~2 min/rung."

best_hs=0; best_t=$orig_t; best_p=$orig_p
idx=0; total=$(echo "$CANDIDATES" | wc -w)
for cand in $CANDIDATES; do
  [ -e "$STOP" ] && { log "Stop requested; ending sweep."; break; }
  idx=$((idx+1))
  t=${cand%%:*}; p=${cand##*:}
  log "[$idx/$total] threads=$t prepare_workers=$p — applying..."
  cfg_set solver_threads "$t"; cfg_set solver_prepare_workers "$p"
  apply_and_wait || { log "Stop during respawn."; break; }
  log "  filling ${FILL}s measurement window..."
  slept=0; while [ "$slept" -lt "$FILL" ]; do [ -e "$STOP" ] && break; sleep 6; slept=$((slept+6)); done
  [ -e "$STOP" ] && { log "Stop during window fill."; break; }
  hs=$(measure)
  g=$(gpu_util)
  mh=$(awk "BEGIN{printf \"%.2f\", $hs/1e6}")
  log "  result: ${mh} MH/s (GPU ${g:-?}%)"
  if awk "BEGIN{exit !($hs>$best_hs)}"; then
    best_hs=$hs; best_t=$t; best_p=$p
    log "  ** new best: ${mh} MH/s @ threads=$t prepare_workers=$p"
  fi
done

best_mh=$(awk "BEGIN{printf \"%.2f\", $best_hs/1e6}")
if awk "BEGIN{exit !($best_hs>0)}"; then
  log "Applying winner: threads=$best_t prepare_workers=$best_p (${best_mh} MH/s)"
  cfg_set solver_threads "$best_t"; cfg_set solver_prepare_workers "$best_p"
  apply_and_wait || true
  printf '{"best_threads":%s,"best_prepare_workers":%s,"best_hs":%s,"best_mh":%s}\n' \
    "$best_t" "$best_p" "$best_hs" "$best_mh" > "$RESULT"
  log "=== Auto-tune complete: BEST ${best_mh} MH/s @ ${best_t}/${best_p} (applied) ==="
else
  log "No positive hashrate measured (miner idle/log stale?). Restoring baseline ${orig_t}/${orig_p}."
  cfg_set solver_threads "$orig_t"; cfg_set solver_prepare_workers "$orig_p"
  apply_and_wait || true
  log "=== Auto-tune ended without a winner ==="
fi
rm -f "$STOP"
