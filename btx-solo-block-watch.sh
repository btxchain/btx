#!/usr/bin/env bash
# Watch for a REAL solo block: a coinbase to our mining address that lands and stays
# in the main chain. Exits 0 the moment one is detected (so the harness pings the
# operator). Lightweight: btx-solo-stats.sh only scans NEW blocks since last run.
set -u
C=/home/eldian/btx-node/bin/btx-cli
D=/home/eldian/.btx
STATS=/mnt/d/BTX/btx-solo-stats.sh
STATE=/mnt/d/BTX/btx-solo-stats.state.json
HB=/mnt/d/BTX/btx-solo-block-watch.log

# Baseline to the current tip so only NEW solo blocks (from now) count.
TIP=$("$C" -datadir="$D" -rpcclienttimeout=10 getblockcount 2>/dev/null)
printf '{"last_height": %s, "wins": []}\n' "${TIP:-0}" > "$STATE"
printf '[%s] watching for solo blocks from height %s\n' "$(date '+%F %T')" "${TIP:-0}" > "$HB"

while true; do
  out=$(bash "$STATS" 2>/dev/null)
  wins=$(printf '%s' "$out" | grep -oE 'solo_blocks_7d=[0-9]+' | cut -d= -f2)
  last=$(printf '%s' "$out" | grep -oE 'solo_last_win=[^ ]*.*' | head -1)
  printf '[%s] check: %s  (7d=%s)\n' "$(date '+%F %T')" "${last:-none}" "${wins:-0}" >> "$HB"
  if [ "${wins:-0}" -gt 0 ]; then
    printf '[%s] *** SOLO BLOCK CONFIRMED ***\n%s\n' "$(date '+%F %T')" "$out" | tee -a "$HB"
    exit 0
  fi
  sleep 480   # 8 min; blocks are ~90s so this catches one within ~8 min
done
