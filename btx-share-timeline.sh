#!/usr/bin/env bash
LOG=/mnt/d/BTX/dexbtx-miner.log
echo "=== last 'share OK' timestamp + counter ==="
grep 'share OK' "$LOG" | tail -1
echo "=== last 'difficulty set to' ==="
grep 'difficulty set to' "$LOG" | tail -3
echo "=== accept vs reject over recent log (last 400 result lines) ==="
tail -4000 "$LOG" | grep -E 'share OK|submit raised' | tail -400 | \
  awk '/share OK/{ok++} /submit raised/{rej++} END{printf "accepted=%d rejected=%d\n", ok, rej}'
echo "=== timeline: result lines in last ~15 min (HH:MM only) ==="
grep -E 'share OK|submit raised|difficulty set to|session ended|connecting to pool' "$LOG" | tail -20
echo "=== solver version in use ==="
grep 'solver auto-update' "$LOG" | tail -1
