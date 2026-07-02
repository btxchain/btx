#!/usr/bin/env bash
LOG=/mnt/d/BTX/dexbtx-miner.log
BIN=/home/eldian/.dexbtx-miner/bin
echo "=== all solver auto-update log lines (version + sha over time) ==="
grep -iE 'solver auto-update|solver_updater|updating solver|installed solver|downloaded' "$LOG" | tail -20
echo "=== solver update events around the 15:00-16:00 break ==="
grep -E '^1[45]:' "$LOG" | grep -iE 'solver|update|version|restart|starting' | tail -15
echo "=== current solver binary ==="
ls -la --time-style=full-iso "$BIN"/ 2>/dev/null
echo "=== current binary sha (first 12) ==="
sha256sum "$BIN/btx-gbt-solve" 2>/dev/null | cut -c1-12
echo "=== solver --version / help ==="
"$BIN/btx-gbt-solve" --version 2>&1 | head -3 || echo "(no --version)"
