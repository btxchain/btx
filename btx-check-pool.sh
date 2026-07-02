#!/usr/bin/env bash
# Report pool miner processes and recent log without matching guard pkill patterns.
set -u
sleep "${1:-5}"
pgrep -af 'dexbtx[-_]miner|btx[-]gbt[-]solve' | grep -v pgrep || echo "(miner not running)"
echo "--- miner log tail ---"
tail -12 /mnt/d/BTX/dexbtx-miner.log 2>/dev/null
