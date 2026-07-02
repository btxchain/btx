#!/usr/bin/env bash
# Start the pool miner WITHOUT the guard (for clean observation), with a given config.
set -u
CFG=/home/eldian/.dexbtx-miner/config.yaml
MINER=/home/eldian/.local/bin/dexbtx-miner
LOG=/mnt/d/BTX/dexbtx-miner.log
GI=${GI:-1}; BATCH=${BATCH:-128}; TH=${TH:-8}

pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
sed -i "s/^gpu_inputs:.*/gpu_inputs: $GI/" "$CFG"
sed -i "s/^solver_batch_size:.*/solver_batch_size: $BATCH/" "$CFG"
sed -i "s/^solver_threads:.*/solver_threads: $TH/" "$CFG"
nohup env BTX_MATMUL_BACKEND=cuda "$MINER" --config "$CFG" >>"$LOG" 2>&1 &
disown
sleep 6
echo "config: $(grep -E '^(gpu_inputs|solver_batch_size|solver_threads):' "$CFG" | tr '\n' ' ')"
pgrep -f '[d]exbtx-miner' >/dev/null && echo "miner UP (pid $(pgrep -f '[d]exbtx-miner' | head -1))" || echo "miner FAILED to start"
