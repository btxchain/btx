#!/usr/bin/env bash
# Apply tuned solver settings to dexbtx config and restart the pool miner.
# gpu_inputs=1 saturates the 3090 (0 starves it on the v0.4.11 solver);
# batch_size=512 confirmed to sustain full boost clocks.
set -u
CFG=/home/eldian/.dexbtx-miner/config.yaml
GI=${GI:-1}; BATCH=${BATCH:-512}; TH=${TH:-12}

cp -f "$CFG" "$CFG.bak.$(date +%Y%m%d-%H%M%S)"
sed -i "s/^gpu_inputs:.*/gpu_inputs: $GI                          # BTX_MATMUL_GPU_INPUTS (1=GPU-gen inputs; saturates GPU on v0.4.11)/" "$CFG"
sed -i "s/^solver_batch_size:.*/solver_batch_size: $BATCH        # BTX_MATMUL_SOLVE_BATCH_SIZE/" "$CFG"
sed -i "s/^solver_threads:.*/solver_threads: $TH/" "$CFG"
echo "=== updated config ==="
grep -E '^(gpu_inputs|solver_batch_size|solver_threads|solver_backend):' "$CFG"

echo "=== restarting pool miner (parent + child, so config reloads) ==="
# The dexbtx-miner PARENT reads config.yaml at startup and passes cached
# threads/batch to each gbt-solve spawn. Killing only the gbt-solve child makes
# the parent respawn with OLD settings. Must restart the parent.
bash /mnt/d/btx/btx-mining-mode.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3
rm -f /tmp/btx-pool-guard.stop
bash /mnt/d/btx/btx-mining-mode.sh pool 2>&1 | head -6
