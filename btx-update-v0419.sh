#!/usr/bin/env bash
# Update dexbtx-miner to v0.4.19 (official installer), preserving config.
# Backs up the working solver (3fbc9d71) so we can roll back if the new
# "preempt" solver (70f16afd) regresses on the 3090.
set -u
ID=/home/eldian/.dexbtx-miner
BIN=$ID/bin
ADDR=btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35

echo "=== backup working solver + config ==="
cp -f "$BIN/btx-gbt-solve" "$BIN/btx-gbt-solve.working-3fbc9d71-bak"
cp -f "$ID/config.yaml" "$ID/config.yaml.bak-pre-v0419"
echo "pre: solver=$(sha256sum "$BIN/btx-gbt-solve" | cut -c1-16)  pkg=$(pip show dexbtx-miner 2>/dev/null | awk '/^Version/{print $2}')"

echo "=== stop guard + miner ==="
bash /mnt/d/btx/btx-pool-guard.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3

echo "=== run official installer (preserves config; SHA-verified + smoke-tested) ==="
curl -fsSL https://github.com/dexbtx/minebtx/raw/main/install.sh | bash -s -- --address "$ADDR" --skip-prompt 2>&1 | tail -40

echo ""; echo "=== POST-UPDATE STATE ==="
echo "pkg=$(pip show dexbtx-miner 2>/dev/null | awk '/^Version/{print $2}')  (want 0.4.19)"
echo "solver=$(sha256sum "$BIN/btx-gbt-solve" 2>/dev/null | cut -c1-16)  (installer pins 70f16afd; working was 3fbc9d71)"
echo "config preserved?:"; grep -E 'gpu_inputs|solver_batch_size|solver_threads|solver_prepare_workers|pool_host|payout_address' "$ID/config.yaml" 2>/dev/null
