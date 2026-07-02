#!/usr/bin/env bash
# Roll back the dexbtx solver to the known-good 0.4.14 (pre-autoupdate backup)
# because the auto-updated 0.4.15 stopped using the GPU. Then restart mining
# with auto-update DISABLED (via the guard's exported env).
set -u
BIN=/home/eldian/.dexbtx-miner/bin
GOOD="$BIN/btx-gbt-solve.pre-autoupdate-bak"   # 0.4.14, sha 2c93d27..., size 13411296

echo "=== stopping guard + miner + solver ==="
bash /mnt/d/btx/btx-pool-guard.sh stop >/dev/null 2>&1 || true
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
sleep 3

echo "=== current (broken 0.4.15) ==="
sha256sum "$BIN/btx-gbt-solve" | cut -c1-16
if [ ! -s "$GOOD" ]; then echo "BACKUP MISSING: $GOOD"; exit 1; fi

echo "=== restoring 0.4.14 from backup ==="
cp -f "$BIN/btx-gbt-solve" "$BIN/btx-gbt-solve.0.4.15-broken-bak"   # keep the broken one
cp -f "$GOOD" "$BIN/btx-gbt-solve"
chmod +x "$BIN/btx-gbt-solve"
echo "restored sha: $(sha256sum "$BIN/btx-gbt-solve" | cut -c1-16)  (expect 2c93d27cb1b0...)"
echo "version: $("$BIN/btx-gbt-solve" --version 2>&1 | head -1 || true)"

echo "=== restarting pool mining (auto-update disabled via guard env) ==="
rm -f /tmp/btx-pool-guard.stop; rmdir /tmp/btx-pool-guard.lock 2>/dev/null || true
DEXBTX_NO_SOLVER_AUTOUPDATE=1 nohup bash /mnt/d/btx/btx-pool-guard.sh run >>/mnt/d/BTX/btx-pool-guard.log 2>&1 &
disown
sleep 2
echo "guard relaunched"
