#!/usr/bin/env bash
# Read-only snapshot of current BTX node + pool-miner + solver + GPU state.
set -u
NODE=/home/eldian/btx-node/bin
SB=/home/eldian/.dexbtx-miner/bin/btx-gbt-solve
LOG=/mnt/d/BTX/dexbtx-miner.log

echo "=== processes (btxd / dexbtx-miner / btx-gbt-solve) ==="
pgrep -af 'btxd|dexbtx-miner|btx-gbt-solve' | grep -vE 'pgrep|status-now' || echo "(none)"

echo ""; echo "=== solver binary on disk ==="
ls -la "$SB" 2>/dev/null
echo "disk sha: $(sha256sum "$SB" 2>/dev/null | cut -c1-16)   [0.4.14=2c93d27cb1b0  broken0.4.15=3f7bd3f7]"
pid=$(pgrep -f '[b]tx-gbt-solve' | head -1)
if [ -n "$pid" ]; then echo "running sha: $(sha256sum /proc/$pid/exe 2>/dev/null | cut -c1-16)  (pid $pid)"; else echo "running: solver NOT up"; fi

echo ""; echo "=== node version + sync ==="
"$NODE/btx-cli" --version 2>&1 | head -1 || echo "btx-cli failed"
"$NODE/btx-cli" getblockchaininfo 2>/dev/null | grep -E '"chain"|"blocks"|"headers"|"initialblockdownload"|"verificationprogress"|"pruned"' || echo "(btxd not responding)"

echo ""; echo "=== miner: recent shares / rejects (last 4000 log lines) ==="
T=$(tail -4000 "$LOG" 2>/dev/null)
echo "share OK:  $(printf '%s\n' "$T" | grep -cE 'share OK|accepted')"
echo "rejects:   $(printf '%s\n' "$T" | grep -cE 'reject|code 23|>= share_target')"
printf '%s\n' "$T" | grep -iE 'share OK|reject|connecting to pool|subscribe|authorize|difficulty set|pool closed|session ended' | tail -6

echo ""; echo "=== GPU (4 samples, 3s apart) ==="
for i in 1 2 3 4; do nvidia-smi --query-gpu=utilization.gpu,power.draw,clocks.sm,temperature.gpu --format=csv,noheader 2>/dev/null; sleep 3; done

echo ""; echo "=== auto-update / version log lines (last 6000 lines, excl 'working') ==="
tail -6000 "$LOG" 2>/dev/null | grep -iE 'auto-update|updating solver|solver version|downloading|installed|0\.4\.1[0-9]' | grep -ivE 'solver: working' | tail -8

echo ""; echo "=== pool-guard env (auto-update disabled?) ==="
grep -nE 'DEXBTX_NO_SOLVER_AUTOUPDATE|GPU_IDLE_W|STALE_SECS' /mnt/d/BTX/btx-pool-guard.sh | head
