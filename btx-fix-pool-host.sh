#!/usr/bin/env bash
# Point the miner at the working stratum endpoint (apex minebtx.com:3333 went
# behind Cloudflare and stopped passing stratum TCP). pool.minebtx.com:3333 works.
set -u
CFG=/home/eldian/.dexbtx-miner/config.yaml
NEWHOST=${NEWHOST:-pool.minebtx.com}
cp -f "$CFG" "$CFG.bak.poolhost.$(date +%Y%m%d-%H%M%S)"
sed -i "s/^pool_host:.*/pool_host: \"$NEWHOST\"/" "$CFG"
echo "=== updated ==="
grep -E '^pool_(host|port|tls):' "$CFG"
echo "=== restarting miner (guard will respawn parent with new host) ==="
pkill -f '[d]exbtx-miner' 2>/dev/null || true
pkill -f '[b]tx-gbt-solve' 2>/dev/null || true
echo "killed; guard restarts within ~15s"
