#!/usr/bin/env bash
# Roll back /home/eldian/btx-node to the pre-v0.32.6 backup.
# v0.32.6 refuses the published v7 shielded snapshot on fresh pruned nodes
# ("use a v8+ BTX shielded snapshot..."), so faststart can never succeed on it.
set -u
NODE=/home/eldian/btx-node
BACKUP=${BACKUP:-/home/eldian/btx-node.backup.20260612-191728}

echo "--- stopping running faststart/sync + btxd ---"
pkill -f '[b]tx-faststart\.py' 2>/dev/null && echo "killed faststart monitor" || echo "no faststart monitor"
"$NODE/bin/btx-cli" -datadir=/home/eldian/.btx -rpcclienttimeout=10 stop 2>/dev/null || true
for _ in $(seq 1 30); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
pkill -x btxd 2>/dev/null || true
sleep 2
echo "btxd running: $(pgrep -x btxd >/dev/null 2>&1 && echo yes || echo no)"

echo "--- waiting for sync lock release ---"
for _ in $(seq 1 20); do [ ! -d /tmp/btx-sync-fast.lock ] && break; sleep 1; done
rmdir /tmp/btx-sync-fast.lock 2>/dev/null || true
echo "lock: $(ls -d /tmp/btx-sync-fast.lock 2>/dev/null || echo released)"

echo "--- swapping binaries ---"
if [ ! -x "$BACKUP/bin/btxd" ]; then echo "backup missing: $BACKUP"; exit 1; fi
rm -rf /home/eldian/btx-node.v0.32.6-snapshot-blocked
mv "$NODE" /home/eldian/btx-node.v0.32.6-snapshot-blocked
cp -a "$BACKUP" "$NODE"
echo "active version: $("$NODE/bin/btxd" --version | head -1)"
echo "v0.32.6 kept at /home/eldian/btx-node.v0.32.6-snapshot-blocked"
