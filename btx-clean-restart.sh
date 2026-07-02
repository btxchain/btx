#!/usr/bin/env bash
# Clean restart: wipe datadir state (keeping wallets + snapshot), then re-run
# btx-faststart.py from the already-downloaded snapshot.
set -eu

DATADIR=/home/eldian/.btx
CLI=/home/eldian/btx-node/bin/btx-cli
BTXD=/home/eldian/btx-node/bin/btxd
FASTSTART=/mnt/d/btx/contrib/faststart/btx-faststart.py
SNAP_MANIFEST=/tmp/btx-sync-fast/snapshot.faststart-by-height.manifest.json

# Stop btxd
"$CLI" -datadir="$DATADIR" stop 2>/dev/null || true
sleep 2
pkill -x btxd 2>/dev/null || true
sleep 1

# Save snapshot and wallets
SAVE=/tmp/btx-clean-restart-save
rm -rf "$SAVE"
mkdir -p "$SAVE"
if [ -d "$DATADIR/wallets" ]; then
    cp -a "$DATADIR/wallets" "$SAVE/wallets"
    echo "Saved wallets"
fi
if [ -f "$DATADIR/faststart/snapshot.dat" ]; then
    mv "$DATADIR/faststart/snapshot.dat" "$SAVE/snapshot.dat"
    echo "Saved snapshot"
fi

# Wipe datadir completely
rm -rf "$DATADIR"
mkdir -p "$DATADIR/faststart"
chmod 700 "$DATADIR"

# Restore wallets and snapshot
if [ -d "$SAVE/wallets" ]; then
    cp -a "$SAVE/wallets" "$DATADIR/wallets"
    echo "Restored wallets"
fi
if [ -f "$SAVE/snapshot.dat" ]; then
    mv "$SAVE/snapshot.dat" "$DATADIR/faststart/snapshot.dat"
    echo "Restored snapshot"
fi
rm -rf "$SAVE"

echo "=== Clean datadir ready ==="
ls -la "$DATADIR/"
echo "---"
ls -lh "$DATADIR/faststart/"

# Now run btx-faststart.py with the local snapshot
echo "=== Starting faststart with local snapshot ==="
export BTX_MATMUL_BACKEND=cuda
export PYTHONUNBUFFERED=1

PEER_ARGS=(
  -dnsseed=1
  -listen=1
  -maxconnections=96
  -addnode=node.btx.tools
  -addnode=peers.minebtx.com
  -addnode=164.90.246.229
  -addnode=146.190.179.86
  -addnode=143.198.155.4
  -blockfilterindex=0
  -fastshieldedstartup=1
  -shieldedstartupaudit=0
)

# Build the manifest if missing
if [ ! -f "$SNAP_MANIFEST" ]; then
    echo "Regenerating snapshot manifest..."
    mkdir -p /tmp/btx-sync-fast
    LATEST_MANIFEST=/mnt/d/btx/snapshot.latest.manifest.json
    RELEASE_TAG=v0.32.5
    REPO=btxchain/btx
    if [ ! -f "$LATEST_MANIFEST" ]; then
        curl -L --fail --retry 3 -o "$LATEST_MANIFEST" \
            "https://github.com/$REPO/releases/download/$RELEASE_TAG/snapshot.manifest.json"
    fi
    python3 -c "
import json, sys
d = json.load(open('$LATEST_MANIFEST', encoding='utf-8'))
d.pop('blockhash', None)
if 'url' not in d and 'asset_url' not in d:
    fn = d.get('filename') or d.get('published_name') or 'snapshot.dat'
    d['url'] = 'https://github.com/$REPO/releases/download/$RELEASE_TAG/' + fn
json.dump(d, open('$SNAP_MANIFEST', 'w', encoding='utf-8'), indent=2)
"
fi

CMD=(python3 -u "$FASTSTART" miner
    --chain=main
    --datadir="$DATADIR"
    --btxd="$BTXD"
    --btx-cli="$CLI"
    --snapshot-manifest="$SNAP_MANIFEST"
    --header-wait-secs=3600
    --rpc-wait-secs=180
    --poll-secs=5
    --keep-snapshot)

for arg in "${PEER_ARGS[@]}"; do CMD+=(--daemon-arg="$arg"); done

"${CMD[@]}" || echo "Faststart exited with $? (may be normal if monitoring lost connection after sync)"

# Final status check
echo "=== Final status ==="
sleep 5
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo 2>&1 || echo "RPC not ready (node may still be starting)"
