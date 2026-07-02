#!/usr/bin/env bash
# Fast-sync the local BTX node for solo mining.
# Uses the latest GitHub release snapshot + faststart helper, then leaves btxd
# running with higher peer limits. Does not stop dexbtx pool mining.
set -Eeuo pipefail

# btxd selects its MatMul accelerator from this env var (default cpu on Linux).
# faststart spawns btxd as a child, so export here or the synced node — which
# keeps running and serves the solo miner — mines on CPU instead of CUDA.
export BTX_MATMUL_BACKEND=${BTX_MATMUL_BACKEND:-cuda}

CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
BTXD=${BTXD:-/home/eldian/btx-node/bin/btxd}
DATADIR=${DATADIR:-/home/eldian/.btx}
REPO=${REPO:-btxchain/btx}
# Override to pin a snapshot release. v0.32.8's binary only recognizes assumeutxo
# snapshots up to height 128605 (=v0.32.7's); its own published 129322 snapshot
# is not yet in the binary's hardcoded list, so pin RELEASE_TAG=v0.32.7.
RELEASE_TAG=${RELEASE_TAG:-}
FASTSTART=${FASTSTART:-/mnt/d/BTX/contrib/faststart/btx-faststart.py}
LOG=${LOG:-/mnt/d/BTX/btx-sync-fast.log}
LOCK=${LOCK:-/tmp/btx-sync-fast.lock}
PIDFILE=${PIDFILE:-/tmp/btx-sync-fast.pid}
WALLET_NAME=${WALLET_NAME:-my-wallet}
KEEP_SNAPSHOT=${KEEP_SNAPSHOT:-1}
# Peer posture for fastest catch-up after the snapshot anchor. DNS seed is the
# canonical seed; minebtx/peers endpoint is a stable public BTX infra node.
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
  -miningchainguardminpeers=1
  -miningchainguardmaxmediangap=30
)

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
trap 'rc=$?; echo "[$(date "+%F %T")] fast sync failed at line $LINENO with exit $rc"; rm -f "$PIDFILE"; rmdir "$LOCK" 2>/dev/null || true; exit $rc' ERR
log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
pybin() { if have python3; then echo python3; elif have python; then echo python; else return 1; fi; }
json_field() { "$(pybin)" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' "$1" "$2"; }
# Keep only the 2 newest datadir backups (all flavors). Wallets are copied to
# /mnt/d/BTX/wallet-backup-* before this is called, so pruned dirs hold no
# unique wallet data.
prune_old_datadir_backups() {
  local old
  for old in $(ls -dt "${DATADIR}".before-fast-sync-* "${DATADIR}".broken-before-faststart-* "${DATADIR}".broken-before-snapshot-* 2>/dev/null | tail -n +3); do
    log "Pruning old datadir backup: $old"
    rm -rf -- "$old"
  done
}

if ! mkdir "$LOCK" 2>/dev/null; then
  log "Fast sync already running (pid=$(cat "$PIDFILE" 2>/dev/null || true))."
  exit 0
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"; rmdir "$LOCK" 2>/dev/null || true' EXIT

log "=== BTX fast local-node sync started ==="
if [ ! -x "$BTXD" ] || [ ! -x "$CLI" ]; then
  echo "Missing BTX binaries under /home/eldian/btx-node/bin. Run /mnt/d/BTX/btx-update-latest.sh first." >&2
  exit 2
fi
if [ ! -f "$FASTSTART" ]; then
  echo "Missing faststart helper: $FASTSTART" >&2
  exit 2
fi
if ! pybin >/dev/null; then
  echo "python/python3 is required in WSL for fast sync." >&2
  exit 2
fi

api="https://api.github.com/repos/${REPO}/releases/latest"
work=/tmp/btx-sync-fast
mkdir -p "$work"
release_json="$work/latest-release.json"
if [ -z "$RELEASE_TAG" ]; then
  log "Resolving latest BTX release."
  curl -L --fail --retry 3 --connect-timeout 15 --max-time 120 -H 'User-Agent: BTX-fast-sync' -H 'Accept: application/vnd.github+json' -o "$release_json" "$api"
  RELEASE_TAG=$("$(pybin)" -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$release_json")
else
  log "Using pinned RELEASE_TAG=$RELEASE_TAG"
fi
manifest_url="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/snapshot.manifest.json"
manifest_local="/mnt/d/BTX/snapshot.latest.manifest.json"
manifest_faststart="$work/snapshot.faststart-by-height.manifest.json"
log "Latest release: $RELEASE_TAG"
log "Downloading latest snapshot manifest: $manifest_url"
curl -L --fail --retry 3 --connect-timeout 15 --max-time 120 -o "$manifest_local" "$manifest_url"
# The current faststart helper waits for getblockheader(blockhash), which can
# hang on BTX pruned/header-only startup even after headers are high enough.
# Feed faststart an equivalent manifest without blockhash so it gates on
# headers>=height, then loadtxoutset validates the snapshot hash/height itself.
#
# Also inject the snapshot download URL. The published manifest uses
# filename/published_name without an explicit url field. When passed as a local
# file, btx-faststart.py can't derive the URL and crashes with "missing url".
snapshot_base_url="https://github.com/${REPO}/releases/download/${RELEASE_TAG}"
"$(pybin)" - "$manifest_local" "$manifest_faststart" "$snapshot_base_url" <<'PY'
import json, sys
src, dst, base_url = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(src, encoding='utf-8'))
d.pop('blockhash', None)
if 'url' not in d and 'asset_url' not in d:
    filename = d.get('filename') or d.get('published_name') or 'snapshot.dat'
    d['url'] = f"{base_url}/{filename}"
json.dump(d, open(dst, 'w', encoding='utf-8'), indent=2)
PY
height=$(json_field "$manifest_local" height)
sha=$(json_field "$manifest_local" sha256)
blockhash=$(json_field "$manifest_local" blockhash)
log "Latest snapshot anchor: height=$height blockhash=$blockhash sha256=$sha"

info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
# A node that is loading its block index / mid-validation answers no RPC for minutes.
# Deciding "not synced" from that silence wipes a perfectly good (even nearly-synced)
# datadir. If a btxd process exists, wait for RPC before judging.
if [ -z "$info" ] && pgrep -f "[b]txd" >/dev/null 2>&1; then
  log "btxd is running but RPC is silent; waiting up to 180s for it before deciding whether a wipe/snapshot is really needed."
  for _ in $(seq 1 36); do
    sleep 5
    info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
    [ -n "$info" ] && break
  done
fi
# A STOPPED node can't report its height either — but a datadir holding gigabytes of
# blocks is never behind the ~430MB snapshot. Start btxd and wait for RPC before ever
# deciding to wipe such a datadir; a snapshot reload can only lose progress here.
blocks_mb=$(du -sm "$DATADIR/blocks" 2>/dev/null | cut -f1 || echo 0)
if [ -z "$info" ] && [ "${blocks_mb:-0}" -gt 3000 ]; then
  log "Datadir holds ${blocks_mb}MB of blocks (far past any snapshot) but no RPC. Starting btxd to read its real height before deciding — refusing a blind wipe."
  if ! pgrep -f "[b]txd" >/dev/null 2>&1; then
    rm -f "$DATADIR/.lock"
    "$BTXD" -datadir="$DATADIR" "${PEER_ARGS[@]}" -daemon >>"$LOG" 2>&1 || true
  fi
  # A multi-GB block index takes minutes to load; the wrapper also needs seconds just to
  # spawn btxd.real. Wait generously, and only treat "process gone" as meaningful after a
  # 30s grace period for it to appear.
  for i in $(seq 1 120); do
    sleep 5
    info=$("$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 getblockchaininfo 2>/dev/null || true)
    [ -n "$info" ] && break
    if [ "$i" -gt 6 ] && ! pgrep -f "[b]txd" >/dev/null 2>&1; then
      log "btxd exited while opening the large datadir; it may be genuinely corrupt."
      break
    fi
  done
  if [ -z "$info" ]; then
    if pgrep -f "[b]txd" >/dev/null 2>&1; then
      log "Node is STILL loading the ${blocks_mb}MB datadir (no RPC after wait). NOT wiping — exiting sync; the solo guard takes over the moment RPC is up."
      exit 0
    fi
    log "Node cannot stay up on this large datadir even after retries; allowing the snapshot path as a last resort."
  fi
fi
blocks=0; headers=0; ibd=true
if [ -n "$info" ]; then
  read -r blocks headers ibd <<EOF
$(printf '%s' "$info" | "$(pybin)" -c 'import json,sys; d=json.load(sys.stdin); print(d.get("blocks",0), d.get("headers",0), str(d.get("initialblockdownload", True)).lower())')
EOF
  log "Current node: blocks=$blocks headers=$headers ibd=$ibd"
fi

write_fast_conf() {
  mkdir -p "$DATADIR"
  touch "$DATADIR/btx.conf"
  for kv in prune=4096 dnsseed=1 listen=1 maxconnections=96 blockfilterindex=0 fastshieldedstartup=1 shieldedstartupaudit=0 miningchainguardminpeers=1 dbcache=1500 maxmempool=100; do
    key=${kv%%=*}
    if grep -q "^${key}=" "$DATADIR/btx.conf" 2>/dev/null; then
      sed -i "s/^${key}=.*/${kv}/" "$DATADIR/btx.conf"
    else
      echo "$kv" >> "$DATADIR/btx.conf"
    fi
  done
  for node in node.btx.tools peers.minebtx.com 164.90.246.229 146.190.179.86 143.198.155.4; do
    grep -qx "addnode=$node" "$DATADIR/btx.conf" 2>/dev/null || echo "addnode=$node" >> "$DATADIR/btx.conf"
  done
}

# If the local chain is already at/past the snapshot anchor, reloading that snapshot
# cannot help — normal peer catch-up is strictly faster. Only wipe when we are genuinely
# BEHIND the snapshot. (ibd alone is a bad signal: a node 300 blocks from tip has ibd=true.)
if [ "${height:-0}" -gt 0 ] && [ "${blocks:-0}" -ge "${height:-0}" ]; then
  log "Local node (blocks=$blocks) is at/past the snapshot anchor ($height); no wipe — peer catch-up + config only."
  write_fast_conf
else
  log "Local node is not synced; using latest fast snapshot instead of slow block-by-block sync."
  log "Stopping btxd only. Pool miner/solver are left alone."
  "$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 stop || true
  for _ in $(seq 1 60); do pgrep -f btxd >/dev/null 2>&1 || break; sleep 1; done
  pkill -f 'btxd(\.real)?' 2>/dev/null || true
  sleep 2

  stamp=$(date '+%Y%m%d-%H%M%S')
  backup="${DATADIR}.before-fast-sync-${stamp}"
  wallet_backup="/mnt/d/BTX/wallet-backup-fast-sync-${stamp}"
  if [ -d "$DATADIR" ]; then
    log "Backing up old datadir to $backup"
    mv "$DATADIR" "$backup"
  fi
  mkdir -p "$DATADIR"
  chmod 700 "$DATADIR" || true
  if [ -d "$backup/wallets" ]; then
    log "Copying wallet directory into fresh datadir."
    cp -a "$backup/wallets" "$DATADIR/"
    mkdir -p "$wallet_backup" && cp -a "$backup/wallets" "$wallet_backup/"
    log "Extra wallet copy saved at $wallet_backup"
  elif [ -f "$backup/wallet.dat" ]; then
    log "Copying legacy wallet.dat into fresh datadir."
    cp -a "$backup/wallet.dat" "$DATADIR/"
    mkdir -p "$wallet_backup" && cp -a "$backup/wallet.dat" "$wallet_backup/"
    log "Extra wallet copy saved at $wallet_backup"
  fi
  prune_old_datadir_backups

  mkdir -p "$DATADIR/faststart"
  if [ -s /mnt/d/BTX/snapshot.dat ]; then
    local_sha=$(sha256sum /mnt/d/BTX/snapshot.dat | awk '{print $1}')
    if [ "$local_sha" = "$sha" ]; then
      log "Reusing matching D:\\BTX\\snapshot.dat in faststart cache."
      cp -f /mnt/d/BTX/snapshot.dat "$DATADIR/faststart/snapshot.dat"
    else
      log "Local D:\\BTX\\snapshot.dat differs from latest; faststart will download the current snapshot."
    fi
  fi

  log "Running btx-faststart.py miner preset. Watch this log for header/download/load progress."
  export PYTHONUNBUFFERED=1
  cmd=("$(pybin)" -u "$FASTSTART" miner
    --chain=main
    --datadir="$DATADIR"
    --btxd="$BTXD"
    --btx-cli="$CLI"
    --snapshot-manifest="$manifest_faststart"
    --header-wait-secs=3600
    --rpc-wait-secs=180
    --poll-secs=5
    --daemon-arg=-debuglogfile=/mnt/d/BTX/btx-faststart-debug.log)
  for arg in "${PEER_ARGS[@]}"; do cmd+=(--daemon-arg="$arg"); done
  if [ "$KEEP_SNAPSHOT" = "1" ]; then cmd+=(--keep-snapshot); fi
  "${cmd[@]}"
fi

if [ -f "$DATADIR/faststart/faststart.conf" ]; then
  log "Merging faststart config into btx.conf."
  cp -f "$DATADIR/faststart/faststart.conf" "$DATADIR/btx.conf"
fi
write_fast_conf

if ! pgrep -f btxd >/dev/null 2>&1; then
  log "Starting btxd with high-peer sync args."
  "$BTXD" -datadir="$DATADIR" "${PEER_ARGS[@]}" -daemon
fi

log "Waiting for RPC."
for _ in $(seq 1 60); do
  if "$CLI" -datadir="$DATADIR" -rpcclienttimeout=3 getblockchaininfo >/tmp/btx-sync-info.json 2>/dev/null; then break; fi
  sleep 2
done
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 loadwallet "$WALLET_NAME" || true
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getblockchaininfo || true
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=10 getconnectioncount || true

# Cache the verified snapshot back to D:\BTX so the next wipe/restore reuses
# it instead of re-downloading 400+ MB from GitHub.
if [ -s "$DATADIR/faststart/snapshot.dat" ]; then
  new_sha=$(sha256sum "$DATADIR/faststart/snapshot.dat" | awk '{print $1}')
  old_sha=$(sha256sum /mnt/d/BTX/snapshot.dat 2>/dev/null | awk '{print $1}' || true)
  if [ "$new_sha" != "$old_sha" ]; then
    log "Updating D:\\BTX\\snapshot.dat cache with the latest release snapshot."
    cp -f "$DATADIR/faststart/snapshot.dat" /mnt/d/BTX/snapshot.dat || true
  fi
fi
log "=== BTX fast local-node sync setup complete. Node will continue catching up with high peer limits. ==="
