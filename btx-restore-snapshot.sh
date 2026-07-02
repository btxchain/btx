#!/usr/bin/env bash
# Restore the D:\BTX WSL BTX node using the same fast-start flow used by EasyBTX/BTX:
# latest release snapshot manifest -> latest snapshot.dat -> loadtxoutset -> monitor getchainstates.
set -Eeuo pipefail

# btxd selects its MatMul accelerator from this env var (default cpu on Linux).
# faststart spawns btxd as a child, so export here or the restored node — which
# keeps running and serves the solo miner — mines on CPU instead of CUDA.
export BTX_MATMUL_BACKEND=${BTX_MATMUL_BACKEND:-cuda}

CLI=${CLI:-/home/eldian/btx-node/bin/btx-cli}
BTXD=${BTXD:-/home/eldian/btx-node/bin/btxd}
DATADIR=${DATADIR:-/home/eldian/.btx}
REPO=${REPO:-btxchain/btx}
# RELEASE_TAG is resolved from the latest GitHub release below unless overridden.
RELEASE_TAG=${RELEASE_TAG:-}
FASTSTART=${FASTSTART:-/mnt/d/BTX/contrib/faststart/btx-faststart.py}
LOG=${LOG:-/mnt/d/BTX/btx-restore-snapshot.log}
GUARD=${GUARD:-/mnt/d/BTX/btx-pool-guard.sh}
WALLET_NAME=${WALLET_NAME:-my-wallet}
# Shared with btx-sync-fast.sh and watched by the solo guard: only one
# snapshot restore/sync flow may touch the datadir at a time. Running two
# concurrently corrupts shielded_state mid-loadtxoutset.
LOCK=${LOCK:-/tmp/btx-sync-fast.lock}
# Keep the downloaded snapshot for reuse so repeated restores do not re-download 400+ MB.
KEEP_SNAPSHOT=${KEEP_SNAPSHOT:-1}

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
trap 'rc=$?; echo "[$(date "+%F %T")] fast restore failed at line $LINENO with exit $rc"; exit $rc' ERR
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
  log "Another snapshot sync/restore already holds $LOCK (pid=$(cat /tmp/btx-sync-fast.pid 2>/dev/null || echo '?')). Refusing to run a second restore on the same datadir."
  log "Wait for it to finish (watch D:\\BTX\\btx-sync-fast.log / btx-restore-snapshot.log), or remove a stale lock with: rmdir $LOCK"
  exit 3
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

log "=== BTX EasyBTX-style fast snapshot restore started ==="
log "This uses the latest GitHub release snapshot, not the older local D:\\BTX\\snapshot.dat if GitHub is newer."

if [ ! -x "$BTXD" ] || [ ! -x "$CLI" ]; then
  echo "Missing BTX binaries under /home/eldian/btx-node/bin. Run Update BTX first." >&2
  exit 2
fi
if [ ! -f "$FASTSTART" ]; then
  echo "Missing faststart helper: $FASTSTART" >&2
  exit 2
fi
if ! pybin >/dev/null; then
  echo "python/python3 is required in WSL for faststart." >&2
  exit 2
fi

log "Stopping guard/miner/node if running."
if [ -x "$GUARD" ]; then bash "$GUARD" stop || true; fi
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=5 stop || true
pkill -f dexbtx-miner 2>/dev/null || true
pkill -f btx-gbt-solve 2>/dev/null || true
pkill -f 'btxd(\.real)?' 2>/dev/null || true
sleep 3

stamp=$(date '+%Y%m%d-%H%M%S')
backup="${DATADIR}.broken-before-faststart-${stamp}"
wallet_backup="/mnt/d/BTX/wallet-backup-${stamp}"
if [ -d "$DATADIR" ]; then
  log "Backing up old datadir to $backup"
  mv "$DATADIR" "$backup"
fi
mkdir -p "$DATADIR"
chmod 700 "$DATADIR" || true

if [ -d "$backup/wallets" ]; then
  log "Copying wallet directory back into fresh datadir."
  cp -a "$backup/wallets" "$DATADIR/"
  mkdir -p "$wallet_backup"
  cp -a "$backup/wallets" "$wallet_backup/"
  log "Extra wallet copy saved at $wallet_backup"
elif [ -f "$backup/wallet.dat" ]; then
  log "Copying legacy wallet.dat back into fresh datadir."
  cp -a "$backup/wallet.dat" "$DATADIR/"
  mkdir -p "$wallet_backup"
  cp -a "$backup/wallet.dat" "$wallet_backup/"
  log "Extra wallet copy saved at $wallet_backup"
fi
prune_old_datadir_backups

if [ -z "$RELEASE_TAG" ]; then
  log "Resolving latest BTX release tag."
  RELEASE_TAG=$(curl -L --fail --retry 3 --connect-timeout 15 --max-time 60 \
    -H 'User-Agent: BTX-restore' -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${REPO}/releases/latest" \
    | "$(pybin)" -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
fi
log "Using release: $RELEASE_TAG"

manifest_url="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/snapshot.manifest.json"
manifest_local="/mnt/d/BTX/snapshot.latest.manifest.json"
manifest_faststart="/tmp/btx-restore-snapshot.manifest.json"
log "Downloading latest snapshot manifest: $manifest_url"
curl -L --fail --retry 3 --connect-timeout 15 --max-time 120 -o "$manifest_local" "$manifest_url"
height=$(json_field "$manifest_local" height)
sha=$(json_field "$manifest_local" sha256)
blockhash=$(json_field "$manifest_local" blockhash)
log "Latest snapshot anchor: height=$height blockhash=$blockhash sha256=$sha"

# Faststart's getblockheader(blockhash) wait can hang on BTX header-only
# startup even after headers pass the anchor height, and the published
# manifest carries no url field (it breaks when passed as a local file).
# Strip blockhash so the wait gates on headers>=height, and inject the
# snapshot URL derived from the release tag. loadtxoutset still validates
# the snapshot sha256/height itself.
"$(pybin)" - "$manifest_local" "$manifest_faststart" "https://github.com/${REPO}/releases/download/${RELEASE_TAG}" <<'PY'
import json, sys
src, dst, base_url = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(src, encoding='utf-8'))
d.pop('blockhash', None)
if 'url' not in d and 'asset_url' not in d:
    filename = d.get('filename') or d.get('published_name') or 'snapshot.dat'
    d['url'] = f"{base_url}/{filename}"
json.dump(d, open(dst, 'w', encoding='utf-8'), indent=2)
PY

# Faststart will download snapshot.dat beside DATADIR/faststart unless a cached file already exists there.
# Seed the cache from D:\BTX\snapshot.dat only if it matches the latest release hash.
mkdir -p "$DATADIR/faststart"
if [ -s /mnt/d/BTX/snapshot.dat ]; then
  local_sha=$(sha256sum /mnt/d/BTX/snapshot.dat | awk '{print $1}')
  if [ "$local_sha" = "$sha" ]; then
    log "Reusing matching D:\\BTX\\snapshot.dat in faststart cache."
    cp -f /mnt/d/BTX/snapshot.dat "$DATADIR/faststart/snapshot.dat"
  else
    log "Existing D:\\BTX\\snapshot.dat is older/different ($local_sha); faststart will download current snapshot."
  fi
fi

log "Starting btx-faststart.py miner preset. Progress lines below are the sync indicator."
log "If it is waiting for headers, watch 'waiting for snapshot anchor header: headers=X/$height'."
log "btxd debug log for this faststart run: D:\\BTX\\btx-faststart-debug.log"
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
  --daemon-arg=-blockfilterindex=0
  --daemon-arg=-miningchainguardminpeers=1
  --daemon-arg=-miningchainguardmaxmediangap=30
  --daemon-arg=-fastshieldedstartup=1
  --daemon-arg=-shieldedstartupaudit=0
  --daemon-arg=-dnsseed=1
  --daemon-arg=-maxconnections=96
  --daemon-arg=-addnode=node.btx.tools
  --daemon-arg=-addnode=peers.minebtx.com
  --daemon-arg=-addnode=164.90.246.229
  --daemon-arg=-addnode=146.190.179.86
  --daemon-arg=-addnode=143.198.155.4
  --daemon-arg=-debuglogfile=/mnt/d/BTX/btx-faststart-debug.log)
if [ "$KEEP_SNAPSHOT" = "1" ]; then
  cmd+=(--keep-snapshot)
fi
"${cmd[@]}"

# Copy generated faststart config to default btx.conf so the guard's normal btxd invocation uses the same fast settings.
if [ -f "$DATADIR/faststart/faststart.conf" ]; then
  log "Copying faststart.conf to btx.conf for guard compatibility."
  cp -f "$DATADIR/faststart/faststart.conf" "$DATADIR/btx.conf"
  for kv in blockfilterindex=0 fastshieldedstartup=1 shieldedstartupaudit=0 prune=4096 dnsseed=1 maxconnections=96 miningchainguardminpeers=1 dbcache=1500 maxmempool=100; do
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
fi

log "Loading wallet if present."
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=30 loadwallet "$WALLET_NAME" || true
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=30 getblockchaininfo || true
"$CLI" -datadir="$DATADIR" -rpcclienttimeout=30 getchainstates || true
log "=== Fast snapshot restore complete. Press RUN + GUARD to start pool mining. ==="
