#!/usr/bin/env bash
# Download/install the latest BTX Linux CUDA release into /home/eldian/btx-node.
set -Eeuo pipefail

REPO=${REPO:-btxchain/btx}
INSTALL=${INSTALL:-/home/eldian/btx-node}
DATADIR=${DATADIR:-/home/eldian/.btx}
PREFER_CUDA=${PREFER_CUDA:-cuda12}
WORK=${BTX_UPDATE_WORK:-/tmp/btx-update-latest}
LOG=${LOG:-/mnt/d/BTX/btx-update-latest.log}

mkdir -p "$(dirname "$LOG")" "$INSTALL" "$WORK"
# Keep a real log while also returning useful text to the GUI.
exec > >(tee -a "$LOG") 2>&1
trap 'rc=$?; echo "[$(date "+%F %T")] BTX update failed at line $LINENO with exit $rc"; exit $rc' ERR

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
json_get() {
  # $1 = small Python expression using variable d, e.g. d["tag_name"]
  if have python3; then
    python3 -c 'import json,sys; d=json.load(sys.stdin); print('$1')'
  elif have python; then
    python -c 'import json,sys; d=json.load(sys.stdin); print('$1')'
  else
    echo "Python is required in WSL for parsing GitHub release JSON." >&2
    return 2
  fi
}

log "Starting BTX update"
api="https://api.github.com/repos/${REPO}/releases/latest"
json_file="$WORK/latest-release.json"
asset_file="$WORK/asset-url.txt"

if ! have curl; then
  echo "curl is required in WSL for BTX updates." >&2
  exit 2
fi

curl -L --fail --retry 3 --connect-timeout 15 --max-time 120 \
  -H 'User-Agent: BTX-updater' \
  -H 'Accept: application/vnd.github+json' \
  -o "$json_file" "$api"

tag=$(json_get 'd["tag_name"]' < "$json_file")
if have python3; then py=python3; elif have python; then py=python; else echo "Python is required in WSL for parsing GitHub release JSON." >&2; exit 2; fi
"$py" -c '
import json, sys
json_file, pref = sys.argv[1], sys.argv[2]
with open(json_file, "r", encoding="utf-8") as f:
    d = json.load(f)
assets = d.get("assets", [])
choices = [
    f"x86_64-linux-gnu-{pref}",
    "x86_64-linux-gnu-cuda12",
    "x86_64-linux-gnu-cuda13",
    "x86_64-linux-gnu",
]
for needle in choices:
    for a in assets:
        name = a.get("name", "")
        if needle in name and name.endswith(".tar.gz"):
            print(a.get("browser_download_url", ""))
            raise SystemExit(0)
print("")
' "$json_file" "$PREFER_CUDA" > "$asset_file"
asset=$(cat "$asset_file")

if [ -z "$tag" ] || [ -z "$asset" ]; then
  echo "Could not find a suitable Linux x86_64 release asset." >&2
  echo "Tag: ${tag:-missing}" >&2
  echo "Release JSON saved at: $json_file" >&2
  exit 1
fi

log "Latest release: $tag"
log "Asset: $asset"

current="unknown"
if [ -x "$INSTALL/bin/btxd" ]; then
  current=$("$INSTALL/bin/btxd" --version 2>/dev/null | head -1 || true)
fi
log "Current: $current"
if printf '%s' "$current" | grep -q "${tag#v}"; then
  log "Already on $tag; no binary replacement needed."
  exit 0
fi

rm -rf "$WORK/extract"
mkdir -p "$WORK/extract"
archive="$WORK/$(basename "$asset")"
if [ ! -s "$archive" ]; then
  curl -L --fail --retry 3 --connect-timeout 15 --max-time 1800 -o "$archive" "$asset"
fi

log "Stopping btxd for binary replacement if it is running..."
if [ -x "$INSTALL/bin/btx-cli" ]; then "$INSTALL/bin/btx-cli" -datadir="$DATADIR" stop || true; fi
for _ in $(seq 1 30); do pgrep -x btxd >/dev/null 2>&1 || break; sleep 1; done
pkill -x btxd 2>/dev/null || true
sleep 2

tar -xzf "$archive" -C "$WORK/extract"
bindir=$(find "$WORK/extract" -maxdepth 3 -type f -name btxd -printf '%h\n' | head -1)
if [ -z "$bindir" ]; then
  echo "Downloaded asset did not contain btxd." >&2
  find "$WORK/extract" -maxdepth 3 -type f | head -50 >&2 || true
  exit 1
fi
# v0.32.7+ split layout: release root holds bin/ (wrappers) + libexec/*.real.
relroot=$(dirname "$bindir")

backup="${INSTALL}.backup.$(date '+%Y%m%d-%H%M%S')"
if [ -d "$INSTALL/bin" ]; then
  mkdir -p "$backup"
  cp -a "$INSTALL/bin" "$backup/"
  [ -d "$INSTALL/libexec" ] && cp -a "$INSTALL/libexec" "$backup/"
  log "Backed up old binaries to $backup"
fi
mkdir -p "$INSTALL/bin"
cp -a "$bindir/." "$INSTALL/bin/"
# Copy the sibling libexec/*.real that the bin wrappers exec (was the layout bug).
if [ -d "$relroot/libexec" ]; then
  rm -rf "$INSTALL/libexec"
  cp -a "$relroot/libexec" "$INSTALL/"
fi
chmod +x "$INSTALL/bin"/* "$INSTALL/libexec"/* 2>/dev/null || true
echo "$tag" > "$INSTALL/VERSION"

# v0.32.8 binaries need libzmq5/libevent runtime libs. If absent (and no root),
# fetch them locally and patch the wrappers to find them. Helpers are idempotent.
if ! "$INSTALL/bin/btxd" --version >/dev/null 2>&1; then
  log "btxd missing runtime libs; fetching locally (no root) + patching wrappers."
  bash /mnt/d/BTX/btx-fetch-libs.sh >/dev/null 2>&1 || true
  bash /mnt/d/BTX/btx-patch-wrappers.sh >/dev/null 2>&1 || true
fi

"$INSTALL/bin/btxd" --version | head -3
log "BTX update complete: $tag"
