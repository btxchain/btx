#!/usr/bin/env bash
# Correctly install an extracted BTX release that uses the bin/ + libexec/ layout
# (v0.32.7+). The stock btx-update-latest.sh only copied the btxd dir (bin/),
# leaving libexec/*.real missing. This copies the whole release tree.
set -Eeuo pipefail
INSTALL=${INSTALL:-/home/eldian/btx-node}
SRC=${SRC:-$(find /tmp/btx-update-latest/extract -maxdepth 2 -type d -name 'btx-*' | head -1)}
[ -z "$SRC" ] && { echo "no extracted release found under /tmp/btx-update-latest/extract"; exit 1; }
echo "installing from: $SRC"

pkill -x btxd 2>/dev/null || true; sleep 1

# libexec is the missing piece; bin holds the wrappers.
[ -d "$SRC/libexec" ] && cp -a "$SRC/libexec" "$INSTALL/"
cp -a "$SRC/bin/." "$INSTALL/bin/"
[ -d "$SRC/contrib" ] && cp -a "$SRC/contrib" "$INSTALL/" || true
chmod +x "$INSTALL/bin/"* "$INSTALL/libexec/"* 2>/dev/null || true

echo "=== installed layout ==="
ls -la "$INSTALL/bin/btxd" "$INSTALL/bin/btx-cli" "$INSTALL/libexec/" 2>/dev/null
echo "=== version check ==="
"$INSTALL/bin/btxd" --version | head -2
"$INSTALL/bin/btx-cli" --version | head -1
