#!/usr/bin/env bash
# Make the v0.32.8 bin/ wrappers self-contained: export LD_LIBRARY_PATH to the
# local runtime-libs dir (root-free lib install) before the ldd check + exec.
set -u
BINDIR=/home/eldian/btx-node/bin
INJECT='export LD_LIBRARY_PATH="$SELF_DIR/../runtime-libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"'
for w in btxd btx-cli; do
  f="$BINDIR/$w"
  [ -f "$f" ] || { echo "missing $f"; continue; }
  if grep -q 'runtime-libs' "$f"; then echo "$w already patched"; continue; fi
  # Insert the export right after the SELF_DIR= line.
  sed -i "/^SELF_DIR=/a $INJECT" "$f"
  echo "patched $w"
done
echo "=== verify (no external LD_LIBRARY_PATH set) ==="
/home/eldian/btx-node/bin/btxd --version | head -1
/home/eldian/btx-node/bin/btx-cli --version | head -1
