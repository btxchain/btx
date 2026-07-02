#!/usr/bin/env bash
# Fetch v0.32.8 btxd runtime libs (libzmq5 + libevent extra/pthreads + zmq deps)
# without root: apt-get download the .debs, extract .so files into a local dir,
# then verify btxd.real resolves via LD_LIBRARY_PATH.
set -u
LIBDIR=/home/eldian/btx-node/runtime-libs
WORK=/tmp/btx-libs
BTXD=/home/eldian/btx-node/libexec/btxd.real
mkdir -p "$LIBDIR" "$WORK"; cd "$WORK"

# Primary missing + libzmq5 transitive deps that are commonly absent on minimal WSL.
PKGS="libzmq5 libevent-extra-2.1-7t64 libevent-pthreads-2.1-7t64 libsodium23 libpgm-5.3-0t64 libnorm1t64 libbsd0 libmd0"
for p in $PKGS; do
  apt-get download "$p" 2>/dev/null && echo "downloaded $p" || echo "skip $p (unavailable)"
done
for deb in "$WORK"/*.deb; do
  [ -f "$deb" ] || continue
  dpkg-deb -x "$deb" "$WORK/x" 2>/dev/null || true
done
find "$WORK/x" -name '*.so*' -exec cp -an {} "$LIBDIR/" \; 2>/dev/null
( cd "$LIBDIR" && ldconfig -n . 2>/dev/null || true )
echo "=== libs collected ==="
ls "$LIBDIR" | head -40
echo "=== remaining missing for btxd.real (with LD_LIBRARY_PATH) ==="
LD_LIBRARY_PATH="$LIBDIR" ldd "$BTXD" 2>/dev/null | grep -i 'not found' || echo "ALL RESOLVED"
echo "=== version test ==="
LD_LIBRARY_PATH="$LIBDIR" "$BTXD" --version 2>&1 | head -2
