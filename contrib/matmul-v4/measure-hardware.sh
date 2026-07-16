#!/usr/bin/env bash
#
# MatMul v4.1 one-command hardware measurement.
#
# Run this ON THE MACHINE you want data from (one invocation per backend). It
# configures + builds ONLY the `matmul-v4-report` tool with the right backend
# flag (same cmake flags as verify-backend.sh), runs it, and tells you where
# the JSON landed. Send that JSON back — aggregated across datacenter, consumer,
# and Apple machines it drives the three activation gates:
#
#   B1  bit-exact determinism   (PASS/FAIL — a FAIL is a hard consensus split)
#   B2b ASERT throughput        (marginal nonce/s; --v3-hashrate -> rescale)
#   B2g datacenter-vs-consumer  (tensor-stage share + implied INT8 utilization)
#
# Usage:
#   contrib/matmul-v4/measure-hardware.sh cpu                       # any host
#   contrib/matmul-v4/measure-hardware.sh cuda                      # NVIDIA sm>=75
#   contrib/matmul-v4/measure-hardware.sh metal                     # Apple M5-class
#   contrib/matmul-v4/measure-hardware.sh hip                       # AMD CDNA
#
# Extra args after the backend are forwarded to the tool, e.g.:
#   contrib/matmul-v4/measure-hardware.sh cuda --n 4096 --window 32 \
#       --device-peak-int8-tops 1979 --v3-hashrate 1200000
#
# Env: CUDA_ARCH / HIP_ARCH (arch lists), BUILD_DIR (build path override).
# Exit: 0 = bit-exact PASS, 1 = FAIL, 2 = usage/build error.

set -euo pipefail
BACKEND="${1:-}"
shift || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-measure-$BACKEND}"

case "$BACKEND" in
  cpu)   CMAKE_FLAGS=() ;;
  cuda)  CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90}") ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;
  hip)   CMAKE_FLAGS=(-DBTX_ENABLE_HIP=ON "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH:?set HIP_ARCH e.g. gfx942}") ;;
  *) echo "usage: $0 <cpu|cuda|metal|hip> [extra --flags for matmul-v4-report]"; exit 2 ;;
esac

echo "== MatMul v4.1 hardware measurement: $BACKEND =="
echo "-- configuring ($BUILD)"
# ENABLE_WALLET=ON + WITH_SQLITE=ON avoids a known CPU-only link failure; the
# report tool only needs the consensus/matmul libraries, so tests are off.
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
      -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DBUILD_TESTS=OFF \
      "${CMAKE_FLAGS[@]}" >/dev/null || { echo "CONFIGURE FAILED"; exit 2; }

echo "-- building matmul-v4-report"
cmake --build "$BUILD" --target matmul-v4-report -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" \
  || { echo "BUILD FAILED"; exit 2; }

BIN="$(find "$BUILD" -type f -name matmul-v4-report | head -1)"
if [ -z "$BIN" ]; then echo "could not locate matmul-v4-report binary"; exit 2; fi

echo "-- running $BIN --backend $BACKEND $*"
set +e
"$BIN" --backend "$BACKEND" "$@"
CODE=$?
set -e

JSON="$(find "$ROOT" -maxdepth 1 -name 'matmul-v4-report-*.json' -newermt '-5 minutes' 2>/dev/null | head -1)"
[ -z "$JSON" ] && JSON="$(ls -t matmul-v4-report-*.json 2>/dev/null | head -1 || true)"
echo ""
if [ -n "$JSON" ]; then
  echo "JSON report: $JSON"
  echo "Send this file back; aggregate across machines to settle the B2g ordering."
else
  echo "NOTE: JSON not found in \$ROOT; check the tool's 'JSON report written:' line above."
fi

if [ "$CODE" -eq 0 ]; then
  echo "RESULT: bit-exact PASS ($BACKEND)."
else
  echo "RESULT: bit-exact FAIL or tool error ($BACKEND) — see output above. A B1 FAIL is a consensus-split signal."
fi
exit "$CODE"
