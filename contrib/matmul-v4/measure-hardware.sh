#!/usr/bin/env bash
#
# MatMul v4.1 / v4.2 one-command hardware measurement.
#
# Run this ON THE MACHINE you want data from (one invocation per backend). It
# configures + builds ONLY the `matmul-v4-report` tool with the right backend
# flag (same cmake flags as verify-backend.sh), runs it, and tells you where
# the JSON landed. Send that JSON back — aggregated across datacenter, consumer,
# and Apple machines it drives the activation gates.
#
# --- v4.1 (ENC-S8, default profile) ---
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
# --- v4.2 (ENC-BMX4C profile) — THE M-t24 measurement ---
#
# doc/btx-matmul-v4.2-bmx4c-spec.md §5/§9: M-t24 decides whether commodity
# block-scaled FP4/MX silicon may run the BMX4-C NATIVE path (needs a PROVEN
# t=24 exact accumulator) or must fail closed to the 1-GEMM INT8 fallback (a
# device proven only t~=14, the Hopper FP8 precedent, is INELIGIBLE for the
# native path). Run this NOW on B200 / RTX 5090-class hardware:
#
#   contrib/matmul-v4/measure-hardware.sh cuda --profile bmx4c --mt24
#   contrib/matmul-v4/measure-hardware.sh metal --profile bmx4c --mt24
#   contrib/matmul-v4/measure-hardware.sh cpu   --profile bmx4c --mt24   # sanity: always PASS
#
# This runs the BMX4-C bit-exactness gate (the B1 analogue: ComputeDigestBMX4C
# determinism + VerifySketchBMX4C round-trip), the §5.3/C-1' M-t24 boundary-
# vector suite (odd-step 2^14 crossing, exact pins at 2^22/2^23/2^24), and the
# ENC-BMX4C per-stage stacked-window timing (the §K.2a-WT/§K.2b analogue), and
# prints ONE GO/NO-GO keyed to BOTH the tensor-stage majority (§K.2b) AND the
# M-t24 verdict. NOTE: no on-device BMX4-C kernel is wired into this repo yet
# (only the v4.1 ENC-S8 IMMA/MFMA kernels are), so a non-CPU backend today
# reports `native_path_eligible=false` with an explicit reason instead of
# fabricating an on-silicon pass — see the tool's own header comment and the
# JSON `mt24.native_path_reason` field.
#
# Env: CUDA_ARCH / HIP_ARCH (arch lists), BUILD_DIR (build path override).
# Exit: 0 = PASS (bit-exact, and under --profile bmx4c also M-t24 PASS), 1 =
# FAIL, 2 = usage/build error.

set -euo pipefail
BACKEND="${1:-}"
shift || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-measure-$BACKEND}"

case "$BACKEND" in
  cpu)   CMAKE_FLAGS=() ;;
  cuda)  CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90;100;120}") ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;
  hip)   CMAKE_FLAGS=(-DBTX_ENABLE_HIP=ON "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH:?set HIP_ARCH e.g. gfx942}") ;;
  *) echo "usage: $0 <cpu|cuda|metal|hip> [extra --flags for matmul-v4-report]"; exit 2 ;;
esac

# Detect the requested profile purely to make the echoed messages accurate;
# the flag itself is forwarded to the tool untouched via "$@" below (no
# separate build step is needed -- matmul_v4_bmx4.cpp is already part of the
# common library linked into matmul-v4-report for every backend).
PROFILE="v41"
prev=""
for a in "$@"; do
  if [ "$prev" = "--profile" ]; then PROFILE="$a"; fi
  prev="$a"
done

if [ "$PROFILE" = "bmx4c" ]; then
  echo "== MatMul v4.2 (ENC-BMX4C) hardware measurement + M-t24: $BACKEND =="
else
  echo "== MatMul v4.1 hardware measurement: $BACKEND =="
fi
echo "-- configuring ($BUILD)"
# ENABLE_WALLET=ON + WITH_SQLITE=ON avoids a known CPU-only link failure; the
# report tool only needs the consensus/matmul libraries, so tests are off.
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
      -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DBUILD_TESTS=OFF -DBUILD_UTIL=ON \
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
  if [ "$PROFILE" = "bmx4c" ]; then
    echo "Send this file back — it carries the M-t24 verdict (mt24_pass / proven_accumulator_bits /"
    echo "native_path_eligible). ENC-BMX4C activation needs M-t24 PASS on >= 2 independent vendors'"
    echo "frontier parts (spec §9 item 1)."
  else
    echo "Send this file back; aggregate across machines to settle the B2g ordering."
  fi
else
  echo "NOTE: JSON not found in \$ROOT; check the tool's 'JSON report written:' line above."
fi

if [ "$PROFILE" = "bmx4c" ]; then
  if [ "$CODE" -eq 0 ]; then
    echo "RESULT: BMX4-C bit-exact PASS + M-t24 PASS ($BACKEND) — see the JSON's native_path_eligible."
  else
    echo "RESULT: FAIL ($BACKEND) — either the BMX4-C bit-exactness gate or M-t24 itself failed; see"
    echo "output above. An M-t24 FAIL means the native block-scaled path is INELIGIBLE on this device"
    echo "and MUST fall back to the 1-GEMM INT8 path (spec §5.2 fallback ladder)."
  fi
else
  if [ "$CODE" -eq 0 ]; then
    echo "RESULT: bit-exact PASS ($BACKEND)."
  else
    echo "RESULT: bit-exact FAIL or tool error ($BACKEND) — see output above. A B1 FAIL is a consensus-split signal."
  fi
fi
exit "$CODE"
