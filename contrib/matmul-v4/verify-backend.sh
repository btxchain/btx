#!/usr/bin/env bash
#
# MatMul v4 GPU backend determinism verification.
#
# Run this ON REAL HARDWARE (one invocation per backend, on a host that has
# that silicon). It builds the backend, runs the cross-backend determinism
# harness, and returns PASS only if the backend reproduces the CPU reference
# digest BIT-FOR-BIT (a one-bit divergence is a consensus split -> FAIL).
#
# The harness INCLUDES the C-1 adversarial HIGH-MAGNITUDE accumulator vectors
# (test cases high_magnitude_* in matmul_v4_backend_determinism_tests.cpp;
# roadmap doc/btx-matmul-v4-multiplatform-roadmap.md §4.1, companion
# doc/btx-matmul-v4-accumulator-eligibility.md): they force s8xs8->s32
# accumulations into the (2^24, 2^31) regime that an FP32-mantissa-bounded
# "int8" accumulator (TPU v4-class MXU) silently rounds. A divergence in that
# regime is a CONSENSUS-SPLIT signal and is a hard FAIL, exactly like any
# other digest mismatch; a run in which those vectors did not execute proves
# nothing about accumulator width and is NOT a PASS.
#
# Activation gate (see ACTIVATION.md): mainnet activation is ready as soon as
# BOTH `cuda` and `metal` return PASS on real hardware. Collect the results
# from an NVIDIA host and an Apple M-series host; two PASSes => GO.
#
# Usage:
#   contrib/matmul-v4/verify-backend.sh cuda    # on an NVIDIA (sm>=75) host
#   contrib/matmul-v4/verify-backend.sh metal   # on an Apple M5-class host
#   contrib/matmul-v4/verify-backend.sh hip     # on an AMD CDNA host (optional coverage)
#
# Exit: 0 = PASS (bit-exact), 1 = FAIL/mismatch, 2 = usage/build error.

set -euo pipefail
BACKEND="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-verify-$BACKEND}"
SUITE="matmul_v4_backend_determinism_tests"

case "$BACKEND" in
  cuda)  CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90}") ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;   # Apple; needs Xcode 26+ for the M5 tensor path
  hip)   CMAKE_FLAGS=(-DBTX_ENABLE_HIP=ON "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH:?set HIP_ARCH e.g. gfx942}") ;;
  *) echo "usage: $0 <cuda|metal|hip>"; exit 2 ;;
esac

echo "== MatMul v4 determinism verification: $BACKEND =="
echo "-- configuring ($BUILD)"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
      -DENABLE_WALLET=ON -DBUILD_TESTS=ON "${CMAKE_FLAGS[@]}" >/dev/null || { echo "CONFIGURE FAILED"; exit 2; }
echo "-- building test_btx"
cmake --build "$BUILD" --target test_btx -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null || { echo "BUILD FAILED"; exit 2; }

BIN="$(find "$BUILD" -type f -name test_btx | head -1)"
echo "-- running $SUITE (incl. C-1 high-magnitude accumulator vectors)"
# --log_level=test_suite so executed test-case names appear in the log: the
# C-1 gate below requires positive evidence that the high_magnitude_* vectors
# actually ran (a log that never entered them must not be recorded as PASS).
OUT="$("$BIN" --run_test="$SUITE" --log_level=test_suite 2>&1)" && CODE=0 || CODE=$?

echo "$OUT" | grep -iE "SKIPPED-PENDING-HARDWARE|CONSENSUS|SPLIT|error:|failure|No errors detected" || true

# PASS iff: suite returned 0, AND this backend was actually exercised (no skip),
# AND no consensus-split mismatch was reported, AND the C-1 high-magnitude
# accumulator-regime vectors ran.
if [ "$CODE" -ne 0 ] || echo "$OUT" | grep -qiE "CONSENSUS|SPLIT|has failed"; then
  echo "RESULT: FAIL ($BACKEND) -- digest diverged from CPU reference; NOT safe to activate."
  echo "If the failure is in a high_magnitude_* case, the device's INT8-matmul accumulator is"
  echo "NOT a true >=32-bit integer accumulator (FP32-mantissa-bounded, e.g. TPU v4-class) --"
  echo "the backend is INELIGIBLE per doc/btx-matmul-v4-accumulator-eligibility.md (roadmap 4.1)."
  exit 1
fi
if echo "$OUT" | grep -qi "SKIPPED-PENDING-HARDWARE"; then
  echo "RESULT: INCONCLUSIVE ($BACKEND) -- backend was not compiled in / not exercised on this host."
  exit 1
fi
# C-1 consensus-protecting gate: the (2^24, 2^31) accumulator regime MUST have
# been exercised, or this run certifies nothing about accumulator width.
if ! echo "$OUT" | grep -q "high_magnitude"; then
  echo "RESULT: FAIL ($BACKEND) -- C-1 high-magnitude accumulator vectors (high_magnitude_*) did"
  echo "not run; true >=32-bit integer accumulation is UNVERIFIED (consensus-split hazard,"
  echo "doc/btx-matmul-v4-accumulator-eligibility.md). NOT safe to activate."
  exit 1
fi
echo "RESULT: PASS ($BACKEND) -- bit-exact vs CPU reference on this hardware,"
echo "including the C-1 high-magnitude (2^24..2^31) accumulator-regime vectors."
echo "Record this result in ACTIVATION.md. Activation GO requires PASS on both cuda and metal."
exit 0
