#!/usr/bin/env bash
#
# MatMul v4 GPU backend determinism verification.
#
# Run this ON REAL HARDWARE (one invocation per backend, on a host that has
# that silicon). It builds the backend, runs the cross-backend determinism
# harness, and returns PASS only if the backend reproduces the CPU reference
# digest BIT-FOR-BIT (a one-bit divergence is a consensus split -> FAIL).
#
# The C-1 adversarial HIGH-MAGNITUDE accumulator vectors force s8xs8->s32
# accumulations into the (2^24, 2^31) regime that an FP32-mantissa-bounded
# "int8" accumulator (TPU v4-class MXU) silently rounds. A divergence in that
# regime is a CONSENSUS-SPLIT signal and is a hard FAIL, exactly like any
# other digest mismatch; a run in which those vectors did not execute on the
# SELECTED DEVICE proves nothing about accumulator width and is NOT a PASS.
#
# G4 (device-certification, not name-matching): a high_magnitude_* unit-test
# NAME appearing in the test log is CPU-only bookkeeping -- it is printed
# whether or not the selected GPU ran anything, so it is NOT evidence the
# device covered the accumulator regime. This script therefore requires an
# explicit RUNTIME MARKER
#     DEVICE_HIGH_MAGNITUDE_PASS:<backend>:<device-id>
# that the harness emits ONLY after the selected device entry point executed
# the (2^24, 2^31) vectors AND matched the CPU reference byte-for-byte. The
# marker is NEVER emitted on skip / unsupported / ALU-fallback / CPU-fallback /
# compile-failure, so its presence is positive proof the chosen silicon --
# identified by <device-id> -- certified true >=32-bit integer accumulation.
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
# --- v4.2 (ENC-BMX4C profile) — the M-t24 verification mode ---
#
#   contrib/matmul-v4/verify-backend.sh cuda --profile bmx4c   # M-t24 on B200/RTX 5090-class
#   contrib/matmul-v4/verify-backend.sh metal --profile bmx4c
#   contrib/matmul-v4/verify-backend.sh hip --profile bmx4c
#
# Builds `matmul-v4-report` (not test_btx) with the same backend CMake flags
# and runs `--profile bmx4c --mt24`: the BMX4-C bit-exactness gate (B1
# analogue), the §5.3/C-1' M-t24 boundary-vector suite, and the ENC-BMX4C
# per-stage stacked-window timing, combined into ONE GO/NO-GO keyed to the
# §K.2b tensor-stage majority AND the M-t24 verdict (doc/btx-matmul-v4.2-bmx4c-
# spec.md §5/§9). PASS here means: bit-exact vs the CPU reference, AND the
# accumulator is PROVEN t=24 on this device (native path eligible). FAIL means
# either a consensus-split digest divergence OR (more likely on commodity
# parts) a t~=14 accumulator that fails the boundary-pin vectors -- which is
# NOT a bug, it is the answer M-t24 exists to get: that device MUST use the
# 1-GEMM INT8 fallback (spec §5.2), never the native block-scaled path.
# ENC-BMX4C activation requires M-t24 PASS on >= 2 independent vendors'
# frontier parts (spec §9 item 1) -- collect results the same way this
# script's v4.1 mode collects cuda+metal PASSes for ACTIVATION.md.
#
# Exit: 0 = PASS (bit-exact [+ M-t24 PASS under --profile bmx4c]), 1 =
# FAIL/mismatch, 2 = usage/build error.

set -euo pipefail
BACKEND="${1:-}"
shift || true
PROFILE="v41"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
if [ "$PROFILE" != "v41" ] && [ "$PROFILE" != "bmx4c" ]; then
  echo "unknown --profile (want v41 or bmx4c): $PROFILE"; exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-verify-$BACKEND}"
SUITE="matmul_v4_backend_determinism_tests"

case "$BACKEND" in
  # External review: include Blackwell (sm_100/sm_120) so a 5090/B200 builds
  # native code instead of JIT'd sm_90 (mirrors measure-hardware.sh).
  cuda)  CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90;100;120}") ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;   # Apple; needs Xcode 26+ for the M5 tensor path
  hip)   CMAKE_FLAGS=(-DBTX_ENABLE_HIP=ON "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH:?set HIP_ARCH e.g. gfx942}") ;;
  *) echo "usage: $0 <cuda|metal|hip> [--profile v41|bmx4c]"; exit 2 ;;
esac

if [ "$PROFILE" = "bmx4c" ]; then
  echo "== MatMul v4.2 (ENC-BMX4C) M-t24 verification: $BACKEND =="
  echo "-- configuring ($BUILD)"
  # External review: BUILD_UTIL defaults to ${BUILD_TESTS}; with BUILD_TESTS=OFF
  # the matmul-v4-report target is never configured and the build step below dies.
  # Force BUILD_UTIL=ON so the report tool is always built (mirrors measure-hardware.sh).
  cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
        -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DBUILD_TESTS=OFF -DBUILD_UTIL=ON \
        "${CMAKE_FLAGS[@]}" >/dev/null || { echo "CONFIGURE FAILED"; exit 2; }
  echo "-- building matmul-v4-report"
  cmake --build "$BUILD" --target matmul-v4-report -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" \
    || { echo "BUILD FAILED"; exit 2; }
  BIN="$(find "$BUILD" -type f -name matmul-v4-report | head -1)"
  [ -n "$BIN" ] || { echo "could not locate matmul-v4-report binary"; exit 2; }

  echo "-- running $BIN --backend $BACKEND --profile bmx4c --mt24"
  set +e
  OUT="$("$BIN" --backend "$BACKEND" --profile bmx4c --mt24 2>&1)"
  CODE=$?
  set -e
  echo "$OUT"

  # C6/H8 (device-certification, not exit-code-alone): a report exit 0 is
  # necessary but NOT sufficient. Mirror the v4.1 mode's device-marker
  # requirement (see the DEVICE_HIGH_MAGNITUDE_PASS gate below): the report must
  # ALSO emit the honest on-device native-tensor marker
  #     DEVICE_BMX4C_MT24_PASS:<backend>:<device-reason>
  # which matmul-v4-report emits ONLY when a real, certified on-silicon BMX4-C
  # native tensor path executed -- NEVER on a CPU-only / emulated run (which now
  # exits non-zero and prints NOT-CERTIFIED). Without this marker a green exit
  # code from a CPU harness self-test can never be mistaken for a device PASS.
  MARKER="$(echo "$OUT" | grep -oE "DEVICE_BMX4C_MT24_PASS:${BACKEND}:[^[:space:]]*" | head -1)"

  if [ "$CODE" -eq 0 ] && [ -n "$MARKER" ]; then
    echo "RESULT: PASS ($BACKEND) -- BMX4-C bit-exact vs the CPU reference AND M-t24 PASS: the"
    echo "accumulator is PROVEN t=24 on the SELECTED device ($MARKER) -- the BMX4-C NATIVE path"
    echo "is ELIGIBLE on this silicon. Record this result in ACTIVATION.md Gate C. ENC-BMX4C"
    echo "activation needs M-t24 PASS on >= 2 independent vendors' frontier parts (spec §9 item 1)."
  elif [ "$CODE" -eq 0 ] && [ -z "$MARKER" ]; then
    echo "RESULT: FAIL ($BACKEND) -- the report exited 0 but emitted NO on-device BMX4-C marker"
    echo "(DEVICE_BMX4C_MT24_PASS:${BACKEND}:<device-reason>): no real on-silicon native tensor path"
    echo "executed (CPU-only / emulated run). A device profile is NOT certified by a CPU harness"
    echo "self-test. NOT safe to activate."
    CODE=1
  else
    if echo "$OUT" | grep -qi "NO-GO(native path): M-t24 FAILED"; then
      echo "RESULT: FAIL ($BACKEND) -- M-t24 FAILED: the accumulator is proven only up to the bits"
      echo "reported above (< t=24). This is NOT a consensus-split bug -- it is the M-t24 answer:"
      echo "this device's native block-scaled path is INELIGIBLE and MUST use the 1-GEMM INT8"
      echo "fallback (spec §5.2 fallback ladder), never the native path."
    else
      echo "RESULT: FAIL ($BACKEND) -- BMX4-C bit-exactness or stage measurement diverged; see output"
      echo "above. A bit-exact FAIL is a CONSENSUS-SPLIT signal -- do NOT activate this backend."
    fi
  fi
  exit "$CODE"
fi

echo "== MatMul v4 determinism verification: $BACKEND =="
echo "-- configuring ($BUILD)"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
      -DENABLE_WALLET=ON -DBUILD_TESTS=ON "${CMAKE_FLAGS[@]}" >/dev/null || { echo "CONFIGURE FAILED"; exit 2; }
echo "-- building test_btx"
cmake --build "$BUILD" --target test_btx -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null || { echo "BUILD FAILED"; exit 2; }

BIN="$(find "$BUILD" -type f -name test_btx | head -1)"
echo "-- running $SUITE (device-vs-CPU determinism + C-1 high-magnitude marker)"
# --log_level=test_suite so executed suite/case names appear AND so the
# harness's runtime marker line is captured in $OUT. The C-1 gate below does
# NOT accept a high_magnitude_* test NAME as evidence (a CPU-only unit test
# prints that name whether or not the SELECTED DEVICE ran); it requires the
# explicit DEVICE_HIGH_MAGNITUDE_PASS runtime marker (see header).
OUT="$("$BIN" --run_test="$SUITE" --log_level=test_suite 2>&1)" && CODE=0 || CODE=$?

echo "$OUT" | grep -iE "SKIPPED-PENDING-HARDWARE|CONSENSUS|SPLIT|error:|failure|No errors detected|DEVICE_HIGH_MAGNITUDE_PASS" || true

# PASS iff: suite returned 0, AND this backend was actually exercised (no skip),
# AND no consensus-split mismatch was reported, AND the SELECTED DEVICE emitted
# the C-1 high-magnitude runtime marker.
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
# C-1 consensus-protecting gate (G4): require the DEVICE runtime marker for THIS
# backend -- DEVICE_HIGH_MAGNITUDE_PASS:<backend>:<device-id>. It is emitted by
# the harness ONLY after the selected device entry point executed the
# (2^24, 2^31) accumulator vectors AND matched the CPU reference, and NEVER on
# skip / unsupported / ALU-fallback / CPU-fallback / compile-failure -- so its
# presence is positive proof the SELECTED silicon (not a CPU unit test) covered
# the accumulator-width regime. A bare high_magnitude_* NAME is NOT accepted.
MARKER="$(echo "$OUT" | grep -oE "DEVICE_HIGH_MAGNITUDE_PASS:${BACKEND}:[^[:space:]]+" | head -1)"
if [ -z "$MARKER" ]; then
  echo "RESULT: FAIL ($BACKEND) -- no device high-magnitude marker"
  echo "(DEVICE_HIGH_MAGNITUDE_PASS:${BACKEND}:<device-id>) was emitted: the SELECTED device did"
  echo "not execute+match the C-1 (2^24..2^31) accumulator vectors, so true >=32-bit integer"
  echo "accumulation is UNVERIFIED (consensus-split hazard, doc/btx-matmul-v4-accumulator-"
  echo "eligibility.md). A high_magnitude_* CPU unit-test NAME in the log is NOT evidence."
  echo "NOT safe to activate."
  exit 1
fi
echo "RESULT: PASS ($BACKEND) -- bit-exact vs CPU reference on this hardware, including the C-1"
echo "high-magnitude (2^24..2^31) accumulator vectors on the SELECTED device ($MARKER)."
echo "Record this result in ACTIVATION.md. Activation GO requires PASS on both cuda and metal."
exit 0
