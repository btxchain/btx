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
#
# --- v4.4-LT Rank-1 (ENC-DR-LT profile) ---
#
# Production-shape measurement (MatExpand + deep-m + Q*):
#
#   contrib/matmul-v4/measure-hardware.sh cuda --profile bmx4c-lt --n 4096 --window 256
#   contrib/matmul-v4/measure-hardware.sh cpu  --profile bmx4c-lt --n 256 --window 8   # smoke
#
# Fast resident-path telemetry when production n=4096 CPU reference work would
# delay the device probe. This deliberately skips exactness/stage gates and its
# telemetry_device_nonce_per_s MUST NOT be used for readiness, ASERT, or G1-G3:
#
#   contrib/matmul-v4/measure-hardware.sh cuda --profile bmx4c-lt \
#       --n 4096 --window 256 --telemetry-only
#   CUDA-review compatibility spelling (same full-Q* telemetry semantics):
#       --n 4096 --window 256 --lt-raw-only --lt-raw-full-window
#
# Emits schema_version 3 JSON with MatExpand/Q* stage boundaries. CUDA/HIP now
# use a full-header batch entry that preserves every nonce-bound seed, generates
# W and hashes Chat on-device, and synchronizes once at the batch boundary.
# Legacy/fallback paths remain host_orchestrated_nonce_per_s diagnostics.
# G2/G3 and ASERT accept a rate only when the backend reports
# device_rate_valid=true, silicon_rate_valid=true,
# execution_path="device-resident-qstar-batched", and proves all of:
# lt.qstar_is_consensus, lt.qstar_device_batched, lt.device_w_generation,
# lt.device_digest, and lt.per_nonce_sync_absent.
# `cpu_reference_tensor_share_pct` is only CPU-reference stage composition.
# Reports record `sha256_implementation`; discard older CPU timing/share
# results from tools that did not initialize SHA256AutoDetect before timing.
# G1 additionally requires
# native_path_eligible=true, device_tensor_timing_valid=true,
# device_tensor_counters_valid=true, timing domain
# `device-kernel-timing-and-counters`, and device_tensor_share_pct > 50.
#
#   contrib/matmul-v4/lt-gate.py <dir-of-json> --manifest parts.tsv
#
# Fail-closed if fields are missing. For inert scaffolding only:
#   scripts/matmul_lt_readiness.sh / lt-gate.py --check-inert
#
# External C-15 (math hardness) remains a separate human gate:
#   doc/btx-matmul-v4.4-lt-external-c15-packet.md
#
# --- ENC_RC (Resident Curriculum) ---
#
# Real CPU episode harness (toy dims by default). Builds matmul-v4-rc-harness
# when present and runs it; aggregate with rc-gate.py (PARTIAL for toy, never
# raises nMatMulRCHeight):
#
#   contrib/matmul-v4/measure-hardware.sh cpu rc --toy --out /tmp/rc.json
#   contrib/matmul-v4/rc-gate.py /tmp/rc.json --out /tmp/rc-summary.json
#
# --- Stage G campaign profiles (same-tip, multi-run, rc-gate schema) ---
#
#   contrib/matmul-v4/measure-hardware.sh cpu --profile rc-toy
#   contrib/matmul-v4/measure-hardware.sh cpu --profile rc-medium
#   contrib/matmul-v4/measure-hardware.sh cpu --profile coupled
#   contrib/matmul-v4/measure-hardware.sh cpu --profile coupled-medium
#
# Emits campaign JSON (evidence_kind, device_resident, tip, walls, RSS,
# variance across ≥3 runs). Interconnect NVLink factor is SIMULATED only.

set -euo pipefail
BACKEND="${1:-}"
shift || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-measure-$BACKEND}"

# Optional first/extra token `rc` selects the ENC_RC harness instead of matmul-v4-report.
RC_MODE=0
STAGE_G_PROFILE=""
if [ "$BACKEND" = "rc" ]; then
  RC_MODE=1
  BACKEND="${1:-cpu}"
  shift || true
fi
# Also accept `rc` anywhere in remaining args (e.g. measure-hardware.sh cpu rc --toy).
FILTERED_ARGS=()
prev=""
for a in "$@"; do
  if [ "$a" = "rc" ] && [ "$prev" != "--profile" ]; then
    RC_MODE=1
  else
    FILTERED_ARGS+=("$a")
  fi
  prev="$a"
done
set -- "${FILTERED_ARGS[@]+"${FILTERED_ARGS[@]}"}"

# Detect Stage G campaign profiles early (before cmake for report tool).
prev=""
for a in "$@"; do
  if [ "$prev" = "--profile" ]; then
    case "$a" in
      coupled|coupled-medium|rc-toy|rc-medium)
        STAGE_G_PROFILE="$a"
        RC_MODE=1
        ;;
    esac
  fi
  prev="$a"
done

case "$BACKEND" in
  cpu)   CMAKE_FLAGS=() ;;
  # External review (vanities): the default arch list omitted Blackwell, so a
  # 5090 (sm_120) / B200 (sm_100) ran JIT'd sm_90 instead of native code. Include
  # 100;120 so the INT8 tensor path is built for Blackwell. (The MXFP4 native GEMM
  # additionally needs the compute_120a variant, but it is currently unserved by
  # cuBLASLt and falls back to INT8 regardless -- see the round-2 remediation doc.)
  cuda)  CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90;100;120}") ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;
  hip)   CMAKE_FLAGS=(-DBTX_ENABLE_HIP=ON "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH:?set HIP_ARCH e.g. gfx942}") ;;
  *) echo "usage: $0 <cpu|cuda|metal|hip> [rc] [extra --flags]"; echo "       $0 rc [cpu|cuda|metal|hip] [extra --flags]"; exit 2 ;;
esac

# Detect the requested profile purely to make the echoed messages accurate;
# the flag itself is forwarded to the tool untouched via "$@" below (no
# separate build step is needed -- matmul_v4_bmx4.cpp is already part of the
# common library linked into matmul-v4-report for every backend).
PROFILE="v41"
TELEMETRY_ONLY=0
prev=""
for a in "$@"; do
  if [ "$prev" = "--profile" ]; then PROFILE="$a"; fi
  if [ "$a" = "--telemetry-only" ] ||
     [ "$a" = "--lt-raw-only" ] ||
     [ "$a" = "--lt-raw-full-window" ]; then
    TELEMETRY_ONLY=1
  fi
  prev="$a"
done

if [ "$RC_MODE" -eq 1 ]; then
  echo "== MatMul ENC_RC (Resident Curriculum) harness: $BACKEND =="
elif [ "$PROFILE" = "bmx4c" ]; then
  echo "== MatMul v4.2 (ENC-BMX4C) hardware measurement + M-t24: $BACKEND =="
elif [ "$PROFILE" = "bmx4c-lt" ]; then
  echo "== MatMul v4.4-LT (ENC-DR-LT MatExpand+Q*) hardware measurement: $BACKEND =="
else
  echo "== MatMul v4.1 hardware measurement: $BACKEND =="
fi
echo "-- configuring ($BUILD)"
# ENABLE_WALLET=ON + WITH_SQLITE=ON avoids a known CPU-only link failure; the
# report tool only needs the consensus/matmul libraries, so tests are off.
# External review (vanities): BUILD_UTIL defaults to ${BUILD_TESTS}, so with
# BUILD_TESTS=OFF the matmul-v4-report target is never configured and the build
# step below dies -- force BUILD_UTIL=ON so the report tool is always built.
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF \
      -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DBUILD_TESTS=OFF -DBUILD_UTIL=ON \
      "${CMAKE_FLAGS[@]}" >/dev/null || { echo "CONFIGURE FAILED"; exit 2; }

if [ "$RC_MODE" -eq 1 ]; then
  echo "-- building matmul-v4-rc-harness"
  cmake --build "$BUILD" --target matmul-v4-rc-harness -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" \
    || { echo "BUILD FAILED (matmul-v4-rc-harness)"; exit 2; }
  BIN="$(find "$BUILD" -type f -name matmul-v4-rc-harness | head -1)"
  if [ -z "$BIN" ]; then echo "could not locate matmul-v4-rc-harness binary"; exit 2; fi

  # Stage G campaign profiles → multi-run same-tip JSON for rc-gate.
  if [ -n "$STAGE_G_PROFILE" ]; then
    echo "-- Stage G campaign profile=$STAGE_G_PROFILE (same-tip, ≥3 runs)"
    export BTX_RC_HARNESS="$BIN"
    export BTX_SOURCE_REVISION="${BTX_SOURCE_REVISION:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)}"
    OUT_ARG=""
    RUNS_ARG=(--runs 5)
    prev=""
    for a in "$@"; do
      if [ "$prev" = "--out" ]; then OUT_ARG="$a"; fi
      if [ "$prev" = "--runs" ]; then RUNS_ARG=(--runs "$a"); fi
      prev="$a"
    done
    if [ -z "$OUT_ARG" ]; then
      OUT_ARG="/tmp/stage-g-campaign-${STAGE_G_PROFILE}.json"
    fi
    set +e
    python3 "$ROOT/contrib/matmul-v4/rc-stage-g-campaign.py" \
      --profile "$STAGE_G_PROFILE" \
      "${RUNS_ARG[@]}" \
      --out "$OUT_ARG" \
      --gate
    CODE=$?
    set -e
    echo ""
    echo "Stage G campaign JSON: $OUT_ARG"
    echo "Aggregate with: contrib/matmul-v4/rc-gate.py $OUT_ARG --out summary.json"
    echo "Toy/CPU campaigns never raise nMatMulRCHeight (stays INT32_MAX)."
    echo "SIMULATED interconnect factor is NOT Stage-I gate 4 evidence."
    if [ "$CODE" -eq 0 ]; then
      echo "RESULT: Stage G campaign harness completed ($BACKEND / $STAGE_G_PROFILE)."
    else
      echo "RESULT: Stage G campaign NO-GO/PARTIAL or harness FAIL ($BACKEND / $STAGE_G_PROFILE)."
    fi
    exit "$CODE"
  fi

  echo "-- running $BIN $*"
  set +e
  "$BIN" "$@"
  CODE=$?
  set -e
  echo ""
  echo "Aggregate ENC_RC GO/PARTIAL/NO-GO with:"
  echo "  contrib/matmul-v4/rc-gate.py <rc-json> --out summary.json"
  echo "Toy runs never raise nMatMulRCHeight (stays INT32_MAX)."
  if [ "$CODE" -eq 0 ]; then
    echo "RESULT: ENC_RC harness ExtractMX self-qual PASS ($BACKEND)."
  else
    echo "RESULT: ENC_RC harness FAIL ($BACKEND) — see output above."
  fi
  exit "$CODE"
fi

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
  if [ "$PROFILE" = "bmx4c-lt" ]; then
    if [ "$TELEMETRY_ONLY" -eq 1 ]; then
      echo "Send this telemetry file back for path diagnosis only. It is not readiness/ASERT evidence"
      echo "and must not be aggregated by lt-gate.py. Rerun without --telemetry-only for gates."
    else
      echo "Send this file back — schema_version 3 / profile bmx4c-lt (MatExpand+Q* stages)."
      echo "Aggregate Rank-1 GO/NO-GO (fail-closed; no invented rates) with:"
      echo "  contrib/matmul-v4/lt-gate.py <dir-of-json> --manifest parts.tsv"
    fi
  elif [ "$PROFILE" = "bmx4c" ]; then
    echo "Send this file back — it carries the M-t24 verdict (mt24_pass / proven_accumulator_bits /"
    echo "native_path_eligible). ENC-BMX4C activation needs M-t24 PASS on >= 2 independent vendors'"
    echo "frontier parts (spec §9 item 1)."
    echo "Aggregate the collected JSONs into ONE GO/NO-GO with:"
    echo "  contrib/matmul-v4/k2b-gate.py <dir-of-json> --manifest parts.tsv"
  else
    echo "Send this file back; aggregate across machines to settle the B2g ordering."
  fi
else
  echo "NOTE: JSON not found in \$ROOT; check the tool's 'JSON report written:' line above."
fi

if [ "$PROFILE" = "bmx4c-lt" ]; then
  if [ "$TELEMETRY_ONLY" -eq 1 ] && [ "$CODE" -eq 0 ]; then
    echo "RESULT: resident Q* TELEMETRY obtained ($BACKEND); no certification/readiness claim."
  elif [ "$TELEMETRY_ONLY" -eq 1 ]; then
    echo "RESULT: resident Q* TELEMETRY unavailable ($BACKEND); inspect telemetry_note."
  elif [ "$CODE" -eq 0 ]; then
    echo "RESULT: ENC-DR-LT silicon-rate PASS ($BACKEND) — see JSON / DEVICE_BMX4CLT_RATE_PASS."
  else
    echo "RESULT: FAIL or NOT-FULLY-NATIVE-CERTIFIED ($BACKEND) — inspect the JSON before discarding it;"
    echo "host_orchestrated_nonce_per_s is diagnostic only. lt-gate.py requires one resident Q*"
    echo "batch with device W generation + digest and no per-nonce sync; CPU timers never count."
  fi
elif [ "$PROFILE" = "bmx4c" ]; then
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
