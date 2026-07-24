#!/usr/bin/env bash
#
# MatMul ENC_RC v4.6 hardware measurement.
#
# *** ENC_RC v4.6 IS THE CURRENT PRODUCT. ***
# Spec: doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md
# Gate: contrib/matmul-v4/rc-gate.py
#
# The legacy matmul-v4-report tool (v4.1 ENC-S8 / v4.2 ENC-BMX4C / v4.4 ENC-DR-LT)
# and its --profile bmx4c / bmx4c-lt paths were RETIRED — every gate they served
# (B1 bit-exact determinism, B2b ASERT calibration, B2g datacenter go/no-go, and
# the M-t24 accumulator-exactness methodology) now lives in the ENC_RC path. This
# script therefore only drives the ENC_RC harness; any non-RC invocation exits with
# a pointer to the RC tools.
#
# For the verbose turnkey full-workload benchmark, prefer:
#   contrib/matmul-v4/run-full-benchmark.py --shape production
# or the RC-only measurement wrapper:
#   contrib/matmul-v4/measure-enc-rc-v46.sh …
#
# --- ENC_RC episode harness ---
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
# Toy/CPU campaigns never raise nMatMulRCHeight (stays INT32_MAX).
#
# Env: CUDA_ARCH / HIP_ARCH (arch lists), BUILD_DIR (build path override).
# HIP also needs HIPCXX (clang that accepts -x hip); if unset the script probes
# clang++-19/18/17/clang++ and passes -DCMAKE_HIP_COMPILER (Amendment v2 §1.D).
# Exit: 0 = harness PASS, 1 = FAIL, 2 = usage/build error / non-RC invocation.

set -euo pipefail
BACKEND="${1:-}"
shift || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-measure-$BACKEND}"

# Optional first/extra token `rc` selects the ENC_RC harness explicitly.
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

# Detect Stage G campaign profiles early (before the cmake configure step).
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

# Amendment v2/v3 §1.D: HIP TUs need a clang that accepts -x hip. Never let
# CMake fall back to host g++/c++. Probe HIPCXX → clang++-{19,18,17,} and fail
# loudly. D2 (hip::device isolation), D3 (strip -fcf-protection on HIP), and D4
# (__HIP_PLATFORM_AMD__ PUBLIC reach) live in src/CMakeLists.txt (btx_hip_device).
# D7 isolated MFMA compile-gate: contrib/matmul-v4/hip-mfma-compile-gate.sh
# (COMPILE PASS required for native-eligibility; gfx1200 runtime needs a card).
btx_resolve_hipcxx() {
  local cand ver
  if [ -n "${HIPCXX:-}" ]; then
    cand="$HIPCXX"
  else
    for cand in clang++-19 clang++-18 clang++-17 clang++; do
      if command -v "$cand" >/dev/null 2>&1; then
        break
      fi
      cand=""
    done
  fi
  if [ -z "$cand" ]; then
    echo "HIP ERROR: no clang HIP compiler found. export HIPCXX=clang++-19 (or 18/17)." >&2
    exit 2
  fi
  case "$(basename "$cand")" in
    g++|c++|gcc|cc|g++-*|c++-*|gcc-*|cc-*)
      echo "HIP ERROR: HIPCXX='$cand' is a host C++ driver; HIP requires clang." >&2
      exit 2
      ;;
  esac
  ver="$("$cand" --version 2>&1 || true)"
  if ! printf '%s\n' "$ver" | grep -qi clang; then
    echo "HIP ERROR: '$cand' is not clang (HIPCXX must be a ROCm/hip-clang)." >&2
    echo "$ver" >&2
    exit 2
  fi
  if ! echo 'int main(){return 0;}' | "$cand" -x hip -c -o /dev/null - 2>/dev/null; then
    echo "HIP ERROR: '$cand' cannot compile HIP (-x hip smoke test failed)." >&2
    echo "Install ROCm hip-clang and export HIPCXX to that clang." >&2
    exit 2
  fi
  # Absolute path so cmake gets a stable CMAKE_HIP_COMPILER.
  if command -v "$cand" >/dev/null 2>&1; then
    cand="$(command -v "$cand")"
  fi
  export HIPCXX="$cand"
  echo "-- HIPCXX=$HIPCXX (Amendment v2 §1.D D1)"
}

case "$BACKEND" in
  cpu)   CMAKE_FLAGS=() ;;
  # External review (vanities): the default arch list omitted Blackwell, so a
  # 5090 (sm_120) / B200 (sm_100) ran JIT'd sm_90 instead of native code. Include
  # 100;120 so the INT8 tensor path is built for Blackwell.
  #
  # Two CUDA recipes (PR #89 plain sm_120 vs feature-qualified sm_120a):
  #   1) Plain packaging (default here) — native block_scale MMA compiled OUT:
  #        -DBTX_CUDA_ARCHITECTURES=100;120   # never 120a in this list
  #      Exact INT8 / streamed path; native_mxfp4=false / no SM120_MMA claim.
  #   2) Rack SM120_MMA — BTX_CUDA_ARCHITECTURES=120 + BTX_CUDA_SM120_MXFP4_NATIVE=ON
  #      (cmake/BTXCudaSm120a.cmake): marker TU + sm_120a fatbin slice on
  #      matmul_v4_rc_mx_ozaki_native.cu (-gencode=arch=compute_120a,code=sm_120a).
  #      Do NOT put 120a in BTX_CUDA_ARCHITECTURES. CUTLASS MXFP4 stays scaffolding.
  #      Set BTX_CUDA_SM120_MXFP4_NATIVE=1 in the environment to enable recipe 2.
  cuda)
    CMAKE_FLAGS=(-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON "-DBTX_CUDA_ARCHITECTURES=${CUDA_ARCH:-75;80;89;90;100;120}")
    if [ "${BTX_CUDA_SM120_MXFP4_NATIVE:-0}" = "1" ] || [ "${BTX_CUDA_SM120_MXFP4_NATIVE:-OFF}" = "ON" ]; then
      CMAKE_FLAGS+=(-DBTX_CUDA_SM120_MXFP4_NATIVE=ON)
    fi
    ;;
  metal) CMAKE_FLAGS=(-DBTX_ENABLE_METAL=ON) ;;
  hip)
    # HIP_ARCH required (e.g. gfx942 MI300 / gfx1200 RDNA4). D4 MFMA-vs-WMMA
    # arch guard is a sibling change; this script still demands an explicit arch.
    : "${HIP_ARCH:?set HIP_ARCH e.g. gfx942 or gfx1200}"
    btx_resolve_hipcxx
    CMAKE_FLAGS=(
      -DBTX_ENABLE_HIP=ON
      "-DBTX_HIP_ARCHITECTURES=${HIP_ARCH}"
      "-DCMAKE_HIP_COMPILER=${HIPCXX}"
    )
    ;;
  *) echo "usage: $0 <cpu|cuda|metal|hip> [rc] [extra --flags]"; echo "       $0 rc [cpu|cuda|metal|hip] [extra --flags]"; exit 2 ;;
esac

if [ "$RC_MODE" -ne 1 ]; then
  # The legacy matmul-v4-report tool (v4.1 ENC-S8 / v4.2 ENC-BMX4C / v4.4 ENC-DR-LT)
  # and its --profile measurement paths have been RETIRED. ENC_RC v4.6 is the
  # product, and every gate the report used to serve now lives in the RC path:
  #   B1  bit-exact backend determinism  -> ProbeRCSelfQual (byte-exact vs the
  #                                         int64 CPU oracle), matmul-v4-rc-harness
  #   B2b ASERT throughput calibration   -> rc-stage-g-campaign.py + rc-gate.py
  #   B2g datacenter-vs-consumer go/no-go -> run-full-benchmark.py
  #   M-t24 accumulator exactness        -> the RC Ozaki exact-panels self-qual
  #                                         (ExactPanelsMatchOracle, boundary pins
  #                                          around 2^24; same BMX4C_..._PROVEN_T=24)
  echo "RETIRED: matmul-v4-report and the v4.1/v4.2/v4.4 measurement profiles were removed." >&2
  echo "ENC_RC v4.6 is the current product. Use one of:" >&2
  echo "  contrib/matmul-v4/measure-enc-rc-v46.sh …" >&2
  echo "  contrib/matmul-v4/measure-hardware.sh $BACKEND rc …" >&2
  echo "  contrib/matmul-v4/measure-hardware.sh $BACKEND --profile coupled" >&2
  echo "  contrib/matmul-v4/run-full-benchmark.py --shape production" >&2
  exit 2
fi
echo "== MatMul ENC_RC (Resident Curriculum) harness: $BACKEND =="
echo "-- configuring ($BUILD)"
# ENABLE_WALLET=ON + WITH_SQLITE=ON avoids a known CPU-only link failure; the
# rc harness only needs the consensus/matmul libraries, so tests are off.
# BUILD_UTIL defaults to ${BUILD_TESTS}, so with BUILD_TESTS=OFF the
# matmul-v4-rc-harness target is never configured and the build step below dies
# -- force BUILD_UTIL=ON so the harness is always built.
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

# (Legacy matmul-v4-report build/run/report section removed — see the RETIRED
# guard above. All non-RC modes exit before reaching here; the RC_MODE block
# above always exits, so there is no remaining work.)
