#!/usr/bin/env bash
#
# Amendment v3 §1.D D7 — isolated MFMA / guard compile-gate for AMD HIP arches.
#
# For each offload arch, compile a tiny kernel that includes
# src/hip/btx_hip_mfma_guard.h and exercises the arch-correct int8 path:
#   gfx90a          → K16 MFMA (__builtin_amdgcn_mfma_i32_16x16x16i8)
#   gfx942 / gfx950 → K32 MFMA (__builtin_amdgcn_mfma_i32_16x16x32_i8)
#   gfx1200         → scalar exact-INT8 only (no MFMA emit)
#
# Native-eligibility for an arch requires COMPILE success here. gfx1200 runtime
# qualification still needs a physical RDNA4 card; this gate only proves the
# fence compiles clean (MFMA not emitted).
#
# Usage:
#   contrib/matmul-v4/hip-mfma-compile-gate.sh
#   BTX_HIP_MFMA_GATE_ARCHS=gfx90a,gfx942 ./contrib/matmul-v4/hip-mfma-compile-gate.sh
#   HIPCXX=clang++-19 ./contrib/matmul-v4/hip-mfma-compile-gate.sh
#
# Env:
#   HIPCXX                 clang HIP driver (required; probed if unset)
#   BTX_HIP_MFMA_GATE_ARCHS  comma-separated arches (default: gfx90a,gfx942,gfx950,gfx1200)
#   BTX_HIP_MFMA_GATE_KEEP=1 keep temp dir on exit
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHS_CSV="${BTX_HIP_MFMA_GATE_ARCHS:-gfx90a,gfx942,gfx950,gfx1200}"

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
    echo "HIP MFMA GATE ERROR: no clang HIP compiler found. export HIPCXX=clang++-19." >&2
    exit 2
  fi
  case "$(basename "$cand")" in
    g++|c++|gcc|cc|g++-*|c++-*|gcc-*|cc-*)
      echo "HIP MFMA GATE ERROR: HIPCXX='$cand' is a host C++ driver; HIP requires clang." >&2
      exit 2
      ;;
  esac
  ver="$("$cand" --version 2>&1 || true)"
  if ! printf '%s\n' "$ver" | grep -qi clang; then
    echo "HIP MFMA GATE ERROR: '$cand' is not clang." >&2
    echo "$ver" >&2
    exit 2
  fi
  if ! echo 'int main(){return 0;}' | "$cand" -x hip -c -o /dev/null - 2>/dev/null; then
    echo "HIP MFMA GATE ERROR: '$cand' cannot compile HIP (-x hip smoke test failed)." >&2
    exit 2
  fi
  printf '%s\n' "$cand"
}

HIPCXX_BIN="$(btx_resolve_hipcxx)"
export HIPCXX="$HIPCXX_BIN"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/btx-hip-mfma-gate.XXXXXX")"
cleanup() {
  if [ "${BTX_HIP_MFMA_GATE_KEEP:-0}" = "1" ]; then
    echo "kept temp dir: $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

# Isolated kernel: include the project guard and emit the correct intrinsic
# (or scalar twin). ~30 lines; no link against bitcoin libs.
cat >"$TMP/mfma_gate.hip" <<'EOF'
#include <hip/hip_runtime.h>
#include <hip/btx_hip_mfma_guard.h>
#include <cstdint>

using int32x4 = int32_t __attribute__((ext_vector_type(4)));

__global__ void BtxMfmaGateKernel(int32_t* out)
{
#if defined(BTX_HIP_MFMA_I8_K16)
    int32x4 acc = {0, 0, 0, 0};
    acc = __builtin_amdgcn_mfma_i32_16x16x16i8(0, 0, acc, 0, 0, 0);
    if (out && threadIdx.x == 0 && threadIdx.y == 0) out[0] = acc[0];
#elif defined(BTX_HIP_MFMA_I8_K32)
    int32x4 acc = {0, 0, 0, 0};
    // CDNA3/4: K=32 packs eight i8 into one i64 lane operand.
    acc = __builtin_amdgcn_mfma_i32_16x16x32_i8(0LL, 0LL, acc, 0, 0, 0);
    if (out && threadIdx.x == 0 && threadIdx.y == 0) out[0] = acc[0];
#else
    // RDNA4 / unknown: scalar exact-INT8 only — never emit MFMA.
    if (out && threadIdx.x == 0) out[0] = 0;
#endif
}

int main() { return 0; }
EOF

IFS=',' read -r -a ARCHS <<<"$ARCHS_CSV"
pass=0
fail=0
echo "HIP MFMA compile-gate (Amendment v3 §1.D D7)"
echo "  HIPCXX=$HIPCXX_BIN"
echo "  arches=${ARCHS[*]}"
echo "  note: COMPILE PASS is required for native-eligibility;"
echo "        gfx1200 runtime qual still needs a physical card."
echo

for arch in "${ARCHS[@]}"; do
  arch="$(echo "$arch" | tr -d '[:space:]')"
  [ -n "$arch" ] || continue
  obj="$TMP/mfma_gate.$arch.o"
  log="$TMP/mfma_gate.$arch.log"
  set +e
  "$HIPCXX_BIN" -x hip -std=c++20 -c \
    -I"$ROOT/src" \
    --offload-arch="$arch" \
    -D__HIP_PLATFORM_AMD__=1 \
    -o "$obj" "$TMP/mfma_gate.hip" >"$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "PASS  $arch"
    pass=$((pass + 1))
  else
    echo "FAIL  $arch (rc=$rc)"
    sed -n '1,20p' "$log" | sed 's/^/      /'
    fail=$((fail + 1))
  fi
done

echo
echo "summary: PASS=$pass FAIL=$fail"
if [ "$fail" -ne 0 ]; then
  exit 1
fi
exit 0
