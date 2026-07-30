#!/usr/bin/env bash
# PR #89 consumer-Blackwell CUDA architecture matrix (plain sm_120 vs sm_120a).
# Historical build matrix only; not MatMul v4.7 Epoch-A performance evidence.
set -euo pipefail
export PATH=/usr/local/cuda/bin:/usr/bin:${PATH:-}
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="${BTX_SRC:-$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)}"
WT="${BTX_WT:-${TMPDIR:-/tmp}/btx-pr89-5090-fix}"
# Frozen local snapshot of the historical PR-89 branch. The full commit was
# resolved from the existing remote-tracking ref without refreshing it. An
# operator may deliberately override it, but the default never follows a
# moving branch.
HISTORICAL_COMMIT="d6b445726f9f7bbd4757a751429930e5da90862a"
REF="${BTX_REF:-$HISTORICAL_COMMIT}"
case "$REF" in
  -*) echo "BTX_REF must name a commit or ref, not an option: $REF" >&2; exit 2 ;;
esac

cd "$SRC"
if ! git cat-file -e -- "${REF}^{commit}" 2>/dev/null; then
  git fetch origin "$REF"
fi
RESOLVED_REF="$(git rev-parse --verify --end-of-options "${REF}^{commit}")"
if [ ! -d "$WT/.git" ] && [ ! -f "$WT/.git" ]; then
  git worktree add --detach "$WT" "$RESOLVED_REF"
else
  cd "$WT"
  git checkout --detach "$RESOLVED_REF"
fi
cd "$WT"
echo "HEAD=$(git rev-parse HEAD)"
git log -1 --oneline

run_cfg() {
  local name="$1"; shift
  local bdir="build-$name"
  echo ""
  echo "========== CONFIG $name =========="
  rm -rf "$bdir"
  if ! cmake -S . -B "$bdir" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=OFF -DBUILD_BENCH=ON -DBUILD_FUZZ_BINARY=OFF \
    -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
    "$@" >"/tmp/btx-cfg-$name.log" 2>&1; then
    echo "CONFIG_$name=FAIL"
    tail -40 "/tmp/btx-cfg-$name.log"
    return 1
  fi
  echo "CONFIG_$name=OK"
  if [ "$name" = "sm120-native" ]; then
    ninja -C "$bdir" -t commands \
      src/CMakeFiles/btx_matmul_backend.dir/cuda/matmul_v4_rc_mx_ozaki_native.cu.o \
      2>/dev/null | tr ' ' '\n' | grep -E 'gencode|generate-code|120' | head -30 || true
  fi
  if ! cmake --build "$bdir" --target btx_matmul_backend btx-matmul-cost-bench -j8 \
    >"/tmp/btx-build-$name.log" 2>&1; then
    echo "BUILD_$name=FAIL"
    grep -nE 'error:|fatal|FAILED|ptxas' "/tmp/btx-build-$name.log" | head -40 || true
    tail -40 "/tmp/btx-build-$name.log"
    return 1
  fi
  echo "BUILD_$name=OK"
}

run_cfg sm120-native \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=120 -DBTX_CUDA_SM120_MXFP4_NATIVE=ON

run_cfg sm100 \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=100 -DBTX_CUDA_SM120_MXFP4_NATIVE=OFF

run_cfg fat-100-120 \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES='100;120' -DBTX_CUDA_SM120_MXFP4_NATIVE=OFF

run_cfg pkg-120rv \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DBTX_CUDA_ARCHITECTURES='120-real;120-virtual' \
  -DBTX_CUDA_SM120_MXFP4_NATIVE=OFF

run_cfg sm120-plain \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=120 -DBTX_CUDA_SM120_MXFP4_NATIVE=OFF

echo ALL_CONFIGS_DONE
