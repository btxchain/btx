#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

usage() {
  cat <<'USAGE'
Usage: scripts/ci/run_cuda_matmul_v3.sh

Configure, build, and run the CUDA MatMul v3 verification lane on a self-hosted
NVIDIA Linux machine.

Required environment:
  BTX_CUDA_ARCHITECTURES   Semicolon-separated CUDA SM architectures, e.g. "86;89;120"

Optional environment:
  BUILD_DIR                Build directory (default: build-cuda)
  CUDA_DEVICE              CUDA device index for benchmarks (default: 0)
  CUDAToolkit_ROOT         CUDA toolkit root, e.g. /usr/local/cuda
  CMAKE_CUDA_COMPILER      nvcc path, e.g. /usr/local/cuda/bin/nvcc
  CMAKE_GENERATOR          CMake generator (default: Ninja)
  CMAKE_BUILD_TYPE         Build type (default: RelWithDebInfo)
  CUDA_ARTIFACT_DIR        JSON/log output directory (default: <BUILD_DIR>/cuda-matmul-v3-artifacts)
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${BTX_CUDA_ARCHITECTURES:-}" ]]; then
  echo "error: BTX_CUDA_ARCHITECTURES is required, e.g. BTX_CUDA_ARCHITECTURES='86;89;120'" >&2
  exit 1
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "error: nvidia-smi not found; this lane requires an NVIDIA host" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not found; this lane requires jq for JSON assertions" >&2
  exit 1
fi

if [[ -n "${CMAKE_CUDA_COMPILER:-}" ]]; then
  NVCC="${CMAKE_CUDA_COMPILER}"
elif command -v nvcc >/dev/null 2>&1; then
  NVCC="$(command -v nvcc)"
else
  echo "error: nvcc not found; set CMAKE_CUDA_COMPILER or install CUDA toolkit" >&2
  exit 1
fi

nproc_detect() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
  else
    echo 4
  fi
}

BUILD_DIR="${BUILD_DIR:-build-cuda}"
CUDA_DEVICE="${CUDA_DEVICE:-0}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-RelWithDebInfo}"
CUDA_ARTIFACT_DIR="${CUDA_ARTIFACT_DIR:-${BUILD_DIR}/cuda-matmul-v3-artifacts}"
mkdir -p "${CUDA_ARTIFACT_DIR}"

cmake_args=(
  -S .
  -B "${BUILD_DIR}"
  -G "${CMAKE_GENERATOR}"
  -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
  -DBUILD_TESTS=ON
  -DBUILD_UTIL=ON
  -DBUILD_BENCH=ON
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON
  -DBTX_CUDA_ARCHITECTURES="${BTX_CUDA_ARCHITECTURES}"
  -DCMAKE_CUDA_COMPILER="${NVCC}"
)

if [[ -n "${CUDAToolkit_ROOT:-}" ]]; then
  cmake_args+=("-DCUDAToolkit_ROOT=${CUDAToolkit_ROOT}")
fi

cmake "${cmake_args[@]}"

cmake --build "${BUILD_DIR}" \
  --target btx-matmul-backend-info btx-matmul-solve-bench btx-matmul-cost-bench test_btx bench_btx \
  -j"$(nproc_detect)"

echo "CUDA host:" | tee "${CUDA_ARTIFACT_DIR}/nvidia-smi.log"
nvidia-smi | tee -a "${CUDA_ARTIFACT_DIR}/nvidia-smi.log"
"${NVCC}" --version | tee "${CUDA_ARTIFACT_DIR}/nvcc-version.log"

BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_REQUIRE_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES="${CUDA_DEVICE}" \
  "${BUILD_DIR}/bin/btx-matmul-backend-info" --backend cuda \
  | tee "${CUDA_ARTIFACT_DIR}/backend-info.json"

jq -e '
  .active_backend == "cuda" and
  .capabilities.cuda.compiled == true and
  .capabilities.cuda.available == true and
  .cuda_runtime.available == true and
  .cuda_runtime.selected_device_count > 0
' "${CUDA_ARTIFACT_DIR}/backend-info.json" >/dev/null

run_test() {
  local name="$1"
  BTX_MATMUL_BACKEND=cuda \
  BTX_MATMUL_REQUIRE_BACKEND=cuda \
  BTX_MATMUL_GPU_INPUTS=1 \
  BTX_MATMUL_CUDA_DEVICES="${CUDA_DEVICE}" \
    "${BUILD_DIR}/bin/test_btx" --run_test="${name}" --catch_system_errors=no \
    | tee "${CUDA_ARTIFACT_DIR}/test-${name//\//-}.log"
}

run_test 'pow_tests/MatMulNonceSeed_cuda_prehash_scan_matches_cpu_gate'
run_test 'pow_tests/MatMulParentMtpSeed_cuda_prehash_scan_matches_cpu_gate'
run_test 'pow_tests/MatMulParentMtpSeed_cuda_solver_uses_gpu_scan_and_variable_base_batch'
run_test 'pow_tests/MatMulNonceSeed_cuda_batch_override_accepts_large_batch'
run_test 'pow_tests/matmul_solve_uses_cuda_batch_defaults_when_backend_is_available'
run_test 'pow_tests/matmul_solve_enables_cpu_confirm_for_cuda_in_strict_mode'
run_test 'pow_tests/cuda_strict_regtest_warning_repro_solves_without_digest_divergence'
run_test 'matmul_accelerated_solver_tests'

BTX_MATMUL_BACKEND=cuda \
BTX_MATMUL_REQUIRE_BACKEND=cuda \
BTX_MATMUL_GPU_INPUTS=1 \
BTX_MATMUL_CUDA_DEVICES="${CUDA_DEVICE}" \
  "${BUILD_DIR}/bin/btx-matmul-solve-bench" \
    --backend cuda \
    --iterations 3 \
    --tries 4194304 \
    --n 512 --b 16 --r 8 \
    --epsilon-bits 18 \
    --block-height 130500 \
    --nonce-seed-height 125000 \
    --parent-mtp-seed-height 130500 \
    --parent-mtp 1780000000 \
    --product-digest-height 61000 \
  | tee "${CUDA_ARTIFACT_DIR}/solve-v3-mainnet-like.json"

jq -e '
  .active_backend == "cuda" and
  .options.parent_mtp_seed_active == true and
  .last_backend_runtime_stats.requested_cuda > 0 and
  .last_backend_runtime_stats.cuda_successes > 0 and
  .last_backend_runtime_stats.cuda_fallbacks_to_cpu == 0 and
  .last_pipeline_stats.batched_digest_requests > 0 and
  .last_pipeline_stats.batched_nonce_attempts > 0
' "${CUDA_ARTIFACT_DIR}/solve-v3-mainnet-like.json" >/dev/null

"${BUILD_DIR}/bin/btx-matmul-cost-bench" \
  --iterations 3 \
  --n 512 --b 16 --r 8 \
  --epsilon-bits 18 \
  --seed-version 3 \
  --block-height 130500 \
  --parent-mtp 1780000000 \
  | tee "${CUDA_ARTIFACT_DIR}/cost-v3-mainnet-like.json"

echo "CUDA MatMul v3 lane complete. Artifacts: ${CUDA_ARTIFACT_DIR}"
