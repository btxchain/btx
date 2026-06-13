#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load CUDA mining defaults (BTX_MATMUL_BACKEND=cuda, async pipeline, CPU confirm).
# shellcheck source=contrib/mining/cuda-mining-env.sh
source "${SCRIPT_DIR}/cuda-mining-env.sh"

DATADIR="${BTX_MINING_DATADIR:-${HOME}/.btx}"
BUILD_DIR="${BTX_CUDA_BUILD_DIR:-${BTX_MINING_BUILD_DIR:-}}"
CLI="${BTX_MINING_CLI:-}"
DAEMON="${BTX_MINING_DAEMON:-}"

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [start-live-mining options]

Start BTX solo mining with CUDA MatMul defaults tuned for RTX 5090-class GPUs.

This script:
  1. exports BTX_MATMUL_BACKEND=cuda and related safe throughput knobs
  2. prefers binaries from a CUDA build directory when present
  3. delegates to contrib/mining/start-live-mining.sh

Environment:
  BTX_CUDA_BUILD_DIR   Directory containing build-cuda/bin/btxd (optional)
  BTX_MINING_BUILD_DIR Fallback build directory
  BTX_MINING_DATADIR   BTX datadir (default: ~/.btx)

Build first (Linux + NVIDIA):
  cmake -S . -B build-cuda \\
    -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \\
    -DBTX_CUDA_ARCHITECTURES=120 \\
    -DCUDAToolkit_ROOT=/usr/local/cuda
  cmake --build build-cuda -j"\$(nproc)"

All other flags are forwarded to start-live-mining.sh (--datadir, --wallet, ...).
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --help|-h)
      print_usage
      exit 0
      ;;
  esac
done

resolve_cuda_binary() {
  local name="$1"
  local candidate=""

  if [[ -n "${BUILD_DIR}" && -x "${BUILD_DIR}/bin/${name}" ]]; then
    candidate="${BUILD_DIR}/bin/${name}"
  elif [[ -x "${SCRIPT_DIR}/../../build-cuda/bin/${name}" ]]; then
    candidate="$(cd "${SCRIPT_DIR}/../.." && pwd)/build-cuda/bin/${name}"
  elif [[ -n "${BTX_MINING_BUILD_DIR}" && -x "${BTX_MINING_BUILD_DIR}/bin/${name}" ]]; then
    candidate="${BTX_MINING_BUILD_DIR}/bin/${name}"
  fi

  if [[ -n "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi
  return 1
}

if [[ -z "${DAEMON}" ]]; then
  if resolved="$(resolve_cuda_binary btxd)"; then
    DAEMON="${resolved}"
  else
    DAEMON="${BTX_MINING_DAEMON:-btxd}"
  fi
fi

if [[ -z "${CLI}" ]]; then
  if resolved="$(resolve_cuda_binary btx-cli)"; then
    CLI="${resolved}"
  else
    CLI="${BTX_MINING_CLI:-btx-cli}"
  fi
fi

if [[ -x "${DAEMON}" ]]; then
  backend_info="${DAEMON%/btxd}/btx-matmul-backend-info"
  if [[ ! -x "${backend_info}" ]]; then
    backend_info="$(dirname "${DAEMON}")/btx-matmul-backend-info"
  fi
  if [[ -x "${backend_info}" ]]; then
    if ! "${backend_info}" --backend cuda 2>/dev/null | grep -q '"available"[[:space:]]*:[[:space:]]*true'; then
      echo "Warning: CUDA backend probe failed for ${backend_info}." >&2
      echo "Build with -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES=120" >&2
    fi
  fi
fi

export BTX_MINING_CLI="${CLI}"
export BTX_MINING_DAEMON="${DAEMON}"

exec "${SCRIPT_DIR}/start-live-mining.sh" "$@"
