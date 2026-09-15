#!/usr/bin/env bash
# Isolated CUDA qualification worker. Refuses to run if BTX_LIVE_ATTESTOR=1
# (unless BTX_ALLOW_SHARED_GPU=1), or if nvidia-smi shows production btxd.real
# using the device and sharing is not allowed.
set -euo pipefail
if [[ "${BTX_LIVE_ATTESTOR:-0}" == "1" ]] && [[ "${BTX_ALLOW_SHARED_GPU:-0}" != "1" ]]; then
  echo "cuda-isolated-qual: refuse live attestor GPU (BTX_LIVE_ATTESTOR=1)"
  exit 2
fi
if command -v nvidia-smi >/dev/null 2>&1; then
  if nvidia-smi --query-compute-apps=process_name --format=csv,noheader 2>/dev/null | grep -q btxd.real; then
    if [[ "${BTX_ALLOW_SHARED_GPU:-0}" != "1" ]]; then
      echo "cuda-isolated-qual: production btxd.real holds GPU; not launching kernels"
      echo "GPU-01 skipped; GPU-02/03 isolation remains library tests"
      exit 0
    fi
  fi
fi
CHECK="${MODELCHECK:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/build-gcc13/bin/btx-modelcheck}"
MODEL="${1:-}"
if [[ -z "$MODEL" ]]; then
  echo "usage: cuda-isolated-qual.sh <safetensors>"
  exit 2
fi
"$CHECK" "$MODEL"
echo "cuda-isolated-qual: structure-only (QualifyRuntime kernels stay off unless compiled with BTX_MODEL_CUDA_QUALIFY_COMPILE)"
