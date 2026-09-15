#!/usr/bin/env bash
# Isolated CUDA granite-size FIT vs ExactReplay reserve.
# Does not cudaMalloc 13.8 GiB. Tiny kernel + FIT math. Fail-fast.
#
#   CUDA_HOST=user@cuda-box contrib/modelnet/e2e-cuda-granite-fit.sh
export LC_ALL=C
set -euo pipefail
die() { echo "E2E_CUDA_FIT FAIL: $*" >&2; exit 1; }
HOST="${CUDA_HOST:?set CUDA_HOST to SSH alias of a dedicated CUDA workstation}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cuda_qual_worker.cu"
GRANITE="${GRANITE_BYTES:-13888336427}"
[[ -f "$SRC" ]] || die "missing $SRC"
if [[ "${BTX_LIVE_ATTESTOR:-0}" == "1" ]]; then die "refuse live attestor"; fi
scp -o BatchMode=yes "$SRC" "$HOST:/tmp/cuda_qual_worker.cu"
REMOTE="$(ssh -o BatchMode=yes "$HOST" 'export PATH=/usr/local/cuda-12.9/bin:/usr/local/cuda/bin:$PATH
nvcc -O2 /tmp/cuda_qual_worker.cu -o /tmp/cuda_qual_worker || exit 1
/tmp/cuda_qual_worker --gpu=0 --allow-shared-gpu --allow-validator-gpu --granite-bytes='"$GRANITE"' --reserve-mib=4096')"
echo "$REMOTE"
echo "$REMOTE" | grep -q 'CUDA_QUAL_WORKER PASS' || die "kernel"
echo "$REMOTE" | grep -q 'CUDA_GRANITE_FIT PASS' || die "granite FIT"
echo "$REMOTE" | grep -q 'ISO-05 FIT' || die "ISO-05"
AFTER="$(ssh -o BatchMode=yes "$HOST" "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv")"
if [[ "${CUDA_REQUIRE_EXACTREPLAY:-0}" == "1" ]]; then
  echo "$AFTER" | grep -q btxd.real || die "production left GPU"
fi
echo "E2E_CUDA_GRANITE_FIT PASS"
