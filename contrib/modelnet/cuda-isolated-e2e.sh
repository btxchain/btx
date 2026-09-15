#!/usr/bin/env bash
# Build+run isolated CUDA worker on a dedicated CUDA workstation SSH host.
# Tiny 4-byte kernel. Never SIGKILL production. Fail-fast. Does not cmake BTX.
#
#   CUDA_HOST=user@cuda-box contrib/modelnet/cuda-isolated-e2e.sh
# Optional: CUDA_REQUIRE_EXACTREPLAY=1 to assert btxd.real still holds the GPU.
# Do not set BTX_LIVE_ATTESTOR=1. May use --allow-shared-gpu.
export LC_ALL=C
set -euo pipefail
die() { echo "cuda-isolated-qual: $*" >&2; exit 1; }
HOST="${CUDA_HOST:?set CUDA_HOST to an SSH alias of a dedicated CUDA workstation}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cuda_qual_worker.cu"
[[ -f "$SRC" ]] || die "missing $SRC"
if [[ "${BTX_LIVE_ATTESTOR:-0}" == "1" ]]; then
  die "refuse live attestor (BTX_LIVE_ATTESTOR=1)"
fi
ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" 'export PATH=/usr/local/cuda-12.9/bin:/usr/local/cuda/bin:$PATH
which nvcc
nvcc --version | tail -1
nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv'
scp -o BatchMode=yes "$SRC" "$HOST:/tmp/cuda_qual_worker.cu"
REMOTE="$(ssh -o BatchMode=yes "$HOST" 'export PATH=/usr/local/cuda-12.9/bin:/usr/local/cuda/bin:$PATH
set +e
nvcc -O2 /tmp/cuda_qual_worker.cu -o /tmp/cuda_qual_worker || exit 1
/tmp/cuda_qual_worker; echo rc_no_gpu=$?
/tmp/cuda_qual_worker --gpu=99; echo rc_bad_gpu=$?
/tmp/cuda_qual_worker --gpu=0; echo rc_gpu0_no_share=$?
set +e
/tmp/cuda_qual_worker --gpu=0 --allow-shared-gpu --allow-validator-gpu
echo GPU-04 finite alarm\(8\) worker returned
(/tmp/cuda_qual_worker --gpu=0 --allow-shared-gpu --allow-validator-gpu & wp=$!; sleep 0.2; kill -9 $wp 2>/dev/null || true; wait $wp 2>/dev/null || true)
echo GPU-05 crash-isolated worker killed
exit 0')"
echo "$REMOTE"
echo "$REMOTE" | grep -q 'rc_no_gpu=2' || die "GPU-02 missing --gpu must fail"
echo "$REMOTE" | grep -q 'rc_bad_gpu=2' || die "GPU-02 gpu=99 must fail before alloc"
echo "$REMOTE" | grep -q 'rc_gpu0_no_share=2' || die "GPU-02 gpu=0 without share must fail"
echo "$REMOTE" | grep -q 'CUDA_QUAL_WORKER PASS' || die "GPU-01 kernel did not PASS"
echo "$REMOTE" | grep -q 'GPU-03 isolation' || die "GPU-03 missing"
echo "$REMOTE" | grep -q 'GPU-04 finite' || die "GPU-04 missing"
echo "$REMOTE" | grep -q 'GPU-05 crash-isolated' || die "GPU-05 missing"
echo "$REMOTE" | grep -q 'GPU-06 backend_hash_observation' || die "GPU-06 missing"
AFTER="$(ssh -o BatchMode=yes "$HOST" "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv")"
if [[ "${CUDA_REQUIRE_EXACTREPLAY:-0}" == "1" ]]; then
  echo "$AFTER" | grep -q btxd.real || die "production btxd.real left the GPU"
fi
echo "gpu apps after kernel:"
echo "$AFTER"
echo "CUDA_ISOLATED_E2E PASS"
