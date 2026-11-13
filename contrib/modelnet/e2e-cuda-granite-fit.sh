#!/usr/bin/env bash
# Isolated CUDA granite-size FIT vs ExactReplay reserve.
# Does not cudaMalloc 13.8 GiB. Tiny kernel + FIT math. Fail-fast.
#
#   CUDA_HOST=user@cuda-box contrib/modelnet/e2e-cuda-granite-fit.sh
# Optional: GRANITE_BYTES=<model bytes> (default: granite, 13888336427).
# Optional: CUDA_FIT_RESERVE_MIB=<MiB> (default 4096). Below 4096 is an
# operator override: it ends in OVERRIDE_PASS and is not release qualification.
export LC_ALL=C
set -euo pipefail
die() { echo "E2E_CUDA_FIT FAIL: $*" >&2; exit 1; }
HOST="${CUDA_HOST:?set CUDA_HOST to SSH alias of a dedicated CUDA workstation}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cuda_qual_worker.cu"
GRANITE="${GRANITE_BYTES:-13888336427}"
DEFAULT_RESERVE_MIB=4096
RESERVE="${CUDA_FIT_RESERVE_MIB:-$DEFAULT_RESERVE_MIB}"
[[ "$GRANITE" =~ ^[0-9]{1,15}$ ]] || die "GRANITE_BYTES must be a decimal byte count"
[[ "$RESERVE" =~ ^[0-9]{1,7}$ ]] || die "CUDA_FIT_RESERVE_MIB must be a decimal MiB count"
[[ -f "$SRC" ]] || die "missing $SRC"
if [[ "${BTX_LIVE_ATTESTOR:-0}" == "1" ]]; then die "refuse live attestor"; fi
scp -o BatchMode=yes "$SRC" "$HOST:/tmp/cuda_qual_worker.cu"
REMOTE="$(ssh -o BatchMode=yes "$HOST" 'export PATH=/usr/local/cuda-12.9/bin:/usr/local/cuda/bin:$PATH
nvcc -O2 /tmp/cuda_qual_worker.cu -o /tmp/cuda_qual_worker || exit 1
/tmp/cuda_qual_worker --gpu=0 --allow-shared-gpu --allow-validator-gpu --granite-bytes='"$GRANITE"' --reserve-mib='"$RESERVE"'')"
echo "$REMOTE"
echo "$REMOTE" | grep -q 'CUDA_QUAL_WORKER PASS' || die "kernel"
if (( 10#$RESERVE < DEFAULT_RESERVE_MIB )); then
  echo "$REMOTE" | grep -q 'CUDA_GRANITE_FIT OVERRIDE_PASS' || die "granite FIT (reserve override $RESERVE MiB)"
  echo "$REMOTE" | grep -q 'ISO-05 OVERRIDE_FIT' || die "ISO-05"
  RESULT="E2E_CUDA_GRANITE_FIT OVERRIDE_PASS reserve_mib=$RESERVE default_reserve_mib=$DEFAULT_RESERVE_MIB (operator override; not release qualification)"
else
  echo "$REMOTE" | grep -q 'CUDA_GRANITE_FIT PASS' || die "granite FIT"
  echo "$REMOTE" | grep -q 'ISO-05 FIT' || die "ISO-05"
  RESULT="E2E_CUDA_GRANITE_FIT PASS"
fi
AFTER="$(ssh -o BatchMode=yes "$HOST" "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv")"
if [[ "${CUDA_REQUIRE_EXACTREPLAY:-0}" == "1" ]]; then
  echo "$AFTER" | grep -q btxd.real || die "production left GPU"
fi
echo "$RESULT"
