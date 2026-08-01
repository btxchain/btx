# Multi-GPU Profile-1 ExactReplay golden compare

Status: **CUDA partial draft**. Ratification gates remain false.
Public Epoch-A heights remain disabled until CUDA+Metal+HIP digests match
and are committed to `CommittedRCProductionGoldenManifest()`.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA, Metal, HIP) ExactReplay on identical frozen canary headers. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

Runner: `contrib/matmul-v4/multi-gpu-golden-corpus.sh`.

## Current corpus

| Backend | Status |
|---|---|
| CUDA (Blackwell-class 16 GiB, CC 12.0) | 8 frozen canary nonces captured |
| Metal | pending (same frozen headers / nonce start=1) |
| HIP | pending (no usable ROCm GPU on CUDA evidence host) |

`complete_multi_gpu_match` is false. Manifest remains empty by design.

## Artifact

See `multi-gpu-digest-compare.json` and `raw/profile1-cuda-8.json` (host identifiers redacted).
