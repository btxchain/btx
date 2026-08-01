# CUDA Profile 1 loaded ExactReplay evidence

Status: corrected 100-run CUDA ExactReplay campaign for MatMul v4.7 Epoch A
(Profile 1) at git tip `c4ac2e439ac4`. Activation remains disabled. This does not clear
Metal cross-check or ratification gates. See the
[canonical transition roadmap](../../btx-matmul-v4.7-transition-roadmap.md)
for the complete activation contract and remaining gates.

## Hardware class (sanitized)

- OS: Linux x86_64
- CPU: Intel Xeon W-class workstation CPU (24 logical CPUs)
- GPU: NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0
- Host RAM: 76 GiB

No hostname, username, SKU name, or personal filesystem paths are recorded.

## Result

| Metric | Value |
| --- | ---: |
| Samples | 100 distinct production headers (`matmul_dim=4096`) |
| Distinct digests | 100 |
| Mean | 32.273 s |
| p50 | 32.311 s |
| p95 | 32.527 s |
| p99 | **32.705 s** |
| Min / max | 31.838 s / 32.709 s |
| MACs / episode | 141,149,805,215,744 |
| CPU GEMM fallbacks | **0** |
| Device path | `cuda_resident_ffn_chain+triple_stream+persistent_ws` |

Versus the 90-second block interval: p99 uses ~36.3% of the interval
(~57.3 s headroom).

## Integration note and evidence boundary

Measured on the ExactReplay CUDA kernels
(`matmul_v4_rc_exact_replay_cuda.cu` md5 `ed1e9477432b1766f549c039b6779632`).
This fingerprint matches the CUDA translation unit at the campaign tip.

PR #97 wires the CUDA kernels through the same `ExactGemmBackend` Launch* ABI
Metal uses (`rc_fused_ffn`, `rc_fused_ffn_chain`, `rc_phase1`). ExpandMx and
Merkle remain host-side on CUDA in this artifact's source snapshot; parallel
host Expand/Merkle paths are enabled when device lanes are absent.

L0 ratification and public-network activation heights remain false /
disabled. This campaign does not flip those gates.

## Artifact

See `profile1-cuda-loaded-100.json`.
