# CUDA Profile 1 loaded ExactReplay evidence

Status: corrected 100-run CUDA ExactReplay campaign for MatMul v4.7 Epoch A
(Profile 1). Activation remains disabled. This does not clear Metal cross-check
or ratification gates.

## Hardware class (sanitized)

- OS: Linux x86_64
- CPU: Intel Xeon W-class workstation CPU (24 logical CPUs)
- GPU: NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0
- Host RAM: 76 GiB

No hostname, username, or personal filesystem paths are recorded.

## Result

| Metric | Value |
| --- | ---: |
| Samples | 100 distinct production headers (`matmul_dim=4096`) |
| Distinct digests | 100 |
| Mean | 21.244 s |
| p50 | 21.240 s |
| p95 | 21.335 s |
| p99 | **21.386 s** |
| Min / max | 21.052 s / 21.402 s |
| MACs / episode | 141,149,805,215,744 |
| CPU GEMM fallbacks | **0** |
| Device path | `cuda_resident_ffn_chain+triple_stream+persistent_ws` |

Versus the 90-second block interval: p99 uses ~23.8% of the interval
(~68.6 s headroom).

## Integration note

Measured on the optimized ExactReplay CUDA kernels
(`matmul_v4_rc_exact_replay_cuda.cu` md5 `66ed7c839df0c2ce264d6bec1591ffdf`).
PR #97 wires those kernels through the same `ExactGemmBackend` Launch* ABI
Metal uses (`rc_fused_ffn`, `rc_fused_ffn_chain`, `rc_phase1`). ExpandMx and
Merkle remain host-side on CUDA in this drop; parallel host Expand/Merkle
paths are enabled when device lanes are absent.

## Artifact

See `profile1-cuda-loaded-100.json`.
