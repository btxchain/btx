# Profile 1 ExactReplay digest corpus (CUDA)

Status: pre-ratification. Public activation disabled. Ratification gates remain
false. This does not populate the committed production golden manifest.

## Hardware class (sanitized)

- OS: Linux x86_64
- CPU: Intel Xeon W-class workstation CPU
- GPU: NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0

## CUDA corpus

| Metric | Value |
| --- | ---: |
| Headers / digests | 8 |
| matmul_dim | 4096 |
| Mean wall | ~32.49 s |
| CPU GEMM fallbacks | 0 |
| All consensus MACs on device | true |
| Provider | `cuda_rc_exact_fused_extract` |

See `profile1-cuda-digests-8.json` for digests and walls.

## Portable match

Independent portable/CPU ExactReplay parity for the same frozen headers is
still outstanding on this host (production-shape CPU probe is multi-hour).
Activation review must not treat CUDA-only digests as a completed gate-1
corpus until portable reproduction matches byte-for-byte.
