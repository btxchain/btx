# Multi-GPU Profile-1 ExactReplay golden compare

Status: **CUDA + Metal match; HIP pending**. Ratification gates remain false,
the production golden manifest remains empty, and public Epoch-A heights remain
disabled.

## Result

The CUDA and Metal providers produced byte-identical ExactReplay digests for
production canary nonces 1 through 8. The comparator also verified identical
182-byte frozen headers, `matmul_dim=4096`, the exact nonce set, full device
coverage, and zero CPU GEMM fallbacks.

| Backend | Hardware class | Headers | Device-only | CPU fallbacks | Result |
| --- | --- | ---: | --- | ---: | --- |
| CUDA | Blackwell-class discrete GPU, 16 GiB | 8 | true | 0 | matches |
| Metal | Apple Silicon M4 Max-class | 8 | true | 0 | matches |
| HIP | AMD/ROCm | 0 | unavailable | unavailable | blocking |

The Metal corpus was produced from source revision
`9dd88b8e54d92a848c4006aa9affca2ab3e0c91c` with provider
`metal_int8_mpp_tensorops_fused_extract`. Its mean wall time was approximately
28.08 seconds per production ExactReplay across the eight headers.

The original CUDA raw artifact did not embed a source revision. Its companion
CUDA corpus records the matching digest set at the earlier reviewed PR tip.
Consequently this result clears the Metal cross-provider reproduction item but
does not replace the exact-final-binary campaign required before activation.

## Policy

Epoch-A production goldens require cross-GPU-backend CUDA, Metal, and HIP
ExactReplay on identical frozen canary headers. Portable CPU ExactReplay is not
accepted as an independent production-golden backend.

`complete_multi_gpu_match` remains false until a qualifying HIP run matches the
same corpus. Do not populate `CommittedRCProductionGoldenManifest()` before the
complete three-backend result and final-binary review.

## Artifacts

- `multi-gpu-digest-compare.json` records the fail-closed comparison.
- `raw/profile1-cuda-8.json` is the sanitized CUDA corpus.
- `raw/profile1-metal-8.json` is the sanitized Metal corpus.

The harness used public-evidence mode. The committed artifacts contain only
machine-class/provider information, not hostnames, account names, filesystem
paths, device serials, or private deployment data.
