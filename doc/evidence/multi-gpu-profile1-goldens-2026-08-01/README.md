# Multi-GPU Profile-1 ExactReplay golden compare

Status: **historical CUDA + Metal digest match**. The production manifest is
now intentionally empty until both providers rerun from one corrected code
freeze under the hardened provenance comparator. Public ratification and
Epoch-A heights remain disabled.

## Result

The CUDA and Metal providers produced byte-identical ExactReplay digests for
production canary nonces 1 through 8. The comparator also verified identical
182-byte frozen headers, `matmul_dim=4096`, the exact nonce set, full device
coverage, and zero CPU GEMM fallbacks.

| Backend | Hardware class | Headers | Device-only | CPU fallbacks | Result |
| --- | --- | ---: | --- | ---: | --- |
| CUDA | Blackwell-class discrete GPU, 16 GiB | 8 | true | 0 | matches |
| Metal | Apple Silicon M4 Max-class | 8 | true | 0 | matches |
| HIP | AMD/ROCm | 0 | unavailable | unavailable | optional/not authorized |

The Metal corpus was rerun from source revision
`bc5f5733867a704185b4f114bf24f56256ad09dd` with provider
`metal_int8_mpp_tensorops_fused_extract`. Its mean wall time was approximately
28.19 seconds per production ExactReplay across the eight headers.

The original CUDA raw artifact's missing revision field was recovered from its
byte-identical companion summary, which records revision
`c4ac2e439ac496245f12dcbf8b42c9575247dbe9`. Public provider identity is bound
to CUDA architecture class `sm_120`. This historical comparison predates the
current exact-revision, source-tree-fingerprint, raw-provider, and harness-binary
checks and therefore cannot authorize runtime readiness.

## Policy

Epoch-A production goldens require the two independent launch implementations,
CUDA and Metal, to run ExactReplay on identical frozen canary headers. Portable
CPU ExactReplay is not accepted as an independent production-golden backend.
HIP is optional; any HIP entry must match this corpus before it is authorized.

`complete_multi_gpu_match` was true under the historical comparator, with no
header, dimension, nonce, digest, provider-identity, or coverage mismatch. The
current manifest deliberately does not consume this artifact.

## Artifacts

- `multi-gpu-digest-compare.json` records the fail-closed comparison.
- `raw/profile1-cuda-8.json` is the sanitized CUDA corpus.
- `raw/profile1-metal-8.json` is the sanitized Metal corpus.

The harness used public-evidence mode. The committed artifacts contain only
machine-class/provider information, not hostnames, account names, filesystem
paths, device serials, or private deployment data.
