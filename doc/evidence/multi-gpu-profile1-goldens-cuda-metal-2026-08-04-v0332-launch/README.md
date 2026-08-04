# Multi-GPU Profile-1 golden corpus — v0.33.2 public launch freeze

CUDA and Metal reproductions of the eight canonical Profile-1 production canaries
(nonces 1–8, `matmul_dim=4096`) at the v0.33.2 launch candidate freeze.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU oracle
reproduction is not required for this GPU-optimized chain.

This corpus is evidence of reproduction only. It does not authorize activation.

## Freeze

| | |
|---|---|
| Source revision | `d9442b9696934a0f8f206a7ec18a4f625df4fbf6` |
| Build-relevant tree fingerprint | `5ac040aec7a09457fbf3e633eba5b0bed7d5756849de5cf2fa513ad7ee63e79d` |
| Episode profile | 1 (Epoch-A consensus shape) |
| Episodes | 8 |

Both providers ran from clean checkouts of that revision under the corpus
script's fail-closed dirty-tree guard, and each independently recomputed the
fingerprint above before this corpus existed.

Each artifact additionally satisfies `embedded_source_revision == git_tip`, so
neither reading came from a binary built off a different tree. That check is not
decorative: an earlier cohort on the predecessor branch reported a clean result
from a harness that had silently failed to relink, and this is the guard that
refused it.

## Result

```
cuda_metal_match:         true
complete_multi_gpu_match: true
mismatches:               0
coverage_failures:        0
```

All eight ExactReplay digests and all eight serialized 182-byte canary headers
are byte-identical across providers. The digests are unchanged from every
previously accepted cohort, which is the required outcome — nothing in this
release may move them.

| | CUDA | Metal |
|---|---|---|
| Provider | `cuda_rc_exact_fused_extract` | `metal_int8_mpp_tensorops_fused_extract` |
| Architecture class | `sm_120` | `m4_class` |
| Device calls | 1'088 | 1'088 |
| Device MACs | 1'129'198'441'725'952 | 1'129'198'441'725'952 |
| CPU GEMM calls / MACs / fallbacks | 0 / 0 / 0 | 0 / 0 / 0 |
| `fully_accelerated` | true | true |
| ExtractMX self-qualification | PASS | PASS |
| Harness SHA-256 | `6ecc3bf5bfb7c88ce1f0cbce0ef9a7ebd1e9d0c31247104e8d1db1763220e5ef` | `64999f05a0bb7faabfb9662dfebdcf81551a316c67b9de053e549cb02b3c4b9c` |

Per-phase wall times differ between providers, as they must — they are different
machines. Nothing consensus-bearing differs.

## Contents

- `multi-gpu-digest-compare.json` — comparator output
- `raw/profile1-cuda-8.json` — CUDA harness record
- `raw/profile1-metal-8.json` — Metal harness record
