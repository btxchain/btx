# Multi-GPU Profile-1 golden corpus — v0.33.2 final freeze

CUDA and Metal reproductions of the eight canonical Profile-1 production canaries
(nonces 1–8, `matmul_dim=4096`) at the v0.33.2 final source freeze.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU oracle
reproduction is not required for this GPU-optimized chain.

This corpus is evidence of reproduction only. It does not authorize activation,
change consensus parameters, or alter ratification flags.

## Freeze

| | |
|---|---|
| Source revision | `540ce328776e24dc4cf97592e239a125ab8b2c0f` |
| Build-relevant tree fingerprint | `26d8be9eff7307928f70a7c13d88ba57cef222a6f77dfcfa3c12d14c618dcd10` |
| Episode profile | 1 (Epoch-A consensus shape) |
| Episodes | 8 |

Both providers ran from clean checkouts of that revision under the corpus
script's fail-closed dirty-tree guard, each built all required targets from that
exact source, and each independently recomputed the fingerprint above.

Every artifact additionally satisfies `embedded_source_revision == git_tip` with
`embedded_source_dirty == false`, so neither reading came from a binary built off
a different or modified tree.

## Result

```
cuda_metal_match:         true
complete_multi_gpu_match: true
mismatches:               0
coverage_failures:        0
```

All eight ExactReplay digests and all eight serialized 182-byte canary headers
are byte-identical across providers. The digests are unchanged from every
previously accepted cohort.

| | CUDA | Metal |
|---|---|---|
| Provider | `cuda_rc_exact_fused_extract` | `metal_int8_mpp_tensorops_fused_extract` |
| Architecture class | `sm_120` | `m4_class` |
| Device calls | 1'088 | 1'088 |
| Device MACs | 1'129'198'441'725'952 | 1'129'198'441'725'952 |
| `require_device` (strict-device) | true | true |
| CPU GEMM calls / MACs / fallbacks | 0 / 0 / 0 | 0 / 0 / 0 |
| `fully_accelerated` | true | true |
| ExtractMX self-qualification | PASS | PASS |
| Harness SHA-256 | `fba686a97ed5537de23d455965e39b5ff62483c722fd97c8db10b5c3270d9b18` | `9371b03d7123eec651be124b82d0e8a8d6feab121795ad96335af535d47c0b1a` |

Per-phase wall times differ between providers, as they must — they are different
machines. Nothing consensus-bearing differs.

## Contents

- `multi-gpu-digest-compare.json` — comparator output
- `raw/profile1-cuda-8.json` — CUDA harness record
- `raw/profile1-metal-8.json` — Metal harness record
