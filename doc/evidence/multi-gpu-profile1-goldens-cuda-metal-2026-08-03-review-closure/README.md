# Multi-GPU Profile-1 golden corpus — review-closure freeze

CUDA and Metal reproductions of the eight canonical Profile-1 production canaries
(nonces 1–8, `matmul_dim=4096`), recorded at the freeze that closes the
nine-finding review round.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU oracle
reproduction is not required for this GPU-optimized chain.

This corpus is evidence of reproduction only. It does not authorize activation.

## Freeze

| | |
|---|---|
| Source revision | `8b40a79f43e4b5d947574a3c2040f2936c524195` |
| Build-relevant tree fingerprint | `62074ec43fcaf22fb7d77c164e280c5c5b85fcb8f826d4eb0360406f8570e0b6` |
| Episode profile | 1 (Epoch-A consensus shape) |
| Episodes | 8 |

Both providers ran from a clean checkout of that revision. The corpus script's
fail-closed dirty-tree guard was active on both, so neither reading can describe
a locally modified build.

The fingerprint is
`sha256(git ls-tree -r --full-tree <rev> -- CMakeLists.txt cmake src)` with
`src/matmul/matmul_v4_rc_production_golden_manifest.cpp` excluded. That file
holds the manifest literal and nothing else; excluding it is what allows a seal
to describe the tree it ships in rather than its parent commit. Both rigs
computed the fingerprint independently and agreed.

## Result

```
cuda_metal_match:         true
complete_multi_gpu_match: true
mismatches:               0
coverage_failures:        0
```

All eight ExactReplay digests and all eight serialized 182-byte canary headers
are byte-identical across providers. The digests are also unchanged from the
previous accepted cohort, which is the expected outcome: the commits in this
round touch admission tests, attestation rate limiting, service-bit withdrawal,
an execution default and the manifest's own translation unit, none of which can
affect a transcript.

| | CUDA | Metal |
|---|---|---|
| Provider | `cuda_rc_exact_fused_extract` | `metal_int8_mpp_tensorops_fused_extract` |
| Architecture class | `sm_120` | `m4_class` |
| Device calls | 1'088 | 1'088 |
| Device MACs | 1'129'198'441'725'952 | 1'129'198'441'725'952 |
| CPU GEMM calls / MACs / fallbacks | 0 / 0 / 0 | 0 / 0 / 0 |
| `fully_accelerated` | true | true |
| ExtractMX self-qualification | PASS | PASS |
| Harness SHA-256 | `97858b30384927f05222c8277de947d480ccab1898fac5b462cbb0fcc2b9195e` | `e5fd22e408d7e0ad7a655fadfc57318562cff72bf48042f795ef2dcd14203902` |

Per-phase wall times differ between the two providers, as they must — they are
different machines. Nothing consensus-bearing differs.

## Contents

- `multi-gpu-digest-compare.json` — comparator output
- `raw/profile1-cuda-8.json` — CUDA harness record
- `raw/profile1-metal-8.json` — Metal harness record
