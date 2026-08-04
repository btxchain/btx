# Multi-GPU Profile-1 golden corpus — review-closure freeze

Status: **superseded and non-admissible for activation.** This historical
corpus used an older fingerprint design that excluded executable manifest
logic. The current design fingerprints the parser and CMake conversion and
excludes only an inert manifest `.data` seal. A fresh exact-final corpus must
pass the current release-seal verifier.

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
| Source revision | `75a6571b209527966a1ff2910fda573a1b009ba4` |
| Build-relevant tree fingerprint | `b4a47c3d7647f5ed4e2bf8639bb871bded18c21809b95ebc4a232d22232501c1` |
| Episode profile | 1 (Epoch-A consensus shape) |
| Episodes | 8 |

Both providers ran from a clean checkout of that revision. The corpus script's
fail-closed dirty-tree guard was active on both, so neither reading can describe
a locally modified build.

The historical fingerprint was
`sha256(git ls-tree -r --full-tree <rev> -- CMakeLists.txt cmake src)` with
`src/matmul/matmul_v4_rc_production_golden_manifest.cpp` excluded. That
exclusion is no longer accepted: the translation unit contained executable
parsing/policy logic. The replacement design fingerprints that code and
excludes only `src/matmul/matmul_v4_rc_production_golden_manifest.data`, whose
bytes are converted to a numeric array by fingerprinted CMake and parsed under
a strict schema by fingerprinted C++. Both historical rigs agreed on their old
fingerprint, but this directory does not satisfy the current seal policy.

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
| Harness SHA-256 | `b48526ad9756e2361b94db8dfd5654f9135c0f2f3cba58b5a95e96a144e3fef0` | `407284a7ba46e2b90ed03572d7acfa472a0852aace9bc63a79a4a02850569ae8` |

Per-phase wall times differ between the two providers, as they must — they are
different machines. Nothing consensus-bearing differs.

## Contents

- `multi-gpu-digest-compare.json` — comparator output
- `raw/profile1-cuda-8.json` — CUDA harness record
- `raw/profile1-metal-8.json` — Metal harness record
