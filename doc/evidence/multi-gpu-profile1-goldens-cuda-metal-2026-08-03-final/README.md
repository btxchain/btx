# Final pre-merge CUDA + Metal Profile-1 golden cohort

Status: **`complete_multi_gpu_match: true` at the final pre-merge freeze.**
This supersedes `../multi-gpu-profile1-goldens-cuda-metal-2026-08-03-sealed`,
which was sealed at `78a88af5` and invalidated by design when seven later
commits touched `src/`.

## Provenance — identical on both halves

- `source_revision` `7dc60146a14c136ec1cb59f383a5b2eb5361c5ac`
- `source_tree_fingerprint`
  `886cd74666ba18379e67e4be5b558222e6522cdebe12cdc3453e550200b3b493`

Both providers checked out that revision from a clean tree and computed the
build-relevant fingerprint independently; the two agree, which is what
`RCProductionGoldenManifestCohortValid` requires and what digest equality alone
never established.

The harness binaries were rebuilt from that checkout on each machine and
necessarily differ:

| provider | backend | `harness_sha256` (prefix) |
| --- | --- | --- |
| cuda | `cuda_rc_exact_fused_extract` | `0aea3575119fe8d1…` |
| metal | `metal_int8_mpp_tensorops_fused_extract` | `c3eb3801b5682617…` |

## Result

Eight canonical 182-byte production canary headers, nonces 1–8,
`matmul_dim=4096`, `episode_profile=1`, `consensus_shape=true`. All eight
ExactReplay digests byte-identical across providers:

```
nonce 1  b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953
nonce 2  d5ca4a68a259c6494128993d752104e6ec4ddf9551e5bc1ee2aeb61dc60264aa
nonce 3  d95d122ad36c749e4a71e6aa449e566c2e0cd5c6d59105b7324d2aaeb063bf7f
nonce 4  0fd1b4a52c59fabf035b6c47f4c87be01f2eaa7b4834eb9e8bd7dd93b28766c7
nonce 5  197d83c30a8090be3ad881c3baf423790c7dffeb529470e384f4712fc1c7853f
nonce 6  dd73fd8532f72659dc75fe38a6623fbde07f7dcfb24c02a32837b67885402698
nonce 7  b85b555946eaa351666044aed7a57724b8e3a694d7e27f50f21d44f6f566140b
nonce 8  5a9041c96f0adeb5bba90d01ae88f4919fd708d41613361b3d3e12d9aea8415a
```

**These are the same digests the `78a88af5` cohort produced.** That is the
useful result, not a formality: the seven commits in between changed the
accelerator workspace estimator, the transcript byte estimator, chainparams,
init, net_processing and the activation height itself, and none of them moved
the consensus predicate. The cohort re-seal proves predicate-neutrality by
measurement instead of asserting it from code reading.

It was sealed twice: once at `807cd19b`, then again here after the activation
height was resized against the live tip. Resizing the height changes `src/`,
so it invalidates a cohort by the same freeze rule the cohort exists to
enforce -- re-running is the rule working, not churn.

Both providers independently report **1,088 device calls** and
**1,129,198,441,725,952 device MACs**, with zero CPU GEMM calls, zero CPU MACs
and zero fallbacks; `ExtractMX` self-qualification PASS and
`digests_stable=true` on both. Episode wall: 32.352 s CUDA (`sm_120`,
`episode_cv` 0.0028) and 27.992 s Metal (M4-class, `episode_cv` 0.0017). The
Metal run reports `full_metal_pipeline=true`; CUDA reports `false`, which is
the expected per-vendor pipeline difference and is exactly the kind of
implementation divergence that makes digest agreement worth having.

## Freeze discipline

Valid **only** for `7dc60146`. The commit that installs this manifest is
necessarily later than the freeze it cites — a manifest cannot name the commit
containing itself — and the cohort validator compares the two entries against
each other, not against HEAD. Any subsequent change to `src/`, `cmake/` or the
root `CMakeLists.txt` needs both providers re-run against that new commit.

## Artifacts

- `raw/profile1-cuda-8.json`, `raw/profile1-metal-8.json` — public-evidence
  harness results.
- `multi-gpu-digest-compare.json` — the complete cross-provider comparison.

Machine-class and provider capability data only: no hostname, account name,
filesystem path, device serial, network address, or credential.
