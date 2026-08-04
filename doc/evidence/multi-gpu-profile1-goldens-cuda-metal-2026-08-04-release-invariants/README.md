# Multi-GPU Profile-1 ExactReplay golden compare

Status: **non-authorizing corpus-runner output**. Inspect
`multi-gpu-digest-compare.json` for the fail-closed comparison result. This
artifact does not change consensus parameters, ratification flags, or the
committed production manifest. The release gate closes only after CUDA and
Metal reproduce the exact final clean code freeze and the reviewed seal is
committed through `CommittedRCProductionGoldenManifest()`.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

## Artifact

See `multi-gpu-digest-compare.json`.
