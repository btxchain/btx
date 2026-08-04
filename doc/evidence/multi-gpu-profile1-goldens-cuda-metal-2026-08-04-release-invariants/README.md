# Multi-GPU Profile-1 ExactReplay golden compare

Status: **valid PR-97-only seal, superseded for the combined release**. Inspect
`multi-gpu-digest-compare.json` for the fail-closed comparison result. CUDA and
Metal validly reproduced the exact `0a1769cdff` build-relevant freeze, and
`df075c5184` populated `CommittedRCProductionGoldenManifest()` from this
cohort. Later build-relevant PR changes and the combined v0.33.2 tree are not
covered by that seal. They require a new exact-final CUDA+Metal corpus and
manifest update before merge or release. This README clarification does not
alter the sealed raw artifacts.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

## Artifact

See `multi-gpu-digest-compare.json`.
