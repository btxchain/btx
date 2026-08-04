> **Historical provenance / current deferral.** This document preserves a dated
> design, audit, or measurement record; its body is not the current activation
> plan. This later, untagged corrective source keeps public-network Epoch A
> (`v4 = BMX4C = RC`) disabled at `INT32_MAX`, with RC ASERT `1/1` and
> GPU-lifecycle ratification false. The public `btxchain/btx` signed annotated
> `v0.33.2` tag, GitHub release, binaries, checksums, and height-179000 snapshot
> assets identify the earlier `H=185000` source tree, not this corrective tree.
> Publishing the correction requires an explicit public release/tag/version
> disposition and regenerated artifacts. See the
> [canonical transition roadmap](btx-matmul-v4.7-transition-roadmap.md).

# V4.5 V3 Wave-0 blockers (integration branch)

Base tip: f861bd567ea203f3f320647197a32d7d2a68ea30

## Push blockers
1. CUDA episode medium-digest mismatch (`rc_dc_cuda_episode_context_medium_digest`).
2. False “48 GiB packed” labelling for 768-page profile (actual packed ≈ 25.5 GiB).
3. Decorative `TotalRCCoupMacs` (ignores pages/slot and rows_per_lobe).
4. `peak_ready` must be derived, never manually asserted true.
5. GKR G1–G5 constructions integrated & validated in-tree; external cryptographic audit pending; arbiter remains OFF.

## Preserve
- SM120 plain vs `BTX_CUDA_SM120_MXFP4_NATIVE` packaging.
- Heights `INT32_MAX`; no activation; no hardware attestation.
