> **HISTORICAL DESIGN / AUDIT EVIDENCE — MatMul v4.7 roadmap takes precedence.**
> This document preserves version-local findings, names, and measurements; it is not
> the current activation plan. The proposed transition is defined by
> `doc/btx-matmul-v4.7-transition-roadmap.md`: Epoch A uses Profile 1 with
> ExactReplay authority and optional shadow proofs; Epoch B requires both a durable
> Profile-1 proof and ExactReplay; Epoch C makes the Profile-1 proof authoritative;
> and Epoch D separately moves to Profile 2 under proof authority. Mainnet Epoch A (v4 = BMX4C = RC) remains a release candidate pending exact-final CUDA+Metal evidence, reviewed ASERT calibration, ratification, and selection of a live activation height; all other transition heights remain disabled. Any older “production,” “default,” “shipping,” direct-fork,
> sampled-verifier, or coupled-profile recommendation below is historical unless the
> canonical roadmap expressly carries it forward.

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
