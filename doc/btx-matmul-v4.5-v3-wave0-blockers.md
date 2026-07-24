> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

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
