# CUDA Blackwell 16 GiB — candidate→authenticated-tip lifecycle (ASERT / spacing)

Status: **historical engineering calibration evidence only**. Ratification
gates remain false. Public RC ASERT remains neutral `1/1`; the measured
`16893794/1` value is a proposal requiring final-binary provider-bound rerun.
Heights remain `INT32_MAX`. This directory does **not** invent authenticated
complete-lifecycle samples or flip
`BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` /
`BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`.

Roadmap reminder (`doc/btx-matmul-v4.7-transition-roadmap.md`): only the live
RC branch receives measured one-time calibration; v4 and BMX4C stay `1/1`.

## Hardware class (sanitized)

- OS: Linux x86_64
- CPU: Intel Xeon W-class workstation CPU (24 logical CPUs)
- GPU: NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0
- Host RAM: ~76 GiB

No hostname, username, SKU, IP, or personal filesystem paths.

## Campaign summary (2026-08-01)

| Field | Value |
| --- | --- |
| Mode | production / CUDA strict-device, two local `btxd` nodes |
| Tip SHA | `c4ac2e439ac496245f12dcbf8b42c9575247dbe9` |
| Wall clock | ~2495 s |
| **Complete** 8-component samples | **0** (fail-closed: authority handoff unavailable) |
| **Core** samples (7 components, no authority) | **20** |
| Contention | primary n=20 steady-only; supplement `--contention-every 2`: core n=6, incomplete n=5 |
| Canary | `missing_golden` (empty production golden manifest) |

Primary artifact: `lifecycle-campaign.json`.

### Post-settings rememeasure (same day)

After AcceptBlock/sync/harness fixes and the historical ASERT proposal: short production
remeasure (`lifecycle-remeasure-post-settings-summary.json`) still reports
**complete n=0**, **core n=3**, core p99 ≈ **96.92 s**. Spacing stays **90 s**
until multi-GPU goldens unlock authority and complete samples exist.

## Required complete sum (activation gate)

```text
candidate_execution + candidate_queue_wait
  + winner_reseal + reseal_queue_wait
  + winner_authority_handoff
  + authenticated_relay
  + tip_validation + validation_queue_wait
```

`winner_authority_handoff` was **not measured** (always absent under
`missing_golden` / no production capability). Complete-sum percentiles are
therefore **undefined** (n=0). Core sum below intentionally omits authority and
is **not** activation-ready.

## Core lifecycle sum (seconds, n=20, no authority)

| Stat | Seconds |
| --- | ---: |
| p50 | 96.674 |
| p95 | 96.985 |
| p99 | 97.318 |
| max | 97.318 |
| mean | 96.717 |
| min | 96.258 |

Core sum ≈ **96.7 s** > `nPowTargetSpacingNormal` (**90 s**).

## Core per-component (seconds, n=20)

| Component | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: |
| candidate_execution_s | 32.337 | 32.591 | 32.597 | 32.597 |
| candidate_queue_wait_s | ~1e-6 | ~1e-6 | ~2e-6 | ~2e-6 |
| winner_reseal_s | 32.203 | 32.343 | 32.366 | 32.366 |
| reseal_queue_wait_s | ~1e-6 | ~1e-6 | ~1e-6 | ~1e-6 |
| authenticated_relay_s | 0.000472 | 0.000545 | 0.000569 | 0.000569 |
| tip_validation_s | 32.168 | 32.391 | 32.476 | 32.476 |
| validation_queue_wait_s | ~1e-6 | ~2e-6 | ~2e-6 | ~2e-6 |
| winner_authority_handoff_s | — | — | — | **not measured** |

Three ExactReplay-class stages dominate (~32 s each). Queues and relay are
sub-millisecond on localhost.

## Methodology clarification

### What `ScaleTargetByTimespan` / RC ASERT rescale actually does

At `next_height == nMatMulRCHeight`, pow applies:

```text
next_target = ScaleTargetByTimespan(parent_target, Num, Den)
            = floor(parent_target × Num / Den)
```

Larger `Num/Den` **loosens** the target for the first RC epoch; ordinary ASERT
then re-anchors from observed block times. That is a **PoW work-unit**
continuity knob, not a substitute for pipeline wall time.

### Lifecycle vs spacing

The activation lifecycle gate screens the **complete** correlated sum against
~90 s spacing. It is **not** the same quantity as a v3→RC nonce/s work ratio.

On this machine class, core ≈ three serial ExactReplay stages. Easing
difficulty does not remove those stages at easy regtest difficulty.
**Rescale alone cannot make ~97 s fit inside 90 s.**

## Proposal math (illustration only — not installed)

Treating `Num/Den ≈ T_core / 90` as a continuity illustration of spacing
overshoot (wrong quantity for mainnet work-ratio install):

| Core stat | Seconds | vs 90 s | Compact draft |
| --- | ---: | ---: | --- |
| p50 | 96.674 | 1.074 | ~967/900 |
| p95 | 96.985 | 1.078 | ~1078/1000 |
| p99 / max | 97.318 | 1.081 | ~1081/1000 |

**Mainnet must remain `1/1`** until a reviewed v3-vs-RC work measurement (or
accepted 1/1 + ASERT transient) is chosen. Do not copy Profile-2’s
`16422/1027` onto Profile 1.

## Contention supplement (competing-tip, core without authority)

| Field | Value |
| --- | --- |
| Samples target | 6 |
| Core (no authority) | 6 |
| Incomplete | 5 |
| Complete (8-component) | 0 |
| Core lifecycle p50/p95/p99/max | 96.587 / 96.873 / 96.873 / 96.873 |
| Phases observed | ['competing_tip', 'steady_mine_relay'] |

Still **NOT activation-complete**. All incomplete samples are `competing_tip` with
`exception:RuntimeError` during dual-mine/reorg; steady cores remain ~96.6 s.
None invent relay or authority.

## Ratification / install state

- `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` = false
- `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED` = false
- Mainnet RC ASERT = `1/1` (unchanged)
- v4 / BMX4C ASERT = `1/1` (unchanged)
- `installs_rc_asert_ratio` = false
- `operationally_ready_claim` = false

## Gaps vs activation gates

1. **Authority handoff:** 0 complete samples until reviewed production goldens +
   startup canary mint a process capability.
2. **Goldens:** production golden manifest empty (`canary_outcome=missing_golden`).
3. **Spacing:** core p50 ≈96.7 s > 90 s even before adding authority.
4. **Contention / IBD:** supplemental competing-tip run collected **6 core** / **5 incomplete** (phases=['competing_tip', 'steady_mine_relay']); multi-peer IBD soak not claimed.
5. **Work-ratio:** paired MatMul v3 vs Profile-1 RC throughput still required
   before any Num/Den install.
6. RPC `complete_lifecycle_readiness` still omits authority and keeps
   `correlated_end_to_end_sample=false`; campaign complete sum is stricter
   (fail-closed).

## Harness

```text
contrib/matmul-v4/measure-cuda-lifecycle-campaign.py
```

Two-node CUDA campaign; counter-correlates miner + validator; records complete
vs core; does not invent missing relay or authority observations.

## Artifacts in this directory

| File | Contents |
| --- | --- |
| `lifecycle-campaign.json` | Sanitized n=20 production campaign (complete n=0) |
| `lifecycle-core-n2-sanitized.json` | Earlier n=2 rootcause probe |
| `asert-vs-spacing-clarification.json` | ASERT vs spacing split |
| `rc-asert-rescale-proposal.json` | Draft Num/Den proposals (non-install) |
| `lifecycle-contention-supplement.json` | Competing-tip supplement (core n=6, incomplete n=5) |
| `asert-work-ratio-proposal.json` | Work-ratio notes (non-install) |
