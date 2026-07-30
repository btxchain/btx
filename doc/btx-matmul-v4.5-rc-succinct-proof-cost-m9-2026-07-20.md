> **HISTORICAL DESIGN / AUDIT EVIDENCE — MatMul v4.7 roadmap takes precedence.**
> This document preserves version-local findings, names, and measurements; it is not
> the current activation plan. The proposed transition is defined by
> `doc/btx-matmul-v4.7-transition-roadmap.md`: Epoch A uses Profile 1 with
> ExactReplay authority and optional shadow proofs; Epoch B requires both a durable
> Profile-1 proof and ExactReplay; Epoch C makes the Profile-1 proof authoritative;
> and Epoch D separately moves to Profile 2 under proof authority. All production
> heights remain disabled. Any older “production,” “default,” “shipping,” direct-fork,
> sampled-verifier, or coupled-profile recommendation below is historical unless the
> canonical roadmap expressly carries it forward.

# ENC_RC succinct proof — prover cost measurement (M9) — 2026-07-20

*Runnable off-CI. No invented silicon rates. Arbiter OFF.*

## How to run

```bash
# Ladder rung (b_seq=256) — typically minutes on a laptop CPU
BTX_RC_GKR_MEASURE_LADDER=1 ./src/test/test_btx --run_test=matmul_v4_rc_gkr_tests/gkr_*
# Or call MeasureWinnerGkrToyMedium / MeasureWinnerGkrCurveCsv from a harness.

# Medium (b_seq=8192 ALL-PHASE + FRI Q=116) — can be hours + multi-GiB RAM
BTX_RC_GKR_MEASURE_MEDIUM=1 BTX_RC_GKR_MEASURE_LADDER=1 …
```

CI keeps both flags unset → toy prove only.

## Outputs

JSON (`MeasureWinnerGkrToyMedium`) and CSV (`MeasureWinnerGkrCurveCsv`) emit for
each rung: `prove_s`, `verify_s`, `proof_bytes`, `peak_rss_kib`, `over_budget`.

## Extrapolation (honest)

Prove cost and peak RAM scale ~**linear in ALL-PHASE trace words** and ~linear
in FRI openings (`Q=116` × path depth); LDE work scales with `blowup=16`.
Do **not** convert laptop seconds into HBM GPU TFLOPS.

## Shipping switch

`over_budget` → `used_shrink_fallback` → `VerifyRCWinnerOrExactReplay` path
`GkrFallbackExactReplay`. Test: `gkr_m9_over_budget_switches_to_exact_replay`.
Arithmetization stays ALL-PHASE (no shrink-to-toy).

## Shrink-vs-HBM crossover

Episode size where ε=0 ExactReplay stays affordable is the shipping default until
a measured consensus-dim prove fits soft budgets on real silicon. Record the
crossover from off-CI ladder→medium curves; do not invent it here.
