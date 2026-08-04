> **Historical provenance / current deferral.** This document preserves a dated
> design, audit, or measurement record; its body is not the current activation
> plan. Current source keeps public-network Epoch A (`v4 = BMX4C = RC`) disabled
> at `INT32_MAX`, with RC ASERT `1/1` and GPU-lifecycle ratification false. The
> signed annotated `v0.33.2` tag identifies an earlier `H=185000` source tree; no
> GitHub v0.33.2 release or assets were published; no v0.33.2 release binaries
> were published. The tag has not moved and is not corrective; changing its
> disposition requires an explicit release decision. See the
> [canonical transition roadmap](btx-matmul-v4.7-transition-roadmap.md).

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
