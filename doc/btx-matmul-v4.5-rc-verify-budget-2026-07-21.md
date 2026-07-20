# ENC_RC Stage-I verification budgets — 2026-07-21

**PROVISIONAL.** Does **not** raise `nMatMulRCHeight` / `nMatMulRCCoupledHeight`.
GKR arbiter stays OFF. ExactReplay (ε=0 int64 CPU) remains the sole consensus oracle.

## Interval-fraction model

Public nets use `nPowTargetSpacing = 90` s. Stage-I budgets are fractions of that
interval (basis points):

| Path | Constant | Default | @ 90 s |
|---|---|---|---|
| Happy-path succinct (GKR+FRI verify, unified) | `kRCVerifyBudgetFracBps` | 100 bps (1%) | **0.9 s** |
| ExactReplay (ε=0 recompute) | `kRCExactReplayBudgetFracBps` | 1000 bps (10%) | **9.0 s** |

Helpers: `RCHappyPathVerifyBudgetS`, `RCExactReplayVerifyBudgetS`,
`VerifyMeetsStageIBudget` in `src/matmul/matmul_v4_rc_verify_budget.h`.

`kRCGkrVerifyBudgetS` / `kRCFriVerifyBudgetS` are aliases of the **single**
happy-path ceiling (previously hardcoded 0.5 / 2.0).

## Two-path reality (today)

1. **Happy-path succinct** — shadow-ON winner GKR+FRI verify. Soft over-budget
   may recommend ExactReplay; it does **not** decide consensus while arbiter is OFF.
2. **ExactReplay** — full int64 CPU recompute. **Load-bearing** until Stage-I
   cutover. If production ExactReplay exceeds ~9 s on commodity multi-core CPU,
   the resolution is shrink-episode or activate-succinct — **not** a silent pass.

## Gate assertion

`VerifyMeetsStageIBudget(measured, interval, path)` returns false when measured
wall exceeds the interval-fraction budget. Unit tests pin 0.9 / 9.0 and
pass/fail thresholds.

## Measured table (Lane C — 5060 Ti / tip cf7d056)

| Profile | Dim | Path | measured | Stage-I budget | Meet? |
|---|---|---|---|---|---|
| toy | episode | happy-path GKR verify | **0.279 s** | 0.9 s | YES |
| toy | episode | GKR prove (soft) | 10.9 s | soft 2 s prove | over (ExactReplay fallback) |
| floor/mid/dc | production ExactReplay | — | **TBD** (full production Mine multi-hour on this preset) | 9.0 s | TBD |

Production coupled Streamed Mine (768×64 MiB page expands) was **not** wall-clocked
end-to-end in Lane C; peak-byte **estimates** and mem-cap compliance are in
`~/Documents/macpro-rack/pr89-results/rc-production-estimates.json`.
Gate verdict remains **NO-GO** for height.
