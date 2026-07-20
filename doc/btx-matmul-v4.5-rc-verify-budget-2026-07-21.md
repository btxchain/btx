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

## Measured table (Lane C — 5060 Ti / tip bf36b7d)

Profiles are **external** (`taskset -c`); harness has **no** `--validator-profile`
flag. C2 pins: floor=`0-3` (4 cores), mid=`0-7` (8 cores), dc=`0-23` (all).
Source: `~/Documents/macpro-rack/pr89-results/c2/`.

| Profile | Cores (taskset) | Dim | Path | measured_s | Stage-I budget_s | Meet? | Evidence file |
|---|---|---|---|---|---|---|---|
| floor | 0-3 | toy | happy-path GKR verify | **0.2867** | 0.9 | **YES** | `floor-toy-gkr.json` |
| mid | 0-7 | toy | happy-path GKR verify | **0.2858** | 0.9 | **YES** | `mid-toy-gkr.json` |
| dc | 0-23 | toy | happy-path GKR verify | **0.2864** | 0.9 | **YES** | `dc-toy-gkr.json` |
| floor | 0-3 | medium | happy-path GKR verify | **0.5119** | 0.9 | **YES** | `floor-medium-gkr.json` |
| mid | 0-7 | medium | happy-path GKR verify | **0.5114** | 0.9 | **YES** | `mid-medium-gkr.json` |
| dc | 0-23 | medium | happy-path GKR verify | **0.5128** | 0.9 | **YES** | `dc-medium-gkr.json` |
| floor | 0-3 | **production** | happy-path GKR verify | **NOT RUN** | 0.9 | TBD | deferred (medium prove ~1440 s / ~7.6 GiB RSS) |
| mid | 0-7 | **production** | happy-path GKR verify | **NOT RUN** | 0.9 | TBD | same |
| dc | all | **production** | happy-path GKR verify | **NOT RUN** | 0.9 | TBD | same |
| dc *(baseline)* | all | **production** | ExactReplay (ε=0) | **≥8416 s (~2.3 h, still running)** | 9.0 | **NO** | `c1-production-episode.json` |
| floor | 0-3 | **production** | ExactReplay (ε=0) | TBD | 9.0 | TBD | opt-in `BTX_RC_C2_RERUN_EXACTREPLAY=1` |
| mid | 0-7 | **production** | ExactReplay (ε=0) | TBD | 9.0 | TBD | same |

Also record vs **full interval**: ExactReplay `meet_90s_interval` — production
ExactReplay already exceeds **90 s** on the in-progress C1b wall (lower bound).

Prove soft-budget note (not Stage-I verify): toy prove ~11 s, medium prove
~1436–1447 s → HBM GKR PARKED / ExactReplay fallback path on all profiles.

### C4 Stage-G (16 GB)

Source: `~/Documents/macpro-rack/pr89-results/c4/c4-stageg-kgate.json`
(device: RTX 5060 Ti 16GB).

| Metric | Value |
|---|---|
| `medium_k_est` mean | **1.22916** |
| `medium_k_est` min | **1.2257** |
| `medium_k_est` max | **1.23105** |
| Gate target | **k ≥ 1.3** |
| Verdict | **NO-GO** |

**Caveat:** Gate `k ≥ 1.3` is specified for **24 GB** parts; this run is the
**16 GB** commodity tail — not a 24 GB Stage-G closeout.

### C3 coupled Streamed (TBD-1 closed)

Production coupled Streamed Mine on 5060 Ti (tip bf36b7d). Full mem-cap sweep
complete (`doc/evidence/lane-c-2026-07-21/c3/`):

| Cap | Streamed wall_s | bank_s | barriers_s | peak_rss_kib | digest |
|---|---|---|---|---|---|
| 512 MiB | **989.83** | 914.25 | 67.42 | 1316876 | `a3e485f1…c868` |
| 2 GiB | **989.95** | 914.28 | 67.48 | 1317016 | same |
| 8 GiB | **990.55** | 915.04 | 67.36 | 1317136 | same |
| uncapped | **985.98** | 911.00 | 66.88 | 1316172 | same |
| Resident | **INFEASIBLE-ON-16GB** (~48.00 GiB required) | — | — | — | — |

Mean Streamed wall ≈ **989.1 s**. `mine_matches_cpu=true` all caps. Cap is
mode-select soft (auto-Streamed); peak RSS ≈1.26 GiB exceeds the 512 MiB soft
floor. Resident-vs-Streamed slowdown **N/A** (Resident not runnable). Gate
remains **NO-GO**.

### C5 verdict (ExactReplay lower-bound; full wall still finalizing)

> **C5 verdict (Lane C / tip bf36b7d):** Production ExactReplay on the Mac Pro
> host is **≥8416 s (~2.3 h)** and still running (C1b) → **busts** both the
> **9.0 s** Stage-I ExactReplay budget (~935×) and the **90 s** block interval
> (~93×) on a lower-bound basis. Toy/medium succinct happy-path verify on
> **floor** (4-core) is **0.287 / 0.512 s** → **clears** the **0.9 s** budget on
> all floor/mid/dc profiles; production GKR prove/verify was **not run** (medium
> prove already ~1440 s / ~7.6 GiB RSS). Production coupled Streamed Mine wall
> ≈ **989 s** (TBD-1 closed); Resident **INFEASIBLE-ON-16GB**. **Resolution the
> data points to:** ExactReplay cannot carry these production dims inside the
> interval → prefer **activate Stage-I succinct verify** once production
> happy-path verify is measured and clears 0.9 s; otherwise **shrink episode**.
> Height stays `INT32_MAX`; arbiter stays OFF. Replace ExactReplay lower-bound
> with the final C1b `phase_wall_s.total` when the process exits.

Gate verdict remains **NO-GO** for height.
