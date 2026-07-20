# ENC_RC P2.2 — Shape / economics phase-split evidence

*Date: 2026-07-20. Tip: `79d3564` (`claude/matmul-v4-design-spec-af23sj`).
Status: measurement evidence only. Non-deciding. Does **not** raise
`nMatMulRCHeight`. Does **not** claim the design ~30/65/<5% time shares hold
on silicon.*

## Question

The unified RC proposal targets Phase-1 residency ≈30% and Phase-2 capacity
≈60–65% of **episode wall time** (Phase 3 <5%). Structural MAC formulas at
epoch-0 dims put almost all MACs in Phase 2. Do measured per-phase walls on
this machine support or undermine that time-share thesis?

## Design averaging theorem (restated)

From `doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md`
§1: phases run in sequence, so the episode strong/weak ratio is a
**time-weighted average** `Σ wᵢ·rᵢ` of per-phase ratios. If Phase 1 (the
residency / bandwidth×precision lever) is a tiny wall-time fraction on
accelerators, that lever **dilutes** — even if its per-phase ratio `r₁` is
large. MAC share ≠ wall-time share; only wall-time weights enter the average.

## Structural MAC fractions (epoch-0 dims) — NOT wall-time

Formulas (`matmul::v4::rc::TotalRCEpisodeMacs` in `src/matmul/matmul_v4_rc.cpp`):

```
p1_per_round = 2 · n_q · n_ctx · d_head
p2_per_round = 3 · L_lyr · b_seq · d_model · d_model
TotalRCEpisodeMacs = R · (p1_per_round + p2_per_round)
```

Phase 3 (Merkle / transcript) contributes **0** to `TotalRCEpisodeMacs`.

Epoch-0 consensus constants (`kRC*` / `DefaultConsensusRCEpisodeParams`):

| Dim | Value |
|---|---|
| `R` | 4 |
| `d_head` | 128 |
| `n_q` | 512 |
| `n_ctx` | 786432 |
| `L_lyr` | 16 |
| `d_model` | 4096 |
| `b_seq` | 16384 |

Computed:

| Bucket | MACs | Share of `TotalRCEpisodeMacs` |
|---|---:|---:|
| Phase 1 | `412 316 860 416` | **0.775194%** (~0.775%) |
| Phase 2 | `52 776 558 133 248` | **99.224806%** (~99.225%) |
| Phase 3 | 0 (not in MAC total) | — |
| Episode | `53 188 874 993 664` | 100% |

Label: **structural MAC count only**. This is **not** wall-time evidence and
must not be read as “Phase 1 is ~0.8% of runtime on silicon.”

For comparison (same formulas, harness dims):

| Shape | P1 MAC share | P2 MAC share |
|---|---:|---:|
| Toy (`MakeToyRCEpisodeParams`) | 40.000% | 60.000% |
| Medium (`MakeMediumRCEpisodeParams`) | 0.518% | 99.482% |

## Measurement method

- Harness: `build/bin/matmul-v4-rc-harness` (existing `RCEpisodeTiming` —
  `phase1_s` / `phase2_s` / `phase3_s` via `std::chrono::steady_clock` inside
  `RunEpisode`; no new timing dump required).
- Backend: `--backend cpu`.
- Host: `cymacpro-linux`, Intel Xeon W-3245 @ 3.20 GHz, 32 threads.
- GPU: `nvidia-smi` fails (driver not communicating). **Accelerator wall-time
  phase split is UNMEASURED** on this machine. Only CPU chrono splits are
  available below.
- Consensus / production dims: **not run** (footprint / runtime; harness
  refuses treating toy/medium as production GO evidence).

Commands:

```bash
./build/bin/matmul-v4-rc-harness --toy --episodes 5 --backend cpu --out /tmp/rc-p2.2-toy.json
./build/bin/matmul-v4-rc-harness --medium --episodes 3 --backend cpu --out /tmp/rc-p2.2-medium.json
```

Fractions below use `phase_i / (phase1+phase2+phase3)` from mean
`phase_wall_s` (episode loop average). Harness `total` also includes a small
amount of non-phase overhead (digest seal); phase shares use the phase sum.

## MEASURE — CPU per-phase wall fractions

### Toy dims (5 episodes, mean)

| Phase | Mean wall (s) | Fraction of phase-sum |
|---|---:|---:|
| Phase 1 | 0.000271150 | **31.74%** |
| Phase 2 | 0.000420378 | **49.21%** |
| Phase 3 | 0.000162703 | **19.05%** |
| Phase sum | 0.000854230 | 100% |
| Reported total | 0.000857468 | — |

Toy MAC split is 40/60; CPU wall is not MAC-proportional (overhead /
Extract / Merkle dominate at tiny dims). Toy walls are **not** predictive of
epoch-0 time shares.

### Medium dims (3 episodes, mean)

| Phase | Mean wall (s) | Fraction of phase-sum |
|---|---:|---:|
| Phase 1 | 0.000436983 | **0.641%** |
| Phase 2 | 0.053189426 | **77.99%** |
| Phase 3 | 0.014574079 | **21.37%** |
| Phase sum | 0.068200488 | 100% |
| Reported total | 0.068219655 | — |

Medium MAC split is already ~0.52% / 99.48%. Measured CPU Phase-1 wall
(**≈0.64%**) sits near the ~0.8% structural-MAC ballpark — **not** near the
design ~30% time target.

### Accelerator

**UNMEASURED.** No usable NVIDIA driver on this host; CUDA/HIP/Metal/Ascend
episode phase walls were not collected. Do not extrapolate CPU fractions to
HBM-resident FlashMX / ExactGemm device paths.

## Outcome (non-deciding)

**Thesis risk (flagged, not decided).** On CPU medium dims, Phase 1 is
≈0.64% of phase-sum wall time — same order as the epoch-0 structural MAC
share (~0.775%), not the design ~30% residency time share. By the averaging
theorem, a residency lever that occupies ≪30% of wall time is diluted even
if its per-phase ratio is strong. Phase 3 on medium is also large (~21%
CPU), far above the <5% design hold — driven by Merkle/stream work on the
large Phase-2 transcript, not by MACs.

**Do not claim 30/65 holds on silicon.** No accelerator measurement exists
here; CPU medium already contradicts treating current shapes as realizing
the proposal’s time weights.

**Shape-rebalance options (owner decision — not chosen here):**

1. **Shrink Phase-2 MACs** (lower `L_lyr`, `b_seq`, and/or `d_model` within
   capacity-gate constraints) so Phase-2 wall share falls toward ~60–65%.
2. **Grow Phase-1 residency work** (larger `n_ctx` / working-set, more
   query rows, or repeated residency passes) until Phase-1 wall approaches
   ~30% on the binding accelerator class.
3. **Revise the thesis** — keep current shapes and restate economics as
   Phase-2-dominated (residency as a secondary / amortized lever), updating
   the ~30/65 narrative and reward model accordingly.
4. **Phase-3 budget** — if transcript hashing stays ≫5% on real dims,
   either reduce leaf/stream volume or accept a larger weak-separation
   fraction explicitly.

**Height:** no change. `nMatMulRCHeight` remains inactive / NO-GO pending
owner decision and accelerator-class measurement.

## Open questions for owner

1. Is the binding success criterion still **~30% Phase-1 wall on the target
   accelerator**, or is Phase-2-dominated economics acceptable?
2. Prefer rebalance via **cutting Phase-2 MACs**, **growing Phase-1
   residency**, or **rewriting the thesis** (option 3 above)?
3. When/where to collect **accelerator** `RCEpisodeTiming` (CUDA/HIP/…) at
   medium and, later, epoch-0-scale dims under a memory cap?
4. Is medium’s ~21% Phase-3 CPU share expected to shrink on device (hash on
   host vs on-chip), or does transcript I/O need an explicit budget fix
   before any GO?
5. Should epoch-0 structural dims stay frozen (table B) while only
   measurement interpretation changes, or is a shape change on the table
   before RC activation gates?
