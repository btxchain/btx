# ENC_RC winner-proof — G1–G5 in-circuit arithmetization integration report

**Date:** 2026-07-22
**Branch:** `wip/gkr-g1g5-integration`
**Integration tip:** `1507ea1`
**Base:** `origin/claude/matmul-v4-design-spec-af23sj` @ `9c1fa6d`

> Consensus posture (unchanged, guarded): arbiter **OFF**; activation heights
> **INT32_MAX**; `RecomputeResidentCurriculumReference` /
> `RecomputeCoupledPuzzleReference` **untouched and authoritative**;
> `VerifyWinnerProofV7` is **never** consensus-authoritative — **ExactReplay
> remains the sole authority**. The G1–G5 wiring is behind the OFF-arbiter guard
> and adds no path that makes v7 consensus-authoritative.

---

## 1. Merge

Three Fable branches (each based on `42ded4c`) were merged into a fresh
`wip/gkr-g1g5-integration` cut from the base. The union of every construction's
files, tests, and doc sections was taken — nothing dropped.

| Branch | Merged SHA | Merge commit | Construction |
|---|---|---|---|
| `origin/wip/gkr-g1g5-eval` | `d1d1d3b` | `bf3c6e4` | I — batched multilinear evaluation opening |
| `origin/wip/gkr-g1g5-air` | `fc62ad6` | `10821b4` | II + III — Extract composition + fixed-reference LogUp |
| `origin/wip/gkr-g1g5-wiring` | `e61ec4f` | `6fbbaee` | IV — copy/permutation wiring |

Conflicts resolved (union kept): three appended sections of
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` (§12 Construction I,
Appendix W3 II/III, Appendix W IV). `src/CMakeLists.txt` and
`src/test/CMakeLists.txt` auto-merged; all four sources
(`matmul_v4_rc_gkr{,_air,_eval,_wiring}.cpp`) and the three new test files are
registered.

## 2. Per-construction separation bounds (post-grind g = 40)

| Construction | Relation | −log2 ε | Notes |
|---|---|---|---|
| I — evaluation opening | G1/G2/G5 | **≥ 74** | `RCGkrConstructionISeparationBits()`; FRI-CONDITIONAL (batched-FRI query term 76.8 rides Theorem 2.1). |
| II — Extract composition | G3 | **80** | `ComposeConstraints` soundness, n_slots ≤ 256: 2·log2 p − 8 − 40. |
| III — fixed-reference membership | G3 | **128** | dual-α over Fp2 (`VerifyLookupAgainstPreprocessed`); single-α is 45–59.6 → forbidden. |
| IV — wiring (equality) | G4 | **83.19** | Schwartz–Zippel MLE, ℓ = 28. |
| IV — wiring (permutation, **dual**) | G4 | **160** | grand product, two (β,γ) pairs. |
| IV — wiring (permutation, single) | — | **60 — BELOW 64** | FORBIDDEN; single-challenge must not be reachable on the ship path (dual is mandatory). |
| Batched-FRI backend | PCS | **65.85 (v4 base)** | parametric; `FriBatchSoundnessBoundBits() = 76.8` at Q = 128 is the hardened target. |
| SHA256d bindings | — | **88** | computational, 2^40-query adversary. |

## 3. The COMPOSED separation bound

`RCGkrComposedSeparation(fri_proximity_bits)` /
`RCGkrComposedSeparationBits()` (`matmul_v4_rc_gkr.{h,cpp}`) combine all four
constructions + the batched-FRI backend + SHA256d by a log-sum-exp of the
per-relation acceptance probabilities, **parametric in the FRI proximity bound**.

**Composed total (current v4 base, FRI proximity 65.85):**

> **−log2(ε_total) ≈ 65.8 bits (conservatively ≥ 65.7).**

- **FRI-DOMINATED and CONDITIONAL.** The number clears 2^-64 by **< 2 bits**, and
  only because the batched-FRI proximity term (65.85) dominates every
  construction term. It is **conditional on the FRI fold being a sound low-degree
  test** — the current base is **FRI v4**; fixing the fold to **v5** is a separate
  hardening line. If the fold is not a sound LDT, the composed bound is **vacuous**.
- **Below-64 items (stated explicitly):** the **single-challenge** grand-product
  wiring is **60 bits** at κ = 2^28 — **below 64**. It is excluded; G4 enforces the
  **dual** form (160 bits). No *included* term is below 64.
- **Hardened path:** with Q = 128 (`FriBatchSoundnessBoundBits() = 76.8`) the FS
  subtotal (72) becomes the floor and the composed bound rises to ≈ **71.9 bits**
  (`RCGkrComposedSeparationBits(FriBatchSoundnessBoundBits())`).

Pinned in the test `gkr_integration_composed_separation_bound`.

## 4. In-circuit relations now CHECKED in `VerifyWinnerProofV7`

`CheckWinnerProofRelationsV7` runs behind the existing §5 native grounding
(defense-in-depth; it never changes the first-failing relation of an
already-rejected forgery):

- **G1** — `a_at_r/b_at_r` bound to the committed A/B columns (Construction I
  matrix-opening claim) + `final_eval = a·b`; every **leaf** operand bound to its
  Λ MxExpand PRF expansion.
- **G2** — layer claim `c_ℓ` bound to the committed Y trace-column **segment**
  (Construction I segment point).
- **G3** — Construction II Extract **composition polynomial** (`Comp ≡ 0`) +
  Construction III **fixed-reference-vector membership** (canonical T_M/T_X
  regenerated, not prover-chosen) + sampler out-binding — REPLACES the
  prover-manufactured lookup (closes the Theorem-5.1 vacuity).
- **G4** — `extract_out(L) == input(L+1)` via Construction IV over the true Λ
  provenance: direct copies by equality, transposed copies by the **DUAL**-challenge
  grand product (single-challenge unreachable); plus the §6.3 round-root↔stream
  binding.
- **G5** — Fwd residual `acc = claim + X̃(pt)`; `extract_in == Y` otherwise
  (Construction I residual binder).

**Malicious-constructor coverage (`ProveMaliciousEpisodeV7ForTest`, the v7
internally-consistent forgeries):** the standalone relation module rejects each
at its construction relation — **not only** by native re-derivation:

| Forgery kind | Construction relation | reason prefix |
|---|---|---|
| ArbitraryAbFactorization | G1 (operand → MxExpand) | `v7:g1:` |
| FabricatedTraceWires | G1 (operand → MxExpand) | `v7:g1:` |
| IdenticalFabricatedLookup | G3 (Extract out-binding / composition) | `v7:g3:` |
| FabricatedExtractIO | G5 (extract_in == claim) | `v7:g5:` |
| UnrelatedLayerRoots | G4 (round-root ↔ stream) | `v7:g4:` |

The pre-existing base v7 soundness suite is **unchanged** and still observes
`v7:ground:*`/`v7:logup:*` as the first-failing relation (native grounding runs
first). No adversarial test was weakened or removed. The coupled verifier
`VerifyWinnerCoupledV7` is **noted but unchanged** — it is re-execution-sound
(sole-authority; a fabricated-witness coupled proof is not constructible), so the
G1–G5 SNARK-soundness wiring does not apply to it; full coupled SNARK-soundness
remains an AIR follow-on.

## 5. Files touched

**Merged (constructions):**
`src/matmul/matmul_v4_rc_gkr_eval.{h,cpp}`,
`src/matmul/matmul_v4_rc_gkr_air.{h,cpp}`,
`src/matmul/matmul_v4_rc_gkr_wiring.{h,cpp}`,
`src/test/matmul_v4_rc_gkr_{eval,air,wiring}_tests.cpp`,
`src/CMakeLists.txt`, `src/test/CMakeLists.txt`,
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`.

**Integration wiring (this wave):**
- `src/matmul/matmul_v4_rc_gkr.h` — G1–G5 relation API
  (`CheckWinnerProofRelationsV7`, `VerifyWinnerRelationsV7ForTest`,
  `RCGkrRelation{,sResult}`), composed-bound API
  (`RCGkrComposedBound`, `RCGkrComposedSeparation{,Bits}`, per-term constants).
- `src/matmul/matmul_v4_rc_gkr.cpp` — `CheckWinnerProofRelationsV7` (G1–G5),
  the gate in `VerifyWinnerProofV7`, the composed-bound functions;
  `#include` of `matmul_v4_rc_gkr_wiring.h` and `<cmath>`.
- `src/test/matmul_v4_rc_gkr_integration_tests.cpp` (new) + `src/test/CMakeLists.txt`.
- `doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` — Appendix INT.
- `INTEGRATION_REPORT.md` (this file).

## 6. Open items

- **External audit** of the four constructions + the G1–G5 composition (the
  in-circuit relations are re-derivations expressed in the construction
  vocabulary; an independent review of the identity coverage is outstanding).
- **FRI v5 dependency (below-64 risk).** The composed bound (≈ 65.8) is
  **conditional** on the FRI fold being a sound low-degree test. The current base
  is FRI v4; the fold-soundness hardening to **v5** is a prerequisite for the
  bound to hold non-vacuously. This is the ONLY dependency that can push the
  effective bound below 64.
- **Single-challenge wiring (60 < 64)** is excluded by construction (dual
  mandatory); it must remain unreachable — a regression that admitted the single
  form would drop G4 below target.
- **Q = 128 batched-FRI hardening** lifts the composed bound to ≈ 71.9; recommended.
- **Consensus dims are PARKED / over-budget** (≈ 2^43 LogUp rows, 2^33-cell
  trace); the ship posture is `over_budget → ExactReplay`. The G1–G5 gate does
  not change this.
