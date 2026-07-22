# ENC_RC winner-proof — G1–G5 in-circuit arithmetization integration report

**Date:** 2026-07-22
**Branch:** `wip/gkr-g1g5-integration`
**Base:** `origin/wip/v7-hardening` @ `3f4e1a0` — the **SOUND v5 FRI fold** hardening
(WP-A..J: v5 half-domain fold, DEEP v5, arbiter hard-disable
`kRCGkrFormalSoundnessReady=false`, V3 transcript domains; validated on the
5060 Ti — GKR 78/78, CUDA green, 3-node IBD PASS).

> ## HEADLINE: composed bound ≈ 65.8 bits — **INADEQUATE MARGIN** (< 2 bits over 64)
>
> On the sound v5 fold the composed separation bound is **NON-VACUOUS** and
> **FRI-dominated at ≈ 65.8 bits (ε_total ≤ 2^-65.7)** — it clears the 2^-64
> target, but by only ≈ **1.8 bits**. This is **INADEQUATE for consensus
> authority.** The **arbiter stays hard-disabled** (`kRCGkrFormalSoundnessReady =
> false`); **ExactReplay remains the sole authority.** Parameter levers to restore
> margin are quantified in §3.

> Consensus posture (unchanged, guarded): arbiter **OFF / hard-disabled**;
> activation heights **INT32_MAX**; `RecomputeResidentCurriculumReference` /
> `RecomputeCoupledPuzzleReference` **untouched and authoritative**;
> `VerifyWinnerProofV7` is **never** consensus-authoritative. No int64 / height /
> arbiter changes; no test weakened.

---

## 1. Merge

`wip/gkr-g1g5-integration` was cut from `origin/wip/v7-hardening` @ `3f4e1a0`
(NOT the old v4 base 42ded4c/9c1fa6d — on v4 the fold is not a sound LDT and the
composed bound is meaningless). The three Fable construction branches were merged
in; the reconciliation keeps **both** the v5 FRI mechanics **and** the G1–G5
constructions. The G1–G5 wiring / test / report / doc were re-applied on top.

| Branch | Merged SHA | Merge commit | Construction |
|---|---|---|---|
| `origin/wip/gkr-g1g5-eval` | `d1d1d3b` | `1dfc93d` | I — batched multilinear evaluation opening |
| `origin/wip/gkr-g1g5-air` | `fc62ad6` | `50720ef` | II + III — Extract composition + fixed-reference LogUp |
| `origin/wip/gkr-g1g5-wiring` | `e61ec4f` | `ba9cb8a` | IV — copy/permutation wiring |

Conflicts (all resolved, union kept): the three appended doc sections of
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` (§12, Appendix W3,
Appendix W). `matmul_v4_rc_gkr_{air,eval}.{cpp,h}` and the FRI/gkr sources
auto-merged with the hardening — both the v5 FRI and the constructions survive.
All four sources (`matmul_v4_rc_gkr{,_air,_eval,_wiring}.cpp`) and the four gkr
test files are registered.

## 2. Per-construction separation bounds (post-grind g = 40)

| Construction | Relation | −log2 ε | Notes |
|---|---|---|---|
| I — evaluation opening | G1/G2/G5 | **≥ 74** | `RCGkrConstructionISeparationBits()`; rides the v5 batched FRI. |
| II — Extract composition | G3 | **80** | `ComposeConstraints`, n_slots ≤ 256: 2·log2 p − 8 − 40. |
| III — fixed-reference membership | G3 | **128** | dual-α over Fp2 (`VerifyLookupAgainstPreprocessed`); single-α 45–59.6 → forbidden. |
| IV — wiring (equality) | G4 | **83.19** | Schwartz–Zippel MLE, ℓ = 28. |
| IV — wiring (permutation, **dual**) | G4 | **160** | grand product, two (β,γ) pairs. |
| IV — wiring (permutation, single) | — | **60 — BELOW 64** | FORBIDDEN; single-challenge unreachable on the ship path (dual mandatory). |
| **FRI fold proximity (v5, DOMINATING)** | PCS | **65.85** | sound v5 half-domain fold, Q = 116; `FriSoundnessBoundBits()`. |
| batched-FRI query term | PCS | 76.8 | `FriBatchSoundnessBoundBits()` (Q = 128) — query-repetition, does NOT lift the fold floor. |
| SHA256d bindings | — | **88** | computational, 2^40-query adversary. |

## 3. The COMPOSED separation bound — number, margin, and levers

`RCGkrComposedSeparation(fri_proximity_bits)` /
`RCGkrComposedSeparationBits()` (`matmul_v4_rc_gkr.{h,cpp}`) combine all four
constructions + the FRI backend + SHA256d by a log-sum-exp of the per-relation
acceptance probabilities, **parametric in the FRI proximity bits**.

> **Composed total (v5 fold floor 65.85): −log2(ε_total) ≈ 65.8 bits,
> ε_total ≤ 2^-65.7. Margin over 64 ≈ 1.8 bits — INADEQUATE.**

This matches the independently-computed whole-protocol Theorem 8.1 figure (≈
2^-65.7) and the Construction II+III agent's number. Honest markers:

- **FRI-floor-limited, and 76.8 is NOT the security level.** The batched query
  term `FriBatchSoundnessBoundBits()` = 76.8 (Q = 128) is the query-repetition
  soundness *assuming* the fold; it does not lift the fold's own proximity
  soundness (65.85), which is the floor. Plugging 76.8 into the composition gives
  only the query-only view (FS subtotal 72 becomes the floor, ≈ 71.9) — reported,
  not claimed. `RCGkrComposedBound::inadequate_margin` is `true`.
- **Below-64 item:** the single-challenge grand-product wiring is **60 bits** —
  excluded (dual mandatory). No *included* term is below 64.

### Parameter levers to restore margin (quantified; NOT applied — tuning is out of scope)

FRI query term = Q·log2(32/17) − 40; FS subtotal = 72 is the next floor.

| Lever | Effect | Composed after | Δ vs 65.8 |
|---|---|---|---|
| **Raise Q 116 → 128** (batched target) | FRI 65.85 → **76.8** | FS subtotal (72) becomes floor ⇒ ≈ **71.9** | **+6.1 bits** |
| Raise Q 116 → 160 | FRI → 106.0 | still FS-bound ⇒ ≈ **71.9** | +6.1 (no more — FS is the ceiling) |
| **Cut the FS union** (fewer sumcheck rounds / tighter RLC) with Q = 128 | FRI 76.8, FS ↑ | ⇒ min(76.8, FS′, 80…) | up to **+10**, into the 74–80 band |
| **Fp3** FS/algebraic challenges alone (|F| ≈ 2^192) | FS/composition/membership/wiring double; **FRI floor UNCHANGED** | ≈ 65.8 unless Q rises | **0 alone** |
| **Fp3 FS + Q = 128 together** | FRI 76.8, FS ≈ 136 | FRI is the floor ⇒ ≈ **76.8** | **+11 bits, real margin** |

**Binding lesson:** the bound is FRI-floor-limited ⇒ **raising Q is the first and
mandatory lever** (Q = 128 alone → ≈ 71.9). Fp3 helps the algebraic terms but
does nothing for the FRI floor until Q rises; the durable fix is **Q = 128 + an
FS subtotal above 76.8**, landing the composed bound in the **74–77 band** with
genuine margin.

## 4. In-circuit relations CHECKED in `VerifyWinnerProofV7`

`CheckWinnerProofRelationsV7` runs behind the existing §5 native grounding
(defense-in-depth; never changes the first-failing relation of an already-rejected
forgery), on the **v5 FRI**:

- **G1** — `a_at_r/b_at_r` bound to the committed A/B columns (Construction I
  matrix-opening claim) + `final_eval = a·b`; every **leaf** operand bound to its
  Λ MxExpand PRF expansion.
- **G2** — layer claim `c_ℓ` bound to the committed Y trace-column **segment**.
- **G3** — Construction II Extract **composition polynomial** (`Comp ≡ 0`) +
  Construction III **fixed-reference-vector membership** (canonical T_M/T_X
  regenerated, not prover-chosen) + sampler out-binding — REPLACES the
  prover-manufactured lookup (closes the Theorem-5.1 vacuity).
- **G4** — `extract_out(L) == input(L+1)` via Construction IV over the true Λ
  provenance: direct copies by equality, transposed by the **DUAL**-challenge
  grand product (single unreachable); plus the §6.3 round-root↔stream binding.
- **G5** — Fwd residual `acc = claim + X̃(pt)`; `extract_in == Y` otherwise.

**Malicious-constructor coverage (`ProveMaliciousEpisodeV7ForTest`):** the
standalone relation module rejects each v7 forgery at its construction relation —
**not only** by native re-derivation:

| Forgery kind | Construction relation | reason prefix |
|---|---|---|
| ArbitraryAbFactorization | G1 (operand → MxExpand) | `v7:g1:` |
| FabricatedTraceWires | G1 (operand → MxExpand) | `v7:g1:` |
| IdenticalFabricatedLookup | G3 (Extract out-binding / composition) | `v7:g3:` |
| FabricatedExtractIO | G5 (extract_in == claim) | `v7:g5:` |
| UnrelatedLayerRoots | G4 (round-root ↔ stream) | `v7:g4:` |

The pre-existing base v7 soundness suite is **unchanged** (native grounding still
fires first: `v7:ground:*`/`v7:logup:*`). The coupled verifier
`VerifyWinnerCoupledV7` is **noted but unchanged** — re-execution-sound
(sole-authority), so the SNARK-soundness G1–G5 wiring does not apply; full coupled
SNARK-soundness is an AIR follow-on.

## 5. Files touched

**Integration wiring (this wave, on the v5 base):**
- `src/matmul/matmul_v4_rc_gkr.h` — G1–G5 relation API
  (`CheckWinnerProofRelationsV7`, `VerifyWinnerRelationsV7ForTest`,
  `RCGkrRelation{,sResult}`), composed-bound API (`RCGkrComposedBound`,
  `RCGkrComposedSeparation{,Bits}`, per-term constants incl.
  `kRCGkrFriProximityBitsV5`, `kRCGkrAdequateMarginBits`).
- `src/matmul/matmul_v4_rc_gkr.cpp` — `CheckWinnerProofRelationsV7` (G1–G5), the
  gate in `VerifyWinnerProofV7`, the composed-bound functions; `#include`
  `matmul_v4_rc_gkr_wiring.h`, `<cmath>`.
- `src/test/matmul_v4_rc_gkr_integration_tests.cpp` (new) + `src/test/CMakeLists.txt`.
- `doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` — Appendix INT.
- `INTEGRATION_REPORT.md` (this file).

**Merged (constructions):** `matmul_v4_rc_gkr_{eval,air,wiring}.{h,cpp}` + their
tests + `src/CMakeLists.txt` + the three doc appendices.

## 6. Open items

- **INADEQUATE MARGIN (≈ 1.8 bits over 64).** The composed bound clears 2^-64
  only barely; it is **not** adequate for consensus authority. Arbiter stays
  hard-disabled. Restoring margin requires the §3 levers — **Q = 128 is the
  first, mandatory step** (→ ≈ 71.9), and Q = 128 + FS > 76.8 for the 74–77 band.
- **External audit** of the four constructions + the G1–G5 composition (the
  in-circuit relations are re-derivations in the construction vocabulary plus the
  new opening/segment/wiring/residual bindings; independent review outstanding).
- **FRI v5 fold** is the sound-LDT dependency and is now the base (`3f4e1a0`); the
  composed bound is non-vacuous **because of it**. Its formal soundness review is
  part of the external audit.
- **Single-challenge wiring (60 < 64)** is excluded by construction (dual
  mandatory) and must remain unreachable.
- **Consensus dims are PARKED / over-budget** (≈ 2^43 LogUp rows, 2^33-cell
  trace); ship posture `over_budget → ExactReplay`, unchanged by the G1–G5 gate.
