# ENC_RC winner-proof — G1–G5 in-circuit arithmetization integration report

**Date:** 2026-07-22 (margin restoration wave: `wip/gkr-margin-bounds`)
**Branch:** `wip/gkr-g1g5-integration`
**Base:** `origin/wip/v7-hardening` @ `3f4e1a0` — the **SOUND v5 FRI fold** hardening
(WP-A..J: v5 half-domain fold, DEEP v5, arbiter hard-disable
`kRCGkrFormalSoundnessReady=false`, V3 transcript domains; validated on the
5060 Ti — GKR 78/78, CUDA green, 3-node IBD PASS).

> ## HEADLINE (updated 2026-07-22, margin restoration): composed bound ≈ **76.80 bits** — margin over 64 ≈ **12.8 bits**, ≥ 74 bar cleared
>
> The two §3 levers are APPLIED to the bound accounting: **fold Q = 116 → 128**
> (`kRCFriNumQueries`, live in this tree) and **FS/algebraic challenges over
> F_{p^3}** (|K| ≈ 2^192, accounted symbolically — the Fp3 implementation is a
> parallel workstream; the affected call-sites are enumerated in §3.5 and MUST
> be cut over for the Fp3-dependent terms to hold). On the sound v5 fold the
> composed separation bound is **NON-VACUOUS** and **FRI-dominated at ≈ 76.80
> bits (ε_total ≤ 2^-76.79)** — clearing the 2^-64 target by ≈ 12.8 bits and
> the 74-bit restored-margin bar (`kRCGkrComposedTargetBits`) by ≈ 2.8. No
> included term is below 64 (smallest algebraic term: FS subtotal 135.5).
> Historical Q=116/Fp2 state: ≈ 65.8 bits, ≈ 1.8-bit margin — INADEQUATE; kept
> as a pinned record in the tests. The **arbiter stays hard-disabled**
> (`kRCGkrFormalSoundnessReady = false`); **ExactReplay remains the sole
> authority** — this is audit accounting, not a consensus switch.

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

## 2. Per-construction separation bounds (post-grind g = 40; Q = 128, Fp3 challenges)

Old = Q=116 fold / Fp2 challenges; New = Q=128 fold / Fp3 challenges
(|K| = 2^191.999…; Fp3-dependent rows conditional on the §3.5 cutover).

| Construction | Relation | Closed form (−log2, pre-grind) | Old | **New** | Notes |
|---|---|---|---|---|---|
| I — evaluation opening | G1/G2/G5 | FS′×2^40 ⊕ FRI-query ⊕ SHA | ≥ 74 | **≥ 76** | `RCGkrConstructionISeparationBits()`; now FRI-query-dominated (FS′ ≤ 2^-138.4). |
| II — Extract composition | G3 | (n_slots−1)/\|K\|, n_slots ≤ 256 | 80 | **144** | 3·log2 p − 8 − 40; `ComposeConstraints`. |
| III — fixed-reference membership | G3 | ((N_w+N_t)/\|K\|)², ≤ 2^44 | 128 | **256** | dual-α (`VerifyLookupAgainstPreprocessed`); N_L=2^43 helper form: 258. Single-α stays forbidden. |
| IV — wiring (equality) | G4 | ℓ/\|K\|, ℓ = 28 | 83.19 | **147.19** | Schwartz–Zippel MLE. |
| IV — wiring (permutation, **dual**) | G4 | (N/\|K\|)², N = 2^28 | 160 | **288** | grand product, two (β,γ) pairs. |
| IV — wiring (permutation, single) | — | N/\|K\| | **60 — BELOW 64** | 124 | STILL FORBIDDEN: the dual mandate is structural (G4); the Fp2 below-64 record is pinned (`kRCGkrWiringPermutationSingleSepBitsFp2`). |
| Whole-protocol FS subtotal ×2^40 | — | Σ(sumcheck 3·2^13 + cond. 2^9 + RLC 2^16)/\|K\| + dual-OOD + dual-α | 72 | **135.5** | `kRCGkrFsSubtotalSepBits`; pre-grind ≈ 2^-175.5. |
| — dual-OOD DEEP (z1,z2) | — | (2κ/(\|K\|−\|D\|))², κ = 2^28 | 196 pre / 156 post | **326 pre / 286 post** | inside the FS subtotal. |
| — dual-α LogUp | — | ((N_w+N_t)/\|K\|)² | 168 pre / 128 post | **296 pre / 256 post** | inside the FS subtotal. |
| **FRI fold proximity (v5, DOMINATING floor)** | PCS | Q·log2(32/17) − 40 | **65.85** (Q=116) | **76.80** (Q=128) | field-independent; `FriSoundnessBoundBits()` = 76 (integer floor). |
| batched-FRI query term | PCS | Q·log2(32/17) − 40 | 76.8 | 76.8 | `FriBatchSoundnessBoundBits()` (Q = 128, unchanged) — now COINCIDES with the fold floor. |
| SHA256d bindings | — | computational | 88 | **88** | 2^40-query adversary; field-independent. |
| **COMPOSED (log-sum-exp)** | all | — | **≈ 65.8 (margin 1.8 — INADEQUATE)** | **≈ 76.80 (margin 12.8; ≥ 74 bar cleared by 2.8)** | `RCGkrComposedSeparationBits()`. |

## 3. The COMPOSED separation bound — number, margin, and the APPLIED levers

`RCGkrComposedSeparation(fri_proximity_bits)` /
`RCGkrComposedSeparationBits()` (`matmul_v4_rc_gkr.{h,cpp}`) combine all four
constructions + the FRI backend + SHA256d by a log-sum-exp of the per-relation
acceptance probabilities, **parametric in the FRI proximity bits**.

> **Composed total (v5 fold floor 76.80, Q = 128, Fp3 challenges):
> −log2(ε_total) ≈ 76.80 bits, ε_total ≤ 2^-76.79. Margin over 64 ≈ 12.8
> bits; over the 74-bit restored-margin bar ≈ 2.8 bits — ADEQUATE
> (`inadequate_margin = false`).**

Both levers identified by the previous revision are applied to the accounting
(the 2026-07-22 margin restoration):

| Lever | Status | Effect on terms |
|---|---|---|
| **Raise fold Q 116 → 128** (`kRCFriNumQueries`) | **APPLIED, live in this tree** | FRI fold floor 65.85 → **76.80** (field-independent); now coincides with the batched query term. |
| **Draw FS/algebraic challenges from Fp3** (\|K\| ≈ 2^192) | **APPLIED to the bound accounting; implementation is a parallel workstream** | FS subtotal 72 → **135.5**; composition 80 → 144; membership 128 → 256; wiring 83.19 → 147.19 / dual 160 → 288; Construction I 74 → 76. **Conditional on the §3.5 call-site cutover.** |

Honest markers:

- **FRI-floor-limited by design, now with margin.** The floor (76.80) is the
  field-independent query-repetition term — exactly why Q had to rise: Fp3
  alone left 65.85 in place (the historical lever table showed +0 for Fp3
  alone). The next terms are SHA (88) and the FS subtotal (135.5).
- **The conservative integer view also clears the bar:** plugging
  `FriBatchSoundnessBoundBits()` = 76 composes to ≈ 76.0 ≥ 74; the margin does
  not hinge on the fractional 0.80.
- **No included term is below 64.** The single-challenge grand-product wiring
  — 60 bits over Fp2, the origin of the dual mandate — remains **excluded and
  structurally unreachable** (G4 enforces dual); over Fp3 it would be 124, but
  the mandate is NOT relaxed, and the Fp2 record stays pinned in code + test.
- **Historical record retained:** composing at the old Q=116 floor (65.85)
  still reports ≈ 65.8 / `inadequate_margin = true`, asserted in the test so
  the "before" state cannot be silently rewritten.

### 3.5 Fp2 → Fp3 challenge sites (MUST be cut over for the Fp3 rows to hold)

The bound treats |K| = 2^192 symbolically. The following challenge-derivation
primitives and call-sites currently draw from **Fp2** and must switch to
**Fp3** (the parallel F_{p^3} implementation workstream). DO-NOT-REWIRE note:
none of these are changed by this margin-bounds branch.

**Samplers (retype these, everything below flows through them):**

1. `FriFs::ChallengeFp2` — `src/matmul/matmul_v4_rc_fri.cpp:234` (FRI
   transcript; every `fri_*`/`frib_*` draw). Includes `FriSampleOodZ`
   (`matmul_v4_rc_fri.cpp:283–289`), whose c1≠0 resample condition needs the
   Fp3 analogue ("outside the base-line / outside D" embedding condition).
2. `FsState::ChallengeFp2` + `FromChallengeBytes2` —
   `src/matmul/matmul_v4_rc_gkr.cpp:208`.
3. coupled-proof `ChallengeFp2` — `src/matmul/matmul_v4_rc_gkr_coupled.cpp:154`.
4. eval-argument `ChallengeFp2` — `src/matmul/matmul_v4_rc_gkr_eval.cpp:315`;
   plus `MuBase`/`MuChallenge` (tag `"mu"`) —
   `src/matmul/matmul_v4_rc_gkr_eval.cpp:101–127`.
5. `WiringChallengeFp2` / `WiringChallengePoint` —
   `src/matmul/matmul_v4_rc_gkr_wiring.cpp:120,141` (decl
   `matmul_v4_rc_gkr_wiring.h:272–275`).

**Call-sites by bound term:**

- **Sumcheck rounds (2ν/|K| rows of the FS subtotal):**
  `matmul_v4_rc_gkr.cpp:282,326` (`"prod_sumcheck_r"`); `851–852, 3212–3213`
  (`"ri"`,`"rj"`); `1705–1706, 2042–2043, 2399–2400` (`"v7_ri"`,`"v7_rj"`);
  `matmul_v4_rc_gkr_coupled.cpp:227,253` (`"prod_sumcheck_r"`), `809, 1000`
  (`"v7c_rj"`), `843–844, 1032–1033` (`"v7c_rp"`,`"v7c_rm"`);
  `matmul_v4_rc_gkr_eval.cpp:506,627` (`"eqopen_r"`).
- **RLC γ/μ/λ + DEEP weights ((M−1)/|K|, (W+2)/|K|):**
  `matmul_v4_rc_gkr_eval.cpp:439,604` (`"eqopen_gamma"`), `101–127` (`"mu"`);
  `matmul_v4_rc_fri.cpp:1115,1278` (`"frib_lambda"`), `1134–1135, 1301–1302`
  (`"frib_w"` w1,w2).
- **Dual-OOD ((2κ/(|K|−|D|))²):** `matmul_v4_rc_fri.cpp:1040` (`"frib_z"` via
  `FriSampleOodZ`); the single-instance DEEP z draws `"deep_z"` at
  `matmul_v4_rc_fri.cpp:564,695` (through `FriSampleOodZ`,
  `matmul_v4_rc_fri.cpp:283–289`).
- **Composition η + LogUp γ/α (dual-α ((N_w+N_t)/|K|)²):**
  `matmul_v4_rc_gkr.cpp:919,3248` (`"logup_alpha"` legacy single-α);
  `1751–1753, 2430–2432` (`"v7_gamma"`,`"v7_alpha1"`,`"v7_alpha2"`);
  `2017–2020` (`"g3_eta"`,`"g3_gamma"`,`"g3_alpha1"`,`"g3_alpha2"` — the G3
  relation replay incl. Construction II's η);
  `matmul_v4_rc_gkr_coupled.cpp:881–883, 1057–1059`
  (`"v7c_gamma"`,`"v7c_alpha1"`,`"v7c_alpha2"`).
- **Wiring ρ / dual (β,γ) (ℓ/|K|, (N/|K|)²):**
  `matmul_v4_rc_gkr_wiring.cpp:136–141,202` (equality ρ via
  `WiringChallengePoint`, `"wire_eq_rho"`), `340–343`
  (`"wire_perm_beta"`/`"wire_perm_gamma"`, both pairs).
- **FRI fold challenges:** `matmul_v4_rc_fri.cpp:539,677` (`"fri_fold"`),
  `1198,1310` (`"frib_fold"`). CAVEAT: fold challenges (and λ/w1/w2) multiply
  codeword values, so moving them to Fp3 entails the Fp3-codeword FRI (or a
  tower embedding) — a protocol decision owned by the Fp3 implementation
  workstream. The FRI proximity floor itself (Q·log2(32/17) − 40) is
  query-repetition-based and field-independent, so the composed floor of
  76.80 does not depend on this caveat; the FS-union rows do.

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

- **Fp3 challenge cutover (the §3.5 list).** The composed bound's
  Fp3-dependent terms (FS 135.5, composition 144, membership 256, wiring
  147.19/288, Construction I 76) hold only once every §3.5 call-site draws
  from F_{p^3}; until then those rows are the TARGET parameterization, not
  the shipped behavior. The Q = 128 fold (and hence the 76.80 floor, which is
  field-independent) is live in this tree. The Fp3-codeword decision for the
  fold/λ/w draws (§3.5 caveat) is owned by the Fp3 workstream.
- **Restored margin is accounting, not authority.** Composed ≈ 76.80
  (margin ≈ 12.8) clears the 74-bit bar, but the arbiter stays hard-disabled
  until the external audit and the Fp3 cutover land; ExactReplay remains the
  sole authority.
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
