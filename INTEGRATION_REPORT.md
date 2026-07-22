# ENC_RC winner-proof — G1–G5 in-circuit arithmetization integration report

**Date:** 2026-07-22 (margin restoration wave: `wip/gkr-margin-bounds`)
**Branch:** `wip/gkr-g1g5-integration`
**Base:** `origin/wip/v7-hardening` @ `3f4e1a0` — the **SOUND v5 FRI fold** hardening
(WP-A..J: v5 half-domain fold, DEEP v5, arbiter hard-disable
`kRCGkrFormalSoundnessReady=false`, V3 transcript domains; validated on the
5060 Ti — GKR 78/78, CUDA green, 3-node IBD PASS).

> ## HEADLINE (2026-07-22, margin-fix integration `wip/gkr-margin`): SHIPPED composed bound ≈ **71.9 bits** — margin over 64 ≈ **7.9 bits**, ADEQUATE. Fp3 lift to ≈ 76.80 is a DEFERRED follow-on.
>
> **What shipped on `wip/gkr-margin`:** the ONE margin lever that is live,
> field-independent, and complete — **fold Q = 116 → 128** (`kRCFriNumQueries`).
> It lifts the FRI fold-proximity floor 65.85 → **76.80** (query repetition, no
> field dependence), which now sits ABOVE the (Fp2) whole-protocol FS subtotal
> (72). So on the sound v5 fold the composed separation bound is **NON-VACUOUS**
> and **FS-subtotal-dominated at ≈ 71.9 bits (ε_total ≤ 2^-71.9)** — clearing
> the 2^-64 target by ≈ **7.9 bits (ADEQUATE**, `inadequate_margin = false`),
> though **below** the ≥ 74-bit `kRCGkrComposedTargetBits` bar. No included term
> is below 64 (smallest included term: FS subtotal 72). Historical Q=116/Fp2
> state: ≈ 65.8 bits, ≈ 1.8-bit margin — INADEQUATE; kept as a pinned test
> record.
>
> **Why Fp3 was NOT shipped (deferred, not abandoned).** The bounds wave
> accounted the algebraic terms over F_{p^3} (|K| ≈ 2^192) to reach ≈ 76.80.
> But moving the challenges to Fp3 is **not a clean challenge-field swap**:
> every algebraic challenge that would move is **codeword-entangled with a
> committed FRI instance** — LogUp α feeds `logup_inv_fri`/`logup_r_fri`
> (`inv_i = 1/(α−t_i)`); the batch RLC λ + DEEP weights w1,w2 and the eval
> μ/γ combine column codewords into the batched FRI; the OOD point z feeds the
> DEEP quotient codeword. Drawing any of them from Fp3 forces an **Fp3-codeword
> FRI** (the §3.5 caveat), an out-of-scope protocol change. Keeping the FRI
> stack in Fp2 (the mandate) caps those FS terms at their Fp2 values, so the
> "algebraic-only" surgical scope is **internally inconsistent** and cannot
> reach 76.80. Additionally, the pure-sumcheck challenges (`prod_sumcheck_r`
> etc.) are prover-sent proof data (`RCGkrSumcheckRound`, `RCGkrLayerClaim`),
> so even the consistent subset is a proof-wire-format + prover + verifier +
> serialization change — not landable **blind** (no compiler in this env)
> without risking a broken half-migration. Per the margin-fix fallback
> directive, a **correct 71.9-bit branch beats a broken 76.8-bit one**. The
> Fp3 upgrade is scoped in §3.5 + §6 as a follow-on owning the Fp3-codeword-FRI
> decision.
>
> The **arbiter stays hard-disabled** (`kRCGkrFormalSoundnessReady = false`);
> **ExactReplay remains the sole authority** — this is audit accounting, not a
> consensus switch.

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

**SHIPPED = Q=128 fold / Fp2 challenges** (the "Old challenge field, new Q"
column below — this is what `wip/gkr-margin` ships). **Fp3 target = the
DEFERRED follow-on** (|K| ≈ 2^192; every Fp3 row is CONDITIONAL on the §3.5
challenge-site cutover AND the Fp3-codeword-FRI decision — NOT shipped). Reading
the table: the SHIPPED per-construction value is the "Old" column EXCEPT the FRI
fold and Construction-I/composed rows, where Q=128 is live (field-independent).

| Construction | Relation | Closed form (−log2, pre-grind) | **SHIPPED (Fp2, Q=128)** | Fp3 target (deferred) | Notes |
|---|---|---|---|---|---|
| I — evaluation opening | G1/G2/G5 | FS′×2^40 ⊕ FRI-query ⊕ SHA | **74** | 76 | `RCGkrConstructionISeparationBits()` = 74 (FS-dominated at 2^-74.4 over Fp2). |
| II — Extract composition | G3 | (n_slots−1)/\|K\|, n_slots ≤ 256 | **80** | 144 | Fp2: 2·log2 p − 8 − 40; `ComposeConstraints`. |
| III — fixed-reference membership | G3 | ((N_w+N_t)/\|K\|)², ≤ 2^44 | **128** | 256 | dual-α over Fp2 (`VerifyLookupAgainstPreprocessed`); single-α stays forbidden. |
| IV — wiring (equality) | G4 | ℓ/\|K\|, ℓ = 28 | **83.19** | 147.19 | Schwartz–Zippel MLE (Fp2). |
| IV — wiring (permutation, **dual**) | G4 | (N/\|K\|)², N = 2^28 | **160** | 288 | grand product, two (β,γ) pairs (Fp2). |
| IV — wiring (permutation, single) | — | N/\|K\| | **60 — BELOW 64** | 124 | STILL FORBIDDEN: the dual mandate is structural (G4); the below-64 record is pinned (`kRCGkrWiringPermutationSingleSepBits` = 60). |
| Whole-protocol FS subtotal ×2^40 | — | Σ(sumcheck + cond. + RLC)/\|K\| + dual-OOD + dual-α | **72** | 135.5 | `kRCGkrFsSubtotalSepBits` = 72 (Fp2); **this is the SHIPPED composed floor at Q=128**. |
| — dual-OOD DEEP (z1,z2) | — | (2κ/(\|K\|−\|D\|))², κ = 2^28 | **196 pre / 156 post** | (z stays Fp2 — codeword-entangled) | inside the FS subtotal; z feeds the DEEP quotient codeword ⇒ stays Fp2 even under the follow-on. |
| — dual-α LogUp | — | ((N_w+N_t)/\|K\|)² | **168 pre / 128 post** | 296 pre / 256 post | inside the FS subtotal; α feeds `logup_inv_fri` ⇒ Fp3 needs Fp3-codeword FRI. |
| **FRI fold proximity (v5, floor)** | PCS | Q·log2(32/17) − 40 | **76.80** (Q=128) | 76.80 (field-independent) | `FriSoundnessBoundBits()` = 76 (integer floor). Was 65.85 at Q=116. |
| batched-FRI query term | PCS | Q·log2(32/17) − 40 | **76.8** | 76.8 | `FriBatchSoundnessBoundBits()` (Q = 128) — coincides with the fold floor. |
| SHA256d bindings | — | computational | **88** | 88 | 2^40-query adversary; field-independent. |
| **COMPOSED (log-sum-exp)** | all | — | **≈ 71.9 (margin 7.9 — ADEQUATE, FS-dominated)** | ≈ 76.80 (margin 12.8; ≥ 74 bar) | `RCGkrComposedSeparationBits()`. Q=116/Fp2 history: ≈ 65.8, INADEQUATE. |

## 3. The COMPOSED separation bound — number, margin, and the levers

`RCGkrComposedSeparation(fri_proximity_bits)` /
`RCGkrComposedSeparationBits()` (`matmul_v4_rc_gkr.{h,cpp}`) combine all four
constructions + the FRI backend + SHA256d by a log-sum-exp of the per-relation
acceptance probabilities, **parametric in the FRI proximity bits**.

> **SHIPPED composed total (v5 fold, Q = 128, Fp2 challenges):
> −log2(ε_total) ≈ 71.9 bits, ε_total ≤ 2^-71.9. Margin over 64 ≈ 7.9 bits —
> ADEQUATE (`inadequate_margin = false`), FS-subtotal-dominated (72 is the
> binding floor; the FRI floor 76.80 sits above it). BELOW the 74-bit
> `kRCGkrComposedTargetBits` bar, which the deferred Fp3 lift would reach.**

| Lever | Status | Effect on terms |
|---|---|---|
| **Raise fold Q 116 → 128** (`kRCFriNumQueries`) | **APPLIED — live, complete, field-independent** | FRI fold floor 65.85 → **76.80**; now above the Fp2 FS subtotal (72), which becomes the composed floor ⇒ composed ≈ **71.9**. |
| **Draw FS/algebraic challenges from Fp3** (\|K\| ≈ 2^192) | **DEFERRED — NOT applied.** Blocked on the Fp3-codeword-FRI decision (see §3.5 caveat + §6) | *Would* raise FS subtotal 72 → 135.5, composition 80 → 144, membership 128 → 256, wiring 83.19 → 147.19 / dual 160 → 288, Construction I 74 → 76, ⇒ composed ≈ **76.80**. Requires the §3.5 cutover. |

Honest markers:

- **SHIPPED bound is FS-subtotal-limited at ≈ 71.9.** Raising Q was the
  mandatory, field-independent first lever; it lifts the FRI floor (76.80)
  above the Fp2 FS subtotal (72), so **72 is now the binding term** and the
  composed bound is ≈ 71.9 (FS-dominated). Fp3 alone would have left the 65.85
  floor in place (+0); Q alone lands 71.9; Q + Fp3 *together* would reach 76.80
  — but only the Q lever is shippable now (see the deferred lever).
- **Why Fp3 is deferred, not applied.** The FS subtotal's dominant rows over
  Fp2 (batch RLC λ / DEEP weights, dual-OOD z) are **codeword-entangled** with
  the committed FRI (they multiply/feed FRI codewords), so drawing them from
  Fp3 forces an Fp3-codeword FRI — the §3.5 caveat, out of scope. Even the
  cleanly-liftable rows (pure sumcheck challenges) are prover-sent proof data
  (`RCGkrSumcheckRound`/`RCGkrLayerClaim`), so any real Fp3 cutover is a
  proof-wire-format + prover + verifier + serialization change, not a challenge
  swap. Done blind (no build here) that risks a broken half-migration; the
  correct 71.9-bit branch is preferred.
- **No included term is below 64.** The single-challenge grand-product wiring
  — 60 bits over Fp2, the origin of the dual mandate — remains **excluded and
  structurally unreachable** (G4 enforces dual); the Fp2 record stays pinned in
  code (`kRCGkrWiringPermutationSingleSepBits` = 60) + test.
- **Historical record retained:** composing at the old Q=116 floor (65.85)
  still reports ≈ 65.8 / `inadequate_margin = true`, asserted in the test so
  the "before" state cannot be silently rewritten.

### 3.5 Fp2 → Fp3 challenge sites — the DEFERRED follow-on scope

This is the enumerated scope for the Fp3 cutover that would raise the composed
bound from the shipped ≈ 71.9 to ≈ 76.80. **It is NOT done on `wip/gkr-margin`
and cannot be done as a challenge-field swap alone**, for two structural
reasons that the follow-on must own:

1. **Codeword entanglement (the hard blocker).** Several of the samplers below
   feed FRI-committed codewords, so retyping them to Fp3 turns the FRI into an
   Fp3-codeword (or tower-embedded) FRI — a separate protocol decision, NOT in
   scope for a challenge swap. Specifically: the FRI fold β and OOD z (sampler
   1) multiply/feed the fold + DEEP-quotient codewords; the LogUp α (composition
   γ/α sites) feeds `logup_inv_fri`/`logup_r_fri` (`inv_i = 1/(α−t_i)`); the
   batch RLC λ + DEEP weights w1,w2 and the eval μ/γ combine column codewords
   into the batched FRI. Keeping the FRI stack in Fp2 (the mandate) caps those
   FS-subtotal rows at their Fp2 values, so an "algebraic-only" Fp3 scope does
   **not** actually reach 135.5 / 76.80.
2. **Proof wire format.** The cleanly-liftable challenges (pure sumcheck `r`,
   wiring ρ/β/γ) drive prover-sent proof data — `RCGkrSumcheckRound`,
   `RCGkrLayerClaim` (`claim`/`a_at_r`/`b_at_r`/`final_eval`), the eval/wiring
   claim structs, `logup_*_sum`/`logup_alpha` — all typed `Fp2`. Moving to Fp3
   is a 16→24-byte wire change touching serialization, prover, verifier, and
   every proof-constructing test. It must be built and tested, not landed blind.

The following challenge-derivation primitives and call-sites currently draw
from **Fp2**. DO-NOT-REWIRE note: none are changed by the margin work; they are
listed as the follow-on's checklist.

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

- **Fp3 challenge cutover (the §3.5 list) — DEFERRED follow-on.** The
  Fp3-dependent terms (FS 135.5, composition 144, membership 256, wiring
  147.19/288, Construction I 76) that would lift the composed bound to ≈ 76.80
  are NOT shipped: they hold only once every §3.5 call-site draws from
  F_{p^3}, which (a) requires the Fp3-codeword-FRI decision for the
  entangled fold/λ/w/z/α draws (§3.5 caveat 1) and (b) is a proof-wire-format +
  prover + verifier change (§3.5 caveat 2), not landable blind. The follow-on
  owns both. The Q = 128 fold (hence the 76.80 FRI floor, field-independent)
  IS live in this tree; it is what makes the shipped 71.9.
- **Shipped margin is accounting, not authority.** The SHIPPED composed bound
  ≈ 71.9 (margin ≈ 7.9 over 64) is ADEQUATE (`inadequate_margin = false`) but
  BELOW the 74-bit target bar; regardless, the arbiter stays hard-disabled
  until the external audit AND the Fp3 cutover land; ExactReplay remains the
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
