# BTX MatMul v4.2 — Consolidated Design: the BMX4-C Committed Object and the Format-Agnostic Multi-Native-Path Architecture

*Status: CONSOLIDATED DESIGN / DETERMINATION deliverable (the unified v4.2 design). NOT a
code change, NOT a spec edit, NOT an activation. This document supersedes-by-consolidation
the open determinations of `doc/btx-matmul-v4-frontier-native-format.md` (BMX4/𝓜₁₅) and
`doc/btx-matmul-v4-committed-object-redesign.md` (F\*/𝓜₁₁) — it PINS the choices those two
documents left split — and it builds on, without re-deriving:
`doc/btx-matmul-v4-design-spec.md` (v4.1, authoritative and UNCHANGED; §0.7, §B, §C, §D,
§E, §K.2a-WT/§K.2b, §L.4, §S.2, Appendix C-13/C-15),
`doc/btx-matmul-v4-multiplatform-roadmap.md` (G-1/O-1, the INT8→FP4 landscape),
`doc/btx-matmul-v4-exact-int-on-float.md` (the no-rounding theorem and the v4.1 Ozaki
bridge), `doc/btx-matmul-v4-accumulator-eligibility.md` (C-1),
`doc/btx-matmul-v4-bmx4-shortcut-cryptanalysis.md` (alphabet SAFE; the {3,6} floor), and
`doc/btx-matmul-v4-bmx4-asic-fpga-deepdive.md` (residual bound; combine ≈ 80 % and
alphabet-independent; the accumulator cliff). Governance/threat framework for format
migration is owned by the companion `doc/btx-matmul-v4.2-longevity-threat-model.md`
(another agent; not written or modified here). Per spec §0.7-(4) no market price appears
anywhere below; every throughput ordering claim is measurement-gated (§K.2a-WT/§K.2b
posture — two prior model-based ordering claims in this program were falsified by
measurement). Written 2026-07-16.*

---

## 0. Executive determination

**v4.2 commits the BMX4-C object**: dense n×n exact-integer matmul whose operands are
**11-value E2M1-integer mantissas 𝓜₁₁ = {0, ±1, ±2, ±3, ±4, ±6}** times a
**per-32-block power-of-two scale 2^e, e ∈ {0,1,2,3} (S = 3, OCP-MX E8M0 discipline)**,
with the sketch projectors **U, V drawn over the same 𝓜₁₁ alphabet (scale-free)**, the
combine retained as the exact C-13 limb-tensor fold (re-pinned to **4 balanced base-2⁶
digits with the remainder-top rule**), and the committed object, sketch, digest, and
**O(n²) Freivalds verifier over q = 2⁶¹−1 byte-for-byte UNCHANGED in form** (R = 3,
b = 4, m = 1024, 8 MiB payload, `H(σ‖Ĉ)`, Fiat–Shamir rule, 182-byte header).

The one-table summary of every decision this document was tasked to make:

| # | Open issue | DECISION | Governing section |
|---|---|---|---|
| 1 | Alphabet: 𝓜₁₁@S=3 (F\*) vs 𝓜₁₅@S=4 (frontier-doc BMX4) | **𝓜₁₁ @ S = 3, E_max = 48** — keeps INT8 hardware 1-GEMM native (no 4× legacy tax), keeps the sub-2²⁴ eligibility-by-bound envelope, halves the worst-case accumulator-cliff ASIC exposure, preserves header n ≤ 65,535; 𝓜₁₅ is retained only as a documented hardening reserve | §2.1 |
| 2 | E2M1-U/V projector co-change | **ADOPTED** (the redesign-doc F\* instantiation, ASIC-doc profile P-B): U, V i.i.d. over 𝓜₁₁, scale-free — the whole *marginal* unit becomes frontier-native, P/Q shrink to 288n, soundness unaffected (format-blind proof), C-15 review scope already covers it | §2.2 |
| 3 | Accumulator-eligibility gate | **C-1′ generalized**: "no operation on the committed path may ever round, integer or float unit"; native block-scaled path requires **proven t = 24**; t ≈ 14 fails closed to the INT8 fallback — which under 𝓜₁₁@S=3 is **one** s8 GEMM at the device's full INT8 rate (tax ≈ 1× in GEMM count, not 4×) | §4 |
| 4 | The combine | **C-13 limb-tensor retained as the moat**, re-pinned: 4 balanced base-2⁶ digits (remainder-top rule; asymmetric-extreme discipline re-applied → pure-balanced total for n ≤ 28,664, remainder-top total to 2²³), 16 pair-GEMMs, every pair bound ≤ 2²² at n = 4096; deliberately NOT made 4-bit-native (it is the alphabet-independent exact-reduction floor) | §5 |
| 5 | Ladder & availability | Preserved and steepened toward the frontier **without taxing anyone in GEMM count**: frontier FP4 native 1×, FP8-only fold 1×, INT8 legacy 1× at its own rate, M-class (incl. pre-M5 int-ALU) unchanged and pooled, CMP/SHA/FPGA excluded | §6 |
| — | Time-resistance | The **format-agnostic multi-native-path architecture** (§8): one canonical exact-integer committed object; the operand *encoding* is a versioned consensus parameter; the verifier never changes; every hardware class computes it via its own exact native path | §8 |
| — | Activation | **STAGED, not the current candidate**, with a conditioned leapfrog clause; gated on ONE real measurement — **t = 24 exactness of block-scaled FP4/MX accumulation on real silicon** (runnable now on B200/RTX 50-series; extend to B300/MI355X) — plus the C-15 external review (commissioned once, covering v4.1 and v4.2 jointly) | §10 |

**Why this is the superior consolidation (one paragraph).** The ASIC deep-dive proved the
moat is the combine + XOF freshness + exact-accumulation floor — **alphabet-independent**
— so going frontier-native costs ≤ ~1.2–1.3× of moat; the cryptanalysis proved the small
alphabet is cryptographically safe; the committed-object redesign proved Freivalds
soundness and determinism are format-blind given power-of-two scales. What none of those
documents individually resolved is *which* narrow object to pin. The consolidation
observes that the two candidate alphabets differ in exactly one load-bearing respect —
𝓜₁₅@S=4 buys 0.4 bits of entropy margin by *spending* the INT8 1-GEMM embedding, the
sub-2²⁴ envelope, and 7,281 of header range — and that everything v4.1 was demonstrably
stronger at (INT8-native availability today, machine-checked determinism maturity,
1-GEMM legacy compatibility, header envelope) is preserved *for free* by 𝓜₁₁@S=3,
because 48 ≤ 127. BMX4-C is therefore simultaneously: one native block-scaled GEMM on
FP4/MX silicon, one plain GEMM on FP8 silicon, one plain GEMM on INT8 silicon, and one
promotion-free pass on any proven-t=24 FP32-accumulate unit. Nobody slices. The frontier
tax (4–9× today) goes to ≈ 1×; the legacy tax goes to ≈ 1× (rate-relative only); the
verifier is unchanged; and the accumulator — the one real cliff — is bracketed by a
1-GEMM INT8 fallback instead of a 4-GEMM slice fallback, halving the worst-case ASIC
exposure the deep-dive quantified.

---

## 1. Hard requirements and the inheritance map (what does NOT change)

The four hard requirements are inviolate and are met as follows:

1. **MatMul is the core work.** The per-nonce unit is still one dense n×n exact integer
   matmul over seed-derived operands (marginal form under I1′: expand B̂ + `B̂·V` +
   combine + digest, §E.3/§K.2b); only the element *encoding* changes.
2. **Cheap O(n²) Freivalds verification UNCHANGED.** Same q = 2⁶¹−1, R = 3, sketch shape
   m = n/b (b = 4), digest `H(σ‖Ĉ)`, Fiat–Shamir rule, per-round error ≤ 2/q, total
   ≤ 2⁻¹⁸⁰; verification gets slightly *cheaper* (≈ 28 % fewer XOF SHA compressions).
   §3 restates why the proof is format-blind.
3. **Universal bit-exact determinism — no rounding, ever.** The no-rounding theorem
   (exact-int-on-float doc §2) plus power-of-two scales: every value on the committed
   path is an exactly representable integer at every step, on every conforming path;
   a device that would round is INELIGIBLE and fails closed (§4).
4. **Scaled-reward ladder, price-independent.** Datacenter > high-end consumer >
   M-class-pooled; cheap mining GPUs/CMP/SHA/FPGA excluded; §6. No market price is an
   input anywhere (§0.7-(4)); all ordering claims are measurement-gated hypotheses until
   the §10 gates run.

**Invariant core carried over byte-for-byte from v4.1** (nothing in this list migrates):
the verifier structure (`SketchFreivalds` algorithm and O(n²) cost), q = 2⁶¹−1, R = 3,
b = 4 / m = 1024 / 8 MiB payload at n = 4096, digest form and Fiat–Shamir rule, the
182-byte header, the seed-scoping rule (template-scoped A/U/V, nonce-fresh B/σ — I1′),
work-unit uniformity I8, the DoS-budget framework (§E.4), §L.4's capacity-gate
impossibility (format-blind, verified to bind *tighter* here — redesign §4.3), §O.2
pooling, the work-unit-neutrality theorem (§L.2.1), the C-13 fold *form*
`Ĉ = Σᵢⱼ 2^{w(i+j)}·S_ij mod q`, the verify+fallback dispatcher contract (`accel_v4.h`),
and price-independence (§0.7-(4)).

**What migrates (the fork surface)** is exactly the redesign doc §6 list, instantiated at
the §2 parameters: operand/projector derivation and domain tags, the consensus magnitude
constants, all golden vectors and C-1 adversarial vectors (regenerated at the new
boundaries), the one-time ASERT rescale to the measured new marginal unit, backend
kernels + self-tests, and the §S.2.2/§A.6 re-disclosures.

---

## 2. The BMX4-C committed object (normative parameters)

### 2.1 Decision 1 — the operand alphabet: 𝓜₁₁ at S = 3 (and why not 𝓜₁₅@S=4)

**Normative:** each operand element is a pair (μ, e-context): mantissa
`μ ∈ 𝓜₁₁ = {0, ±1, ±2, ±3, ±4, ±6}` — the exact-*integer* subset of FP4 E2M1
([OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf);
±5 is not an E2M1 value and never occurs; ±0.5/±1.5 are excluded to stay on the integer
grid) — and one shared scale `2^e, e ∈ {0..3}` per **32-element block along the
contraction dimension** (A: along columns; B: along rows; OCP block length L = 32, scale
format E8M0 restricted to codes 127..130). The dequantized committed operand is the exact
integer `Â[i,k] = μ_A[i,k]·2^{e_A(i,⌊k/32⌋)}`, `|Â| ≤ E_max = 6·2³ = 48`. The committed
product is the exact integer matrix `C̄ = Â·B̂`.

The two source documents pinned different alphabets under the same v4.2 banner
(cryptanalysis doc §7.5 flagged the discrepancy as a finding). Resolution, criterion by
criterion — the row set is exactly the three axes the mandate names (determinism
eligibility, hardness, frontier-nativeness) plus the two v4.1-strengths axes the
consolidation exists to preserve (availability today, envelope/maturity):

| Criterion | 𝓜₁₁ @ S=3, E_max=48 (**CHOSEN**) | 𝓜₁₅ @ S=4, E_max=192 (frontier doc) |
|---|---|---|
| Frontier-nativeness | 1 native block-scaled FP4 GEMM (𝓜₁₁ ⊂ E2M1 exactly; 2^e exact in E8M0 and in UE4M3 slots) — identical to 𝓜₁₅ | 1 native FP4 GEMM; sampler keeps 1 more nibble code (15/16 vs 11/16 acceptance) — the only frontier-side gain |
| Determinism eligibility | **Sub-2²⁴ envelope**: every marginal-unit stage < 2²³ at n ≤ 8192, base product < 2²⁴ at n = 4096 ⇒ proven-t=24 FP32-accumulate units are **eligible by bound, zero promotions** (redesign §4.4); t≈14 devices retain a 1-GEMM INT8 fallback | Base product 2²⁷·² ⇒ K′-blocked promotion always required; t≈14 ⇒ K′ = 0 ⇒ the 4-GEMM INT8 slice fallback (frontier doc §4.3) |
| Hardness | SAFE (cryptanalysis §7.2): min-entropy 3.46 (+0.06 scale) bits/elem, 5 nonzero magnitudes, {3,6} non-power-of-two mass 36.4 %, P(0) = 9.09 % — sits *at* the §7.3-c floor with all conditions met; ~9× above the BNN cliff, ~3 octaves above the table channel | SAFE with more margin (3.91 bits; closes even the single INT8 Strassen level). The margin is real but buys nothing any identified channel needs (every closure holds for both with ≥ 10²× slack) |
| Backwards compatibility (the v4.1 strength) | **E_max = 48 ≤ 127 ⇒ every INT8 part runs ONE s8 GEMM on pre-shifted operands** — H100 stays at its full 1,979 TOPS, TPU v6e/Gaudi/M5/RTX 30-40 unchanged in GEMM count | 192 > 127 ⇒ 2-slice ⇒ **4 s8 GEMMs**: H100 1,979 → ≈ 495 effective; today's entire honest miner base taxed 4× at fork time |
| ASIC worst case (the cliff) | If commodity FP4 proves t≈14, the commodity fallback is 1-GEMM INT8 (≈ 2× rate loss on B200: 7,702→3,927 [C]) ⇒ cliff ≈ residual × ~2 ≈ **3–5×** [M] | Same failure ⇒ commodity pays the 4× slice tax ⇒ cliff **6–14×** (ASIC deep-dive §0/§7 — "the one real cliff") |
| Header/verifier envelope | int32 ceiling n ≤ ⌊(2³¹−1)/2304⌋ = 932,067 ⇒ **full header range n ≤ 65,535 preserved**; full-C aliasing gap 2·2304n < 2²⁶ ≪ q | n_max tightens to 58,254 (a header-range parameter break) |
| Strassen | One level on the INT8 path only (48·2 = 96 ≤ 127), zero on FP4/FP8 paths; ≤ 12.5 %, difficulty-absorbed; §A.6 rewrite required either way | Zero levels everywhere (192·2 > 127) — the one hardening 𝓜₁₅ adds, worth ≤ 12.5 % on the legacy path only |

**Determination.** 𝓜₁₅'s two genuine advantages (0.4 bits of entropy margin; closing a
≤ 12.5 % legacy-only Strassen level) are luxuries; its costs (4× tax on the entire
present INT8 installed base, loss of eligibility-by-bound, doubled worst-case
accumulator-cliff exposure, header-range tightening) are structural. The tax-inversion
goal never required *punishing* legacy INT8 — the frontier wins the ladder on absolute
FP4 TOPS growth (Rubin-class 35–50 PF vendor-peak vs H100's 1,979 — roadmap §3.2), not
on handicapping H100s. **𝓜₁₁ @ S = 3 is pinned.** S remains the documented tax dial:
S = 3 is the largest scale range with E_max ≤ 127 (`6·2³ = 48`; even S = 4 with 𝓜₁₁
would keep 96 ≤ 127 but forfeits sub-2²⁴; S = 3 keeps both). 𝓜₁₅@S=4 stays on the shelf
as the **hardening reserve** (cryptanalysis §7.4): if the C-15 external review demands
entropy margin above the floor, it is the pre-analyzed fallback — but it is a *different
consensus object* (different sampler, bounds, golden vectors) and the choice is hereby
pinned **before** any golden vector is generated, as §7.5 required.

### 2.2 Decision 2 — the E2M1-native U/V co-change: ADOPTED (profile P-B)

**Normative:** `U (m×n)` and `V (n×m)` are drawn i.i.d. uniform over 𝓜₁₁, **scale-free**
(no scale planes on projectors), template-scoped exactly as in v4.1 (§A.2/I1′), with new
domain tags (§2.3).

Rationale, consolidating the ASIC deep-dive's central side-finding (§5 cross-check ii and
§8-4): with balanced-s8 U/V (profile P-A), the *marginal* sketch unit is **not**
frontier-native — V's magnitudes up to 125 are not E4M3/E2M1-exact, so `S2: Q = B̂·V`
cannot run on the FP4/FP8 pipe as one GEMM, and on FP-only parts (Trainium3, FP4-heavy
NVIDIA) it re-imports the very Ozaki slice tax v4.2 exists to remove. Under 𝓜₁₁ U/V:

- **S2 becomes one block-scaled FP4-rate GEMM** on MX hardware (B̂ native E2M1+E8M0, V
  mantissa-only at scale 2⁰), one plain s8 GEMM on INT8 hardware (both operands fit s8),
  one plain FP8 GEMM on E4M3 hardware — 1 GEMM everywhere.
- **P = U·Â and Q = B̂·V shrink to |·| ≤ n·6·48 = 288n** (≈ 2²⁰·² at n = 4096, ≈ 2²¹·² at
  8192) — the input to the §5 limb re-pinning, and the reason the whole marginal
  pipeline fits under 2²³.
- **Soundness is unaffected**: the Freivalds proof (redesign §2, P1–P3) never uses the
  U/V distribution — the Schwartz–Zippel test lives over the F_q challenges x, y, which
  remain Fiat–Shamir/nonce-fresh. What U/V must supply is full rank m (work-binding of
  the sketch), and i.i.d. 11-symbol m×n matrices are rank-m except with probability
  2^−Ω(n) ([Bourgain–Vu–Wood](https://arxiv.org/abs/0905.0461),
  [Tikhomirov](https://arxiv.org/abs/1812.09016)) — the same argument as I2.
- **The new attack surface is already adjudicated**: the cryptanalysis doc analyzed
  exactly this configuration (𝓜-valued template-scoped V) and closed the
  four-Russians/mailman/table family at ≥ 30–100× on-silicon and ≥ 10²× structurally
  (its §2), with the opening condition (≤ ~1.5 effective symbols) three octaves below
  |𝓜| = 11. Condition inherited: the C-15 external review must name the small-alphabet
  batch-algebra family verbatim (§10, condition R-3).

The deferred item in the frontier doc (§4.5 "optional co-change … deferred") is hereby
resolved ADOPTED; the redesign doc's F\* row already assumed it, and the ASIC deep-dive
quantified P-A as *worse than s8 for the commodity GPU* (its §5 table: S2 doubles on the
INT8 pipe) — i.e. shipping v4.2 without the co-change would fail the design's own goal
on the very unit difficulty prices.

### 2.3 Derivation and sampling (consensus-normative)

Seed scoping is v4.1's, verbatim (template hash binds everything but the nonce; B and σ
nonce-fresh), with v4.2 domain tags:

```
seed_A = SHA256("BTX_MATMUL_SEED_V42"     || template_hash    || 0x41)   # TEMPLATE
seed_B = SHA256("BTX_MATMUL_SEED_V42"     || full_header_hash || 0x42)   # NONCE-fresh
seed_U = SHA256("BTX_MATMUL_V42_SKETCH_U" || template_hash)              # TEMPLATE
seed_V = SHA256("BTX_MATMUL_V42_SKETCH_V" || template_hash)              # TEMPLATE
sigma  = SHA256d(header)                                                 # NONCE-fresh
```

- **Mantissa plane** (per operand, and for U/V): wide SHA-256 counter-mode XOF (C-12
  discipline, unchanged primitive), consumed as **one 4-bit nibble per element** in
  stream order; a pinned bijection maps 11 of the 16 nibble codes onto 𝓜₁₁ and rejects
  the other 5 (acceptance 11/16 ≈ 68.75 %; ≈ 5.82 XOF bits/element). The E2M1-hole rule
  is structural: no code maps to ±5, ±0.5, ±1.5, or −0.
- **Scale plane** (operands only; U/V have none): 2 bits per 32-element block, consumed
  from the same keystream, mapping directly to e ∈ {0,1,2,3} (rejection-free). n²/32
  scales per operand; each operand's scale plane derives from that operand's own seed —
  B̂'s scale plane is nonce-fresh with B̂ (redesign condition #6: **no template-scoped
  structure on B's planes**, restated normative).
- **XOF volume**: ≈ 5.88 bits/element total ⇒ per-nonce expand-B ≈ 385 k SHA
  compressions at n = 4096, ~28 % below the s8 object's 535 k — the SHA freshness floor
  survives (it is an anti-amortization floor, not a cost floor — ASIC doc §4.4) while
  the §K.2a-WT tensor-majority requirement gets easier.

### 2.4 Magnitude bounds (all re-derived; the numbers every gate tests against)

| Stage | Bound (general) | n = 4096 | n = 8192 | v4.1 s8 @ 4096 |
|---|---|---|---|---|
| Dequantized operand `Â` | M_max·2^S = 48 | 48 (**≤ 127: s8-native**) | 48 | 125 |
| Base product `C̄ = Â·B̂` (full-C / CPU reference) | n·E_max² = 2304n | 9,437,184 ≈ 2²³·¹⁷ **< 2²⁴** | 1.89×10⁷ ≈ 2²⁴·¹⁷ | 6.4×10⁷ ≈ 2²⁵·⁹ |
| Projections `P = U·Â`, `Q = B̂·V` | n·6·48 = 288n | 1,179,648 ≈ 2²⁰·¹⁷ | 2,359,296 ≈ 2²¹·¹⁷ | 6.4×10⁷ |
| Limb-pair GEMM `S_ij` (base-2⁶ digits, §5) | n·32² = 1024n | 4,194,304 = **2²²** | 2²³ | exactly 2²⁴ |
| In-block mantissa sum (L = 32) | 32·36 = 1152 | < 2¹¹ | < 2¹¹ | n/a |
| int32 ceiling from the base product | n ≤ ⌊(2³¹−1)/2304⌋ | **932,067** (header 65,535 preserved) | — | 137,438 |
| Full-C aliasing gap vs q | 2·2304n | < 2²⁵ ≪ q | < 2²⁶ ≪ q | < 2³² ≪ q |

Two consequences worth stating once: (i) the **marginal unit** (the thing difficulty
prices — P/Q and the limb pairs) is bounded by 2²³ at both production dimensions, and by
2²² at mainnet n = 4096; (ii) the **base product** is < 2²⁴ at n = 4096 (zero-promotion
eligibility by bound at t = 24) and 2²⁴·¹⁷ at n = 8192 (≤ 1 promotion per output on a
t = 24 unit, K′ = 7,264). q = 2⁶¹−1 and the exact-int32 discipline cover everything with
≈ 7× more headroom than today; no field change, no round-count change.

---

## 3. The verifier — UNCHANGED (restated, not re-derived)

The verifier never touches FP and never sees the compute path. From the header seeds it
re-derives the (μ, e) streams, forms `Â = μ·2^e` and `B̂` as integers via exact shifts,
and runs the identical machinery: recompute `H(σ‖Ĉ)` over the 8 MiB payload; for
t = 1..R = 3 derive `(xₜ, yₜ)` from `H(σ‖H(Ĉ))` and check

```
xₜᵀ · Ĉ · yₜ  ==  (Uᵀxₜ)ᵀ · Â · (B̂ · (V·yₜ))     over F_q, q = 2⁶¹−1
```

— O(n²), per-round error ≤ 2/q (bilinear Schwartz–Zippel, format-blind: redesign §2
P1–P3), total ≤ 2⁻¹⁸⁰; full-C profile ≤ 2⁻¹⁸³. Per-MAC cost is one 64-bit Mersenne
multiply-fold with a ≤ 48-magnitude integer — identical constant to today. Operand
regeneration is ~28 % cheaper in SHA compressions (§2.3), easing the one §D.4 line item
flagged for re-benchmark (B2d). DoS budgets (§E.4), payload plumbing, node tiers, SPV —
all unchanged. **The verifier is compute-path-agnostic by construction (§D.3): it would
pass a correct Ĉ from an abacus.** This is the load-bearing fact of the entire v4.2
program: one committed object, many native evaluation paths, zero verifier surface.

What Freivalds does not certify is inherited honestly and unchanged: the §E.3
work-binding gap (soundness binds correctness of Ĉ; difficulty prices the marginal unit)
and the I1′ relaxation's NEEDS-EXTERNAL-REVIEW status (C-15) — §10.

---

## 4. Determinism and the generalized eligibility gate (C-1′)

### 4.1 The invariant (normative for v4.2; generalizes C-1 verbatim in spirit)

> **Exact-integer-arithmetic eligibility (C-1′).** Every backend MUST compute every
> operation on the committed path — scale application, slice/mantissa products,
> every accumulation (base GEMM, `B̂·V`, each limb-pair GEMM), extraction, promotion —
> such that every intermediate value is an exactly held integer, whether the unit is
> nominally integer or floating point. A device is eligible for a stage iff the stage's
> §2.4 consensus magnitude bound is ≤ the device's **proven** exact-integer capacity for
> that datapath (2^t for an FP-mantissa accumulator; 2^(w−1) for a w-bit
> two's-complement accumulator), or the backend imposes a blocked extract-and-promote
> schedule (K′) that keeps every partial sum inside it. A device that would round
> anywhere on the committed path is INELIGIBLE for that path and MUST fail the
> determinism self-test loudly; the verify+fallback dispatcher (`accel_v4.h`,
> contract unchanged) re-verifies every device result, so a mis-rounding device can only
> lose throughput, never split the chain.

Datasheet claims are never trusted: nominal "FP32 accumulation" is a register-format
claim, not an exactness claim — the standing precedent is Hopper's FP8 path retaining
only ~14 mantissa bits (a 22-bit fixed-point datapath:
[DeepSeek-V3 §3.3.2](https://arxiv.org/pdf/2412.19437),
[SemiAnalysis tensor-core evolution](https://newsletter.semianalysis.com/p/nvidia-tensor-core-evolution-from-volta-to-blackwell),
[DeepSeek-V3 issue #197](https://github.com/deepseek-ai/DeepSeek-V3/issues/197)).
Public evidence that Blackwell improved FP8/FP4 accumulation is suggestive but is **not**
an exactness proof at the 2^t boundaries
([arXiv:2512.02189](https://arxiv.org/abs/2512.02189),
[vLLM FP8 blog, 2026](https://vllm.ai/blog/2026-04-22-fp8-kvcache)) — hence the §10
gating measurement.

### 4.2 Exactness envelopes per native path (the K′ table)

Per-MAC dequantized product bound on the block-scaled path: E_max² = 2304 (operand GEMM)
and 48·6 = 288 (the S2 projection). `K′ = ⌊2^t / bound⌋` floored to a multiple of 32:

| Path | Per-MAC bound | K′ at proven t = 24 | K′ at t ≈ 14 | Verdict |
|---|---|---|---|---|
| Block-scaled FP4/MX, operand GEMM (full-C/reference) | 2304 | 7,264 → **zero promotions at n = 4096** (7,264 ≥ 4,096); one promotion at n = 8192 | 7 → **0** | t = 24 REQUIRED for the native hardware-scaled path |
| Block-scaled FP4/MX, S2 `B̂·V` (the marginal stage) | 288 | 58,254 → zero promotions at every header n | 56 → 32 (1 MX block) — technically alive, throughput-hostile | t = 24 for native rate; t≈14 → fallback |
| FP8 E4M3 scale-fold (TPU v7, Trn2; values ≤ 48 exact) | 2304 / 288 | as above | as above | t = 24 required (Hopper's t≈14 FP8 fails → its INT8 path) |
| FP16/BF16 fold (M-class simdgroup FP32-accum, BF16 systolic) | 2304 / 288 | as above (t = 24) | — | eligible with proven t |
| INT8 s8×s8→s32 (IMMA/MFMA/TensorOps/MXU-int32) | operands ≤ 48 ⊂ s8 | true int32: **whole pipeline in one pass, no K′** (all §2.4 bounds < 2³¹) | n/a | the C-1 gate as today; **1 GEMM — no slicing** |
| Limb-pair GEMMs on FP8 (FP-only parts, §5) | 64 (base-2⁴ digits) | 2¹⁸ | **256** — works even at t≈14 (DeepSeek cadence) | the one stage that tolerates t≈14 |

K′, block ordering, and promotion cadence remain **miner-local free choices** —
exactness, not schedule, delivers bit-identity (the machine-checked
schedule-independence of the Ozaki reference carries over), so committed bytes are
schedule-independent by construction.

### 4.3 The eligibility self-test (regenerated adversarial vectors — normative)

The existing HM-A/HM-B/HM-C vectors force accumulations in (2²⁴, 2³¹) that BMX4-C
operands **cannot produce**; replayed verbatim they would silently stop testing anything
(redesign §3 consequence (b)). The v4.2 set MUST cover, per backend and per claimed
path, with analytic expected values and cross-path byte-equality:

1. **t-discrimination vectors**: rail operands (all-blocks-e=3, extreme mantissas)
   driving base-product partial sums in **odd steps** across 2¹⁴ and up to exactly
   2304n (2²³·¹⁷ at n = 4096) — a t≈14 device must round deterministically; a t = 24
   device must be bit-exact with zero promotions.
2. **Boundary-pin vectors**: partial sums at exactly the claimed 2^t; limb-pair sums at
   exactly 2²² (n = 4096) and 2²³ (n = 8192); and, for any miner-local base-2⁷ limb
   variant, at exactly 2²⁴ (the FP32-boundary-exact case).
3. **Scale-exactness vectors**: mixed-exponent K-runs; E8M0 application as a pure
   exponent add (no significand bit changes) for all (μ, e); 2^e hosted in UE4M3 scale
   slots (consumer Blackwell) verified exact.
4. **Alphabet-hole vectors**: no slice/mantissa value of ±5 (or any non-𝓜₁₁ value) may
   ever appear anywhere on the committed path; sampler rejection verified against pinned
   streams.
5. **Sign-extreme / promotion-cadence sweeps**: byte-identity across
   K′ ∈ {32, 256, spec-pinned, unbounded-at-t=24} and across block orders.

Rules carried over: a log that never entered the regime is **not** a PASS
(`verify-backend.sh` fails if the vectors did not run); backends become mining-capable
only after bit-for-bit replay (M-2/B2a discipline, now including FP4/FP8-path devices);
the CPU integer reference remains the sole source of truth.

### 4.4 The fallback ladder (graceful, fail-closed, bounded)

A device failing a native-path envelope falls to the next path it can prove, never off
the network:

| Fails | Falls to | GEMM-count tax | Rate consequence [illustrative, measurement-gated] |
|---|---|---|---|
| FP4 block-scaled t = 24 unproven | its FP8 fold (needs t ≥ 17 for K′ ≥ 32; t = 24 preferred) | 1× | FP8-vs-FP4 rate gap (~2× on B200-class [C]) |
| FP8 fold too (t ≈ 14, Hopper-style) | **INT8 1-GEMM on pre-shifted operands** (dequant shift is O(n²) int work) | **1×** | its own full INT8 rate — H100 ≈ 1,979 TOPS, *unchanged from today* |
| No INT8 tensor unit (Trainium-class) and FP t unproven | mantissa-plane K′ = 32 extraction (in-block sums ≤ 1152 < 2¹¹, exact even at t≈14), scales applied at promotion | 1× GEMM, heavy extraction overhead | throughput-poor but correct; or vector-engine/host path |
| Everything (pre-tensor / CMP / SHA silicon) | CPU reference via dispatcher | — | excluded from competitive mining, as today |

This is the consolidation's headline structural win over the naive-BMX4 fallback: under
𝓜₁₁@S=3 the backwards-compat path is a **single** s8 GEMM (the mandate's "bounded ~4×
tax" was an 𝓜₁₅ artifact — here it improves to ≈ 1× in GEMM count, with only the
relative-rate steepening the ladder intends). The 4× slice machinery
(`DecomposeSlicePlanes`, remainder-top rule) remains in the toolbox for hypothetical
future devices whose only exact pipe is narrower than the committed width — that is the
Ozaki bridge in the other direction, miner-local, verifier-invisible.

---

## 5. The combine (C-13′): the moat, re-pinned

The combine `Ĉ = P·Q mod q` is **~80 % of the marginal unit's tensor MACs and is 100 %
alphabet-independent** (ASIC deep-dive §2/§4.3) — it multiplies int-magnitude P/Q
entries, not committed operands. It is simultaneously the workload's bottleneck and its
ASIC-resistance floor (the dedicated wide-integer mod-q datapath is the *only* real
bespoke lever, the same 2–4× stage factor it already had against s8). Determination:

1. **Limb-tensor form retained; NOT made 4-bit-native.** Deliberate: (a) exact
   wide-integer reduction is the invariant a bespoke chip cannot escape and commodity
   silicon executes well on its INT8 pipes; (b) an E2M1-digit combine would cost
   ~64 pair-GEMMs at FP4 rate ≈ 32 FP8-equivalents vs 16 s8 GEMMs — strictly worse on
   every part with an INT8 pipe. The combine runs on whatever exact pipe the device
   proves: s8 limbs on INT8 units, E4M3 limbs on FP-only units, ALU-direct mod-q where
   that measures faster (miner-local, §K.2a-WT-measured).
2. **Reference decomposition re-pinned to the new magnitudes** (P/Q ≤ 288n, §2.4):
   **4 balanced base-2⁶ digits in [−32, 31] with the remainder-top rule** (top digit
   carries the exact remainder, ∈ [−32, +32]) — total and unique for |x| < 64⁴/2 = 2²³,
   covering 288n up to n = 29,127 and the whole 4096–8192 window with ~3.5× margin.
   The **asymmetric-extreme discipline** (the n ≤ 8522 correction pattern —
   `src/matmul/matmul_v4.cpp::CheckCombineLimbBound`) is re-applied and CORRECTED for
   the new base: a *pure* balanced base-2⁶ scheme covers positives only to
   31·(64⁴−1)/63 = **8,255,455** (the redesign doc's 8,255,527 is off by 72), i.e.
   n ≤ **28,664**, not 28,665 — moot under the remainder-top rule, which the reference
   adopts precisely so no asymmetric-coverage caveat survives into v4.2. The
   `CheckCombineLimbBound` successor pins `288·n ≤ 2²³ − 1`.
3. **Every limb-pair GEMM bound n·32² = 1024n ≤ 2²³ at n ≤ 8192** — sub-2²⁴, so the
   combine itself is runnable on any proven-t=24 unit, on any true-int32 unit (digits
   ⊂ s8), and — via balanced base-2⁴ digit re-slicing ([−8,7] ⊂ E4M3, 6 digits, 36
   pair-GEMMs, per-MAC ≤ 64 ⇒ K′ = 256 even at t≈14) — on FP8-only silicon at a bounded
   ~2–2.5× stage tax [M]. 16 pair-GEMMs take the §K.2b stacked m × Q·m × n shape
   unchanged.
4. **Fold unchanged in form**: `Ĉ = Σᵢⱼ 2^{6(i+j)}·S_ij mod q`, O(m²) int-ALU, weights
   `2^{6(i+j)} mod q` precomputed; byte-identical to the direct mod-q combine; limb base
   is miner-local in effect but the CPU reference pins base-2⁶ (C-13 discipline) and the
   golden vectors pin the fold bytes.
5. **Honest disclosure carried into the v4.2 §S.2.2 rewrite**: the combine is where the
   bespoke edge lives (2–4× stage lever, format-independent); any future commodity-side
   combine improvement *narrows* the ASIC residual and is welcome; nothing about BMX4-C
   makes the combine worse.

---

## 6. Per-tier hardware story (the ladder, with each tier's tax)

GEMM-count taxes are exact arithmetic (width-ratio law); rate figures are illustrative
cited peaks/measurements, **never load-bearing** — ordering ships only after the §10
measurements (two prior model-based orderings were falsified; §K.2b posture).

| Tier | Devices | Native path under BMX4-C | GEMMs | Tax vs own frontier rate | Illustrative rate |
|---|---|---|---|---|---|
| Frontier DC FP4 | B200/B300/GB300 (`tcgen05` `mxf4`/`mxf8f6f4`, UE8M0), Rubin ⚠, MI355X (CDNA4 OCP MX), Trainium3 (Matmul-MX) | native block-scaled FP4, zero promotions at t = 24 | **1** | **≈ 1× — the 4–9× inversion delivered** | B200 7,702 TOPS measured FP4 [C]; B300 15 PF class; MI355X 10.1 PF; Trn3 ≈ 4× BF16 |
| Frontier DC FP8-only | TPU v7 (no FP4), Trainium2 | scale-fold → 1 plain FP8 GEMM (t = 24 to prove) | 1 | FP8-vs-FP4 gap only (its own silicon's choice) | TPU v7 4,614 TF FP8 |
| INT8 DC legacy | H100/H200, TPU v5e/v6e, Gaudi 3 | pre-shift → **1 s8 GEMM**, true int32 | **1** | **≈ 0 — unchanged from today** (the 𝓜₁₁ dividend) | H100 1,979 TOPS |
| Consumer frontier | RTX 5090/5080 (consumer Blackwell) | FP4 with 2^e in UE4M3 scale slots (exact embed) or INT8 | 1 | ≈ 1× | 5090 ~1,676 FP4 / 838 INT8 [C] |
| Consumer legacy | RTX 40/30 | INT8 1-GEMM (Ada may prove FP8-fold) | 1 | ≈ 0 | 4090 660, 3090 285 |
| M-class (pooled) | M5-family Neural Accelerators (INT8→INT32); pre-M5 (M1-class) int-ALU tile path | INT8 1-GEMM; **pre-M5 general-ALU path preserved** (values ≤ 48 trivially in-range) | 1 | ≈ 0 | M5 Max ~110–140; pooled per §O.2 |
| Excluded | CMP/pre-tensor, SHA ASICs, FPGAs | none competitive | — | — | FPGAs ≥ 13× behind (typically 15–30× on the marginal unit — ASIC doc §6); table/BNN channels closed (cryptanalysis §2/§5) |

**Ladder reading:** Rubin-class ≫ B300 > B200 > MI355X/Trn3 > TPU v7 > H100 ≈ today >
5090-FP4 > 40/30-series > M-class-pooled. The ladder **steepens toward the frontier
purely through absolute frontier throughput** (FP4 pipes at ~2× INT8 on the same silicon
and doubling generationally), with no punitive tax anywhere — every current miner keeps
approximately current throughput at fork time, which is also what makes the one-time
ASERT rescale (B2b analogue) a clean single-population calibration rather than a
heterogeneous 4×-shock. Availability today: the object is mineable **at fork time** on
the entire existing INT8 installed base (unchanged kernels except sampler + shift +
limb-rebase), while being native to silicon this repo has never run on — that is the
"works on TODAY's hardware while native to the frontier" requirement, met by
construction rather than by transition period.

---

## 7. Why BMX4-C is superior — the best-of-both table

| Dimension | v4.1 s8 only (status quo) | Naive BMX4 only (𝓜₁₅@S=4, frontier doc as-written) | **BMX4-C (this design)** |
|---|---|---|---|
| Frontier tax (B300/Rubin/Trn3/MI355X) | 4–9× Ozaki slice tax, growing each generation | ≈ 1× (committed object), but marginal unit NOT native (s8 U/V: S2 taxes the INT8 pipe 2×) | **≈ 1× including the marginal unit** (E2M1 U/V) |
| Legacy INT8 tax (H100, TPU v6e, 30/40-series, M-class) | 0 | **4×** (2-slice, H100 1,979→≈495) | **≈ 0** (1 s8 GEMM at full rate) |
| ASIC residual (deep-dive model) | 1.4–2.4× realistic / ≤ ~3× | 1.5–2.5× / ≤ ~4×; **cliff 6–14×** if commodity t≈14 | 1.5–2.5× / ≤ ~4× [M]; **cliff halved to ~3–5×** (1-GEMM INT8 fallback) |
| Determinism maturity | machine-checked, shipped | new envelope, sub-2²⁴ lost, K′ always required | **sub-2²⁴ marginal pipeline; eligible-by-bound at t = 24 (zero promotions at n = 4096)**; inherits the machine-checked no-rounding framework |
| Availability | Trainium excluded; frontier taxed | frontier native; today's base taxed 4× at fork | **everyone, 1 GEMM each, at fork time** |
| Verifier | O(n²), unchanged | unchanged | **unchanged, ~28 % cheaper regeneration** |
| Hardness / entropy | 7.97 b/elem | 3.91 b/elem, extra margin | 3.52 b/elem — **SAFE with all floor conditions met** (cryptanalysis §7.2/§7.3); 𝓜₁₅ held as hardening reserve |
| Header envelope | n ≤ 65,535 | n_max 58,254 (parameter break) | **n ≤ 65,535 preserved** |
| Longevity | decouples from the frontier over 2–3 generations (roadmap §3.2 — the reason v4.2 exists) | native to *this* frontier format | **format-agnostic profile machinery (§8): native to this frontier AND re-targetable to the next without touching the verifier** |
| SHA freshness floor | 535 k comp./nonce | 290 k | 385 k — floor intact, wall-time share smaller |
| Fork cost | none | full hard fork | full hard fork (identical surface to naive BMX4 — the superiority is free at equal fork cost) |

Against v4.1-only: BMX4-C removes the growing 4–9× frontier tax, admits Trainium-class
silicon for the first time, and shrinks the verifier's own cost — at the price of one
hard fork and a bounded ≤ ~1.3× ASIC-residual widening. Against naive-BMX4-only: BMX4-C
keeps every v4.1 strength (INT8 1-GEMM availability, sub-2²⁴ eligibility, header range,
determinism-envelope maturity), makes the *marginal* unit — not just the committed
object — frontier-native, and halves the worst-case accumulator-cliff exposure, at zero
additional cost anywhere. It strictly dominates naive BMX4 and dominates v4.1 everywhere
except entropy-per-element (safe, per the final cryptanalysis) and the ASIC residual
delta (bounded ≤ ~1.3×, disclosed).

---

## 8. The format-agnostic multi-native-path architecture (the time-resistance core)

This section formalizes why the design withstands hardware evolution *by construction*
rather than by forecast.

### 8.1 The split: invariant verification core vs versioned encoding profile

Consensus is factored into two layers with a one-way dependency:

- **The invariant core (never changes across formats):** the committed object is a
  canonical **exact-integer** matrix product `C̄ = Â·B̂` committed via the sketch
  `Ĉ = U·C̄·V ∈ F_q^{m×m}`, digest `H(σ‖Ĉ)`, verified by O(n²) Freivalds over
  q = 2⁶¹−1 with Fiat–Shamir challenges from `H(σ‖H(Ĉ))`. The soundness proof consumes
  exactly three properties — canonical F_q object, bilinear identity, nonce-fresh
  challenges (redesign §2 P1–P3) — none of which mention the operand encoding. The core
  also fixes: R, b/m, payload form, header, seed-scoping (I1′), I2–I8, DoS budgets,
  §L.4 closure, pooling, price-independence.
- **The encoding profile (a versioned consensus parameter block):** everything that
  defines how header seeds become exact integer operands — the mantissa alphabet 𝓜, the
  scale structure (L, S, E8M0 discipline), the U/V alphabet, the sampler bijection and
  rejection rule, the domain tags, the derived magnitude constants (§2.4), and the
  golden vectors. v4.1 pins profile **ENC-S8** (balanced s8, no scales); v4.2 pins
  profile **ENC-BMX4C** (§2). A profile change is a hard fork — but it is a fork of
  *parameters and vectors into the same machine*, never of the machine.

### 8.2 Multi-native-path evaluation (why every hardware generation gets a 1-GEMM life)

Because the committed object is exact integers and the verifier is compute-path-agnostic
(§3), **any** evaluation strategy that lands byte-identical committed integers is
consensus-legal and verifier-invisible. The eligible strategies form an open set,
governed miner-side only by C-1′ (§4):

- INT8 IMMA/MFMA/TensorOps/int32-MXU (pre-shift, 1 GEMM under ENC-BMX4C);
- block-scaled FP4/FP6/FP8 microscaling with the K′ exactness discipline;
- plain FP8/FP16/BF16 scale-fold embeddings;
- Ozaki slice decomposition for any pipe narrower than the committed width (k² GEMMs —
  the tax direction the width-ratio law assigns);
- limb re-basing of the combine to any proven accumulator width (L-1 generalization);
- int-ALU/VPU direct paths.

The **embedding rule** makes the future legible: a hardware format hosts the profile at
1 GEMM iff its provable exact-integer set (elements × scale mechanism) contains
`𝓜·2^{0..S}`; otherwise it pays `⌈w_needed/w_native⌉²` (width-ratio law). ENC-BMX4C was
chosen as the **greatest-common-divisor alphabet** of every shipping and announced exact
pipe (E2M1 ⊂ E4M3 ⊂ FP16/BF16-int ⊂ s8 ⊂ int32), so at pin time *nobody* slices — the
tax falls only on hypothetical future hardware *narrower* than E2M1, which is below the
§8.3 floor and therefore a regime the chain refuses to follow.

### 8.3 The floor any future profile must satisfy (consolidated, normative)

A future encoding profile (an ENC-vNext fork) MUST satisfy, before golden vectors:

1. **Scales:** powers of two only (E8M0-class), consensus-pinned small exponent range;
   fractional (E4M3-valued) block scales and FP32 tensor scales are permanently excluded
   from committed objects (determinism-hostile: unprovable dequant exactness, K′
   collapse, single-vendor — frontier doc §3a, redesign §3).
2. **Alphabet floor** (cryptanalysis §7.3-c, sharpened): min-entropy ≥ ~3.4 bits/element;
   ≥ 4 distinct nonzero magnitudes; P(0) ≤ 10 %; **≥ 2 non-power-of-two magnitudes at
   ≥ ~25 % combined mass** (the anti-shift-only clause — {3, 6} at 36.4 % in 𝓜₁₁);
   sign/ternary objects categorically rejected (the BNN/table cliff at ≤ ~1.5 effective
   symbols).
3. **Exactness envelope:** all committed-path bounds derivable and pinned (a §2.4
   analogue); marginal pipeline ≤ the widest broadly-proven exact accumulator class;
   C-1′ vectors regenerated at the new boundaries (a set that never enters the new
   regime certifies nothing).
4. **Verifier untouched:** q, R, sketch shape, digest, Fiat–Shamir, O(n²) budget —
   re-benched ≤ current budget.
5. **Measurement + review gates re-run:** §K.2a-WT/§K.2b analogues on the profile's
   reference silicon; C-15-class external review of any new algebraic surface; §S.2.2
   ASIC re-disclosure.

**Why this is future-proof by construction:** the frontier can move its formats; the
verifier never changes; each hardware class computes the same committed integers on its
own strongest exact path; the conversion tax always lands on whoever is furthest from
the canonical form — and the profile mechanism lets governance re-center the canonical
form on the frontier *when justified by shipped silicon* (the G-1 trigger), at
parameters-and-vectors fork cost, never at redesign cost. The governance mechanics,
trigger thresholds, capture/threat analysis, and multi-profile transition safety are the
companion longevity doc's scope (`doc/btx-matmul-v4.2-longevity-threat-model.md`) and
are deliberately not duplicated here.

---

## 9. Hardness, ASIC/FPGA, and gate dispositions (consolidated verdicts)

Inherited verdicts, restated with what BMX4-C changes (nothing is re-derived here; the
two FINAL companion analyses are adopted as-is with the 𝓜₁₁/P-B instantiation both
already cover):

| Surface | Verdict under BMX4-C | Source + delta |
|---|---|---|
| Freivalds soundness | Preserved exactly (≤ 2/q per round; format-blind) | redesign §2; no delta |
| I1/I1′–I8 invariants | All survive; I1′ retains its NEEDS-EXTERNAL-REVIEW status (C-15), scope extended to small-alphabet batch algebra and 𝓜-valued V | redesign §4.1; cryptanalysis §7.3-a |
| Small-alphabet shortcuts | SAFE: tables/four-Russians/mailman ≥ 10²× losers (opening condition ≤ ~1.5 effective symbols); BNN cliff ~9×/18–27× below; 2:4 sparsity impossible by counting; zero-skip ≤ 9.1 % bespoke-only; combined worst case ≈ 0 % frontier path, ≤ 12.5 % INT8 path (one Strassen level, §A.6 rewrite required), ≤ ~20 % bespoke — difficulty-absorbed | cryptanalysis §0/§7 verbatim (it analyzed 𝓜₁₁ as primary) |
| ASIC residual | ≈ 1.5–2.5× realistic / ≤ ~4× worst [M]; delta vs s8 ≤ ~1.3× because commodity FP4 already ships the BMX4 multiplier; the combine (~80 %, alphabet-independent) is the bespoke lever either way; XOF is a freshness floor, not a cost floor (< 0.1 % ASIC energy); no memory wall (AI ≈ 2,048 ops/byte) | ASIC deep-dive §0/§7–§8; **delta: the t≈14 cliff shrinks from 6–14× to ≈ 3–5×** [M] because the commodity fallback is 1-GEMM INT8 (§2.1) — to be re-disclosed in the v4.2 §S.2.2 rewrite |
| FPGA | ≥ 13× behind DC (typically 15–30× on the marginal unit), ~3–6× behind consumer FP4, worse J/op, even granting the maximum 4-bit LUT dividend | ASIC deep-dive §6; no delta |
| Capacity/bandwidth gate | Impossible, closed, format-independent; BMX4-C moves *further* from any gate (operands pack ~n²/1.36 bytes… mantissa nibbles + scale plane ≈ 0.53 n² bytes; AI_opt doubles) | §L.4 + redesign §4.3; no delta |
| Rent-and-dump / pooling / floor economics | Unchanged mechanisms (§S.4, §O.2, work-unit-neutrality §L.2.1); ρ re-measured on FP4 rental centrals at activation (disclosure, never a parameter) | spec §S.4/§L.2.1; calibration-only delta |

---

## 10. Migration & activation plan, and the staged-vs-current recommendation

### 10.1 Sequencing (normative recommendation)

1. **Now — v4.1 ENC-S8 remains the activation candidate.** Its own gates (B2g batched
   GO/NO-GO on real H100/B200/5090; B2a golden vectors; B2b ASERT rescale; B4/C-15
   review) are the critical path. Nothing in this document blocks or reorders them.
2. **Now, in parallel — run the one v4.2-gating measurement (M-t24)**: the §4.3
   t-discrimination and boundary vectors on real block-scaled silicon —
   **B200 and RTX 5090-class are rentable/buyable today; extend to B300, MI355X, and
   Trainium3 (NKI) as access permits**. Prediction registered by the ASIC deep-dive:
   passes on CDNA4/Trn3 (architected FP32 accumulate), genuinely uncertain on Blackwell
   TMEM (Hopper precedent). This measurement decides (a) native-path eligibility,
   (b) which side of the ASIC-residual band applies, (c) whether the FP8-fold tier
   exists. It is cheap (a kernel + vectors, no consensus code) and is THE long-lead
   item.
3. **Now, once — commission the C-15 external adversarial review covering v4.1 and
   v4.2 jointly** (the I1′ relaxation is common to both; the v4.2 increment is the
   small-alphabet batch-algebra scope of cryptanalysis §7.3-a and the 𝓜-valued U/V).
   One review, two objects — cheaper and more coherent than sequential reviews.
4. **Bridge (zero consensus risk):** the v4.1 exact-int-on-float Ozaki path lets
   FP-only/frontier silicon mine ENC-S8 at (FP TOPS)/k² meanwhile — real, taxed
   participation that both relieves pressure and produces the FP-silicon measurement
   infrastructure v4.2 needs.
5. **v4.2 ENC-BMX4C activation trigger — BOTH of:**
   (a) the roadmap **G-1 decoupling trigger confirmed on shipped silicon** (B300's INT8
   cut and Rubin's FP4/FP8-only doubling are most of the way there — confirm on silicon
   per R-1, not launch slides); and
   (b) the **measured GO/NO-GO passes**: M-t24 on ≥ 2 independent vendors' frontier
   parts; §K.2a-WT marginal wall-time tensor-majority at Q ≥ 32 on a real FP4 part
   (the model predicts the combine at ~70–80 % — measure, don't trust); cross-vendor
   golden vectors (B2a analogue incl. FP4/FP8 devices); C-15 review closed; ASERT
   rescale computed from the measured marginal unit on the rational path.
6. **Conditioned leapfrog clause (explicit, honest):** if M-t24 and the joint C-15
   review complete **before** v4.1's own activation gates clear, governance SHOULD
   consider activating v4.2 ENC-BMX4C directly as the first fork — one fork instead of
   two, at no cost to the INT8 installed base (which mines ENC-BMX4C at 1 GEMM,
   ≈ unchanged throughput, §6). The leapfrog is *only* available because of the §2.1
   alphabet decision; it MUST NOT be taken on unmeasured FP-path assumptions — if the
   FP-silicon wall-time split (5b) is still open, ship v4.1 and stage v4.2.

### 10.2 Recommendation, stated plainly

**STAGED: hold BMX4-C as the parameter-frozen, shelf-ready v4.2; do not make it the
current activation candidate today.** The single gating measurement is **M-t24 —
proven t = 24 exact accumulation on the commodity block-scaled FP4/MX path** (frontier
doc §4.6 vectors; runnable now on B200/RTX 50-series, extending to B300/MI355X/Trn3),
because every load-bearing v4.2 property that is not pure arithmetic — native-path
eligibility, the ladder's top tier, the bounded-vs-cliff ASIC band — pivots on it, and
no other open item comes close (ASIC deep-dive §7 sensitivity). Everything else on the
critical path (C-15 review, wall-time split, golden vectors, ASERT rescale) is shared
machinery this program already knows how to run. This document freezes the parameters
(§2, §5) so that golden-vector generation can begin the day M-t24 and the review land.

### 10.3 Consensus classification (unchanged from the redesign; restated)

ENC-BMX4C is a **hard-fork-level committed-object change** (`nMatMulV42Height`-style
height gate): same headers produce different operands → different Ĉ → different digest.
It is emphatically *not* a float or MX sketch — the committed object remains exact
integers; the verifier is unchanged in form. Miner K′/schedules/limb bases/embeddings
are miner-local; the C-1′ vectors are consensus-protecting; difficulty recalibration is
consensus-adjacent calibration; S, 𝓜, L, n, b are consensus parameters of the profile,
fixed at fork time from measurement.

---

## 11. Residual open questions (what must be measured/reviewed before mainnet)

Priority-ordered; owners in parentheses:

1. **M-t24** (gating): t = 24 exactness proof per commodity block-scaled path — B200/
   B300 `mxf4`-E8M0 TMEM, RTX 5090 UE4M3-hosted-2^e path, MI355X CDNA4, Trn3 Matmul-MX
   PSUM, TPU v7 FP8 MXU — via §4.3 vectors. (Measurement; runnable now for the first
   two.)
2. **`mxf4`-E8M0 rate parity with NVFP4** on B200/B300, and survival of an E8M0 FP4 kind
   on Rubin (R-1-class monitoring; sets the commodity denominator — vendor docs list the
   kinds, no public rate-parity benchmark exists).
3. **§K.2a-WT/§K.2b marginal wall-time split at Q ≥ 32 on a real FP4 part** — tensor
   majority required; model prediction combine ≈ 70–80 % [M]; the mod-q combine has
   violated this requirement once before on GPU. Includes GPU-side on-die XOF expansion
   status (host expansion is today's operational bottleneck).
4. **C-15 external adversarial review** (mainnet blocker, shared with v4.1): I1′
   marginal-work floor; small-alphabet batch algebra over fixed (P, V) with the
   cryptanalysis §2.6 opening condition as the attack target; 𝓜-valued template-scoped
   U/V; difficulty-calibration gaming between template refreshes.
5. **NKI explicit committed-scale-tensor support on Trainium3** (kernel prototype —
   `quantize_mx` derives scales from data; consensus scales must be loadable).
6. **Cross-vendor golden vectors** (B2a analogue) regenerated for ENC-BMX4C on
   NVIDIA + AMD + Apple + at least one FP4/FP8-path device, incl. the full §4.3
   adversarial set; a replayed s8-era vector set is void.
7. **ASERT one-time rescale** (B2b analogue) from the measured marginal unit on the
   path rational miners actually run; nonce-rate re-benchmark per class; §S.4.6 ρ
   re-measured on FP4 rental centrals at activation (disclosure only).
8. **Entropy-floor slack**: 𝓜₁₁ meets every floor condition with little slack
   (3.46 bits vs ≥ 3.4; 9.09 % vs ≤ 10 % zeros). If the C-15 review asks for margin,
   the pre-analyzed 𝓜₁₅ reserve exists — with its §2.1 costs. (Review outcome.)
9. **Spec-text debts at fork time**: §A.6 Strassen rewrite (one INT8-path level at
   E_max = 48; zero frontier levels); §S.2.2 ASIC-residual re-disclosure per §9 incl.
   the halved-cliff mechanism; `CheckCombineLimbBound` successor with the corrected
   base-2⁶ constants (§5.2, incl. the 8,255,455 figure); C-1 → C-1′ codification.
10. **What no pre-tapeout measurement settles** (inherited, disclosed): the bespoke
    ASIC cell/array numbers themselves — bracketed by the empirical iso-node record
    above and revealed commodity ratios below (ASIC deep-dive §9-5).

---

## 12. Confidence

| Claim | Confidence | Basis |
|---|---|---|
| Verifier soundness/cost preserved exactly under ENC-BMX4C | **High** | Format-blind proof (redesign §2) + §2.4 bounds; pure arithmetic |
| Determinism with power-of-two scales; fractional scales excluded; no-rounding envelope per §4.2 | **High** (format arithmetic; machine-checked framework inherited) — **Medium** for real-device behavior pending M-t24 | Ozaki doc §2 theorem + OCP MX format facts; DeepSeek t≈14 precedent |
| 𝓜₁₁@S=3 keeps INT8 1-GEMM native; sub-2²³ marginal pipeline; header range preserved | **High** | Exact arithmetic (§2.4, §5) |
| Alphabet hardness SAFE (tables/BNN/sparsity/Strassen dispositions) | **High** (closures are counting/bandwidth inequalities with ≥ 10²× slack) | Cryptanalysis FINAL, adopted; C-15 review still the blocker for the "no unknown channel" residue |
| ASIC residual band and ≤ ~1.3× delta; halved cliff under the 1-GEMM fallback | **Medium** (modeled, bracketed by cited anchors) | ASIC deep-dive §5/§7 + §2.1 fallback arithmetic |
| Frontier ≈ 1× / ladder ordering on real silicon | **Low by design — unmeasured** | No BTX kernel has run on any FP4 part; §K.2b posture; gated by §10 |
| Staged recommendation + leapfrog conditions | **High** (decision logic) | Follows from the gate structure; no unmeasured claim is load-bearing |

## References

Repo: `doc/btx-matmul-v4-design-spec.md` (§0.7, §A.2/§A.6, §B, §C, §D, §E, §K.2a-WT,
§K.2b, §L.2.1/§L.4, §S.1–S.4, App. C-1/C-12/C-13/C-15) · the seven companion docs named
in the header · `src/matmul/matmul_v4.{h,cpp}` (`CheckCombineLimbBound`),
`src/matmul/matmul_v4_exact_float.{h,cpp}`, `src/matmul/matmul_v4_batch.{h,cpp}`,
`src/matmul/int8_field.h`, `src/test/matmul_v4_backend_determinism_tests.cpp`.

External (load-bearing subset; full lists in the companions):
[OCP Microscaling Formats MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) ·
[OCP OFP8 v1.0](https://www.opencompute.org/documents/ocp-8-bit-floating-point-specification-ofp8-revision-1-0-2023-12-01-pdf-1) ·
[Blackwell microbenchmarks, arXiv:2512.02189](https://arxiv.org/abs/2512.02189) (B200 INT8 3,927 / FP8 3,851 / FP4 7,702 TOPS measured) ·
[DeepSeek-V3, arXiv:2412.19437 §3.3.2](https://arxiv.org/pdf/2412.19437) (Hopper FP8 ~14-bit accumulation) ·
[SemiAnalysis — tensor core evolution Volta→Blackwell](https://newsletter.semianalysis.com/p/nvidia-tensor-core-evolution-from-volta-to-blackwell) ·
[DeepSeek-V3 issue #197 (FP8 mantissa precision)](https://github.com/deepseek-ai/DeepSeek-V3/issues/197) ·
[vLLM — FP8 KV-cache & attention (Blackwell accumulation improvement, 2026)](https://vllm.ai/blog/2026-04-22-fp8-kvcache) ·
[CUTLASS Blackwell block-scaled kinds](https://docs.nvidia.com/cutlass/latest/media/docs/cpp/blackwell_functionality.html) ·
[Colfax — Blackwell block scaling](https://research.colfax-intl.com/cutlass-tutorial-hardware-supported-block-scaling-with-nvidia-blackwell-gpus/) ·
[NVIDIA — Introducing NVFP4](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/) ·
[Tom's Hardware — B300 NVFP4 "at the cost of INT8 and FP64"](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support) ·
[NVIDIA Rubin platform](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/) ·
[AMD MI355X datasheet](https://www.amd.com/content/dam/amd/en/documents/instinct-tech-docs/product-briefs/amd-instinct-mi355x-gpu-brochure.pdf) ·
[Trainium3 NKI architecture guide](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/guides/architecture/trainium3_arch.html) ·
[NKI MXFP matmul deep dive](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/deep-dives/mxfp-matmul.html) ·
[Google TPU7x docs](https://docs.cloud.google.com/tpu/docs/tpu7x) ·
[RTX Blackwell whitepaper](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf) ·
[Ozaki–Ogita–Oishi–Rump 2012](https://doi.org/10.1007/s11075-011-9478-1) ·
[ozIMMU, arXiv:2306.11975](https://arxiv.org/abs/2306.11975) ·
[FP64 emulation on FP8 tensor cores, arXiv:2508.00441](https://arxiv.org/abs/2508.00441) ·
[Bourgain–Vu–Wood, JFA 2010](https://arxiv.org/abs/0905.0461) ·
[Tikhomirov, Annals 2020](https://arxiv.org/abs/1812.09016) ·
[Bit Fusion, ISCA 2018](https://arxiv.org/pdf/1712.01507) ·
[Jouppi et al., TPU v4 vs A100, ISCA 2023](https://arxiv.org/abs/2304.01433) ·
[Horowitz, ISSCC 2014](https://gwern.net/doc/cs/hardware/2014-horowitz-2.pdf) ·
[Liberty–Zucker mailman algorithm](https://edoliberty.github.io/papers/mailmanAlgorithm.pdf) ·
[SemiEngineering — 3 nm NRE](https://semiengineering.com/big-trouble-at-3nm/) ·
[Deterministic FP noise structure, arXiv:2511.00025](https://arxiv.org/pdf/2511.00025).
