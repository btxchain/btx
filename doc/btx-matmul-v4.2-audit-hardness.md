# BTX MatMul v4.2 / BMX4-C — Independent C-15 Adversarial Audit: MatMul Hardness & Freivalds Soundness

*Status: EXTERNAL ADVERSARIAL AUDIT (one panel lens). NOT a code change, NOT a spec
edit, NOT an activation decision, NOT a C-15 sign-off. This report attacks the hardness
and soundness claims of `doc/btx-matmul-v4.2-consolidated-design.md` (BMX4-C / ENC-BMX4C),
challenges the prior favorable analyses in
`doc/btx-matmul-v4-bmx4-shortcut-cryptanalysis.md` and
`doc/btx-matmul-v4-committed-object-redesign.md` rather than trusting them, and audits the
v4.1 verifier (`src/matmul/matmul_v4.cpp`, `src/matmul/pow_v4.cpp`,
`src/matmul/int8_field.{h,cpp}`) as it would run under BMX4-C operands. A lead auditor will
synthesize this with the other panel lenses. Written 2026-07-16 by the independent hardness
reviewer. Confidence is stated per finding; proven is distinguished from argued throughout.
This audit does NOT by itself close C-15 — a single reviewer cannot prove a lower bound.*

---

## 0. Scope, method, and the one framing fact

**Scope.** (i) MatMul hardness: is the committed object `Ĉ = U·(Â·B̂)·V ∈ F_q^{m×m}`
computable, or passable-in-verification, materially cheaper than the honest marginal unit?
(ii) Freivalds soundness: can a cheating prover pass `SketchFreivalds` with a wrong or
cheaply-derived `Ĉ`? Method: academic-crypto peer review of the *proofs and their unstated
assumptions* + PoW red-team (enumerate and cost concrete attacks) + break-your-own-crypto
(report the *margin*, not "closed").

**The one framing fact that governs the whole audit.** Freivalds binds only the
*correctness* of `Ĉ` against the consensus-derived `Â, B̂` (the verifier regenerates both
from the header seeds and recomputes the true right-hand side by matvecs — `matmul_v4.cpp`
lines 543–589). It says **nothing** about the *cost* of producing that correct `Ĉ`. So the
entire hardness case rests on a single unproven proposition:

> **(H) The marginal per-nonce unit — evaluate `Ĉ_k = P·(B̂_k·V)` for a fixed,
> template-scoped `P = U·Â` and `V`, over a nonce-fresh pseudorandom `B̂_k` — admits no
> algorithm materially cheaper than the honest ≈ n³-MAC two-GEMM-plus-combine path,
> amortized over the nonce sweep.**

Every companion document concedes, correctly, that (H) is **"no known algorithm," not a
lower bound** (cryptanalysis §6 last row, §8; redesign §4.5; consolidated §3, §11-4). This
audit's central result is that (H) is not merely un-proven at the margins — its *strongest
form is false in practice today* (Finding F2) and its structure hands an adversary two
concrete, previously-under-analyzed levers (F1, F3). None of these is a full break; all
are margin-erosion that stacks, and the residue is exactly what must go to external human
cryptographers.

**Implementation-state note (INFO, but load-bearing for the panel).** The audited code is
still the **v4.1 s8 object**, not BMX4-C: `int8_field.h` pins `kBalancedBound = 125`,
`kElementSqBound = 15625`; `matmul_v4.h` pins `kCombineLimbBase = 128` (base-2⁷ digits);
`ExpandBalancedS8Stream` samples 251-value balanced s8; `CheckCombineLimbBound` derives the
`n ≤ 8522` bound from `15625·n`. BMX4-C (`𝓜₁₁`, base-2⁶ limbs, scale planes, E2M1 U/V,
`288n`/`2304n` bounds) exists only in the design docs. "The verifier is unchanged in
*form*" is true; but every *bound constant* the verifier and combine reference is s8-specific
and silently wrong for BMX4-C. This is not a hardness hole per se, but it means the audited
artifact cannot be the thing that ships, and the golden-vector/bound regeneration (design
§10.1, redesign cond. 3–4) is a prerequisite, not a detail. See F9.

---

## 1. Findings summary

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | I1′ marginal-work floor is an **assumption, not a theorem**; the fixed-`(P,V)` map is a rank-`m²` linear sketch of `B̂` — a structured, amortizable, previously-unnamed batch surface | **High** (assumption-not-theorem; no break) | Open → external review |
| F2 | Sub-cubic matmul on the **combine (≈80% of the unit)**: the "one Strassen level / difficulty-absorbed ≤12.5%" bound is a *narrow-datapath artifact*, and lower-complexity matmul now **provably breaks vendor GEMM peaks at these dimensions on real tensor cores and on FPGA/ASIC** | **High** | Bound is real but not tight; margin quantified |
| F3 | Four-Russians/mailman over the **combine with fixed template-scoped `P` limb-planes** — the cryptanalysis dismissed this channel for a *partially wrong reason* (it missed that `P` is amortizable and only checked the alphabet size) | **Medium** | Still closed by bandwidth; must be named in C-15 |
| F4 | Freivalds soundness is **genuinely format-blind and the 2/q bound is tight**; Fiat–Shamir grinding is closed with ~2⁻¹⁸⁰ margin — but three tightness caveats (R=3 headroom, single-round degeneracies, challenge-stream uniformity) | Low → Info | Closed with margin |
| F5 | The **sketch-rank shortcut** the mandate names gives *no* compute skip; but it sharpens the honest statement of the §E.3 work-binding gap | Info | Closed |
| F6 | The **entropy/alphabet floor is met with essentially zero slack** (3.46 vs ≥3.4 bits; 9.09% vs ≤10% zeros); the closures inherit this fragility | Medium | Assumption; monitor |
| F7 | Scale-class / product-histogram / cross-nonce channels | Info | Closed (agree with cryptanalysis) |
| F8 | Multiple "closed" verdicts silently depend on a **tensor:ALU:bandwidth hardware-ratio assumption**; a bespoke wide-integer-MAC ASIC changes the ratio and *simultaneously* reopens F2 (more Strassen levels) and softens F3 | **Medium** | Assumption; cross-cutting |
| F9 | Verifier/combine **bound constants are s8-specific**; BMX4-C reuse without regeneration is a latent consensus/soundness bug | Info→Low | Prerequisite |

---

## 2. F1 — The I1′ marginal-work floor is an assumption; the fixed-`(P,V)` batch sketch (High)

### 2.1 The exact structure the design commits to

Under I1′ (verified in code: `DeriveOperandSeed` uses `ComputeTemplateHash` for A and
`DeriveProjectorSeeds` uses the template hash for U,V — `matmul_v4.cpp` 91–138), `A, U, V`
are **template-scoped** and `B, σ` are **nonce-fresh**. Therefore across an entire nonce
sweep (up to 2⁶⁴ nonces under one template) the miner holds fixed:

- `P = U·Â` — an `m×n` matrix (computed once, stage S0, amortized to ≈0 per nonce), and
- `V` — the `n×m` right projector,

and the marginal unit is precisely the evaluation of the **fixed bilinear/linear operator**

```
    L : F^{n×n} → F^{m×m},   L(B) = P · B · V     (equivalently vec(Ĉ) = (P ⊗ Vᵀ)·vec(B))
```

on the pseudorandom stream `B_1, B_2, …`. The honest cost of one application is
`n²m` (form `B·V`) `+ 16·n·m²` (the limb combine `P·Q`) ≈ `n³/4 + n³ = 1.25 n³` int-MACs
at `m = n/4` (matches design §5: combine ≈ 80%).

### 2.2 Why (H) is an assumption, made concrete

Two structural facts the design states but does not fold into a lower bound:

**(a) `L` has rank exactly `m²`, so `Ĉ` is a fixed linear *sketch* of `B`.** `P` and `V`
each have rank `m` (i.i.d. 11-symbol matrices are full-rank w.p. `1 − 2^{−Ω(n)}` —
[Bourgain–Vu–Wood](https://arxiv.org/abs/0905.0461),
[Tikhomirov](https://arxiv.org/abs/1812.09016)). The Kronecker operator `P ⊗ Vᵀ` therefore
has rank `m·m = m²`. **`Ĉ` depends on the `n²` entries of `B` only through `m² = n²/16`
fixed linear functionals** — a 16× compression, with a *fixed, precomputable* sketching
operator. The design nowhere argues that a fixed rank-`m²` linear sketch of a matrix cannot
be evaluated below two-GEMM cost with `(P,V)` preprocessed offline. That is a real,
named open problem (matrix multiplication / linear-map evaluation *with preprocessing of one
argument*), and recent work is specifically about lower bounds for exactly this
"restrict/fix the first matrix" setting
([automated bilinear-complexity lower bounds over finite fields, arXiv:2603.07280](https://arxiv.org/html/2603.07280v5))
— which is evidence the question is *live*, not settled.

**(b) The amortization is over a fixed operator, not fresh randomness.** The I1′ relaxation
was adopted to let the batched-sketch profile (§K.2b) share S0. But the same relaxation is
what turns the per-nonce problem into "apply one fixed linear operator to many inputs" — the
canonical setting where preprocessing pays. The design's own defense (cryptanalysis §2) only
closes the *table/Four-Russians* instantiation of preprocessing; it does not close
preprocessing in general.

### 2.3 What I could and could not build

I could **not** construct an `o(n²m)` evaluator for dense pseudorandom `B` — consistent with
"no known algorithm." The information floors do hold: `Ĉ` has `m²·61` output bits that
genuinely depend on all of `B` (any correct sketch must read the full nonce-fresh
`n²·3.46`-bit `B̂` — cryptanalysis §6, agreed), so there is a hard `Ω(n²)` *read* floor.
But `Ω(n²)` reads is far below the claimed `Θ(n³)` *compute* floor, and **nothing in the
document bridges that gap with a proof.** The honest status:

- **Proven:** `Ω(n²)` (must read `B`); soundness forces bit-exact `Ĉ` (no approximation).
- **Argued, not proven:** the `Θ(n³)` compute floor — i.e. (H) itself.
- **Margin:** the entire hardness thesis. If a fixed-operator sketch evaluator at, say,
  `O(n²·m^{1−ε})` or `O(n^{ω})` *with a good constant on the fast pipe* exists, the PoW is
  underpriced by that factor, uniformly, for whoever finds it first — a centralization risk,
  not just a difficulty-recalibration.

**Recommendation.** State (H) as the load-bearing *conjecture* it is, in the spec, at the
same visibility as the soundness theorem. The C-15 charge must name the *fixed-operator
rank-`m²` linear-sketch* framing explicitly (not only the table family), and point reviewers
at the preprocessing/one-argument-restricted bilinear-complexity literature above as the
attack target. **This is the finding that most needs external human cryptographers.**

---

## 3. F2 — Sub-cubic matmul on the combine: the "one level" bound is a datapath artifact (High)

### 3.1 The claim under attack

Design §5 and cryptanalysis §3 bound Strassen/bilinear recursion at **exactly one level on
the INT8 path, zero on FP4/FP8**, hence **≤12.5% of tensor multiplies, difficulty-absorbed.**
The derivation (cryptanalysis §3.1): a Strassen level sums two operand blocks, and
`E_max·2^d ≤ 127` gives `d ≤ 1` for `E_max = 48`; on the FP4/FP8 pipe the level-1 sums
(e.g. 77) are not E2M1/E4M3-representable, so `d = 0`.

### 3.2 Why the bound is real but not a hardness lower bound

The bound is a property of **insisting the recursion run on the narrow exact tensor
datapath.** It is *not* a bound on the adversary's achievable work reduction, for three
reasons:

1. **The combine is `≈80%` of the unit and is alphabet-independent** (design §5). It is a
   square-ish matmul (`m×m` output, contraction `n = 4m`) over 6–7-bit limb digits. Strassen
   and Strassen–Winograd apply to it as *field* algorithms regardless of the operand
   alphabet. The 12.5% figure is *per level*; the design caps levels at 1 only via the
   datapath argument.

2. **Lower-complexity matmul now provably breaks hardware peaks at exactly these
   dimensions.** The design's own cited GPU-Strassen literature (TOMS 2020) is stale on this
   point. As of 2026, [FalconGEMM (arXiv:2605.06057)](https://arxiv.org/pdf/2605.06057)
   deploys lower-complexity matmul algorithms (LCMAs) on real GPU tensor cores and
   **surpasses vendor GEMM libraries by up to 17.85% and AlphaTensor-class schemes by up to
   55.61%** at `n ≥ 1024` — precisely the `m = 1024`, `n = 4096` regime here. So even the
   "practically <12.5%, single-digit-% in practice" hedge (cryptanalysis §3.1, Medium
   confidence) is now on the wrong side of the evidence: peak-breaking is a shipping
   technique, not a theoretical curiosity.

3. **On FPGA and bespoke silicon the recursion is a *hardware* choice, not a datapath
   constraint.** [Strassen multisystolic arrays (arXiv:2502.10063)](https://arxiv.org/pdf/2502.10063)
   and [practical Strassen on FPGAs (arXiv:2406.02088)](https://arxiv.org/pdf/2406.02088)
   build the operand-sum width into the array. A bespoke exact-integer array can carry
   level-1 (or level-2) sums in a wider internal datapath *for free*, harvesting the MAC
   reduction the commodity s8 pipe cannot. This couples directly to F8 and to the ASIC
   residual the ASIC deep-dive already discloses.

### 3.3 The narrow-pipe slicing counter, and where it holds

The design's implicit defense (redesign, ASIC deep-dive) is that emulating a wide Strassen
sum on the s8 pipe via Ozaki slicing costs ~4 s8 GEMMs per summed product (a 2-limb ×
2-limb = 3–4 partial products), so `7 products × 4 slices = 28` vs `8` → **3.5× worse** —
Strassen-on-the-narrow-pipe loses. **This counter is correct and I verified the arithmetic.**
It genuinely blocks *unbounded* tensor-pipe recursion. But it only defends the *commodity
narrow-pipe* case; it does not defend against (i) one honest level (already conceded ≤12.5%,
now shown practically *achievable*, not just theoretical), (ii) wider-datapath commodity
paths (FP16/BF16/int32 accumulate, where a level-1 sum of 96 or of 62 limb-digits fits
natively — no slicing tax), or (iii) bespoke arrays (§3.2-3).

### 3.4 Margin

- **Commodity today:** bounded, ≈ the conceded ≤12.5% but now demonstrably *realizable*
  (FalconGEMM), so difficulty must absorb a **real** double-digit-% shift, not a theoretical
  one. This is fine *iff* it is uniform across the honest population — but FP4-only frontier
  parts get `d = 0` while INT8/wider parts get `d ≥ 1`, so it is **not** uniform; it slightly
  *flattens* the very ladder the design engineers, in favor of wider-datapath parts. Minor.
- **Bespoke:** the level cap is `d = 1` only by commodity-datapath assumption; a wide-int MAC
  array is not bound by it, stacking with the ASIC residual. Unquantified in these docs.

**Recommendation.** Rewrite §A.6 not as "one level, ≤12.5%, absorbed" but as "≥1 level is
*practically realizable* on wider-datapath and bespoke parts; the advantage is bounded by the
tensor:wide-ALU throughput ratio, disclosed with the ASIC residual, and is non-uniform across
the ladder." Re-measure the optimal-miner combine with an LCMA backend before the ASERT
rescale (design §11-3, §11-7) — otherwise difficulty is calibrated to a schoolbook combine
the rational miner will not run.

---

## 4. F3 — Four-Russians/mailman over the combine with *fixed* `P` planes (Medium)

### 4.1 The gap in the prior analysis

Cryptanalysis §2.5 and §1 dismiss any table channel on the combine with: *"neither factor is
small-alphabet — P, Q entries are ≤ 2²¹; the limb digits are 64-valued, so a table is 64^t —
strictly worse than 11^t."* This is **two-thirds right and one-third wrong**:

- Right that the digit alphabet (64) is larger than `𝓜` (11), so tables are bigger.
- **Wrong by omission** that it never uses the load-bearing fact that in the combine
  `Ĉ = Σ_{ij} 2^{w(i+j)} (P_i · Q_{j})`, the left factor `P_i` (an `m×n` limb-plane of the
  template-scoped `P = U·Â`) is **fixed across the entire nonce sweep** — exactly the
  amortization property that made the `B̂·V` table channel worth analyzing in the first place.
  The dismissal checked *alphabet size* but not *which operand is amortizable*, so it did not
  actually rule out a fixed-`P` preprocessing scheme; it ruled out a naive per-nonce one.

### 4.2 Constructing the fixed-`P` combine table, and closing it properly

Amortizable construction: in `C = P_i · Q_j` with `C[a][c] = Σ_k P_i[a][k] Q_j[k][c]`,
group the contraction `k` into chunks of `t`. Index by the *streaming* operand `Q_j`'s
`t`-symbol column patterns; tabulate `T[pattern] = Σ_{k'} P_i[:,k']·pattern[k']`, an
`m`-vector depending only on the **fixed** `P_i`. Table: `64^t · m` entries per chunk per
limb-plane. Per nonce, per output column (`m`), per chunk (`n/t`): gather one `m`-vector.

The closure is the same bandwidth-collapse inequality as cryptanalysis §2.4, and it is
*stronger* here, so the conclusion survives:

- The 64-valued digit alphabet forces `t` small for any resident table (`64^t·m·w ≤ SRAM`
  gives `t ≤ 2` at `m·w ≈ 8 KB`, 50 MB L2), and the op-exchange break-even needs
  `2t ≥ R ≈ 100–250` — impossible by ~2 orders of magnitude (as §2.4).
- The mandatory gather traffic `m·(n/t)·m·w` per nonce **exceeds the honest `16nm²` combine
  MAC volume** at any resident `t`, so the channel is bandwidth-bound and loses on every real
  memory system — the §L.4 regime.

So the channel **is** closed, at ≥10²×, but for the *bandwidth* reason, not the
*alphabet-size* reason the cryptanalysis gave. The distinction matters because F8: a bespoke
gather-optimized memory fabric attacks the bandwidth premise, and the doc's stated defense
("bigger alphabet") would not survive that — the real defense ("mandatory traffic > honest
MACs") does.

### 4.3 Margin and recommendation

Closed at ≥10²× on commodity hardware; the opening condition remains the ≤~1.5-effective-
symbol / ≥100 TB/s random-gather regime. **Recommendation:** correct the cryptanalysis §2.5
disposition to close the combine table channel on the *bandwidth* inequality with the
fixed-`P` amortization made explicit, and add "batch algebra over fixed `(P,V)` limb-planes"
verbatim to the C-15 scope alongside the fixed-`V` family.

---

## 5. F4 — Freivalds soundness: format-blind, 2/q tight, grinding closed (Low → Info)

I attempted to pass `SketchFreivalds` (`matmul_v4.cpp` 501–596) with a wrong/cheap `Ĉ` and
could not beat the stated bounds. The soundness case is the **strongest part of the design.**

### 5.1 Format-blindness and 2/q tightness — confirmed

The verifier's check `xᵀĈy == (Uᵀx)ᵀ Â (B̂(Vy))` reconstructs the RHS from the
consensus-regenerated `Â, B̂` (lines 543–589), never trusting the prover's compute path. For
`E := Ĉ − U(ÂB̂)V ≠ 0`, `g(x,y) = xᵀEy` is bilinear; `Pr[g=0] ≤ Pr[Ey=0] + Pr[xᵀ(Ey)=0 |
Ey≠0] ≤ 1/q + 1/q = 2/q`. This is **tight** (achieved when `E` is rank-1) and **uses nothing
about the operand alphabet** — the polynomial identity lives entirely over `F_q`. BMX4-C
changes only `Â, B̂`'s *values*, which the proof never touches. The aliasing side-condition
holds with room to spare: for the sketch profile `Ĉ` is already canonical mod q
(`ParseSketch` rejects any word `≥ q`, `matmul_v4.cpp` 461), and for the full-C profile
distinct entries differ by `≤ 2·E_max²·n = 2·2304·4096 ≈ 2²⁵ ≪ q`. **Genuinely closed with
margin; format-blindness is a theorem, not an assumption.**

### 5.2 Fiat–Shamir grinding — closed at ~2⁻¹⁸⁰

Challenges derive from `H(σ ‖ H(payload))` with `σ = SHA256d(header)` (`DeriveChallengeSeed`,
485–497; `ComputeSketchDigest` checked against `header.matmul_digest` *before* Freivalds,
`pow_v4.cpp` 76–79). The binding order is correct: the miner commits `Ĉ` (hence the digest,
hence the block PoW target) *before* the challenges — which depend on `Ĉ` — are knowable.
The only grinding avenue is the **self-referential fixed point**: pick a wrong `Ĉ'`, derive
its self-consistent challenges, hope they satisfy the identity. Per attempt: success prob
`(2/q)³ ≈ 2⁻¹⁸⁰`, and *each attempt itself costs an O(n²) RHS reconstruction that requires
the true `Â, B̂`* — i.e. grinding is strictly more expensive than honest verification per
try, with a `2⁻¹⁸⁰` yield. No advantage. Payload-grinding to bias challenges is defeated
because any payload change changes the digest and thus requires redoing the block PoW.

### 5.3 Three tightness caveats (all currently benign)

1. **R = 3 headroom.** `(2/q)³ = 2⁻¹⁸⁰`. Fine today. But if a future profile ever shrinks
   `q` (e.g. to a 31-bit field for a narrower verifier) the per-round bound is `2/q`, and
   `R` must scale to hold `2⁻¹²⁸`+. Pin `R·log₂(q/2) ≥ 128` as a normative floor so a future
   editor cannot lower `q` without raising `R`. (Cross-profile hygiene; not a v4.2 bug.)
2. **Single-round degeneracies.** `x = 0` or `y = 0` makes a round pass vacuously; each has
   probability `q^{−m}` (negligible) and `ExpandFqStream` rejects only the value `q` itself.
   No adversarial control over the stream (it is `H(σ‖H(payload))`-seeded). Benign, but worth
   a one-line assert in the reference that not all-`x`/all-`y` are zero — defense in depth.
3. **Challenge-stream uniformity across rounds.** The three rounds share seed material
   differing only by a LE32 round counter (491–493). They are independent under the SHA-256
   PRF assumption; no finding, noted for completeness.

**Verdict:** soundness is closed with large margin and is the right kind of closed (a
theorem). The caveats are cross-profile hygiene, not v4.2 defects.

---

## 6. F5 — The sketch-rank shortcut gives no compute skip (Info)

The mandate asks: "`Ĉ = U·C·V` is rank ≤ m — does committing only the sketch let you skip
work?" **No.** `Ĉ` is `m×m`, so rank ≤ m is automatic (an output-dimension fact), and it is
*inherent to the honest object* — `ComputeSketchOptimal` (`matmul_v4.cpp` 420–439) already
never forms the `n×n` `C`; it computes `P = U·Â`, `Q = B̂·V`, then `P·Q`. The rank ceiling
buys the *honest* miner the `Θ(n²m)` factoring over `Θ(n³)`; it buys a *cheating* miner
nothing, because the verifier pins `Ĉ` to `U(ÂB̂)V` for the specific consensus `U,V` (§5.1).
A cheater cannot commit an arbitrary rank-`m` matrix and cannot exploit the
`(n²−m²)`-dimensional kernel of the sketch (the freedom would be a different *`C`*, but the
verifier uses the *true* `Â,B̂`, not a prover-chosen `C`). The genuine residual is exactly
F1: the sketch structure makes the honest floor a *fixed-operator* problem, which is a
hardness question, not a soundness one. **Closed as a shortcut; folded into F1 as the real
open item.**

---

## 7. F6 — The alphabet/entropy floor is met with essentially zero slack (Medium)

The cryptanalysis floor (§7.3-c) is: min-entropy ≥ ~3.4 bits/element; ≥ 4 nonzero magnitudes;
P(0) ≤ 10%; ≥ 2 non-power-of-two magnitudes at ≥ ~25% mass. `𝓜₁₁` meets each at the
*boundary*: `log₂11 = 3.459` vs 3.4; `P(0) = 1/11 = 9.09%` vs 10%; `{3,6}` at 36.4% vs 25%;
5 nonzero magnitudes vs 4. The design itself flags this ("sits *at* the floor with all
conditions met," §2.1; "little slack," §11-8). Two adversarial observations:

1. **Every closure inherits the fragility.** The BNN-cliff margin (§5: ~9× above ternary),
   the singularity bound, the zero-skip bound (≤9.09%), and the shift-only escape all sit a
   *constant factor* above their cliffs, not orders of magnitude. `𝓜₁₁` is a
   minimum-viable-entropy object by construction (it is the GCD alphabet chosen for
   hardware-nativeness, §8.2, *then* checked for safety — the causality is
   hardware-first). Any later sampler re-weighting "for hardware reasons" that nudges P(0)
   up or drops a magnitude breaches a floor. The floor must be a *consensus-enforced
   invariant with a checked assertion at sampler-definition time*, not a design-doc sentence.
2. **The min-entropy claim vs the actual sampler.** The mantissa sampler is uniform over 11
   codes (11/16 nibble acceptance), so 3.459 bits is correct *for the mantissa plane*. The
   scale plane adds 2 bits/32-block of *structured* (not per-element-independent) entropy;
   the "+0.06 bits/elem" accounting (§2.1) is honest but means the per-*element* min-entropy
   the BNN/table closures actually consume is **3.459, not 3.52** — the scale bits do not
   raise the per-element compute-alphabet richness that the cliff arguments depend on (they
   are a shared per-block shift). The closures that matter use the right number (3.46), but
   the headline "3.52 bits/elem — SAFE" slightly over-states the margin the cliff arguments
   see. Minor, but the panel should not let 3.52 be quoted as the anti-cliff margin.

**Recommendation.** (a) Encode the four floor conditions as a compile-time/consensus check
over the pinned sampler, not prose. (b) If C-15 asks for margin, the `𝓜₁₅` reserve exists
but costs the sub-2²⁴ envelope (§7.4) — a real trade, not a free hardening. (c) Quote 3.46,
not 3.52, as the anti-cliff margin.

---

## 8. F7 — Remaining channels (Info, agree with prior analysis)

I re-derived and concur: low-rank/singularity (`≤ 2^{−Ω(n)}`, in truth `~(1/11)^n`-order);
2:4 structured sparsity impossible by counting (needs 50% zeros/row, alphabet gives 9.09%,
permutation-invariant); product-histogram and 11×11-LUT are compute-neutral (the multiply is
not the bottleneck, the accumulate is); scale grinding defeated by footprint-invariance (I8);
cross-nonce block collisions at `2⁻³⁵` per `2²⁰` sweep. These closures are counting/arithmetic
and do not depend on hardware ratios. **Closed.** One nit: the singularity exponents are for
*i.i.d. uniform* entries; the operands are *PRF-derived*, so the correct statement is "assuming
SHA-256 is a PRF, the draw is computationally indistinguishable from i.i.d., hence the bounds
hold" — the docs treat the draw as literally i.i.d.; the PRF caveat should be explicit (it is
the same assumption soundness-of-grinding already relies on, so it costs nothing to state).

## 9. F8 — The hidden cross-cutting assumption: the hardware-ratio premise (Medium)

Several "closed with ≥10²× margin" verdicts are **not** pure counting arguments — they are
*inequalities in the tensor:vector-ALU:bandwidth throughput ratios* `R_v ≈ 250`, `R_b ≈
400–960`:

- Table/Four-Russians closure (cryptanalysis §2.4; F3 here): needs `R_v, R_b ≫ 2t`.
- "Strassen difficulty-absorbed" (F2): needs the narrow-pipe slicing tax to exceed the level
  saving, i.e. tensor MAC ≫ wide-ALU op.
- FPGA "≥13× behind": needs the commodity FP4 rate advantage to hold.

A **bespoke exact-integer ASIC with wide-datapath MAC cells at tensor density** moves all
three ratios at once: it (i) narrows `R_v/R_b` so tables/mailman get *relatively* closer
(F3), (ii) removes the slicing tax so it can carry `d ≥ 1` Strassen levels for real (F2), and
(iii) is the very residual the ASIC deep-dive discloses at ~1.5–2.5× / ≤~4×. These are not
independent risks — a single bespoke-silicon adversary collects all of them. The design
treats them in separate documents with separate margins; **no document sums them.** The
honest combined worst case for a frontier-node bespoke attacker is therefore *larger* than
any single doc's figure, and is un-quantified here. This is a disclosure gap, not a proof of
break: the NRE and difficulty-absorption arguments (ASIC deep-dive §S.2.2) still apply. But
the panel should require **one** combined-adversary accounting, not five separate ones.

## 10. F9 — s8-specific bound constants under BMX4-C operands (Info → Low)

As in §0: `kElementSqBound = 15625`, `kCombineLimbBase = 128`, `CheckCombineLimbBound`'s
`133,160,895` / `n ≤ 8522` derivation, and the s8 aliasing-gap comment (`< 2³²`) are all
literally wrong for BMX4-C (`288n`, base-2⁶ digits, `< 2²⁵` gap). The design's own §5.2
already flags the redesign's `8,255,527` figure as off-by-72 (correct value 8,255,455) — a
concrete sign that these hand-derived limb bounds are error-prone and must be regenerated and
machine-checked, not transcribed. If BMX4-C operands were fed to the *current* code
unchanged, `CheckCombineLimbBound` would gate on the wrong constant and `DecomposeLimbPlanes`
(base-128) would silently mis-decompose base-2⁶ inputs — a determinism/soundness split, not a
hardness issue. **Not a hardness finding, but a prerequisite** the lead must not let slip
between "verifier unchanged in form" and "verifier unchanged in fact."

---

## 11. Verdict

### 11.1 Genuinely closed, with margin (theorems or tight counting)
- **Freivalds soundness** (F4): format-blind, per-round 2/q tight, total 2⁻¹⁸⁰, FS grinding
  ~2⁻¹⁸⁰, aliasing `≪ q`. A theorem; the strongest part of the design.
- **Sketch-rank "shortcut"** (F5): no compute skip; inherent to the honest object.
- **Low-rank / 2:4 sparsity / histogram / scale-grinding / cross-nonce** (F7): closed by
  counting, modulo the (free) PRF-not-i.i.d. caveat.
- **Table/four-Russians/mailman**, both the `B̂·V` and (corrected) fixed-`P` combine forms
  (F3): closed by the *bandwidth* inequality at ≥10²× — provided the hardware-ratio premise
  (F8) holds.

### 11.2 Assumption, not theorem (the load-bearing conjectures)
- **(H), the I1′ marginal-work floor** (F1): the central hardness claim is "no known
  algorithm" for evaluating a fixed rank-`m²` linear sketch of `B` — *not* a lower bound.
  This is the single most important thing for the panel to label honestly.
- **The Strassen level cap and its "≤12.5%, absorbed" disposition** (F2): true only under
  the commodity-narrow-datapath assumption; lower-complexity matmul demonstrably breaks
  hardware peaks at these dimensions today, and wider/bespoke datapaths break the cap.
- **The entropy floor** (F6): met at the boundary; every cliff margin is a constant factor,
  not orders of magnitude.
- **The hardware-ratio premise** (F8): several closures are inequalities in throughput
  ratios, and a single bespoke adversary moves all of them together, un-summed.

### 11.3 Must go to external human cryptographers (a single reviewer cannot prove a lower bound)
1. **(H) as a lower-bound question**, framed as *matrix multiplication / linear-map
   evaluation with one preprocessed argument* over `F_q` and over the small integer alphabet
   — the fixed-`(P,V)` rank-`m²` sketch of `B̂`. Attack target: any `o(n²m)` or
   fast-pipe-`O(n^ω)` batched evaluator. (F1)
2. **Batch algebra over fixed `(P,V)` beyond tables** — including the fixed-`P` combine
   family (F3), the mailman/preprocessing variants, and the recent finite-field
   bilinear-complexity lower-bound machinery ([arXiv:2603.07280](https://arxiv.org/html/2603.07280v5))
   turned *offensively*.
3. **The LCMA/Strassen advantage on the actual optimal-miner combine** measured, not
   assumed, before the ASERT rescale (F2), and a **single combined bespoke-adversary
   accounting** summing F2+F3+F8 with the ASIC residual (F8).
4. Confirmation that the **entropy floor** at the `𝓜₁₁` boundary is adequate, or a call for
   the `𝓜₁₅` reserve with its disclosed sub-2²⁴ cost (F6).

### 11.4 Bottom line
No break. Soundness is a theorem and holds under BMX4-C. **The hardness rests entirely on an
unproven conjecture (H)** whose strongest form is already false in practice (peak-breaking
matmul on the 80%-dominant combine), whose structure hands an adversary a fixed-operator
linear-sketch surface the prior analysis did not fully name, and whose supporting closures
are boundary-tight or hardware-ratio-dependent. This is *exactly* the shape of a PoW whose
"no known algorithm" barrier must be adjudicated by external human cryptographers before
mainnet — the C-15 gate is not a formality here; it is the crux. This audit sharpens and
scopes that gate; it does not close it.

---

## 12. Confidence

| Claim | Confidence | Basis |
|---|---|---|
| Soundness format-blind, 2/q tight, grinding closed (F4, F5) | **High** | Re-derived Schwartz–Zippel + read of `SketchFreivalds`/`pow_v4.cpp` binding order |
| (H) is an assumption, not a theorem; fixed-`(P,V)` rank-`m²` sketch framing (F1) | **High** (that it is *open*) / **Low** (that it is *breakable*) | Could not build an `o(n²m)` evaluator; docs concede "no known algorithm"; live lower-bound literature |
| Combine sub-cubic advantage is real and under-bounded (F2) | **Medium-High** | FalconGEMM peak-breaking at `n≥1024`; Strassen FPGA/systolic arrays; narrow-pipe slicing counter re-verified |
| Combine table channel closed by bandwidth (not alphabet size) with fixed-`P` amortization (F3) | **High** | Same inequality as cryptanalysis §2.4, re-derived with the amortizable operand corrected |
| Entropy floor boundary-tight; quote 3.46 not 3.52 (F6) | **High** | Direct arithmetic on the sampler |
| Combined bespoke-adversary risk is un-summed (F8) | **Medium** | Cross-document reading; the individual margins are the docs' own |
| s8 bound-constant mismatch under BMX4-C (F9) | **High** | Direct read of `int8_field.h` / `matmul_v4.h` / `CheckCombineLimbBound` |

**Could not verify (inherited posture):** any figure on real FP4/FP8 silicon (no frontier
hardware); the true constant-factor of an LCMA combine on the optimal-miner path (needs the
measurement of design §11-3); bespoke-ASIC cell/array numbers.

## References
Repo: `doc/btx-matmul-v4.2-consolidated-design.md`,
`doc/btx-matmul-v4-bmx4-shortcut-cryptanalysis.md`,
`doc/btx-matmul-v4-committed-object-redesign.md`;
`src/matmul/matmul_v4.cpp` (`ComputeSketchOptimal`, `ComputeCombineLimbTensorStacked`,
`CheckCombineLimbBound`, `SketchFreivalds`, `DeriveChallengeSeed`),
`src/matmul/pow_v4.cpp` (`ComputeDigest`, `VerifySketch`),
`src/matmul/int8_field.{h,cpp}`, `src/matmul/matmul_v4.h`.

External:
[FalconGEMM — peak-breaking lower-complexity matmul on GPUs, arXiv:2605.06057](https://arxiv.org/pdf/2605.06057) ·
[Strassen multisystolic array hardware, arXiv:2502.10063](https://arxiv.org/pdf/2502.10063) ·
[Practical Strassen on FPGAs, arXiv:2406.02088](https://arxiv.org/pdf/2406.02088) ·
[Low-Rank GEMM with FP8, arXiv:2511.18674](https://arxiv.org/pdf/2511.18674) ·
[Automated bilinear-complexity lower bounds over finite fields, arXiv:2603.07280](https://arxiv.org/html/2603.07280v5) ·
[More Asymmetry Yields Faster Matrix Multiplication (ω<2.3715), arXiv:2404.16349](https://arxiv.org/abs/2404.16349) ·
[New Bounds for Matrix Multiplication: from Alpha to Omega (Williams–Xu–Xu–Zhou, SODA 2024)](https://epubs.siam.org/doi/10.1137/1.9781611978322.63) ·
[Strassen's Algorithm Reloaded on GPUs, ACM TOMS 2020](https://dl.acm.org/doi/fullHtml/10.1145/3372419) ·
[Bourgain–Vu–Wood, JFA 2010](https://arxiv.org/abs/0905.0461) ·
[Tikhomirov, Annals 2020](https://arxiv.org/abs/1812.09016) ·
[Liberty–Zucker mailman algorithm, IPL 2009](https://edoliberty.github.io/papers/mailmanAlgorithm.pdf) ·
[Method of Four Russians](https://en.wikipedia.org/wiki/Method_of_Four_Russians).
</content>
</invoke>
