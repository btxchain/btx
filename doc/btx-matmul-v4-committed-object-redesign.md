# BTX MatMul v4 — Committed-Object Redesign to a Frontier-Native Low-Precision Format: Security & Consensus Determination

*Status: STUDY + DETERMINATION (security/consensus review deliverable). Not a code
change, not a spec edit, not an activation decision. Companion to
`doc/btx-matmul-v4-design-spec.md` (the spec, authoritative and UNCHANGED),
`doc/btx-matmul-v4-multiplatform-roadmap.md` (§3.2 decoupling risk, §3.3 Option B/C,
§3.4 consensus classification), `doc/btx-matmul-v4-exact-int-on-float.md` (the
miner-only Ozaki path this redesign is weighed against), and
`doc/btx-matmul-v4-accumulator-eligibility.md` (the C-1 invariant generalized in §3).
The concrete operand format is owned by the companion deliverable
`doc/btx-matmul-v4-frontier-native-format.md`; this document is deliberately
**format-robust** — every result below is stated against a parameterized format
family and instantiated on one reference point, so it survives reasonable format
choices by the format owner. Per spec §0.7-(4), no market price appears anywhere in
this analysis. Written 2026-07-16.*

---

## 0. Verdict

**WITH-CONDITIONS.** A frontier-native committed object — small exact-integer
mantissas + per-block power-of-two microscales (MX-style E8M0 discipline) — **can**
preserve all four hard requirements and every §C hardness invariant, but only inside
a specific safe envelope, and it is unambiguously a **hard-fork-level consensus
change (a v4.2)**, unlike the miner-only Ozaki path. The load-bearing findings:

1. **Freivalds soundness is exactly preserved** (§2). The soundness proof never uses
   the operand format — only that the committed object is an exact integer/F_q
   object reproducible from the header in O(n²). Per-round error stays ≤ 2/q
   (sketch) / ≤ 1/q (full-C), R = 3 → ≤ 2⁻¹⁸⁰/2⁻¹⁸³, verification stays O(n²),
   integer-exact, and gets slightly *cheaper* (fewer XOF bits).
2. **Determinism is preservable iff scales are pure powers of two** (§3).
   Dequantization by 2^e is an exact shift; the whole PoW reduces to an exact
   integer matmul + exact shifts. **NVFP4-style fractional (E4M3-valued) block
   scales are excluded from the committed object** — they round, and rounding is a
   chain split. The C-1 eligibility invariant generalizes cleanly to "no operation
   on the committed path may ever round, whether the unit is integer or float," and
   the format can even be sized so the entire pipeline stays below 2²⁴, making
   FP32-accumulate hardware *eligible by bound* (§4.4).
3. **The two top-risk hardness questions come back bounded, not broken** (§4.2,
   §4.3): per-nonce operand entropy drops to ≈ 44 % of balanced-s8 but remains
   ~5.9×10⁷ bits — astronomically above every structural-attack threshold, with a
   hard floor stated; the ASIC/FPGA residual (spec §S.2.2's disclosed
   "mining-only tensor chip" caveat) **widens modestly** (from ~1.5–2× to an
   estimated ~2–3× worst case) because narrower multipliers cheapen bespoke MAC
   arrays — a real, honest weakening, but no cliff, and the capacity-gate
   impossibility (§L.4) is format-independent and stays closed.
4. **The scaled-reward ladder is preserved in peak-spec arithmetic and steepens
   toward frontier silicon — but per this repo's own posture it is a HYPOTHESIS
   until measured on real FP4/FP8 silicon** (§5). Two prior model-based ordering
   claims in this program were falsified by measurement; this document does not
   make a third.

**Conditions (consolidated ledger in §8):** power-of-two scales only, with a small
consensus-pinned exponent range; a multi-magnitude mantissa alphabet with
≥ ~3.4 bits/element min-entropy and small zero mass; generalized-C-1 exact-
accumulation eligibility with re-derived adversarial boundary vectors; re-derived
accumulation/limb bounds (§4.4, including the corrected asymmetric C-13 bound
n ≤ 8522 pattern); the §K.2b-style GO/NO-GO re-measured on real FP4/FP8 silicon;
the still-open I1′ external adversarial review extended to the new format; and full
hard-fork migration machinery (§6). **Recommendation (§7): do not fork now** — ship
v4.1 INT8, use the miner-only Ozaki path as the bridge, and hold this redesign as a
shelf-ready v4.2 gated on the roadmap G-1 decoupling trigger plus measured GO/NO-GO.

---

## 1. The object under review (format-robust parameterization)

The redesign replaces the committed balanced-s8 operands (entries in [−125, 125],
spec §0.7/§B) with a **microscaled integer format** parameterized by:

- **𝓜** — the mantissa alphabet: a finite set of exact integers, |𝓜| symbols,
  max magnitude `M_max`;
- **L** — the block length along the reduction dimension (MX convention: 32;
  NVFP4 convention: 16 — [OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf),
  [NVIDIA NVFP4 blog](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/));
- **𝓔** — the per-block scale set, REQUIRED to be `{2^e : e ∈ [0, e_max]}` with a
  small consensus-pinned `e_max` (§3 makes this non-negotiable).

A committed operand is a pair of planes `(M, E)` expanded from the existing §A.2
seeds by the wide XOF: an n×n mantissa plane over 𝓜 and an (n/L)-per-column scale
plane over 𝓔, blocks running along the reduction (k) axis. The dequantized operand
`Â[i,k] = M_A[i,k]·2^{E_A(i, blk(k))}` is an **exact integer** with
`|Â| ≤ E_max = M_max·2^{e_max}`, and the committed product `C = Â·B̂` is an exact
integer matrix, committed exactly as today via the sketch `Ĉ = U·C·V ∈ F_q^{m×m}`,
digest `H(σ‖Ĉ)`, Freivalds over `q = 2⁶¹−1`. **Nothing else changes**: seed rule
(template-scoped A/U/V, nonce-fresh B and σ — §A.2 v4.1), sketch shape, digest
form, Fiat–Shamir rule, R = 3, header layout.

**Reference instantiation F\*** (used for all worked numbers; the format owner may
move within the §8 envelope):

| Parameter | F\* value | Rationale |
|---|---|---|
| 𝓜 | `{0, ±1, ±2, ±3, ±4, ±6}` — the **exact-integer subset of FP4 E2M1** (±5 is not an E2M1 value; ±0.5, ±1.5 excluded to stay integer) | Single-pass native on FP4 (E2M1), FP8 (E4M3 holds all of [−6,6] exactly), and INT8 (trivially s8) — the greatest-common-divisor alphabet across E2M1/E4M3/s8 |
| L | 32 | OCP MX block length; shorter than every hardware K′, so in-block accumulation is exact even at t = 14 (§3) |
| 𝓔 | `{1, 2, 4, 8}` (e ∈ [0,3], 2 bits/block) | Bounded magnitude spread keeps every aligned partial sum exact (§3/§4.4); E8M0-representable and exactly representable in E4M3 scale registers too (powers of two are exact in both) |
| E_max | 6·2³ = **48** (vs 125 today) | Drives every bound in §4.4 |
| U, V | re-derived over 𝓜 (scale-free), not balanced-s8 | Keeps the projections `P = U·A`, `Q = B·V` under 2²¹ at n = 4096 (§4.4); soundness is indifferent to U/V entropy (§2) |

---

## 2. Freivalds soundness re-derivation over the new object (hard req. 2)

**Claim: the soundness bound, the challenge derivation, and the O(n²)/integer-exact
verification cost are all unchanged.** The proof of §D/§E.2 is *format-blind*: it
uses exactly three properties of the committed object, each of which the new format
preserves.

**(P1) The committed object is a canonical F_q matrix; the true object is a
well-defined exact integer matrix.** `Ĉ = U·(Â·B̂)·V` with `Â, B̂` exact integers
(power-of-two scales = exact shifts, §3) and every intermediate below the §4.4
bounds — so `C` and `Ĉ` are unique exact objects, independent of evaluation order
or hardware, exactly as today. Payload words remain canonical residues in [0, q).
For the full-C alternative profile, distinct canonical committed entries differ by
`|Δ| ≤ 2·E_max²·n = 2·2304·4096 < 2²⁵ ≪ q`, so a wrong integer entry can never
alias to a correct residue: per-round error ≤ 1/q, tighter headroom than the
current 2³² < q argument (§D.3).

**(P2) The bilinear sketch identity holds and each round is a degree-2
Schwartz–Zippel test.** The verifier's check is unchanged:

```
xₜᵀ · Ĉ · yₜ  ==  (Uᵀxₜ)ᵀ · Â · (B̂ · (V·yₜ))    over F_q,  t = 1..R
```

The right side is computed by expanding `(M_B, E_B)` from the seed (O(n²) XOF),
then per-MAC `m·2^e·w mod q` — the shift is a multiply by one of the four
precomputed constants `2^e mod q`, exact 64-bit integer arithmetic, identical cost
profile to today's `FqMul` MAC. If the committed `Ĉ′ ≠ U·C·V` in even one word,
`g(x, y) = xᵀ(Ĉ′ − U·C·V)y` is a nonzero bilinear form of total degree 2 over F_q;
by Schwartz–Zippel, `Pr[g(x,y) = 0] ≤ 2/q` per round. Nothing in this step touches
the operand format — the polynomial identity lives entirely over F_q.

**(P3) Challenges stay Fiat–Shamir-bound and nonce-fresh.** `(xₜ, yₜ)` derive from
`H(σ ‖ H(payload))` with `σ = SHA256d(full header, nNonce64 included)` — the I7
residue of §C. The redesign does not move σ, the payload hash, or the derivation,
so the miner still commits the payload before seeing any challenge, rounds are
independent, and the total error is `(2/q)^R = 2⁻¹⁸⁰` at R = 3 (sketch) /
`(1/q)³ = 2⁻¹⁸³` (full-C) — bit-for-bit the §0.7-(2) numbers.

**Verification cost does not increase; it decreases slightly.** Per round: two
dense O(n²) matvecs + O(nm) projections + O(m²) left side — unchanged asymptotics
and unchanged constant (a mod-q MAC with a ≤ 48-magnitude integer costs the same as
with a ≤ 125-magnitude one). Operand regeneration gets **cheaper**: F\* consumes
≈ 5.9 bits/element (4-bit nibble rejection at 11/16 acceptance + 2 scale bits per
32 elements) vs ≈ 8.2 bits/element for balanced-s8 (251/256 byte rejection) —
~28 % fewer SHA compressions in the §E.2-step-1 regeneration envelope, easing the
one §D.4 line item that was flagged for re-benchmark (ACTIVATION B2d). The 8 MiB
payload SHA and the DoS budgets (§E.4) are unchanged. **Verification stays under
the §D.5 budget with more margin than today.**

**What Freivalds does NOT certify (unchanged, inherited honestly):** the §E.3
work-binding gap — soundness binds *correctness* of `Ĉ`, difficulty prices the
*marginal work* — is identical under the new format, including the I1′
template-amortization relaxation and its NEEDS-EXTERNAL-REVIEW status (§4.1, C-15).

---

## 3. Determinism (hard req. 3) — the no-rounding argument, and C-1 generalized

The redesign's determinism rests on the same theorem as the Ozaki path
(`doc/btx-matmul-v4-exact-int-on-float.md` §2): **a rounding function is the
identity on exactly representable values**, so if every value on the committed path
is an exactly representable integer at every step, all vendor FP differences
(rounding mode, FMA fusion, accumulation order, internal accumulator width past the
proven bound, subnormal flushing) are neutralized simultaneously. Applied here:

1. **Power-of-two scales are exact — fractional scales are excluded.**
   `m·2^e` is an exponent add in FP and a shift in integer arithmetic: exact in
   both, on every vendor. This admits the **MX (OCP) E8M0 scale discipline**, whose
   scales are powers of two by construction
   ([OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf)).
   It **excludes NVFP4's native scale semantics** — E4M3-valued (fractional) block
   scales plus an FP32 tensor-level scale
   ([NVIDIA NVFP4 blog](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/),
   [cuDNN block-scaling docs](https://docs.nvidia.com/deeplearning/cudnn/frontend/latest/operations/BlockScaling.html)):
   a general E4M3 scale multiply rounds, and one rounded bit is a chain split
   (§K.4). NVFP4 *hardware* remains usable: powers of two in [2⁰, 2³] are exactly
   representable in an E4M3 scale register, so a miner feeds the consensus scales
   into the NVFP4 datapath and the scale multiply is exact — the *format on the
   wire* is what consensus pins, not the vendor's calibration recipe.
2. **In-block accumulation is exact on every plausible accumulator.** Mantissa
   products are ≤ 36 = M_max²; one MX block accumulates ≤ L·M_max² = 32·36 = 1152
   < 2¹¹ — exact even in the ~14-bit effective accumulators documented for Hopper
   FP8 tensor cores ([DeepSeek-V3, arXiv:2412.19437 §3.3.2](https://arxiv.org/pdf/2412.19437)).
   The MX block length L = 32 is *shorter than every K′*, so the format's own block
   structure does the §2.2 extract-and-promote blocking for free.
3. **Cross-block accumulation is exact by bound or by promotion.** After shift
   alignment, every partial sum of the full K-dimension is
   ≤ n·E_max² = 2304·n = 9,437,184 < 2²⁴ at n = 4096 — **exactly representable in
   a true FP32 (t = 24) accumulator with no promotion at all**. A device that
   *proves* t = 24 (Blackwell NVFP4/MXFP8 paths document FP32 accumulation) runs
   the entire committed GEMM natively, single pass. A device with unproven or
   narrower t must extract-and-promote at its proven K′ (e.g. per scale block on a
   t = 14 part, since an aligned block sum ≤ 1152·2⁶ ≈ 2¹⁶·² exceeds 2¹⁴) —
   throughput cost, never a correctness cost.
4. **Everything downstream is pure integer arithmetic** — the mod-q combine, the
   limb fold, serialization, the digest — exactly as today. No FP value ever
   reaches the committed object.

**C-1 generalized (normative proposal for the v4.2 edition).** The accumulator-
eligibility invariant of `doc/btx-matmul-v4-accumulator-eligibility.md` §1
generalizes from "true ≥32-bit integer accumulator" to:

> **Exact-integer-arithmetic eligibility.** Every backend MUST compute every
> accumulation on the committed path such that every intermediate value is an
> exactly held integer — whether the unit is nominally integer or floating point.
> A device is eligible for a stage iff the stage's consensus magnitude bound (§4.4)
> is ≤ the device's *proven* exact-integer capacity for that datapath (2^t for an
> FP-mantissa accumulator, 2^(w−1) for a w-bit two's-complement accumulator), or
> the backend imposes an extract-and-promote schedule that keeps every partial sum
> inside it. A device that would round on the committed path is INELIGIBLE for
> that path and MUST fail the determinism self-test loudly.

Two consequences worth stating plainly: (a) because F\* keeps the base GEMM and the
𝓜-alphabet projections below 2²⁴ at n = 4096, **FP32-mantissa-bounded units (the
TPU-v4 class that C-1 exists to exclude today) become eligible *by bound* for those
stages** — the invariant is unchanged, but the workload now sits inside the weaker
class's exact envelope; (b) the C-1 adversarial vectors MUST be re-derived at the
new boundaries — the current HM-A/HM-B/HM-C vectors force accumulations in
(2²⁴, 2³¹) that the new operands *cannot produce* in the base GEMM, so replayed
verbatim they would silently stop testing anything (§4.4 gives the new boundary
regimes). The verify+fallback dispatcher (`accel_v4.h`) and the fail-loud self-test
discipline carry over unchanged.

---

## 4. §C hardness / anti-amortization invariants re-derived

### 4.1 The invariant table

| Invariant / §C item | Under the frontier-native object | Status |
|---|---|---|
| **I1′** — nonce-fresh B/σ, template-scoped A/U/V, marginal-unit difficulty | Seed rule untouched; mantissa AND scale planes of each operand derive from that operand's seed (B's scale plane is nonce-fresh with B). The relaxation's open review (C-15) is inherited, with one NEW review item: low-alphabet batch-algebra over fixed (P, V) — §4.5 quantifies the obvious candidate (table/Four-Russians) as non-viable, but the external review scope must include it. | **Survives; still ⚠ needs the same external review, scope extended** |
| **I1 corollary** — per-block memorylessness (no pre-mining) | Template hash still binds hashPrevBlock; nothing computable before the parent exists. Format-independent. | **Survives** |
| **I2** — full-rank dense operands | i.i.d. over an 11-symbol multi-magnitude alphabet: singularity probability of an i.i.d. discrete random matrix is exponentially small — ≤ (1/√2+o(1))ⁿ for general non-degenerate entries ([Bourgain–Vu–Wood, JFA 2010](https://arxiv.org/abs/0905.0461)), (1/2+o(1))ⁿ even for ±1 Bernoulli ([Tikhomirov, Annals 2020](https://arxiv.org/abs/1812.09016)) — ≈ 2⁻²⁰⁴⁸-order at n = 4096. No rank cliff anywhere near the envelope. | **Survives** (with the §4.2 entropy floor) |
| **I3** — no reusable additive split | The (mantissa, scale) pair is a *multiplicative* per-entry structure, wholly nonce/template-fresh; no term independent of nNonce64 exists. Block scales shared across 32 entries do not create a cacheable product term (both factors of every partial GEMM are fresh). | **Survives** |
| **I5** — no pre-hash lottery | ε = 0 untouched; every nonce still pays the full marginal unit. | **Survives** |
| **I6** — bit-exact arithmetic | §3: exact shifts + exact integer accumulation; estimate-then-patch still impossible (digest equality demands the exact Ĉ). | **Survives, conditional on power-of-two scales (else FAILS)** |
| **I7 residue** — nonce-fresh Fiat–Shamir challenges | Unchanged derivation `H(σ‖H(payload))`, σ nonce-fresh. | **Survives** |
| **I8** — work-unit uniformity | Footprint/FLOPs/bytes identical for every nonce (scale planes are fixed-size, block-aligned; no nonce-dependent resource variation). | **Survives** |
| **§A.6 anti-Strassen** | Weakens by exactly one level: with E_max = 48, one Strassen level's operand sums (≤ 96) now FIT s8, which the s8-range barrier previously blocked at 125+125 = 250 > 127. Two levels (≤ 192) still don't. Residual saving ≤ ~12.5 % of multiplies minus O(n²) add passes — constant-factor, difficulty-absorbed, same disposition as today's ≤ 1.2–1.3× posture. The §A.6 text must be rewritten for v4.2, not silently reused. | **Survives with a parameter-note** (needs spec-text change) |
| **Entropy / no structured shortcut** (I2/I3 corollary) | §4.2: 3.52 bits/element, 5.9×10⁷ bits/operand (44 % of today) — far above every threshold; hard floor stated. | **Survives with floor conditions** |
| **Capacity/bandwidth/working-set gate (§L.4)** | The impossibility proof (verifier-linearity collapse, selection filtering, batch-streaming winner-recompute) nowhere references element width; it binds tighter here (footprint shrinks ~36 → ~20 MiB, AI_opt doubles in ops/byte). Still closed, still not a lever. | **Survives (closure unchanged)** |
| **ASIC/FPGA opening (§S.1/§S.2)** | §4.3: the disclosed §S.2.2 residual widens from ~1.5–2× to an estimated ~2–3×; FPGAs stay ≥ ~13× behind; "AI-native necessity" holds but shifts from *identity* toward *approximation* on hardware that must impose exact-accumulation discipline. | **At-risk (bounded), must be re-disclosed; the top residual risk** |
| **Accumulation bound / field (§B.4, C-13, C-1)** | §4.4: all bounds re-derived, all looser; C-13 asymmetric-bound pattern (n ≤ 8522 correction) re-applied; C-1 vectors must be regenerated at new boundaries. | **Survives; needs-parameter-change (new constants + new vectors)** |
| **§K.2a-WT wall-time majority / §K.2b GO/NO-GO** | SHA floor shrinks ~28 %; tensor volume per nonce identical in MACs but faster on FP4-native parts (shares shift both ways). Unmeasured on any FP4/FP8 part. | **Needs re-measurement (activation blocker, as today)** |
| **Work-unit-neutrality (§L.2.1)** | Format-independent theorem; absolute W_nonce changes don't move economics — only *relative* per-class throughput does, which is the intended change and the thing to measure. | **Survives** |

### 4.2 Entropy — quantified (top-risk question #1)

Per-element and per-operand entropy, uniform sampling:

| | balanced-s8 (today) | F\* (frontier-native) |
|---|---|---|
| Alphabet | 251 values | 11 mantissa values (+ 2 scale bits / 32 elements) |
| Bits/element | log₂251 = **7.97** | log₂11 + 2/32 = **3.52** |
| Bits/operand (n = 4096) | **1.34×10⁸** | **5.91×10⁷** (44 %) |
| XOF bits consumed/element | ≈ 8.16 (251/256 byte-rejection) | ≈ 5.88 (11/16 nibble-rejection + scales) |

What entropy is actually load-bearing for, checked one by one:

- **Freivalds soundness: zero dependence.** Soundness is 2/q per round regardless
  of operand entropy (§2). An adversary who *knows* A and B completely still cannot
  pass with a wrong Ĉ.
- **Full-rank / no low-rank or structured shortcut (I2):** needs only that the
  operand distribution is non-degenerate i.i.d.; the singularity probability is
  2⁻Ω(n) down to even a ±1 alphabet (citations in the table). 3.5 bits/element has
  thousands of bits of margin. **No cliff within any plausible format choice.**
- **Cross-nonce freshness (I1′):** carried by the 256-bit seeds and the PRF, not by
  per-element entropy; unchanged.
- **The real monotone hazard is the *compute* alphabet, not randomness:** as the
  alphabet shrinks toward signs, the workload approaches binary/ternary matmul —
  the regime where XNOR-popcount BNN accelerators and LUT fabrics genuinely excel
  and where the tensor-core-optimality argument (§S.1) fails. F\* (11 values, four
  magnitude levels, 9 % zero mass) is comfortably away from that regime, but this
  fixes the **hard floor**: min-entropy ≥ ~3.4 bits/element, ≥ 4 distinct nonzero
  magnitudes, P(0) ≤ ~10 % (large zero mass would also hand leverage to
  zero-skipping sparse datapaths; at 9 % random zeros, structured-sparsity units —
  which need 2:4 patterns — get nothing, and zero-skipping gains ≤ 9 %,
  difficulty-absorbed). **Never go below w ≈ 3-bit-equivalent mantissas; a
  sign/ternary committed object is categorically rejected.**

**Determination: entropy survives with wide margin at F\*, with the floor above as
a consensus-design constraint.**

### 4.3 ASIC / FPGA / capacity-gate re-derivation (top-risk question #2)

**Capacity gate: unchanged, closed.** §L.4's three lemmas are format-blind
(they operate on verifier asymptotics, nonce-selection PRFs, and 32-byte candidate
state — never on element width). The redesign moves *further* from any gate:
packed operands are ~n²/2 bytes, the enforceable resident set drops toward
~20 MiB, and AI_opt in ops/byte roughly doubles, so every eligible device sits even
further above its ridge. No re-opening.

**FPGA: stays closed, with numbers.** The AI-hardened flagship FPGAs post
133–145 INT8 TOPS (spec §S.2.1). Granting LUT-fabric 4-bit multipliers a generous
2–4× over those hardened-INT8 figures (~300–600 4-bit-TOPS-equivalent), they remain
≥ ~13× behind a single B200's dense FP4 (7,702 TOPS —
[arXiv:2512.02189](https://arxiv.org/html/2512.02189v1)) and ~4.6× behind even a
consumer RTX 5090's dense FP4 (~1,676 TOPS —
[RTX Blackwell whitepaper](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf),
[5090 specs](https://www.spheron.network/blog/nvidia-rtx-5090-specs/)), at worse
TOPS/W. The §S.2.1 conclusion (the FPGA industry's own answer to dense low-precision
GEMM was to harden matmul blocks — no reconfigurability dividend remains) applies
with the same force at 4-bit.

**Bespoke ASIC: the honest weakening, quantified.** The §S.2.2 residual caveat —
"a mining-only tensor chip could strip FP64/graphics/NVLink for a modest cost/watt
edge" — **grows** under the redesign, for two stacking reasons:

1. *Narrower multipliers cheapen bespoke arrays.* Multiplier area/energy scales
   roughly quadratically in operand width; a 4-bit exact-integer MAC array packs
   ~3–4× the MACs/mm² of an 8-bit one. Commodity silicon captures much of the same
   gain (B200 FP4 = 1.96× its own INT8; Rubin doubles tensor width for FP4/FP8
   only — [NVIDIA Rubin blog](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/),
   [SemiAnalysis](https://newsletter.semianalysis.com/p/vera-rubin-extreme-co-design-an-evolution)) —
   so the *ratio* bespoke/commodity moves less than the raw 4×, but it moves.
2. *The exact-integer semantics diverge from the commodity FP4 pipeline.* At INT8,
   the commodity circuit (IMMA) natively computes the consensus arithmetic — the
   "optimal ASIC *is* the AI chip" claim is an identity. At FP4/FP8-with-microscale,
   the commodity unit natively computes *rounded* arithmetic with fractional scales;
   the PoW uses it inside an exactness envelope (§3). On parts with proven FP32
   accumulation and the F\* bounds, the envelope costs ≈ 0 at n = 4096 (single
   pass, full K-dim, no promotion) and the identity nearly holds; on
   narrower-accumulator parts the promotion overhead is real, and a bespoke
   exact-INT4 array pays none of it.

Net assessment: the disclosed residual edge of a mining-only chip widens from
~1.5–2× to an estimated **~2–3× worst case** — still a TPU-class AI-adjacent MAC
array facing frontier-node NRE ($0.5–1.5 B at 3 nm, §S.2.2) against difficulty that
absorbs each commodity generation, and still not reopening participation to SHA
farms, junk cards, or FPGAs. **This is the largest genuine hardness cost of the
redesign.** It is bounded and disclosable, *conditional on frontier FP4/FP8 rates
continuing to track the narrow-multiplier scaling* (they are the industry's entire
current scaling vector — Rubin: FP4/FP8 ~3.5× GB200 while BF16 rises only ~1.6×);
if the frontier ever stopped shipping cheap narrow tensor compute, the bespoke gap
would widen further, which is exactly the condition the roadmap G-1 monitor watches
in the opposite direction. Re-disclosure in the v4.2 edition of §S.2.2 is a
condition of adoption.

### 4.4 Accumulation bounds, field, and the C-13/C-1 interaction

All bounds re-derived for F\* (E_max = 48, U/V over 𝓜 so |u|,|v| ≤ 6):

| Stage | Bound (general) | F\* @ n = 4096 | F\* @ n = 8192 | Today (s8) @ 4096 |
|---|---|---|---|---|
| Base product `C = Â·B̂` | n·E_max² = 2304n | **9,437,184 ≈ 2²³·¹⁷ < 2²⁴** | 1.89×10⁷ ≈ 2²⁴·¹⁷ | 6.4×10⁷ ≈ 2²⁵·⁹ |
| Projections `P = U·Â`, `Q = B̂·V` | n·M_max·E_max = 288n | **1,179,648 ≈ 2²¹·¹⁷** | 2,359,296 | 6.4×10⁷ |
| INT32 ceiling (n_max) | ⌊(2³¹−1)/2304⌋ | **932,067** | — | 137,438 |
| In-block mantissa sum | L·M_max² = 1152 | < 2¹¹ | < 2¹¹ | n/a |
| Full-C aliasing gap vs q | 2·2304n < 2²⁵ ≪ q | ✓ | ✓ | < 2³² ≪ q ✓ |

Consequences:

- **q = 2⁶¹−1 and the exact-INT32 discipline cover everything with ~7× more
  headroom than today.** No field change, no round-count change.
- **The C-13 limb combine gets easier and must be re-pinned.** P/Q entries shrink
  from 15,625n to 288n. The corrected asymmetric-coverage discipline (4 balanced
  base-2⁷ digits reach +63·(128⁴−1)/127 = 133,160,895, hence **n ≤ 8522, not
  8589** — `src/matmul/matmul_v4.cpp::CheckCombineLimbBound`,
  `matmul_v4_field_tests.cpp`) must be re-applied to whatever digit base v4.2
  pins: with 288n, four base-2⁷ digits cover n ≤ 462,364 with the same
  positive-extreme caveat; better, **4 balanced base-2⁶ digits** (digits in
  [−32,31], positive extreme 31·(64⁴−1)/63 = 8,255,527 ≥ 288n for n ≤ 28,665)
  bring the limb-pair GEMM bound down to n·32² = 2²² at n = 4096 — **the entire
  pipeline, combine included, then sits below 2²⁴**, making the whole miner path
  runnable on any device with a proven 24-bit-exact accumulator. (Limb-base choice
  remains miner-local in effect — the fold is byte-identical — but the CPU
  reference must pin one, per C-13.)
- **C-1 vectors must be regenerated, not replayed.** The new boundary regimes are:
  partial sums at exactly the pinned 2^t envelope (2²² limb / 2²³·¹⁷ base at F\*),
  scale-plane extremes (all-blocks-2³ rail operands hitting 2304n), odd-step
  crossings just above the envelope of any *narrower* class one intends to
  exclude, and the E2M1-hole check (no slice/mantissa value of 5 may ever appear).
  A vector set that never enters the new regime certifies nothing — the
  accumulator-eligibility doc's §4 discipline verbatim.

### 4.5 New channels specific to microscaling — audited

- **Low-alphabet lookup evaluation (Four-Russians/Kronrod) against template-scoped
  V — the one genuinely new I1′-adjacent channel.** With |𝓜| = 11, a miner could
  precompute, per k-chunk of t columns, all 11^t combinations `Σ vⱼ·V[k+j,:]`
  (tables depend only on template-scoped V → amortize across the nonce sweep) and
  evaluate `Q = B̂·V` by table lookup, replacing t·m MACs with one lookup + m adds.
  Sized at t = 3, n = 4096, m = 1024: ~15 GiB of tables and, decisively, **~4 KiB
  of random-access table traffic per row-chunk ≈ 23 GB of reads per nonce** vs
  ~16 MiB of operand streaming for the tensor evaluation — the lookup path is
  ~10³× slower than tensor cores on any real memory system (the same
  bandwidth-collapse that kills every §L.4 construction). **Non-viable, but it is
  exactly the "batch-algebra shortcuts over fixed (M, V)" family that Appendix
  C-15 already sends to external review — the review scope must name the
  small-alphabet variant explicitly.**
- **Scale-plane structure as an amortization channel: none found.** Scales are
  PRF-derived per operand per nonce/template exactly like mantissas; a
  template-scoped scale plane on the nonce-fresh B is *not* proposed and MUST NOT
  be introduced (it would be a gratuitous shared-structure risk for zero
  hardware benefit). The segmented product `Σ_blocks 2^{eA+eB}·(M_A^b·M_B^b)` has
  no nonce-invariant factor.
- **Sparsity/zero-skipping:** covered in §4.2 — ≤ P(0) gain, absorbed; keep P(0)
  small.
- **Selection filtering over scales (I8):** scale planes are fixed-size and
  footprint-invariant; no nonce-dependent resource variation exists to grind.

---

## 5. Hard requirements 1 and 4 — core work and the reward ladder

**Req. 1 (MatMul is the core work): preserved.** The per-nonce unit is still one
dense n×n exact matmul (marginal form: expand B̂ + `B̂·V` + combine + digest under
I1′); only the element encoding changed. The enforced shape remains the §K.2b
large dense batched GEMM.

**Req. 4 (scaled-reward ladder): preserved in peak-spec arithmetic; a hypothesis
until measured.** Peak dense throughput on the F\* object (single-pass on FP4, FP8,
and INT8 units — that is the point of the GCD alphabet):

| Class | Best native path | Peak on F\* (dense TOPS) | vs today (INT8 path) |
|---|---|---|---|
| Rubin-class DC (2026/27) | FP4 (NVFP4 unit, scales pinned to 2^e) | ~3.5× GB200's FP4 ([NVIDIA](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/), [SemiAnalysis](https://newsletter.semianalysis.com/p/vera-rubin-extreme-co-design-an-evolution)) | The generation the redesign exists for: INT8 flat/unlisted, FP4 doubled |
| B200/B300 | FP4 | 7,702 ([arXiv:2512.02189](https://arxiv.org/html/2512.02189v1)) | ~2× its own INT8 3,927; B300's INT8 *cut* becomes irrelevant ([Tom's Hardware](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support)) |
| H100/H200 (older DC) | FP8 (E4M3 holds 𝓜 exactly) or INT8 | 1,979 either way | **Unchanged — the backwards-compat tax is relative rate, not extra work** |
| RTX 5090 (consumer) | FP4 | ~1,676 dense ([RTX Blackwell WP](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf)) | ~2× its INT8 838 |
| Trainium2/3 | FP8/MXFP8, **single slice** (vs Ozaki's k² = 4–9) | enters the eligible set for the first time | Previously excluded entirely (no INT8 matmul unit) |
| Apple M5-class | INT8→INT32 (no FP4) | ~110–140 | Unchanged path; **still mines**, earns proportionally less — the intended bottom rung |
| Pre-tensor / CMP / SHA silicon | none | excluded | Unchanged |

The INT8-chip "backwards-compat tax" is architecturally mild by construction:
mantissas ≤ 6 and dequantized values ≤ 48 fit s8, so an INT8 part runs either the
(mantissa GEMM + exact shift-fold) or a single plain s8 GEMM on pre-shifted
operands — no k²-slice emulation, only the loss of the 2× narrow-format rate it
never had. The ladder therefore *steepens toward the frontier* (Rubin ≫ B200 >
H100 ≈ today > consumer FP4 > consumer INT8 > M-class) — which is the stated
intent, and is the scaled-reward outcome, not exclusion: every current INT8 miner
keeps mining at approximately current throughput while frontier parts pull ahead.

**Mandatory caveat (repo posture):** per-nonce ordering is decided by measured
wall-time, not peak TOPS — the SHA floor shrinks ~28 % (helps), the FP4 tensor
stage speeds up ~2× on FP4 parts (shrinks the tensor share), promotion/fold
overhead lands on non-tensor units (erodes it). Two prior peak-based ordering
claims in this program were falsified on real silicon (§K.2b). **The §K.2a-WT
wall-time-majority and §K.2b GO/NO-GO gates must be re-run on physical FP4/FP8
silicon (B200/B300-class + a 5090-class consumer anchor + an H100-class INT8
legacy anchor) before any ordering claim ships.** Until then, req. 4 is
*preserved-as-hypothesis* — the same epistemic status the current INT8 ordering
holds under ACTIVATION B2g.

---

## 6. Consensus-change classification and migration (what this IS, honestly)

**Classification: COMMITTED-OBJECT CHANGE → HARD FORK (a v4.2).** Roadmap §3.4 rows
3–4 already classify this exactly: "changing the committed object … or the operand
field to suit a new accumulator width — CONSENSUS FORK; alters the verified object
and every golden vector." For the same header, the new derivation produces
different operands → different Ĉ → different digest: old and new nodes reject each
other's blocks unconditionally. This is categorically different from the miner-only
Ozaki path (`btx-matmul-v4-exact-int-on-float.md` §5), which produces byte-identical
committed objects and touches zero consensus surface.

**What migrates (the fork surface):**

| Item | Change |
|---|---|
| Operand/projector derivation (§A.2/§H.4 family) | New XOF alphabet sampling (𝓜 rejection rule), new scale-plane derivation, new domain tags (e.g. `"BTX_MATMUL_SEED_V42"`); U/V re-specified over 𝓜 |
| Consensus constants | E_max, 𝓜, L, 𝓔/e_max, limb base + `CheckCombineLimbBound` replacement (with the §4.4 asymmetric-extreme discipline), `kElementSqBound` successor |
| Golden vectors & C-1 adversarial vectors | **All regenerated** at the new magnitude boundaries (§4.4); cross-vendor set re-pinned on real silicon (ACTIVATION B2a analogue), now including FP4/FP8-path devices |
| Difficulty | One-time ASERT rescale to the measured new marginal unit (ACTIVATION B2b analogue); nonce-rate re-benchmark per class |
| Activation | Height-gated (`nMatMulV42Height`-style), with the full measurement-gated tracker discipline (B2a–B2g analogues) re-run on the new format |
| Backend kernels & self-tests | All backends re-implement expansion + (mantissa, scale) GEMM path; determinism self-tests extended with §3/§4.4 boundary vectors |
| Disclosure | §S.2.2 ASIC-residual re-disclosure (§4.3); ρ (§S.4.6) re-measured on FP4-rental centrals; §A.6 Strassen note rewrite; public docs |
| External review | The I1′/C-15 adversarial review MUST cover the new format (small-alphabet batch algebra, §4.5) — it remains a mainnet blocker |

**What does NOT migrate (the invariant core):** the verifier *structure*
(`SketchFreivalds`'s algorithm and its O(n²) cost), `q = 2⁶¹−1`, R = 3, the sketch
shape m = n/b and the 8 MiB payload (at unchanged n = 4096, b = 4), the digest form
`H(σ‖Ĉ)`, the Fiat–Shamir rule, the 182-byte header, the DoS-budget framework, the
§L.4 capacity-gate closure, §O.2 pooling, the work-unit-neutrality theorem, the
price-independence rule (§0.7-(4)), and the generalized C-1 discipline.

**Honest cost statement.** This is a second v4-scale migration: every measurement
gate re-opened, every golden vector regenerated, every backend re-validated, a new
external-review round, pool/miner ecosystem re-tooling, and the ordinary hard-fork
coordination risk — on top of a pipeline whose *current* form has not yet cleared
its own activation gates. The one mercy is that the verifier, payload plumbing, and
economic theorems carry over unchanged, so the fork is "new operands into the same
machine," not a redesign of the machine.

---

## 7. Recommendation — frontier-native object vs the miner-only Ozaki path

**Do not fork now. Stage it.**

1. **Now:** ship v4.1 on the exact-INT8 committed object. The INT8 ordering still
   holds in absolute TOPS on current silicon (roadmap §3.2 conclusion 1), and the
   v4.1 gates (B2g measurement, C-15 review) are already the critical path — do
   not stack a hard fork on an unactivated design.
2. **Bridge (zero consensus risk):** the miner-only Ozaki path
   (`btx-matmul-v4-exact-int-on-float.md`). It lets FP-only silicon (Trainium,
   FP4-heavy NVIDIA) mine the *existing* committed object at (FP TOPS)/k²
   (÷4 at FP8, ÷9 at FP4). That tax is real and growing — which is precisely the
   quantified case for the redesign — but it buys frontier participation with no
   fork, no new hardness surface, and no new review burden.
3. **v4.2 trigger:** adopt the frontier-native object only when BOTH hold:
   (a) the roadmap **G-1 decoupling trigger** fires on shipped silicon — INT8
   flat/cut while frontier FP4/FP8 ≥ 2× across a generation. Rubin's published
   posture (FP4/FP8 ~3.5× GB200, BF16 ~1.6×, INT8 unlisted) is most of the way to
   firing it; confirm on silicon (R-1) rather than on launch slides; and
   (b) the redesign's own **measured GO/NO-GO passes** on real FP4/FP8 hardware
   (§5), with every §8 condition satisfied. If (a) fires and (b) fails, the honest
   fallback is the Ozaki bridge plus difficulty absorbing the k² tax — a worse
   ladder, but no security regression.
4. **Why the redesign is worth holding ready rather than rejecting:** unlike the
   Ozaki bridge it eliminates the k² tax (single-pass on E2M1/E4M3/s8 alike),
   re-admits FP32-accumulate hardware by bound (§4.4), *shrinks* the SHA floor, and
   keeps every soundness/verification property bit-for-bit (§2). Its costs — the
   ~2–3× ASIC residual (§4.3), the halved-but-ample entropy (§4.2), and a full
   hard fork (§6) — are real but bounded and disclosed. On this review's analysis,
   **no hard requirement or §C invariant is *broken* by the redesign; the risks
   are parameterizable and measurable, not structural** — which is what
   distinguishes it from every capacity-gate/bandwidth proposal §L.4 closed.

**Bottom line: WITH-CONDITIONS approve as a designed, shelf-ready v4.2 contingency;
reject as an immediate change.** The v4 program's security rests on measurement
gates and structural invariants; this redesign passes the structural test on paper
and must now be held to the same measurement bar as everything else in the program.

---

## 8. Conditions ledger (all normative for any v4.2 adoption)

| # | Condition | Anchor |
|---|---|---|
| 1 | Scales are powers of two ONLY (E8M0-style), consensus-pinned small exponent range (F\*: e ∈ [0,3]); fractional (E4M3-valued) scales and FP32 tensor-scales excluded from the committed object; hardware scale registers must be fed exactly-representable 2^e values | §3 |
| 2 | Mantissa alphabet: exact-integer subset common to E2M1/E4M3/s8 (F\*: {0,±1,±2,±3,±4,±6}); min-entropy ≥ ~3.4 bits/element; ≥ 4 nonzero magnitudes; P(0) ≤ ~10 %; sign/ternary objects categorically rejected | §4.2 |
| 3 | Generalized C-1 eligibility ("no rounding on the committed path, integer or float unit"), with regenerated adversarial vectors at the new §4.4 boundaries; a vector set that never enters the new regime is not a PASS | §3, §4.4 |
| 4 | Accumulation/limb bounds re-pinned with the asymmetric-positive-extreme discipline (the n ≤ 8522-style correction) for the chosen digit base; recommended: keep the full pipeline < 2²⁴ at n = 4096 (base-2⁶ limbs) to widen eligibility by bound | §4.4 |
| 5 | Freivalds surface untouched: q = 2⁶¹−1, R = 3, sketch shape, digest form, Fiat–Shamir rule; verification re-benched ≤ current budget (expected cheaper) | §2 |
| 6 | Scale planes derive from the same seed/scope as their operand; no template-scoped structure on B's plane | §4.5 |
| 7 | §K.2a-WT wall-time majority + §K.2b GO/NO-GO re-measured on real FP4/FP8 silicon (frontier DC + consumer FP4 + legacy INT8 anchors) before any ordering claim; peak-TOPS arguments advisory only | §5 |
| 8 | I1′/C-15 external adversarial review extended to small-alphabet batch algebra over fixed (P, V); remains a mainnet blocker | §4.1, §4.5 |
| 9 | §S.2.2 ASIC-residual and §A.6 Strassen-level re-disclosure in the v4.2 spec edition; ρ re-measured on FP4 rental centrals | §4.3, §4.1 |
| 10 | Full hard-fork machinery per §6 (activation height, golden vectors, ASERT rescale, backend re-qualification, public docs) | §6 |

## 9. Confidence per major claim

| Claim | Confidence | Basis |
|---|---|---|
| Freivalds soundness/O(n²)/challenge derivation preserved exactly | **High** | Format-blind proof (§2); every property re-verified against the pinned code surface (`matmul_v4.h::SketchFreivalds`, `pow_v4.h`) |
| Determinism with power-of-two scales; fractional scales must be excluded | **High** | Identity-on-representables theorem + per-op enumeration (Ozaki doc §2, machine-checked pattern); OCP MX / NVFP4 format facts cited |
| Sub-2²⁴ envelope makes FP32-accumulate hardware eligible by bound | **High (arithmetic), Medium (real-device behavior)** | Bounds are exact; device t-values must still be proven per class (DeepSeek t≈14 precedent) |
| Entropy sufficiency at ≥ 3.4 bits/element | **High** | Exponential singularity bounds (Tikhomirov, Bourgain–Vu–Wood); all entropy-dependent surfaces enumerated |
| ASIC residual bounded at ~2–3×, FPGA closed | **Medium** | Scaling arguments + cited commodity FP4 rates; conditional on frontier FP4 continuing to scale; not measurable pre-silicon |
| Capacity gate stays closed | **High** | §L.4 lemmas are format-independent; footprint/AI move the wrong way for any gate |
| Reward-ladder ordering on the new format | **Low-Medium (hypothesis)** | Peak-spec only; two prior falsifications in this program; gated on measurement (condition 7) |
| Hard-fork classification and migration surface | **High** | Roadmap §3.4 rows 3–4; enumerated against the actual consensus constants in `src/matmul/` |

## References

Spec sections: `btx-matmul-v4-design-spec.md` §0.7, §A.2/§A.6, §B.4/§B.6, §C,
§D.2–D.5, §E.1–E.3, §K.2a/K.2b/K.4, §L.2.1/§L.4, §S.1–S.4, Appendix C-1/C-13/C-15,
Appendix D. Code: `src/matmul/matmul_v4.h`, `src/matmul/matmul_v4.cpp`
(`CheckCombineLimbBound`), `src/matmul/pow_v4.h`,
`src/test/matmul_v4_field_tests.cpp`, `src/test/matmul_v4_batch_tests.cpp`.

External:
[OCP Microscaling Formats MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) ·
[OCP OFP8 v1.0](https://www.opencompute.org/documents/ocp-8-bit-floating-point-specification-ofp8-revision-1-0-2023-12-01-pdf-1) ·
[NVIDIA — Introducing NVFP4](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/) ·
[cuDNN block scaling](https://docs.nvidia.com/deeplearning/cudnn/frontend/latest/operations/BlockScaling.html) ·
[NVFP4 vs MXFP4 guide (Spheron)](https://www.spheron.network/blog/nvfp4-vs-mxfp4-gpu-cloud-4bit-quantization-guide/) ·
[Pretraining LLMs with NVFP4 (arXiv:2509.25149)](https://arxiv.org/html/2509.25149v1) ·
[Blackwell microbenchmarks (arXiv:2512.02189)](https://arxiv.org/html/2512.02189v1) ·
[NVIDIA Rubin platform blog](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/) ·
[SemiAnalysis — Vera Rubin](https://newsletter.semianalysis.com/p/vera-rubin-extreme-co-design-an-evolution) ·
[Tom's Hardware — Blackwell Ultra NVFP4 at the cost of INT8](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support) ·
[RTX Blackwell architecture whitepaper](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf) ·
[RTX 5090 specs (Spheron)](https://www.spheron.network/blog/nvidia-rtx-5090-specs/) ·
[DeepSeek-V3 (arXiv:2412.19437) §3.3.2 — 14-bit FP8 tensor-core accumulation](https://arxiv.org/pdf/2412.19437) ·
[Fasi–Higham–Mikaitis–Pranesh — Numerical behavior of NVIDIA tensor cores](https://peerj.com/articles/cs-330/) ·
[Ozaki–Ogita–Oishi–Rump 2012](https://doi.org/10.1007/s11075-011-9478-1) ·
[ozIMMU (arXiv:2306.11975)](https://arxiv.org/abs/2306.11975) ·
[FP64 emulation on FP8 tensor cores (arXiv:2508.00441)](https://arxiv.org/abs/2508.00441) ·
[Tikhomirov — Singularity of random Bernoulli matrices (Annals 2020)](https://arxiv.org/abs/1812.09016) ·
[Bourgain–Vu–Wood — Singularity of discrete random matrices (JFA 2010)](https://arxiv.org/abs/0905.0461) ·
[Deterministic FP noise structure (arXiv:2511.00025)](https://arxiv.org/pdf/2511.00025).
