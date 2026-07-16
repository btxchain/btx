# BMX4-C (MatMul v4.2) — Lead Adversarial Review (C-15 internal)

*Reviewer: lead (hands-on). Scope: the ENC-BMX4C committed-object encoding as of
commit `1a54d73` (`src/matmul/matmul_v4_bmx4.{h,cpp}`, the unchanged verifier core
it reuses, and the consensus params). Companion lens reports:
`btx-matmul-v4.2-audit-hardness.md` (lens A), `btx-matmul-v4.2-audit-determinism-dos.md`
(lens B). Date 2026-07-16.*

> **This is a rigorous internal adversarial review. It de-risks and SCOPES the C-15
> gate; it does NOT close it.** A matmul-hardness *lower bound* cannot be established
> by any single reviewer (human or otherwise) — the value of the external C-15 review
> is diverse, independent cryptographic eyes. This document states exactly what an
> internal review can and cannot settle, and hands the external reviewers a concrete,
> sharpened scope.

## 1. Methodology (grounded in how real crypto/consensus audits are run)

Drawn from Trail of Bits' invariant-driven methodology (codify properties that must
*always* hold, then test them), Hacken's cryptography-audit methodology (nonce/seed
generation, canonical encoding, malleability, forgery resistance), and the
specification-anchored / differential-testing literature. Tactics applied here:

1. **Invariant codification + checking** — enumerate the properties that must hold and
   check each against the code (not against the code's own asserts).
2. **Independent oracle / differential testing** — recompute the pinned constants and
   the sampler bijection from the *spec* in a separate tool (Python) and diff against
   the implementation; cross-check the independent code paths that must agree.
3. **Manual line-by-line review** of the core artifact + spec↔implementation conformance.
4. **Adversarial probing** — seed/nonce derivation, canonical F_q encoding, replay /
   malleability, forgery via the Freivalds soundness margin, concrete counterexample
   construction.

## 2. Trust assumptions / architecture

The committed object is an **exact integer** matmul sketch `Ĉ = U·C·V ∈ F_q^{m×m}`,
`q = 2⁶¹−1`, verified by the **UNCHANGED** O(n²) sketch-Freivalds (design L0 fixed
core). ENC-BMX4C changes only the operand *encoding*: mantissas in `M11 =
{0,±1,±2,±3,±4,±6}` × a per-32-block power-of-two (E8M0) scale for A/B; scale-free M11
for U/V. Determinism rests on **no operation ever rounding** on the committed path
(all integer). Verification is compute-path-agnostic: it regenerates the *dequantized*
integer operands and runs the same verifier regardless of how a miner computed `Ĉ`.

## 3. Findings

Severity: Critical / High / Medium / Low / Info. Each verified by me against the code
and/or the independent oracle.

### Consensus-safety / determinism — CLEAN (verified hands-on)

- **INV-1 (sampler exactness) — HOLDS.** `SampleMantissaNibble` / `kMantissaTable`:
  my independent oracle reproduced the E2M1 decode and confirmed **exactly 11 accepted
  / 5 rejected**, rejected nibbles `{1,3,8,9,11}` = `{±0.5,±1.5,−0}`, accepted value set
  `= M11`, and the map is **bijective** (each M11 value from exactly one nibble) ⇒ the
  post-rejection distribution is **uniform over M11**. This is the distribution the
  hardness/entropy analysis assumes — now verified, not trusted.
- **INV-2 (dequant range) — HOLDS.** `Dequant(μ,e) = μ·2^e`, `μ∈M11 (|·|≤6)`, `e∈{0,1,2,3}`
  ⇒ `|Âhat|≤48 < 128`; the `int8_t` cast is lossless. `ExpandScaleStream` emits only
  `e∈{0,1,2,3}` (2-bit `&0x03`), so `2^e∈{1,2,4,8}` — no out-of-range exponent.
- **INV-3 (no float on the committed path) — HOLDS.** Confirmed by read + lens B grep.
- **INV-4 (E8M0 exactness) — HOLDS.** Dequant is a pure integer shift; it never touches
  a mantissa bit, so it is exact under any rounding scheme (the no-rounding theorem).
- **Sampler stream separation — HOLDS.** Mantissa (`'m'`=0x6D) and scale (`'e'`=0x65)
  planes use distinct XOF domain bytes, both distinct from int8_field's `'s'/'q'` — a
  seed can never produce correlated mantissa/scale/s8/Fq keystreams.
- **Scale-plane orientation — CORRECT.** A: scale indexed `[i][k/32]` (block along the
  columns = contraction); B: `[k/32][j]` (block along the rows = contraction). Both
  index the contraction dimension, matching the base product's contraction (this is the
  same orthogonality the CUDA backend relies on to apply E8M0 as an exact shift).
- **Combine decomposition totality — VERIFIED.** `DecomposeLimbPlanesBMX4C` (base-2⁶,
  remainder-top): my oracle checked 200k random values + the extremes ±(2²³−1) and
  ±288·{4096,8192}: **0 defects**, every value reconstructs exactly, low digits in
  [−32,31], top digit provably in **[−32,32]** (max observed 32). `CheckCombineLimbBoundBMX4C`
  (`288n ≤ 2²³−1 ⇒ n≤29,127`) is correct and tight; the corrected extreme constant
  **8,255,455** matches (the redesign doc's 8,255,527 is off by 72 — the code fixed it).
- **Canonical encoding / no aliasing — HOLDS.** `ParseSketch` rejects words `≥ q`; the
  combine weights `2^{6(i+j)}` (max exp 36 < 61) are canonical; `ComputeCombineModQ`
  yields unique canonical residues.
- **The committed digest is base-independent — GOOD (positive finding).** `ComputeDigestBMX4C`
  commits `Ĉ = ComputeCombineModQ(P,Q)` (direct integer combine), *not* the base-2⁶ limb
  path. So the digit base is **not a consensus-object parameter** — it is purely a
  tensor-hardware decomposition (`ComputeCombineLimbTensorBMX4C`) that must *reproduce*
  the committed residues (test-enforced, and the reason base-2⁶ is chosen: it keeps the
  limb-pair GEMMs at ≤1024n = 2²² < 2²⁴, exact on a proven-t=24 FP4 accumulator, whereas
  base-2⁷ hits 2²⁴). This is a cleaner separation than the design prose implied.

### Sharp edges / hardening (Low / Info)

- **F-L1 (Info, documented constraint — NOT a bug):** the base product `|C| ≤ 2304n`
  exceeds 2²⁴ at **n=8192** (18,874,368 > 16,777,216), so a hypothetical *direct-C*
  FP-native evaluation would be ineligible-by-bound at n=8192. The code **correctly never
  forms C** on the committed miner path; the marginal GEMMs it does form (P/Q ≤288n,
  limb-pairs ≤1024n) stay < 2²⁴ even at n=8192. Recommendation: state this explicitly in
  §2.4/§4 (FP-native eligibility-by-bound is a property of the **marginal** unit, not of
  a direct C) so no future backend forms C on an FP unit at n=8192.
- **F-L2 (Low, defense-in-depth):** `ComputeDigestBMX4C` reuses the `"BTX_MATMUL_V4"`
  digest domain tag. Safe today (ENC-S8/ENC-BMX4C are height-disjoint with different
  operands and different `hashPrevBlock`→σ, so no cross-profile collision or replay —
  and under the unified direct-to-v4.2 model, `nMatMulBMX4CHeight == nMatMulV4Height`,
  ENC-S8 has no public height interval at all, which only strengthens this), but
  an explicit per-profile digest domain tag is a clean one-line hardening to decide at
  fork time (also flagged by the foundation implementer).
- **F-L3 (Low, defense-in-depth — my verifier-core finding):** `VerifySketchBMX4C` (like
  the v4.1 `VerifySketch`) does not guard `rounds == 0`, while `SketchFreivalds` returns
  `true` unconditionally for `rounds == 0`. Not exploitable (`rounds` is a fixed consensus
  param, never 0, never attacker-controlled), but the verifier should fail-closed on
  `rounds == 0` to match `ComputeDigest`'s guard.
- **F-L4 (Low, from lens B):** `DecomposeLimbPlanes*` drops the remainder with no
  hot-loop assert; totality rests on the bound gate. Add a debug assert. The v4 payload
  cap is ~32× the exact size (backstopped by `ParseSketch`'s O(1) size reject — not
  exploitable); tighten it.

### Hardness — the genuine open questions (from lens A, verified as characterizations)

- **F-H1 (High): the anti-amortization / marginal-work floor is an ASSUMPTION, not a
  theorem.** Template-scoping A/U/V makes the per-nonce unit "apply the *fixed* rank-m²
  linear operator `B ↦ P·B·V` to a stream of pseudorandom B." The proven work floor is
  only Ω(n²) (must read B); the *claimed* floor is Θ(n³). This is precisely "no known
  algorithm ≠ lower bound." **→ external cryptographers.**
- **F-H2 (High): a real, cited sub-cubic/LCMA advantage on the combine** (~80% of the
  unit): peak-breaking GEMM (FalconGEMM, 2026) already beats vendor peak ~15–18% at these
  dimensions; the "one Strassen level / ≤12.5%" cap is a narrow-datapath artifact. Small
  and difficulty-absorbable today, unbounded in principle, larger on bespoke silicon.
- **F-H3 (Med): entropy margin is boundary-tight** (3.46 vs the 3.4-bit floor); the M15
  reserve alphabet is the lever if the external review demands slack. (My oracle confirms
  the M11 sampler is uniform, so the per-element entropy is the clean `log2(11)=3.459`
  bits, consistent with the tight-margin characterization.)

## 4. Verdict

- **Consensus safety / determinism / soundness: CLEAN.** No break, no consensus-split,
  no practical DoS. Soundness (Freivalds ≤2/q per round, R=3 ⇒ ≤2⁻¹⁸⁰, Fiat–Shamir
  binding σ+H(payload)+round) is a genuine theorem and survives the encoding change
  unchanged. The reference is exact-integer, the sampler is exact and uniform, the
  combine decomposition is total, and verification is compute-path-agnostic. My
  independent oracle confirmed every pinned constant.
- **Hardness: OPEN by design, not breakable-by-this-review.** The marginal-work floor
  (F-H1) and the sub-cubic advantage (F-H2) are the real C-15 substance; both are
  assumption-not-theorem and MUST go to external human cryptographers. The narrower BMX4-C
  alphabet makes this review *firmer* than for v4.1 (tighter entropy, sub-cubic on the
  combine).
- **Actionable now:** F-L1 (document the n=8192 direct-C constraint), F-L2 (profile digest
  tag), F-L3 (rounds==0 fail-closed), F-L4 (decompose assert + payload cap). None block
  the CPU reference; all are cheap hardening.

**External C-15 scope (sharpened):** (1) the fixed-operator / preprocessed-one-argument
lower bound behind F-H1; (2) a *measured* LCMA-combine advantage (F-H2) before the ASERT
rescale; (3) the M11-vs-M15 entropy-margin decision (F-H3); (4) batch algebra over the
fixed (P,V). Plus the standing gate: the on-silicon **M-t24** accumulator-exactness
measurement (throughput-only for safety, but it decides native-path eligibility).
