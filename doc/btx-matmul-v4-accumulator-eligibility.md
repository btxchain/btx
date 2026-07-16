# BTX MatMul v4.1 — True-Integer-Accumulator Backend Eligibility (C-1)

*Status: NORMATIVE backend-eligibility rule + its enforcing test vectors.
Consensus-PROTECTING, not consensus-changing: nothing here alters `q`, `n`, `b`,
the committed sketch/digest, or the Freivalds verifier. Companion to
`doc/btx-matmul-v4-multiplatform-roadmap.md` §4.1 (the flaw) and §5 item C-1
(this fix), and to the design spec `doc/btx-matmul-v4-design-spec.md` §B.4/§B.6.
Code-level statements of the invariant live in `src/matmul/int8_field.h`
(`kRequiredAccumulatorBits`, `kFp32MantissaAccumulatorBound`,
`AccumulatorWidthEligible`) and `src/matmul/matmul_v4.h` (C-13 limb-combine
warnings). Written 2026-07-16.*

---

## 1. The invariant (normative)

> **Every accelerated backend MUST perform ALL v4 INT8-matmul accumulations —
> the base product `C = A·B`, the projections `P = U·A` and `Q = B·V`, and each
> of the 16 Appendix C-13 limb-pair GEMMs — in a TRUE two's-complement INTEGER
> accumulator at least 32 bits wide (`matmul::int8_field::kRequiredAccumulatorBits`).
> A device whose "INT8 matmul" accumulates into a floating-point-mantissa-bounded
> register — exact only up to 2²⁴ = 16,777,216, e.g. the FP32-mantissa MXU of
> Google TPU v4 — is INELIGIBLE for every v4 stage and MUST NOT be flagged
> mining-capable.**

The spec's exactness argument (§B.6-(1): "`s8×s8→s32` MMA is exact … given §B.4
no accumulator wraps") is true **only** on hardware that satisfies this
invariant. On FP-mantissa-bounded hardware the phrase "int8 matmul" is
marketing, not arithmetic: partial sums past 2²⁴ are silently rounded, the
committed integers change, the digest changes — a chain split, not a slowdown
(roadmap §4.1). The invariant is therefore a *precondition* the current spec
text silently assumed; this document and the code comments make it explicit,
and the vectors in §4 make it *tested*.

Note the last clause of the code-level predicate: `AccumulatorWidthEligible`
is meaningful only for genuine integer accumulators. An FP accumulator does not
qualify at **any** nominal register width — its exact-integer range is the
mantissa (2²⁴ for FP32), not the register (32 bits).

## 2. The magnitude math (why 2²⁴ is inside the workload, not headroom)

All bounds below are the spec's own (§B.4, Appendix C-13); operands are
balanced s8 in [−125, 125], limb digits are balanced base-2⁷ in [−64, 63].

| Stage | Per-entry accumulated bound | At n = 4096 (mainnet) | At n = 8192 (retarget) |
|---|---|---|---|
| Base product `C = A·B` | `n·125²` = 15,625·n | **6.4×10⁷** ≈ 2²⁵·⁹ | 1.28×10⁸ ≈ 2²⁶·⁹ |
| Projections `P = U·A`, `Q = B·V` | `n·125²` = 15,625·n | **6.4×10⁷** | 1.28×10⁸ |
| C-13 limb-pair GEMM `S_ij` | `n·64²` = 4,096·n | **exactly 2²⁴** (16,777,216) | **2²⁵** (33,554,432) |

Facts that follow:

- **The FP32-mantissa ceiling (2²⁴) sits at or below every stage's peak on the
  exact dimension window v4 targets (n = 4096–8192).** The limb-pair combine
  hits it *exactly* at mainnet n = 4096 — the limb path is *less* portable than
  the base GEMM, not more.
- Everything stays below 2³⁰ (base/projections, `CheckAccumulationBound`) and
  2³¹ (limb pairs, all header n ≤ 65,535), so a **true 32-bit** integer
  accumulator is sufficient for every stage: 32 bits is the eligibility floor.
- **Random operands never get near the ceiling** — XOF-uniform balanced-s8
  dot products concentrate around ±5,250·√n (≈ 2²¹ worst observed entry at any
  header dimension), and limb-pair entries around ±1,365·√n ≈ 2¹⁷. This is why
  the pre-C-1 golden vectors (generated on true-int32 NVIDIA/AMD/Apple silicon,
  ACTIVATION B2a) would **never catch** an FP32-mantissa accumulator: a
  mis-accumulating device passes them by luck, then diverges at whatever future
  block first needs the regime — or, worse, never diverges on-chain data but
  cannot be *proven* conforming. Adversarial vectors are required.

## 3. Platform pass/fail under the invariant

From the roadmap §2 feasibility matrix (citations there):

| Platform | True ≥32-bit integer accumulator? | Eligible? |
|---|---|---|
| NVIDIA Turing→Blackwell (IMMA `mma.*.s32.s8.s8.s32`) | Yes, true int32 | **Yes** (self-test still required, §N.3-v) |
| AMD CDNA MI100–MI35x (MFMA `i8i8i32`) | Yes, true int32 | **Yes** |
| Apple M5 Neural Accelerators (Metal 4 INT8 TensorOps, INT8→INT32) | Yes | **Yes** |
| Google TPU v5e/v5p, v6e, v7 | Yes — true int32 MXU accumulator | **Yes** (pending C-1 vectors on real silicon, M-2) |
| **Google TPU v4** | **No — FP32-mantissa-bounded (2²⁴)** | **NO — INELIGIBLE.** Would silently round `C`/`P`/`Q` (peak 6.4×10⁷) and the limb combine (2²⁴ at n = 4096) |
| AWS Trainium2/3 | No integer matmul unit at all (float-only systolic) | **No** (different failure: no INT8 path; see roadmap O-1) |
| Tenstorrent / Gaudi 3 | Claimed INT8; accumulator width **unverified** | **Unknown — must pass the C-1 vectors before onboarding** |

The existing eligibility classifiers (`backend_capabilities_v4.h` §S.1) already
gate on *having* an integer tensor path; the C-1 vectors additionally verify the
*accumulator width behind* that path empirically, so a future backend (TPU,
Tenstorrent, Gaudi) cannot be onboarded on datasheet claims alone.

## 4. How the adversarial vectors enforce it

`src/test/matmul_v4_backend_determinism_tests.cpp`, test cases
`high_magnitude_*` — the normative C-1 adversarial golden-vector set, run by
`contrib/matmul-v4/verify-backend.sh` as part of the standard PASS gate:

- **HM-A `high_magnitude_base_product_regime`** — saturating ±125-rail operands
  at n = 1088 (the smallest b=4-compatible n with 15,625·n > 2²⁴) force **every**
  entry of `C` to exactly ±17,000,000 ∈ (2²⁴, 2³¹); the accumulator's partial
  sums climb in **odd** steps of 15,625 and cross 2²⁴ (where FP32 spacing is 2),
  so an FP32-mantissa accumulator **must** round. The high-magnitude `C` is then
  pushed through all three consensus-equivalent sketch paths (full-C `U·C·V`,
  direct `P·Q mod q`, C-13 limb-tensor) with byte-equality plus
  serialize/parse/digest round-trips required. At mainnet n = 4096 the same rail
  operands reach the §B.4 peak 6.4×10⁷; n = 1088 lands in the identical rounding
  regime while keeping the Θ(n³) reference affordable in CI.
- **HM-B `high_magnitude_projected_gram_regime`** — **real XOF-derived operands
  at the mainnet n = 4096** (genuine `ExpandOperand` matrices from pinned
  seeds). The projector is a Gram slice of the operand itself (U rows = columns
  of A; V columns = rows of B — every entry a genuine balanced-s8 value), so
  `P[r][col_r] = Σᵢ A[i][col_r]²` and the mirrored `Q` entries are sums of
  squares ≈ 5,250·4,096 ≈ 2.15×10⁷ > 2²⁴. Sixteen such accumulations are pinned
  to golden int32 constants (21,133,642…22,147,078 — generated on the true-int32
  CPU reference and re-derived in-test via int64), and the resulting
  past-2²⁴-valued `P`/`Q` are pushed through the C-13 limb combine, exercising
  the top base-2⁷ digit plane (d₃ ≠ 0). This is the "danger zone from the real
  derivation" vector.
- **HM-C `high_magnitude_limb_pair_boundary_regime`** — drives the limb-pair
  GEMM itself to its accumulator peak: all-64 inputs (digits (−64, +1)) make
  `S₀₀` accumulate to **exactly n·64² = 2²⁴ at n = 4096** and **2²⁵ at
  n = 8192**; all-65 inputs (digit −63) at n = 4352 accumulate 17,273,088 > 2²⁴
  in **odd** steps of 3,969 (deterministic FP32 rounding, not data-dependent);
  negative-side (−2²⁴ → canonical residue q − 2²⁴), inputs-above-2²⁴, and the
  §K.2b stacked-combine shape are covered. Every sub-case asserts the exact
  analytic canonical residue *and* limb-vs-direct byte-equality.

Enforcement chain:

1. **CPU (consensus reference):** the vectors pass by construction — verified
   at generation time on true-int32 hardware; every assertion is an
   analytically-derived exact integer or cross-path byte-equality.
2. **Backend onboarding (roadmap M-2):** a backend may be flagged
   mining-capable only after replaying the determinism suite **including these
   vectors** bit-for-bit (spec §N.3-v posture). An FP32-mantissa device fails
   them deterministically and loudly.
3. **`verify-backend.sh`:** any divergence is the existing hard **FAIL**
   (consensus-split signal), now annotated with the accumulator-width
   diagnosis; additionally the script FAILs if the `high_magnitude_*` cases did
   not run at all — a log that never entered the regime certifies nothing about
   accumulator width and must not be recorded as PASS.
4. **Runtime safety net (unchanged):** even a mis-gated device cannot split the
   chain — `accel_v4.h`'s dispatcher re-verifies every device result with the
   O(n²) sketch-Freivalds check and falls back to CPU. C-1 exists so such a
   device is caught at *qualification time* with a clear diagnosis, instead of
   burning 100 % of its throughput on rejected results (or being trusted on the
   strength of vectors that never exercised its failure mode).

## 5. What this deliberately does NOT do

- No change to `q = 2⁶¹−1`, `n`, `b = 4`, the limb base 2⁷, the committed
  sketch bytes, the digest rule, or `VerifySketch` — the committed integers for
  every existing header are bit-identical before and after this change.
- No change to the O(n²) Freivalds verification requirement (spec §D/§E.2).
- No change to backend admissibility *classifiers* (`ClassifyCudaDevice` etc.);
  the invariant tightens what a *future* classifier/onboarding must check
  (e.g. a `Kind::TPU` probe MUST distinguish v4 from v5e+, roadmap T-1) and
  gives it an empirical test to prove it.
- Accumulator-width-*parametric* limb decompositions (narrower limbs for
  narrower true-integer accumulators) remain possible miner-side without a
  consensus change and are tracked separately (roadmap L-1). They do not rescue
  FP-mantissa hardware for the base/projection GEMMs, whose 6.4×10⁷ peak is
  fixed by consensus operands.
