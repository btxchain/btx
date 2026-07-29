> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.1 — Exact-Integer-on-Float (Ozaki-Scheme) Miner Path

*Status: MINER-SIDE reference implementation + numerical proof. Companion to
`doc/btx-matmul-v4-design-spec.md` (the spec, authoritative — UNCHANGED by this
document), `doc/btx-matmul-v4-multiplatform-roadmap.md` §3.3 Option C / backlog
O-1 (the design brief this delivers), and `ACTIVATION.md`. Written 2026-07-16.*

*Code: `src/matmul/matmul_v4_exact_float.{h,cpp}` (CPU reference of the
decomposition/recombination pipeline), `src/test/matmul_v4_exact_float_tests.cpp`
(byte-identity suite). Per spec §0.7-(4) nothing here reasons from token or
market price; all hardware framing is throughput-only.*

---

## 1. Why this exists, and the enabling insight

The AI frontier is leaving INT8 (roadmap §3.2): Blackwell Ultra **cut INT8** to
fund NVFP4; Rubin doubles tensor width **only for FP4/FP8**; AWS Trainium 2/3
have **no INT8 matmul unit at all**; the frontier low-precision formats are
FP8/FP4/microscaling. If the PoW is mineable only on native-INT8 tensor cores,
"reward scales with AI compute" decouples over 2–3 hardware generations.

**The enabling fact (spec §D.3/§E.2, roadmap §3.3-C):** the consensus verifier
checks the committed integer sketch `Ĉ = U·C·V` over `q = 2⁶¹−1` by re-deriving
the honest operands and testing `xᵀĈy ≟ (Uᵀx)ᵀA(B(Vy))`. It **never observes
how the miner computed `Ĉ`** — only that the committed integers are correct.
Therefore a miner that produces the **byte-identical** committed integers on an
FP8/FP4 tensor core is indistinguishable, at every consensus surface, from one
using INT8 IMMA/MFMA. An exact-integer-on-float evaluation path is a
**miner-side computation variant, additive, verifier UNCHANGED — not a fork**,
*provided* the committed object stays the exact integer `C`/`Ĉ` down to the
last byte. Delivering exactly that — with a proof that no floating-point
rounding can ever perturb a bit — is what this document and its code do.

The construction is the **Ozaki scheme** (error-free transformation of matrix
multiplication: [Ozaki, Ogita, Oishi, Rump, *Numerical Algorithms* 59(1):95–118,
2012](https://doi.org/10.1007/s11075-011-9478-1)), in the same direction the
HPC community already runs it in production: computing exact/high-precision
GEMM on low-precision matrix engines by slicing operands so every partial
product and partial sum is exact — on INT8 tensor cores
([Ootomo, Ozaki, Yokota, IJHPCA 2024, arXiv:2306.11975 — "ozIMMU"](https://arxiv.org/abs/2306.11975);
[Uchino, Ozaki, Imamura, IJHPCA 2025, arXiv:2409.13313](https://arxiv.org/abs/2409.13313)),
via integer-modular variants ([Ozaki Scheme II, arXiv:2504.08009](https://arxiv.org/abs/2504.08009)),
and on **FP8 tensor cores** ([DGEMM without FP64 arithmetic — FP64 emulation on
FP8 tensor cores, arXiv:2508.00441](https://arxiv.org/abs/2508.00441); survey:
[HPCwire, 2025](https://www.hpcwire.com/2025/04/17/have-you-heard-about-the-ozaki-scheme-you-will/)).
BTX's task is *easier* than the literature's: the operands are already tiny
integers (balanced s8), so the slice count is 2–3, not 7–8 — and the repo
already ships the integer analogue of this exact trick: the **Appendix C-13
limb combine** (`ComputeCombineLimbTensor`: int32 → 4 balanced base-2⁷ s8
digits → 16 exact s8 GEMMs → shifted fold), which this path uses as its
structural template.

---

## 2. The determinism theorem (the centerpiece)

Floating point is implemented differently on every platform: rounding mode,
FMA fusion vs separate multiply-add, accumulation order and internal width,
subnormal flushing — and AI tensor cores are **not** IEEE-754 compliant, with
vendor-undocumented accumulators and rounders
([Fasi, Higham, Mikaitis, Pranesh, "Numerical behavior of NVIDIA tensor
cores", *PeerJ Computer Science* 7:e330, 2021](https://peerj.com/articles/cs-330/)).
Any single rounded bit → a different `Ĉ` → a different digest → a chain split
(spec §K.4; [arXiv:2511.00025](https://arxiv.org/pdf/2511.00025)). This path
therefore does **not** pin a schedule, does **not** model any vendor's rounder,
and does **not** trust any FP operation that could round. It rests entirely on
one theorem:

> **No-rounding-ever.** A floating-point operation whose true mathematical
> result is exactly representable in the destination format returns that result
> **identically** under **any** rounding scheme (round-to-nearest-even,
> truncation, a vendor's undocumented tensor-core rounder), with or without FMA
> fusion, in **any** accumulation order, and regardless of subnormal-flush
> behavior — because there is nothing to round, no order-dependent rounding
> error to commute, and no subnormal anywhere in range.

Rounding functions are the identity on representable values — every rounding
scheme, IEEE or not, must return a representable value and must return *x*
itself when *x* is representable (this is the defining property of a rounding,
and holds for truncating/hybrid tensor-core datapaths too: an exact result that
fits the output significand has no discarded bits to truncate). Sums of
integers are order-independent as *integers*; ordinarily FP addition breaks
this via intermediate rounding, but if **every** intermediate partial sum is
exactly representable, no order introduces error, so all orders agree.
Consequently, if every FP value on the committed path is an exactly
representable integer at every step, **all platform FP differences are
neutralized simultaneously.** Exactness — not schedule-pinning — is what
delivers cross-vendor bit-identity, which also means slice width, block
length, and accumulation order are **miner-local free choices** (verified
byte-identical across choices by the test suite).

### 2.1 Enumeration of every FP operation on the committed path, each proven exact

The pipeline (per §3 below) presents the FP unit with exactly four operation
classes. Bounds are for FP8 E4M3 (slice width w=4) and FP4 E2M1 (w=3); `t` is
the guaranteed-exact accumulator significand width and `K′ = 2^(t−2(w−1))` the
accumulation block length.

| # | FP operation | True result | Why exactly representable |
|---|---|---|---|
| 1 | **Encode** a slice digit into FP8/FP4 | integer, magnitude ≤ 2^(w−1) (8 / 4) | Any integer with ≤ p significant bits and within the finite range is an exact format value. FP8 E4M3 (p=4, max finite 448, [OCP OFP8 v1.0](https://www.opencompute.org/documents/ocp-8-bit-floating-point-specification-ofp8-revision-1-0-2023-12-01-pdf-1)): all of [−8, 8]. FP4 E2M1 (p=2, max finite 6, [OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf)): exact values {0, ±0.5, ±1, ±1.5, ±2, ±3, ±4, ±6} ⊇ slice set [−4, 4]; the integer 5, which E2M1 cannot hold, **never occurs as a slice**. No slice is subnormal (magnitudes are 0 or ≥ 1), so FTZ/DAZ behavior is irrelevant. Exhaustively machine-checked over all 256 s8 inputs (`IsExactInFormat`, test 1). |
| 2 | **Multiply** slice × slice inside the MMA | integer, magnitude ≤ 2^(2(w−1)) (64 / 16), ≤ 2p significant bits | A p-bit × p-bit significand product has at most 2p significant bits and is formed in full inside the multiplier array; 2p (8 / 4) ≤ t for every accumulator considered (even the 14-bit case). Exact in any product datapath. |
| 3 | **Accumulate** within one block of ≤ K′ products | integer partial sum, magnitude ≤ K′·2^(2(w−1)) **≤ 2^t** | Every intermediate partial sum, in every order the hardware may use (serial, tree, split-K), is an integer of magnitude ≤ 2^t — exactly representable with t significand bits. By the theorem, the block sum is bit-exact under any rounder/order/FMA policy. **Native FP accumulation is never trusted beyond this bound** — see §2.2. |
| 4 | **Extract** the block sum (FP→integer conversion / register read) | the same integer, < 2^31 | Conversion of an exactly held integer value is exact in any conversion mode. |

Everything else — cross-block accumulation, the 2^(w(s+t)) recombination
shifts, the C-13 limb fold, the mod-q reduction, serialization — is **pure
integer ALU/VPU arithmetic; no FP value ever reaches the committed object.**
FP is used strictly as an exact integer-product engine.

### 2.2 The real teeth: blocked extract-and-promote accumulation (K′)

An FP accumulator rounds the moment a partial sum needs more than its
significand width t — and **t varies across vendors and is sometimes
shockingly small**. The nominal FP32 accumulator has t=24, but the
**DeepSeek-V3 technical report ([arXiv:2412.19437](https://arxiv.org/pdf/2412.19437),
§3.3.2)** documents that H800 (Hopper) FP8 tensor-core accumulation retains
only **~14 mantissa bits**, which is precisely why DeepSeek promotes partial
results from tensor cores to FP32 CUDA-core registers **every 128 elements**.
This path adopts the same promotion mechanic but derives the interval from an
exactness inequality rather than an error-tolerance argument:

> Accumulate at most **K′ = 2^(t − 2(w−1))** slice-pair products natively;
> every partial sum is then an integer ≤ K′ · 2^(2(w−1)) = 2^t, exactly
> representable — the accumulator provably **never rounds**. At each block
> boundary, extract the exact block sum and **promote** it into a wide integer
> accumulator (int32/int64 on the int ALU/VPU/CUDA cores); reset; continue.
> Cross-block accumulation is exact integer arithmetic. DeepSeek promotes
> often enough to *limit* error; BTX promotes early enough that error is
> *impossible*.

| Format | slice width w | max slice-pair product | K′ at t=14 (conservative) | K′ at t=24 (proven FP32 accum) | promoted total at n=65,535 (header max) |
|---|---|---|---|---|---|
| FP8 E4M3 | 4 | 64 = 2⁶ | **256** | 2¹⁸ (never binding: n ≤ 65,535) | ≤ 2²² (fits int32 with 9 bits to spare) |
| FP4 E2M1 | 3 | 16 = 2⁴ | **1024** | 2²⁰ (never binding) | ≤ 2²⁰ |

`kConservativeAccumSignificandBits = 14` is the default the reference assumes
when a device's true exact-accumulation width is unproven; a device that
*proves* full-FP32 accumulation (t=24 — e.g. NVFP4 MMA paths that accumulate
in FP32, per the [OCP MX spec](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf)
and NVIDIA's Blackwell documentation) may use the larger K′ — **the committed
bytes are identical either way** (schedule-independence, pinned by the tests
across t ∈ {2(w−1), 14, 24}). Block-scaled formats (NVFP4/MXFP8) are used with
all block scales pinned to exactly 1 (2⁰) so the scale multiply is the
identity; plain unscaled E4M3/E2M1 MMA needs no such pin.

**Failure boundary (eligibility, not consensus).** A platform whose FP unit
rounds *within* this bounded regime — an accumulator narrower than its assumed
t, an inexact slice product, no way to extract exact block partial sums, or a
scale it silently applies — computes wrong integers → a wrong digest → the
`accel_v4.h` verify+fallback dispatcher **rejects the result and recomputes on
CPU**, and the backend determinism self-test fails **loudly** on the
boundary-regime vectors (partial sums at exactly 2^t; recombined entries
crossing 2²⁴). Such a device is **ineligible for this path**, exactly as a
TPU-v4-class FP32-mantissa-bounded MXU is ineligible for the INT8 path
(roadmap §4.1). This is the same discipline as backlog **C-1**, generalized:
*"the eligibility invariant is exact-integer accumulation on the committed
path — whether the unit is nominally integer or float; no operation on the
committed path may ever round."* A mis-rounding device can only lose
throughput, never split the chain.

---

## 3. The construction (what the code implements)

All in `src/matmul/matmul_v4_exact_float.{h,cpp}`, namespace
`matmul::v4::exact_float`, parameterized by `FpFormat {FP8_E4M3, FP4_E2M1}`.

**Slicing (`DecomposeSlicePlanes`).** Every s8 value on the pipeline — the
balanced-s8 operands in [−125, 125] *and* the C-13 limb digits in [−64, 63] —
splits into k base-2^w slices: k−1 **balanced** digits in [−2^(w−1), 2^(w−1)−1]
(the same digit rule as C-13's `DecomposeLimbPlanes`, w=7) plus a **top slice
carrying the exact remainder**, provably in [−2^(w−1), +2^(w−1)] for every s8
input. FP8: w=4, **k=2** (slices in [−8, 8]). FP4: w=3, **k=3** (slices in
[−4, 4]). The remainder-top form matters: a *pure* balanced scheme covers the
asymmetric range [−h·(bᵏ−1)/(b−1), (h−1)·(bᵏ−1)/(b−1)] — at w=4/k=2 that is
[−136, 119], which **misses s8 inputs 120..127**; the reference's exhaustive
256-value test caught exactly this during development. Max slice magnitude is
2^(w−1) either way, so the product bound (§2.1-#2) is unchanged.

> *Flagged observation for the C-1 owner (no file of theirs is edited here):
> the same asymmetry exists in the consensus C-13 limb decomposition. Four
> balanced base-2⁷ digits cover [−135,274,560, **+133,160,895**], not the
> symmetric ±2²⁷ stated in the `CheckCombineLimbBound` comment. The bound
> admits n ≤ 8589, but positive P/Q entries above 133,160,895 (possible only
> for n ≥ 8523) would not decompose totally; the actual 4096..8192 window
> (max entry 15,625·8192 = 128,000,000) is safe. Worth tightening the
> documented bound to n ≤ 8522 or adding the remainder-top rule if the window
> is ever widened.*

**Exact GEMM (`ExactGemmViaFloatSlices`).** For an exact s8×s8→s32 GEMM
(rows×inner by inner×cols): decompose both operands into slice planes, run the
**k² slice-pair GEMMs** — each ONE native FP8/FP4 MMA GEMM on device — with
the §2.2 blocked extract-and-promote schedule, then recombine on the int ALU:
`out = Σ_{s,t} 2^(w(s+t)) · S_st`, exact integer shifts into an int64
accumulator, final value < 2³¹ by the §B.4 bound. The CPU reference computes
each step in exact integer arithmetic **mirroring the device schedule step for
step** (explicit K′ blocks, explicit promotion); it validates the
decomposition/recombination pipeline, while §2's per-op proof — not a CPU
float simulation — is what carries the claim that an FP unit reproduces each
step bit-exactly.

**Pipeline plumbing (mirrors the integer miner exactly).**
- `ComputeExactProductViaFloat` ≡ `ComputeExactProduct` (full C = A·B).
- `ComputeProjectedLeftViaFloat` / `RightViaFloat` ≡ `ComputeProjectedLeft`
  / `Right` (P = U·A, Q = B·V — the §E.3 optimal-miner GEMMs).
- `ComputeCombineLimbTensorViaFloat` ≡ `ComputeCombineLimbTensor`: identical
  C-13 limb planes and identical shifted mod-q fold
  (`FqFromSigned`/`FqMul`/`FqAdd`, weights 2^(7(i+j))); only the 16 limb-pair
  s8 GEMMs route through the FP slice engine (16·k² MMA GEMMs total). A miner
  may equivalently flatten limb+slice into one wider decomposition of int32
  P/Q (7 base-2⁴ slices → 49 GEMMs at FP8, vs 64 two-level) — the committed
  integers are identical; the reference keeps the two-level form to reuse the
  pinned C-13 fold. The §K.2b stacked/batched form applies unchanged (stack
  Q-columns exactly as `ComputeCombineLimbTensorStacked` does).
- `ComputeSketchViaFloat` ≡ `ComputeSketchOptimal` ≡
  `ComputeSketch(U, ComputeExactProduct(A,B), V)`: identical exact integers at
  every stage → identical unique canonical F_q residues → identical
  `SerializeSketch` bytes → identical digest `H(σ‖Ĉ)`.

**Byte-identity evidence** (`src/test/matmul_v4_exact_float_tests.cpp`, all
assertions for BOTH formats): exhaustive slice exactness/recomposition over
all 256 s8 inputs; K′ derivation incl. fail-closed K′=0; GEMM vs integer
oracle over the full s8 input range across accumulator widths
t ∈ {2(w−1), 14, 24} (schedule-independence); the **high-magnitude regime** —
dot products > 2²⁴ at the header-max inner dimension 65,535 and limb-pair
sums at **exactly 2²⁴** (n=4096 all-(−64) planes — the roadmap §4.1 hazard
boundary) plus random full-magnitude P/Q (|x| ≤ 15,625·8192); the **FP8
block-boundary regime** (partial sums hitting exactly 2¹⁴ = 2^t); product
byte-identity vs `ComputeExactProduct` on XOF-derived and adversarial
sign-extreme operands; and the headline committed-object identity — sketch
residues, `SerializeSketch` payload bytes, and `ComputeSketchDigest` — on real
header-derived A/B/U/V at n=256, b=4.

---

## 4. How every HARD requirement is preserved

1. **MatMul stays the core work.** The workload is the identical dense matmul
   over the identical seed-derived operands; only the *evaluation engine* for
   the s8×s8→s32 GEMMs changes (k² FP MMA GEMMs + exact recombination instead
   of one INT8 MMA GEMM). The marginal-unit shape (expand B, B·V, combine,
   digest) is untouched.
2. **Cheap O(n²) Freivalds verification UNCHANGED.** The committed object is
   the same exact integer sketch `Ĉ` over q = 2⁶¹−1; the verifier, digest
   rule, q, n, b, kTileB, kCombineLimbs, and every golden vector are untouched
   — no consensus file is modified by this deliverable. The verifier is
   method-agnostic by construction (§D.3): it would pass a correct `Ĉ` from an
   abacus.
3. **Cross-vendor bit-exact determinism.** By the §2 theorem plus the per-op
   exactness enumeration, no FP operation on the committed path ever rounds —
   so rounding mode, FMA policy, accumulation order, accumulator width (past
   the K′ gate), and subnormal handling are all simultaneously irrelevant, on
   every vendor. No floating-point *value* ever enters the committed object.
   Byte-identity to `ComputeExactProduct`/`ComputeSketch` is machine-checked
   including the boundary regimes; a device that violates its exactness
   envelope fails the self-test loudly and is quarantined by verify+fallback.
4. **Scaled rewards preserved; M-class still mines.** The ordering lever
   remains dense tensor throughput. Effective INT8-equivalent throughput on
   the FP path is ≈ (dense FP TOPS)/k²: on a B200-class part
   ([arXiv:2512.02189](https://arxiv.org/html/2512.02189v1): INT8 3927, FP8
   3851, FP4 7702 TOPS) that is ~963 (FP8, ÷4) / ~856 (FP4, ÷9) — i.e. today
   native INT8 remains the rational miner path and nothing changes. The
   escape hatch binds where INT8 stagnates or vanishes: a Rubin-class part
   whose FP4 doubles while INT8 stays flat rides its *frontier* silicon into
   the same workload, and Trainium-class parts (no INT8 matmul unit) become
   able to mine at all — so "reward scales with AI compute" tracks the
   frontier instead of a legacy unit. Datacenter FP4/FP8 TOPS ≫ consumer
   ≫ M-class holds in absolute terms exactly as the INT8 ordering does; and
   the M-class path is **untouched** — Apple Neural Accelerators keep their
   native INT8→INT32 backend and simply earn proportionally less, as today.
   (Whether the FP-path wall-time split preserves the measured ordering is a
   §K.2a-WT measurement obligation — §6 — not an assumption, consistent with
   the repo's measure-don't-model posture.)
5. **Price-independence (§0.7-(4)).** No market quantity appears anywhere in
   this construction, its calibration, or its eligibility rules; every knob
   (w, k, K′, t) is derived from format arithmetic and measured hardware
   throughput only.

---

## 5. Miner-only vs consensus-adjacent (per roadmap §3.4)

| Item | Class | Why |
|---|---|---|
| The FP slice path itself (this deliverable): producing the byte-identical `C`/`Ĉ` on FP8/FP4 units | **Miner-only** | Verifier checks integers, not methods (§D.3); dispatcher re-verifies every device result and falls back to CPU. Identical committed bytes ⇒ zero consensus surface. |
| Slice width w, slice count k, block length K′, assumed accumulator width t, two-level vs flattened combine | **Miner-local** (not even network-visible) | Exactness, not schedule, delivers determinism (§2); all choices produce identical bytes (test-pinned). Nothing to pin in consensus. |
| A new `accel_v4` backend `Kind` hosting the path (Trainium/NKI, FP-only NVIDIA) | **Miner-only** | Same plug-in contract as CUDA/METAL/HIP: safe-by-construction under verify+fallback (§6 of the roadmap). |
| Eligibility self-test vectors for the FP boundary regimes (2^t partial sums, 2²⁴ crossings) | **Consensus-protecting, not consensus** | Backend gating à la C-1; prevents a rounding device from ever sealing a divergent block (it cannot anyway — verify+fallback — but it must fail loudly, not waste throughput silently). |
| **Difficulty calibration** once FP-path miners are material: the marginal work unit `W_nonce` and nonce/s move with the k² GEMM factor and FP throughput | **Consensus-adjacent (measurement/calibration, NOT a verifier change)** | §I.4 difficulty and the one-time ASERT rescale (ACTIVATION **B2b**) are calibrated to the measured marginal unit on whatever path rational miners actually use. Re-measure per §K.2a-WT/B2g on FP hardware; the work-unit-neutrality theorem (§L.2.1) says absolute `W_nonce` shifts don't move economics — only *relative* per-class throughput does, which is exactly what must be measured. |
| Changing the committed object to a float/MX sketch, or changing q/n/b/limb base | **CONSENSUS FORK — out of scope, explicitly not done** | Roadmap §3.4 rows 3–4. |

---

## 6. §K.2a-WT wall-time note (the erosion risk) and what must be measured

The datacenter lever exists only if **tensor GEMM dominates measured per-nonce
wall-time** (spec §K.2a-WT, normative; extended to the batched marginal unit in
§K.2b). The FP path shifts the stage split in both directions:

- **Tensor volume ×k²** (4 at FP8, 9 at FP4) for the same committed work — more
  MMA time, which *helps* the majority requirement but *divides* effective
  throughput by k² (partially offset by FP4/FP8 units being 2× wider than INT8
  on current parts, fully offset only if the frontier keeps widening FP).
- **New int-ALU/VPU work** that is NOT on tensor units and directly erodes the
  lever: slice decomposition of operands and of the int32 P/Q limb planes
  (O(k·n²) digit extractions per nonce-side matrix), the per-block
  extract-and-promote adds (one integer add per K′ inner elements per output —
  the DeepSeek promotion cost, ~n/K′ extra adds per output entry), and the
  k²-term recombination folds (k²·O(m·Q·m) per stacked combine window vs the
  INT8 path's 16 folds).

**Requirement carried over unchanged:** on every reference FP device, the
measured tensor share of the *marginal* per-nonce wall-time MUST be the strict
majority at window Q ≥ 32, instrumented at the same stage boundaries as
`src/bench/matmul_v4_stage_bench.cpp` (S0 excluded as template-amortized),
bit-exact against the reference digest at every stage. The mod-q combine
already violated this once on GPU (measured 35.5% pre-fix — spec §K.2a-WT
history); the FP path adds analogous non-tensor stages, so **the wall-time
majority MUST be re-measured on real FP hardware (Trainium NKI, FP4-path
Blackwell/Rubin) before the path is flagged mining-capable — never inferred
from MAC counts.** Two prior model-based estimates in this program were
falsified by measurement; this document does not make a third. Similarly the
ASERT rescale (ACTIVATION B2b) must use the measured marginal `W_nonce` on the
path the measuring miner actually runs (§5 table) — a calibration input, not a
verifier change.

---

## 7. How it plugs into `accel_v4` (verifier/fallback untouched)

`accel_v4.h` is already the right shape and needs **no contract change**:

1. A new backend (e.g. `matmul_v4::trainium` via an NKI kernel, or an FP4
   variant inside the existing CUDA backend selected by
   `BTX_MATMUL_V4_BACKEND`/a kernel-choice env) implements the existing
   `AccelFn`/`BatchAccelFn` signatures — `ComputeDigestAccel` /
   `ComputeDigestsBatchedAccel` — producing `digest_out`/`payload_out`
   byte-identical to `matmul_v4::ComputeDigest`. Internally it runs: host XOF
   expansion (unchanged) → slice planes → k² FP MMA GEMMs with K′-blocked
   promotion → int recombination → C-13 fold → serialize → digest. The CPU
   functions in `matmul_v4_exact_float.h` are the audit reference for each
   stage.
2. Compile-gating mirrors the existing backends: a strong definition behind a
   CMake define, weak stub (`accel_v4_stub.cpp` pattern) otherwise.
3. The dispatcher (`ComputeDigestDispatched` / `ComputeDigestsBatchedDispatched`)
   re-verifies **every** device result with `matmul_v4::VerifySketch` and
   falls back to the CPU reference on any mismatch — so even a device that
   violates its exactness envelope can only lose throughput, never mine a
   wrong block. The verifier and fallback paths are byte-for-byte the ones
   that exist today; this deliverable does not modify `accel_v4.*`.
4. Before any mining-capable flag: the backend must pass the determinism
   self-test (`matmul_v4_backend_determinism_tests` / `verify-backend.sh`
   pattern) extended with the FP boundary-regime vectors (§2.2), and clear the
   §6 wall-time measurement (ACTIVATION B2g instruments, remote-runner mode
   per roadmap M-1 for cloud parts).

---

## 8. What is proven vs what awaits hardware

| Claim | Status |
|---|---|
| Slice decomposition is total/unique over the full s8 range and every slice is an exact FP8/FP4 value | **Machine-checked exhaustively** (256/256 inputs, both formats) |
| Every FP op on the committed path is exact under the K′ discipline (any rounder/order/FMA/flush) | **Proved** (§2 theorem + §2.1 enumeration; bounds machine-checked) |
| FP-path `C`, `P`, `Q`, combine, sketch payload, digest are byte-identical to the integer consensus reference, incl. >2²⁴ and 2^t boundary regimes, across block schedules | **Machine-checked** (test suite + standalone harness run against the prebuilt consensus objects) |
| A real FP8/FP4 tensor core reproduces the reference bytes end-to-end | **Pending real silicon** — requires the §7-(4) self-test on device (this repo has no FP-frontier hardware; same posture as ACTIVATION's B2a/B2g gates) |
| Wall-time majority + datacenter ordering on the FP path | **Unmeasured hypothesis** — §6 obligations; explicitly not asserted |
| Effective-throughput ÷k² arithmetic on B300/Rubin/Trainium parts | Cited-spec arithmetic only; re-confirm on silicon (roadmap G-1/R-1 monitoring) |
