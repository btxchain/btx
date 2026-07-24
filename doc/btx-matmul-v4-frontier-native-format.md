> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.2 — Frontier-Native Committed Format (Tax-Inversion Study & Determination)

> **Execution-status correction (2026-07-20).** This is a format/tax study,
> not proof that the repository issues native MXFP4. “One native GEMM” tables
> are conditional hardware models. The current portable grouped path is exact
> integer emulation; tested cuBLASLt B200/5090 configurations expose no OCP
> MXFP4 algorithm, and the branch has no admitted tcgen05/CUTLASS or CDNA
> native kernel. LT's CUDA/HIP path now keeps logical MX components by default
> and lowers them exactly through four exponent-partitioned INT8 IMMA/MFMA (or
> exact device-ALU fallback) GEMMs on every supported architecture, including
> H200/MI300. `BTX_MATMUL_V4_LT_DENSE_BHAT=1` selects the one-dense-GEMM
> diagnostic lane; `BTX_MATMUL_V4_LT_LOGICAL_MX=1` is a legacy no-op. Neither
> exact-integer lane is native MXFP4.
> Static planner labels are not execution proof.

*Status: STUDY + DETERMINATION deliverable (design doc). NOT a code change, NOT an
activation, and — unlike the miner-only v4.1 Ozaki path — the object designed here IS a
consensus (hard-fork-level) workload change, explicitly classified in §7. Companion to
`doc/btx-matmul-v4-exact-int-on-float.md` (the no-rounding discipline and the current k²
tax this document inverts), `doc/btx-matmul-v4-multiplatform-roadmap.md` (§3 precision
landscape, G-1/O-1), `doc/btx-matmul-v4-accumulator-eligibility.md` (C-1, generalized
here), and `doc/btx-matmul-v4-design-spec.md` (authoritative, UNCHANGED by this document).
The full soundness/hardness re-derivation for any new committed object is owned by the
companion `doc/btx-matmul-v4-committed-object-redesign.md` and is deferred there
throughout. Per spec §0.7-(4), nothing here reasons from token or market price; all
hardware framing is throughput-only, and every throughput ordering claim below is
**measurement-gated** (§K.2b posture: peak-TOPS ratios are illustrative, never
load-bearing). Written 2026-07-16.*

---

## 1. The problem, and the governing width-ratio law

Today's committed object is a dense **balanced-s8** integer matmul (operands in
[−125, 125], ≈7.97 bits) verified exactly by Freivalds over `q = 2⁶¹−1`. That choice makes
INT8 tensor hardware *native* (1 GEMM, no tax) and forces FP4-frontier hardware to pay the
**Ozaki-slicing k² tax** to reproduce the exact integer object: k=3 slices at FP4 E2M1 →
**9 GEMMs**, k=2 at FP8 E4M3 → **4 GEMMs** (`btx-matmul-v4-exact-int-on-float.md` §3). As
the AI frontier abandons INT8 — B300 cut INT8 to fund NVFP4, Rubin doubles only FP4/FP8,
Trainium 2/3 and TPU v7 have no INT8 matmul unit at all (roadmap §3.2) — that k² tax lands
on exactly the chips the reward ladder wants to WIN.

The direction of the tax is not an accident of any one format; it is a **width ratio**:

> **Width-ratio law.** For an exact (no-rounding) reproduction of a committed integer
> matmul whose operands need `W_obj` bits, a device whose fastest exact pipe holds `w`
> exact operand bits pays `k² = ⌈W_obj / w⌉²` GEMMs. The conversion tax falls on whichever
> hardware's exact-integer capacity is NARROWER than the committed operand width.

Current object: `W_obj ≈ 8` → FP4 (w=3) pays 9, FP8 (w=4) pays 4, INT8 (w=8) pays 1.
**To invert the tax, shrink the committed *mantissa* to exactly the frontier format's
exact-integer subset (frontier pays 1), and move the remaining committed information into
a structure the frontier applies in hardware for free but integer hardware must
materialize as extra width: the microscaling block EXPONENT.** A power-of-two block scale
is a free exponent-field operation on MX hardware and an exact bit-shift for the verifier
— but on an INT8 unit it widens the dequantized integers past 8 bits, forcing the s8 part
to slice. That is the entire mechanism of this document: the new chips' native structure
becomes the committed structure; the old chips emulate it and pay `⌈(w_mant + S)/7⌉²`.

The hard constraint never relaxes (exact-int-on-float doc §2, restated): floating point
enters consensus **only as an exact-integer engine**. Every operand exactly representable,
every product exact, every partial sum exactly representable under a blocked
extract-and-promote schedule (`K′`), no FP value ever reaching the committed object. The
no-rounding theorem — *an operation whose true result is exactly representable returns it
identically under any rounding scheme, order, FMA policy, or subnormal behavior* — is what
makes a frontier-native format usable at all; the whole design below is the search for the
frontier format that admits the largest exact-integer envelope.

---

## 2. Frontier-format census (research; confirmed spec vs inference marked)

### 2.1 The two scale disciplines — the load-bearing distinction

| Property | **OCP MX (MXFP8/MXFP6/MXFP4/MXINT8)** | **NVFP4 (NVIDIA-proprietary)** |
|---|---|---|
| Block size | 32 elements along the contraction dim | 16 elements |
| Block scale format | **E8M0** — 8-bit pure exponent, value 2^(code−127), no mantissa | **E4M3 (UE4M3)** — a *fractional* FP8 value (+ a second-level per-tensor FP32 scale) |
| Dequant `v = X·P` | **Exact bit-shift** (exponent-field add; changes no significand bit; exact for any representable P absent overflow) | A true multiply by a 4-significant-bit number: the product needs up to `p_elem + 4` significand bits, is **not** an exponent-only operation, and grid-misaligns block sums |
| Determinism posture | **Friendly**: no-rounding provable from format arithmetic alone | **Hostile**: exactness depends on undocumented internal dequant datapath width; and committing fractional scales multiplies verifier-side integers by odd factors |
| Standardization | OCP MX v1.0 — AMD, Arm, Intel, Meta, Microsoft, NVIDIA, Qualcomm | NVIDIA only |

Sources: [OCP Microscaling Formats (MX) v1.0 spec](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf);
[Microscaling Data Formats for Deep Learning, arXiv:2310.10537](https://arxiv.org/pdf/2310.10537);
[FPRox — OCP MX scaling formats](https://fprox.substack.com/p/ocp-mx-scaling-formats);
[NVIDIA — Introducing NVFP4](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/);
[NVFP4 vs MXFP4 format guides](https://insiderllm.com/guides/fp4-inference-llamacpp-nvfp4-mxfp4/),
[Spheron NVFP4-vs-MXFP4](https://www.spheron.network/blog/nvfp4-vs-mxfp4-gpu-cloud-4bit-quantization-guide/).

**One asymmetric embedding fact that resolves the NVIDIA question painlessly:** every
power-of-two `2^e` with e in a small non-negative range is itself an **exact UE4M3
value** (zero mantissa bits set). So NVFP4-*hardware* (UE4M3 scale slots, e.g. consumer
Blackwell sm_120) can host an E8M0-scaled committed object **exactly**; the reverse
embedding — a fractional E4M3 scale into an E8M0 slot or into another vendor's
power-of-two scale hardware — is impossible without rounding. Rejecting NVFP4 as the
*committed* format costs NVIDIA hardware nothing; it only rejects fractional scale
*values*. On datacenter Blackwell the dedicated `tcgen05.mma` block-scaled kinds
`mxf8f6f4` and `mxf4` take **UE8M0 scales natively**, and `mxf4nvf4` accepts either UE8M0
or UE4M3 ([CUTLASS Blackwell functionality](https://docs.nvidia.com/cutlass/latest/media/docs/cpp/blackwell_functionality.html);
[Colfax block-scaling tutorial](https://research.colfax-intl.com/cutlass-tutorial-hardware-supported-block-scaling-with-nvidia-blackwell-gpus/);
[Triton tcgen05-mma-scaled tutorial](https://triton-lang.org/main/getting-started/tutorials/gluon/tcgen05-mma-scaled.html)).

### 2.2 Per-platform microscaling / low-precision semantics

Legend: *scale HW* = what the matmul unit's scale slot holds; *exact-int subset* = the
contiguous-or-listed integers the element format represents exactly (grid-normalized);
*t* = exact-accumulation significand width (proven vs nominal); ⚠ = needs silicon
confirmation.

| Platform | Block-scaled matmul formats | Block / scale HW | Element exact-int subset (×2-normalized for E2M1) | Accumulator | No-rounding exact-integer matmul at ~native rate? |
|---|---|---|---|---|---|
| **NVIDIA B200 / B300 / GB300** | MXFP8/MXFP6/MXFP4 (`mxf8f6f4`, `mxf4`: UE8M0) + NVFP4 (`mxf4nvf4`: UE4M3 or UE8M0) | 32 (MX) / 16 (NVF4); scales staged via TMEM, dequant fused in MMA | E2M1: {0,±1,±2,±3,±4,±6,±8,±12}; E4M3: all ints in [−16,16] (⊃ [−15,15]) | FP32 into TMEM (nominal t=24) ⚠ *prove on silicon; Hopper FP8 precedent is t≈14* | **YES** — `mxf4`/`mxf8f6f4` with pinned or committed E8M0 scales, K′-blocked promotion |
| **NVIDIA Rubin / Rubin Ultra (2026/27)** | FP4/FP6/FP8 headline; NVFP4 35 PF training / 50 PF inference per GPU (vendor), FP8 ≈16 PF dense; INT8 unlisted | expected as Blackwell ⚠ (MX-E8M0 full-rate on Rubin **unconfirmed**) | as Blackwell | ⚠ unpublished | **Expected YES** ⚠ — carries the B300 path; must confirm `mxf4`-E8M0 rate survives |
| **AMD MI350X/MI355X (CDNA4)** | OCP MXFP8/MXFP6/MXFP4 in hardware; MXFP4/6 10.1 PF dense, MXFP8 5.0 PF dense | 32; E8M0 per OCP | same OCP element sets | FP32 matrix-core accumulate (nominal) ⚠ | **YES** — the most standards-pure OCP MX host |
| **AWS Trainium2 / Trainium3** | Trn3 (NeuronCore-v4): MXFP8 + MXFP4, dequant fused in Matmul-MX, 512×128 effective systolic, 4× BF16 rate, 2× Trn2 MXFP8; Trn2: FP8/BF16 (no INT8 matmul on either) | 32 along contraction; scale tensor = **UINT8 power-of-two exponents** (E8M0 semantics) | same | **FP32 or BF16 PSUM** — use FP32 (nominal t=24) ⚠ | **YES on Trn3** (Matmul-MX). One wrinkle: NKI's `quantize_mx` derives scales from data; committed scales must be loadable as an explicit scale tensor ⚠ (kernel-level workaround expected; verify in NKI) |
| **Google TPU v7 (Ironwood)** | Native FP8 (E4M3/E5M2), **no FP4**, no MX block scales (first TPU with native FP8); FP8 4,614 TF/chip, MXU FP32 accumulation | n/a (per-tensor scaling) | E4M3 ints [−16,16]; hosts E2M1×2^e ≤448 exactly by scale-folding | FP32 (nominal t=24) ⚠ | **YES via scale-folding into E4M3** (§4.4): 1 plain FP8 GEMM at FP8 rate |
| **Google TPU v6e (Trillium)** | INT8 + BF16; **no native FP8** (FP8 arrived with v7) | n/a | s8 | true int32 | No frontier-FP path — takes the INT8 backwards-compat path (§5) |
| **Apple M5 (context)** | INT8→INT32 Neural Accelerators; FP16 with FP32 accumulate available | n/a | s8 / FP16 ints ≤ 2^11 | int32 / FP32 | Not frontier; §5 shows its bounded compat path |
| **OCP MXINT8 (format, not a chip)** | INT8 elements + E8M0 scale — *the ideal determinism host on paper* | 32 / E8M0 | full s8 | — | **NO SILICON**: no announced tensor unit accelerates MXINT8 matmul at frontier rate (Blackwell block-scaled kinds cover FP8/6/4 elements only; Trn3 MX covers FP8/FP4; CDNA4 covers MXFP8/6/4). Rejected for lack of a hardware constituency |

Sources: [CUTLASS Blackwell functionality](https://docs.nvidia.com/cutlass/latest/media/docs/cpp/blackwell_functionality.html);
[Colfax block-scaling tutorial](https://research.colfax-intl.com/cutlass-tutorial-hardware-supported-block-scaling-with-nvidia-blackwell-gpus/);
[Blackwell microbenchmark, arXiv:2512.02189](https://arxiv.org/abs/2512.02189) (B200: INT8 3,927 / FP8 3,851 / FP4 7,702 TOPS measured);
[Tom's Hardware — B300 NVFP4 boost "at the cost of INT8 and FP64"](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support);
[NVIDIA Vera Rubin platform](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/),
[Tom's Hardware Vera Rubin in depth](https://www.tomshardware.com/pc-components/gpus/nvidias-vera-rubin-platform-in-depth-inside-nvidias-most-complex-ai-and-hpc-platform-to-date),
[NextPlatform Vera-Rubin](https://www.nextplatform.com/ai/2026/01/06/nvidias-vera-rubin-platform-obsoletes-current-ai-iron-six-months-ahead-of-launch/4092179);
[AMD MI355X datasheet](https://www.amd.com/content/dam/amd/en/documents/instinct-tech-docs/product-briefs/amd-instinct-mi355x-gpu-brochure.pdf),
[AMD MI355X product page](https://www.amd.com/en/products/accelerators/instinct/mi350/mi355x.html),
[ROCm MXFP4/MXFP6 blog](https://rocm.blogs.amd.com/software-tools-optimization/mxfp4-mxfp6-quantization/README.html);
[Trainium3 NKI architecture guide](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/guides/architecture/trainium3_arch.html),
[NKI MXFP matmul deep dive](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/deep-dives/mxfp-matmul.html),
[Trainium2 NKI architecture guide](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/guides/architecture/trainium2_arch.html);
[Google TPU7x docs](https://docs.cloud.google.com/tpu/docs/tpu7x),
[Ironwood FP8 analysis (XPU.pub)](https://xpu.pub/2025/04/16/google-ironwood/),
[Google Ironwood blog](https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/ironwood-tpu-age-of-inference/).

### 2.3 The accumulator reality check (the ~14-bit surprise, carried forward)

Nominal "FP32 accumulation" is a *claim about a register format, not about exactness*. The
[DeepSeek-V3 technical report, arXiv:2412.19437 §3.3.2](https://arxiv.org/pdf/2412.19437)
documented that Hopper's FP8 tensor-core accumulation retains only **~14 mantissa bits**
(independently characterized as a 22-bit fixed-point path with 13-bit mantissa + sign;
see also [arXiv:2512.02189](https://arxiv.org/abs/2512.02189) and
[SemiAnalysis tensor-core evolution](https://newsletter.semianalysis.com/p/nvidia-tensor-core-evolution-from-volta-to-blackwell)).
Every eligibility number below is therefore parameterized by the **proven** exact
significand width `t`, with `t = 14` the conservative default and `t = 24` claimable only
after a device passes boundary self-test vectors (the C-1 discipline of
`btx-matmul-v4-accumulator-eligibility.md`, generalized in §4.6). This single parameter
decides which chips get the native path: with the §4 profile, **t = 24 is required for
native-rate eligibility**; a t≈14 device (Hopper FP8) is pushed to its integer path.

---

## 3. The determination

**(a) NVFP4's fractional E4M3 block scale is REJECTED as a committed format.** Three
independent reasons, any one sufficient: (i) dequantization by a 4-significant-bit
fractional scale is a real multiply whose exactness depends on vendor-undocumented
internal datapath width — not provable from format arithmetic, violating the no-rounding
discipline; (ii) even where the products are exact, fractional scales destroy the common
integer grid of a K-run: block sums become multiples of `2^(e−6)`-grids that shrink the
provably-exact `K′` by up to 2⁶ (to `K′ ≈ 4` at t=14 — useless); (iii) it is
single-vendor: AMD CDNA4 and Trainium3 scale slots hold power-of-two exponents only, so a
fractional-scale committed object would force *every non-NVIDIA frontier chip* to slice —
the opposite of the goal. Per §2.1, rejecting NVFP4 scale *values* costs NVIDIA hardware
nothing (UE8M0 is accepted by `mxf4`/`mxf4nvf4`, and 2^e is an exact UE4M3 value).

**(b) The committed host is OCP-MX with E8M0 power-of-two scales and the element format's
exact-integer subset — concretely MXFP4-E2M1 ("BMX4"), with MXFP8-E4M3 ("BMX8") specified
as the fallback profile.** MXFP4-E2M1 is chosen over MXFP8-E4M3 as primary because the
frontier's transistor budget is going to FP4 (B300 +50% dense NVFP4 *at the cost of INT8*;
Rubin 35–50 PF FP4 vs ~16 PF FP8; MI355X 10.1 PF FP4 vs 5.0 PF FP8), because the E2M1
value set embeds exactly into every wider pipe (E4M3, FP16, BF16, s8) so *every* chip gets
a graceful 1-GEMM fallback at its own best rate, and because it is the OCP multi-vendor
format, not a proprietary one. Its cost — an ~3.9-bit element alphabet instead of ~7.97 —
is a hardness/entropy question deferred to the companion committed-object-redesign doc.
If that re-derivation rejects the narrow alphabet, BMX8 (integer mantissas in [−15, 15],
~4.95 bits, native at FP8/MXFP8 rate incl. TPU v7) is the drop-in alternative; every
formula below is written in terms of the mantissa bound so both profiles read off the
same math.

---

## 4. The exact recipe — the BMX4 committed object (v4.2 candidate)

### 4.1 Operand exact set and block structure

- **Element (mantissa) alphabet.** Each operand element is an FP4 E2M1 value from
  `V = {0, ±0.5, ±1, ±1.5, ±2, ±3, ±4, ±6}` — 15 distinct values, exactly the E2M1
  representable set ([OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf)).
  Grid-normalize by ×2: `μ = 2v ∈ M = {0, ±1, ±2, ±3, ±4, ±6, ±8, ±12}` (all integers).
  Sampling: one XOF nibble per element, uniform over the 15 non-redundant codes by
  rejecting one 4-bit pattern (≈6.25% rejection; −0 excluded). **XOF volume per operand
  halves** vs the s8 object (4 bits + 1/32 scale byte per element ≈ 0.53 bytes/element vs
  1) — the per-nonce SHA floor *shrinks*, helping the §K.2a-WT tensor-majority requirement.
- **Microscale block structure.** OCP-standard blocks of **32 elements along the
  contraction dimension of the projection that consumes each operand** (A: rows in
  `U·A`; B: columns in `B·V` — matching `tcgen05` / Matmul-MX / CDNA4 scale layout).
  One scale per block, format **E8M0 restricted to
  `X = 2^e, e ∈ {0, 1, …, S}` with S = 4** (codes 127…127+S; the *scale constraint*:
  non-negative, power-of-two, range-bounded). Scale exponents are seed-derived uniform
  over {0..S} (3-bit rejection sampling), `n²/32` scales per operand.
- **The committed integer operands** are
  `Ā[i][k] = μ_A[i][k] · 2^(e_A[⌊i/32⌋, k])` and
  `B̄[k][j] = μ_B[k][j] · 2^(e_B[k, ⌊j/32⌋])`, each an integer of magnitude
  ≤ `12·2^S = 192` (< 2⁸ but > 127 — deliberately: §5's old-chip dial). The
  committed product is the exact integer matrix
  `C̄ = Ā·B̄` — entries ≤ `n·144·2^(2S) = n·36,864` (≈1.51×10⁸ at n = 4096, still inside
  int32; `n_max = ⌊(2³¹−1)/36,864⌋ = 58,254`, slightly below the old 65,535 header bound —
  a v4.2 parameter note).

**Why S = 4:** it is the smallest scale range that (a) pushes the dequantized integer
width past s8 (192 > 127 ⇒ INT8 hardware must 2-slice ⇒ the 4× backwards-compat tax), while
(b) keeping `K′ = 2^(t−16) = 256` at t = 24 (a native-rate promotion cadence — cf.
DeepSeek's every-128 promotion), (c) keeping `C̄`, `P`, `Q` inside int32 at n = 4096–8192,
and (d) letting scale-folding stay inside E4M3/FP16 for the fallback hosts (`6·2⁴ = 96 ≤
448`). S is the **tax dial**: S = 0 degenerates to a small-integer object nobody pays
conversion tax on (but with no microscale structure and no width lever); larger S raises
the old-chip tax toward 9× at the cost of a smaller K′ and wider verifier integers.

### 4.2 Exactness enumeration on the frontier path (no operation ever rounds)

The MX-hardware evaluation presents the FP unit with exactly these operation classes, in
the ×4-normalized integer view (`ā·b̄` terms are integers on grid 1):

| # | Operation | True result | Why exact |
|---|---|---|---|
| 1 | Hold an element (E2M1 code) | a value of `V` | operands ARE format values — no encode step exists |
| 2 | Apply block scale `×2^e` (hardware dequant) | `v·2^e` | E8M0 dequant is an exponent-field add; no significand bit changes; max `6·2⁴ = 96` ≪ any overflow bound. This is the step that is exact for E8M0 and unprovable for fractional E4M3 scales |
| 3 | Multiply inside the MMA | products with ≤ 2+2 = 4 significant bits (e.g. 1.5×1.5 = 2.25, 6×6 = 36), shifted by `2^(e_A+e_B)` | a p=2 × p=2 significand product has ≤ 4 significant bits; exponent shifts consume none; exact in any datapath with ≥4-bit product significand |
| 4 | Accumulate ≤ K′ products | integer (×4-grid) partial sums ≤ `K′·144·2^(2S)` ≤ 2^t | every partial sum in every order is an exactly representable integer ⇒ bit-exact under any rounder/order/FMA (the no-rounding theorem, exact-int-on-float §2) |
| 5 | Extract block sum (TMEM/PSUM read, FP32→int convert) | the same integer < 2³¹ | conversion of an exactly-held integer is exact in any mode |

Everything downstream — cross-block promotion, the verifier's `2^e` shifts, mod-q, C-13
limb fold, serialization — is pure integer ALU arithmetic. **No FP value ever reaches the
committed object.**

### 4.3 The blocked-K′ exact-accumulation schedule

> Accumulate at most `K′ = ⌊2^t / (144·2^(2S))⌋` products natively (rounded down to a
> multiple of the 32-element MX block); extract the exact block sum; **promote** into an
> int32/int64 accumulator on integer units; reset; continue. Cross-K′ accumulation is
> exact integer arithmetic.

| Proven t | K′ at S = 4 (multiple of 32) | Verdict |
|---|---|---|
| 24 (true FP32 accumulate — nominal for Blackwell TMEM, CDNA4, Trn3 FP32-PSUM, TPU v7 MXU) | ⌊2²⁴/36,864⌋ = 455 → **448 (14 MX blocks)**; spec-pin 256 for margin | **Native path eligible** — one promotion per 256–448 K-elements, DeepSeek-cadence, near-zero overhead |
| 14 (conservative default; measured on Hopper FP8) | ⌊2¹⁴/36,864⌋ = **0** | **INELIGIBLE for the native path** — the device falls back to its integer path (§5) or to mantissa-plane slicing. Fail-closed, same as K′=0 in the v4.1 reference |

Eligibility therefore *requires proving t = 24* on the block-scaled path via the §4.6
boundary vectors — nominal datasheet "FP32 accumulation" is never trusted (the ~14-bit
Hopper surprise is the standing precedent). As in v4.1, K′, block ordering, and promotion
cadence are **miner-local free choices** — exactness, not schedule, delivers bit-identity,
so committed bytes are schedule-independent by construction.

### 4.4 Fallback embeddings (every chip gets its widest exact host)

Because `V·2^{0..S}` ⊂ exact-integer/dyadic subsets of every wider format, the committed
operands embed exactly, with block scales **folded into the element**:

- **FP8 E4M3 hosts (TPU v7, Trainium2, Blackwell FP8 pipe):** `v·2^e ≤ 96 ≤ 448`, and
  `m·2^e` keeps E2M1's ≤2-bit significand ⇒ exact E4M3 values. **One plain FP8 GEMM**, no
  block-scale hardware needed, same K′ table (needs t = 24; Hopper's t≈14 FP8 pipe fails
  and Hopper routes to INT8 instead).
- **FP16/BF16 hosts (Apple M-class with FP32-accumulate simdgroup ops, any BF16 systolic):**
  values ≤ 96 and 4-bit products — exact; `K′` from the same formula with the host's t.
- **INT8 hosts:** dequantize on integer units (`ā = μ·2^e`, a shift), then 2-slice
  balanced base-2⁷ (digits in [−64, 64], remainder-top rule of the v4.1 path) → **4 s8
  GEMMs**. This IS the backwards-compat tax (§5).

### 4.5 Recovery of the exact integer object for Freivalds (verifier UNCHANGED in form)

The verifier never touches FP. From the header seeds it re-derives `(μ, e)` streams,
forms `Ā = μ·2^e` and `B̄` **as integers via exact power-of-two shifts**, and runs the
identical machinery: committed sketch `Ĉ = U·C̄·V` over `q = 2⁶¹−1`, checked as
`xᵀĈy ≟ (Uᵀx)ᵀ Ā (B̄ (Vy)) mod q` — O(n²), same q, same digest rule, same
serialization form. Miner-side recovery is: mantissa products (exact, ≤ 2⁸ ×4-grid) +
exact power-of-two shifts (`2^(e_A+e_B)`, applied in-hardware by the MX unit) + exact
K′-blocked accumulation + integer promotion. Downstream bounds at S = 4, n = 4096:
`P = U·Ā` ≤ `n·125·192 = 9.83×10⁷` and `C̄` ≤ 1.51×10⁸ — both inside int32 and inside the
existing 4-limb base-2⁷ C-13 combine envelope (positive cap 133,160,895, per the
asymmetry note in `btx-matmul-v4-exact-int-on-float.md` §3). At n = 8192 the limb
decomposition needs the remainder-top rule or a 5th limb (P ≤ 1.97×10⁸ exceeds the 4-limb
positive cap) — a miner-side re-parameterization, flagged for the L-1 owner. An optional
co-change — drawing U/V themselves from the E2M1 set so the `B̄·V` projection also runs
at FP4 rate and P/Q shrink — is attractive but alters sketch soundness inputs; **deferred
to the companion committed-object-redesign doc.**

### 4.6 Eligibility invariant (C-1, generalized to scaled-FP paths)

> A backend is eligible for the BMX4 native path only if it PROVES, via boundary
> self-test vectors, that on its block-scaled path: (i) E8M0 scale application is an
> exact shift for all committed (μ, e); (ii) slice products are exact; (iii) every
> partial sum up to `K′·144·2^(2S) = 2^t` is bit-exact in any order (vectors that pin
> partial sums at exactly 2^t, mixed-exponent blocks, sign-extremes); (iv) exact block
> sums are extractable. A device that rounds anywhere in this envelope is INELIGIBLE for
> the native path (falls back per §4.4/§5) — and, as today, the `accel_v4`-style
> verify+fallback dispatcher re-verifies every device result, so a mis-rounding device
> can only lose throughput, never split the chain.

This is the same invariant as C-1 — *exact-integer accumulation on the committed path,
whether the unit is nominally integer or float; no operation on the committed path may
ever round* — with the scale-application clause added.

---

## 5. The tax-inversion table

GEMM-count tax is exact arithmetic (width-ratio law); throughput columns are
**illustrative vendor/measured peaks, never load-bearing** — real ordering requires
B2g-style stage-boundary measurement on silicon (§K.2a-WT/§K.2b; two prior model
estimates in this program were falsified by measurement). "eff" = peak ÷ GEMM-count tax.

### 5.1 Under the CURRENT balanced-s8 object (W_obj ≈ 8 bits)

| Platform | Best exact path | Slices k → GEMMs k² | Illustrative eff. exact-matmul rate | Tax vs own frontier rate |
|---|---|---|---|---|
| B200 | native INT8 IMMA | 1 → 1 | 3,927 TOPS | ~2× (its FP4 7,702 is unusable) |
| **B300/GB300** | reduced INT8, or FP4 Ozaki | 1 (INT8, cut) / 3 → 9 (FP4) | INT8: unpublished-but-cut; FP4: ~15,000/9 ≈ 1,700 | **~4–9× off its NVFP4 frontier** |
| **Rubin** | FP8 Ozaki / FP4 Ozaki (INT8 unlisted) | 2 → 4 (FP8) / 3 → 9 (FP4) | ~16,000/4 ≈ 4,000 / ~35,000/9 ≈ 3,900 | **~4–9×** |
| **MI355X** | native INT8 MFMA | 1 → 1 | INT8 retained (rate not pinned) | its 10,100 FP4 unusable → ~2×+ |
| **Trainium2/3** | FP8/MXFP8 Ozaki (no INT8 matmul) | 2 → 4 | MXFP8-rate/4 | **4×, or excluded entirely pre-v4.1** |
| **TPU v7** | native INT8 (v7 retains INT8; FP8 t unproven) | 1 → 1 | INT8 rate | FP8 frontier idle |
| RTX 5090 | native INT8 | 1 → 1 | 838 TOPS | ~0 (INT8 is its near-frontier) |
| H100 | native INT8 | 1 → 1 | 1,979 TOPS | 0 |
| Apple M5 Max | native INT8→INT32 | 1 → 1 | ~130 TOPS | 0 |

**Reading:** the tax sits on exactly the chips the ladder wants to win — the FP4 frontier
pays 4–9×; INT8 legacy pays nothing.

### 5.2 Under the NEW BMX4 object (E2M1 mantissa + E8M0 scales, S = 4; W_int ≈ 8.6 bits for integer emulation, ~0 bits for MX hardware)

| Platform | Best exact path | GEMMs | Illustrative eff. rate | Tax |
|---|---|---|---|---|
| **B300/GB300** | native `mxf4` block-scaled MMA (E8M0), K′=256–448 promotion | **1** | ≈ dense FP4 rate (~1.5× B200's 7,702 measured) | **≈1× — tax removed (was 9×)** |
| **Rubin** | native FP4 block-scaled ⚠ (confirm E8M0 kind survives) | **1** | ≈ 35–50 PF vendor peak class | **≈1×** ⚠ |
| **MI355X** | native OCP MXFP4 | **1** | ≈ 10,100 TOPS class | **≈1×** |
| **Trainium3** | native Matmul-MX (MXFP4), FP32 PSUM, K′-blocked | **1** | ≈ 4× BF16 rate | **≈1× — newly mineable at frontier rate** |
| **B200** | conditional tcgen05/CUTLASS MXFP4 target; **not admitted in this branch** (current LT path: MX-layout, four-pass INT8 IMMA lowering) | **1 if a native kernel qualifies** | FP4 application rate unmeasured for this workload | modeled ≈1× only after kernel + M-t24 qualification |
| **RTX 5090 (consumer Blackwell)** | FP4 with power-of-two scales in UE4M3 slots (exact embed) | **1** | ≈ its FP4 rate (~2× its 838 INT8) | ≈1× — ladder preserved by absolute TOPS |
| **TPU v7** | scale-fold → 1 plain FP8 GEMM (needs proven t=24) | **1** | ≈ 4,614 TF FP8 | ≈1× in GEMM count; pays only the FP8-vs-FP4 rate gap (no FP4 unit exists) |
| **Trainium2** | scale-fold → FP8 (t must prove 24) else vector-engine/host path | 1 ⚠ | FP8 rate | ≈1× ⚠ (t unproven) |
| **H100/H200** | FP8 fold FAILS (t≈14 ⇒ K′=0) → INT8 2-slice | **4** | 1,979/4 ≈ **495 TOPS** | **4× backwards-compat tax** (was 0) |
| **B200-class INT8-only / TPU v6e / Gaudi-class** | dequant-shift + 2-slice balanced base-2⁷ → 4 s8 GEMMs | **4** | INT8-rate/4 (v6e: ~INT8/4) | **4× backwards-compat** |
| **RTX 40/30, CMP, pre-M5 Apple** | Ada: FP8-fold if t proven, else INT8 4×; Ampere/CMP: INT8/DP4A 2-slice | 1–4 | e.g. 3090: 285/4 ≈ 71 TOPS | **≤4×, bounded — still mines, just less** |
| **Apple M5** | INT8 2-slice (4×) or FP16-with-FP32-accum fold (1× at FP16 rate) | 4 / 1 | ~33 TOPS (INT8/4) or ~FP16 rate | **≤4× — M-class keeps mining at the ladder's bottom, as intended** |

**The old-chip backwards-compat tax, quantified and bounded:** an INT8-only part pays
(i) the k² = 4 GEMM multiplier (192 > 127 forces exactly 2 balanced base-2⁷ slices —
never more, since `12·2^S ≤ 16,383` keeps 2 digits sufficient up to S = 10); plus (ii)
O(n²) integer dequant-shift and slice decomposition off the tensor units (same class of
overhead the v4.1 FP path already budgets, §K.2a-WT re-measure obligation); plus (iii)
zero change to its XOF/combine/digest stages. Net ≈ **INT8-rate/4** — e.g. a 5-year-old
3090 still mines at ~71 TOPS-equivalent. No cliff, no exclusion: the reward ladder
compresses old chips by ~4× and re-anchors the top to frontier FP4 TOPS, which is the
intended scaled-reward outcome (datacenter FP4 ≫ consumer FP4/INT8 ≫ M-class, in absolute
terms).

**Headline: the 9× (FP4) / 4× (FP8-only) conversion tax on frontier chips drops to ≈1×;
the 1× on INT8-only legacy rises to a bounded 4×.** The width-ratio law, applied in the
chosen direction.

---

## 6. Honest verdict

1. **Can the new-chip tax be driven to ≈1×? Conditionally — for an admitted
   OCP-MX-E8M0 kernel, and only with power-of-two scales.** On a future qualified
   B200/B300 tcgen05/CUTLASS path,
   MI350X/MI355X (OCP MX in CDNA4), and Trainium3 (Matmul-MX with UINT8 power-of-two
   scale tensors), the BMX4 object is one native block-scaled GEMM plus a K′=256–448
   extract-and-promote cadence whose overhead is the same one promotion per few hundred
   K-elements that production FP8 training already pays (DeepSeek's every-128 promotion)
   — near-native by construction, *pending an implemented kernel and the t=24 proof on real silicon*. FP8-only
   frontier chips (TPU v7, Trainium2) reach ≈1× in GEMM count at their FP8 rate via exact
   scale-folding; they pay only the FP4-vs-FP8 rate gap that their own silicon defines.
2. **NVFP4's fractional E4M3 scale is unusable as a committed format** (§3a: unprovable
   dequant exactness; K′ collapse; single-vendor) — **route to MX-power-of-two**, which
   NVIDIA hardware hosts at the same FP4 pipes anyway (UE8M0 kinds; 2^e is exact UE4M3).
   This is the precise sense in which "MXFP8/MX-E8M0 is determinism-friendly and NVFP4 is
   determinism-hostile": the scale format, not the element format, is what decides.
3. **What it costs the old chips:** a bounded 4× GEMM-count tax plus O(n²) dequant/slice
   overhead (§5.2). H100 — the sharpest case — drops from 1,979 native to ≈495 effective,
   because its FP8 accumulator (t≈14) fails the native path *and* its INT8 unit must
   slice. Old chips keep mining; the ladder compresses rather than excludes.
4. **What it costs the design:** (i) element entropy falls from ~7.97 to ~3.9(+0.07
   scale) bits — whether the seed-grinding/anti-amortization/hardness story survives the
   narrower alphabet is exactly the companion doc's re-derivation to deliver, and BMX8
   ([−15,15] mantissas at FP8/MX rate, ~4.95 bits) is the specified fallback if it does
   not; (ii) `n_max` tightens to 58,254 (header-range note); (iii) the C-13 limb combine
   needs the remainder-top/5th-limb fix beyond n = 4096; (iv) the combine stage's s8 limb
   GEMMs are not FP4-native — on FP4-only parts they run via the FP8 pipe (49-GEMM
   flattened variant), the int-ALU mod-q direct path, or E2M1-native U/V (deferred), and
   the §K.2a-WT wall-time majority must be re-measured on the new object before any
   ordering claim.
5. **Measurement-gated, throughout.** Every throughput number above is a vendor peak or a
   third-party microbenchmark; the program's own history (two falsified model estimates)
   forbids treating them as results. The B2g-style obligations: prove t on each
   block-scaled path (boundary vectors at exactly 2^t, mixed-exponent K-runs); confirm
   `mxf4`-E8M0 runs at the full FP4 rate on B200/B300 and survives on Rubin; confirm NKI
   accepts explicit committed scale tensors; re-run the wall-time stage split at Q ≥ 32.
   No token/market-price quantity appears anywhere in this design (spec §0.7-(4)).

---

## 7. Consensus classification

| Item | Class |
|---|---|
| **Changing the committed operand format to BMX4/BMX8** (new operand alphabet + block-scale structure + sampler + magnitude bounds; new golden vectors; ASERT rescale re-calibration) | **CONSENSUS CHANGE — hard-fork-level workload change (a v4.2 object)**, per roadmap §3.4 rows 3–4. Note precisely what it is NOT: it is *not* a float or MX *sketch* — the committed object remains exact integers; Freivalds over q = 2⁶¹−1, the sketch shape, digest rule, and O(n²) verifier cost are unchanged in form. But the operands, their derivation, and every golden vector change ⇒ fork. |
| Soundness/hardness re-derivation for the new object (alphabet entropy, anti-grinding, sketch collision bounds, E2M1 U/V option) | **Deferred to the companion `doc/btx-matmul-v4-committed-object-redesign.md` (owned by another agent; not written here).** BMX4 must not activate before that re-derivation lands. |
| Miner K′/block schedule, promotion cadence, scale-folding embeds, old-chip 2-slice decomposition, limb re-parameterization | **Miner-local** (schedule-independence: exactness, not schedule, delivers bit-identity) |
| §4.6 eligibility self-test vectors (t-proof, scale-exactness, 2^t boundaries) | **Consensus-protecting, not consensus** (C-1 pattern; verify+fallback still backstops) |
| Difficulty/W_nonce recalibration on the new object | **Consensus-adjacent calibration** (measured marginal unit, §K.2a-WT/B2g; not a verifier change) |
| Choosing S (the tax dial), b, n within the new object | Consensus *parameters* of the v4.2 object — fixed at fork time from measurement |

Sequencing note: the v4.1 exact-int-on-float miner path (no fork) remains the bridge —
frontier chips can mine the s8 object at k²-tax today; BMX4 is the fork that removes
their tax when governance triggers (roadmap G-1) fire and the companion re-derivation
plus B2g measurements pass.

---

## 8. Confidence & what could not be verified

| Claim | Confidence | Basis / caveat |
|---|---|---|
| OCP MX = block-32 + E8M0 power-of-two scale; E2M1/E4M3 exact sets as stated | **High** | OCP MX v1.0 spec; exact sets are format arithmetic (machine-checkable, as the v4.1 suite did for slices) |
| E8M0 dequant is an exact shift; fractional E4M3 scale dequant is not provably exact | **High** (format arithmetic) | Exponent-field add vs 4-significant-bit multiply; internal NVFP4 dequant width undocumented — the *unprovability* is the point |
| Blackwell `mxf4`/`mxf8f6f4` accept UE8M0 scales; `mxf4nvf4` accepts UE8M0 or UE4M3; FP32 accumulate into TMEM | **High** (documented) / **Medium** (exactness) | CUTLASS docs, Colfax, Triton tutorials. Whether the FP32 TMEM accumulate is truly t=24 exact (vs a Hopper-style narrowed path) is **unverified — the single biggest risk**, gating native eligibility; must be proven by §4.6 boundary vectors on real B200/B300 |
| `mxf4`-E8M0 runs at the same rate as NVFP4 on B200/B300; Rubin keeps an E8M0 FP4 kind | **Medium / Low-Medium** | Same 4-bit pipe per CUTLASS kinds (rate parity not benchmarked anywhere I could find); Rubin precision list confirms FP4/FP8 but not scale-kind detail — R-1-style monitoring item |
| Trainium3 Matmul-MX: UINT8 power-of-two scales, FP32 PSUM, 4× BF16 rate | **High** | AWS NKI architecture guide + MXFP deep dive. **Unverified:** whether a kernel can feed *committed* (not `quantize_mx`-derived) scale tensors — flagged ⚠, needs an NKI prototype |
| TPU v7: native FP8 E4M3, FP32 MXU accumulation, 4,614 TF, no FP4 | **High** (specs) / **Medium** (t=24 exactness) | Google TPU7x docs + Ironwood blog; exactness unproven on silicon (M-2 posture) |
| MI355X MXFP4/6 10.1 PF, MXFP8 5.0 PF dense | **High** | AMD datasheet |
| Hopper FP8 accumulator ≈14-bit ⇒ H100 fails the native path | **High** (finding) / **Medium** (BTX consequence) | DeepSeek-V3 §3.3.2 + microbenchmark literature; consequence follows from K′ arithmetic |
| Old-chip tax is exactly 4 GEMMs (2-slice) at S=4, bounded to n≈58k int32 envelope | **High** | Pure integer arithmetic (width-ratio law + §B.4-style bounds); slice totality needs the remainder-top rule, machine-checkable |
| The new-chip ≈1× and the resulting nonce/s *ordering* on real silicon | **Low (unproven by design)** | No BTX kernel has ever run on B300/MI355X/Trn3/TPU v7; peak ratios are illustrative; §K.2a-WT wall-time majority on the new object unmeasured — B2g obligations before any activation claim |
| BMX4's ~3.9-bit alphabet preserves PoW hardness | **Not assessed here** | Deferred in full to the companion committed-object-redesign doc |

**Could not verify at all:** B300's post-cut INT8 TOPS; any Rubin scale-kind or
accumulator detail beyond vendor precision lists; MXFP4-vs-NVFP4 rate parity on any
shipping part; NKI explicit-scale-tensor support; any real-silicon exactness run for any
block-scaled path (this repo has no frontier-FP hardware — same posture as ACTIVATION
B2a/B2g).
