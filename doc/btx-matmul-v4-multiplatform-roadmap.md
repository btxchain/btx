# BTX MatMul v4.1 — Multi-Platform & Future-Facing Solver / Optimization Roadmap

*Status: RESEARCH + ARCHITECTURE deliverable. Not a code change and not a consensus
change. Companion to `doc/btx-matmul-v4-design-spec.md` (the spec, authoritative) and
`ACTIVATION.md` (the measurement-gated activation tracker). Written 2026-07-16.*

> **Posture (inherited from the spec and ACTIVATION.md, and preserved here):** the
> datacenter-favoring ordering is a **HYPOTHESIS pending real-hardware measurement**
> (§K.2b GO/NO-GO, ACTIVATION B2g). Two prior model estimates were falsified. Nothing
> in this document upgrades a hypothesis to a result. Forward-looking hardware claims are
> cited and are explicitly split into **confirmed specs** vs **rumor/roadmap**. Per spec
> §0.7-(4) (PRICE-INDEPENDENCE), no reasoning here uses BTX or token market price as an
> input; where hardware "cost" appears it is opportunity-cost/throughput framing only.

---

## 1. Executive summary

**Is the exact-INT8 workload multi-platform? — YES, but on a shrinking island.** Today,
exact `s8×s8→s32` integer matmul with a true INT32 accumulator is available and
bit-reproducible on **NVIDIA (Turing→Blackwell IMMA), AMD (CDNA MFMA), Apple (M5 Neural
Accelerators), Google TPU (v5e/v5p and later, true-int32 MXU), and Intel Gaudi 3**, and
is *programmable by third parties* on all of NVIDIA/AMD/Apple/TPU/Tenstorrent. The three
existing backends (`accel_v4.h` Kind{CUDA,METAL,HIP}) already cover the permissionless
tiers; the dispatch contract's **verify-every-result-and-fall-back-to-CPU** rule means
any *new* backend is safe-by-construction (a wrong digest can only lose throughput, never
split the chain). So adding platforms is low-risk engineering, not a consensus gamble.

**Is it future-facing? — WITH SERIOUS CAVEATS, and the caveat is the whole story.** The
AI industry is unambiguously moving its *frontier* low-precision compute off INT8 and onto
**FP8 / FP4 / microscaling (MXFP8, NVFP4)**. This is not a forecast; it is already shipping:

- **NVIDIA Blackwell Ultra (B300/GB300)** delivers up to **50 % more dense NVFP4
  throughput "at the cost of INT8 and FP64 performance"** — i.e. NVIDIA *reduced* INT8 on
  its newest datacenter part to make room for NVFP4
  ([Tom's Hardware](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support)).
- **NVIDIA Rubin / Rubin Ultra** (2026/2027): the tensor-core width **doubling applies only
  to FP4 and FP8**; BF16/TF32 stay flat, and INT8 is not called out as a first-class fast
  path in NVIDIA's own precision lists
  ([Rubin platform blog](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/),
  [SemiAnalysis](https://newsletter.semianalysis.com/p/vera-rubin-extreme-co-design-an-evolution)).
- **AWS Trainium2 / Trainium3**: the systolic **Tensor (matmul) Engine is float-only** —
  FP8/BF16/FP16/TF32/FP32 on Trn2, BF16+MXFP8 on Trn3. There is **no INT8 matmul on the
  systolic array at all**; INT8 lives only on the non-matmul Vector Engine
  ([Trainium2 NKI arch guide](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/guides/architecture/trainium2_arch.html),
  [Trainium3 overview](https://awesomeagents.ai/hardware/aws-trainium3/)).

**The single biggest strategic risk, stated plainly:** binding the PoW to *exact-integer
INT8* means that as each new datacenter generation pours its transistor budget into
FP4/FP8, the **INT8 lever the PoW actually measures will stagnate or shrink relative to the
true AI-compute frontier.** The "reward scales with AI compute" thesis holds *today*
(a B200/B300 still has far more absolute INT8 TOPS than a 5090), but it **decouples over
2–3 generations**: a future accelerator can be an AI monster in NVFP4 and a mediocre INT8
part, and a whole class of new AI silicon (Trainium) is *already* excluded from the INT8
path entirely. INT8 is on track to become a legacy/compatibility precision, not the
frontier — exactly the opposite of where the design wants to sit.

**Recommendation (three parts, none of them "panic"):**
1. **Keep exact-INT8 as the consensus baseline now.** It is the *only* cross-vendor
   **bit-exact, ZK-free** tensor path that exists (§K.4). FP8/FP4 are non-associative and
   would fork or need attestation. There is no drop-in replacement.
2. **Treat the INT8→FP shift as a monitored, governance-triggered risk** (new backlog item
   G-1): track dense-INT8-TOPS vs dense-FP4/FP8-TOPS on every new datacenter generation; if
   INT8 decouples from the AI frontier past a threshold, escalate.
3. **Fund the escape hatch as research, not as a fork:** an **exact-integer-on-float
   (Ozaki-scheme) path** that reproduces the *same* bit-exact integer product on float-only
   tensor cores. This is the only known way to follow the frontier onto FP-only hardware
   (Trainium, future NVIDIA) *without* giving up determinism — but it is a **consensus
   change** and carries a real cross-vendor determinism burden (§3). Do the feasibility
   study before it is on the critical path, not after.

**Two concrete architectural flaws for future hardware are called out in §3.4 and must be
read before any TPU/Trainium/other-vendor onboarding** — chiefly that the spec's
"`s8×s8→s32` MMA is exact" determinism argument (§B.6) silently assumes a **true ≥32-bit
integer accumulator**, which **TPU v4-class MXUs do not have** (they saturate at the FP32
mantissa, 2²⁴), so a naïve TPU-v4 backend would compute *wrong high-magnitude entries and
split the chain.* This is a genuine, concrete, cross-vendor bit-exactness hazard, not a
throughput footnote.

---

## 2. Per-platform feasibility matrix

Legend — **Exact-INT8 path?** = is there an `s8×s8→s32` (or equivalent exact-integer)
*matmul* unit with a true INT32 accumulator? **Det?** = bit-exact & order-independent
across units/runs? **3P-prog?** = can a third-party miner write a custom PoW kernel (open
SDK/ISA vs locked inference stack)? **DC-fav?** = does it advance the datacenter-over-
consumer ordering the design wants? **Permissionless?** = buyable/rentable without a single
gatekeeper (vs one hyperscaler). **accel_v4 effort** = work to reach the plug-in contract.

| Platform | Exact-INT8 path? | Det? | 3P-prog? | DC-fav? | Permissionless? | accel_v4 plug-in effort |
|---|---|---|---|---|---|---|
| **NVIDIA H100/H200/B200** (Hopper/Blackwell IMMA) | **Yes**, `mma.*.s32.s8.s8.s32`, true int32 accum | **Yes** (int, order-indep.) | **Yes** (CUDA/cuBLASLt, open) | **Yes** (absolute INT8 TOPS ≫ consumer — *hypothesis, ACTIVATION B2g*) | **Yes** (buy or rent anywhere) | **Done** — `src/cuda/matmul_v4_accel.cu` (cuBLASLt IMMA + C-13 limb). Re-measure only. |
| **NVIDIA Blackwell Ultra B300/GB300** | **Yes but reduced** — INT8 cut to fund NVFP4 [1] | Yes | Yes | **Weakening** — its AI edge is now in NVFP4, which the PoW can't see | Yes | **Covered** by CUDA backend; risk is *economic decoupling*, not code |
| **NVIDIA Rubin / Rubin Ultra** (2026/27) | **Likely yes, flat** — INT8 IMMA presumed retained but *not* doubled; **not listed** in NVIDIA's headline precision set [2] ⚠needs-confirm | Yes (if present) | Yes | **Eroding** — 2× only for FP4/FP8; INT8 stagnates | Yes | CUDA backend should carry forward; **confirm INT8 IMMA survives on Rubin** |
| **AMD MI300/MI325X (CDNA3), MI350/MI355X (CDNA4)** | **Yes**, MFMA INT8 int32-accum; 8-bit throughput 2×/CU vs MI300 [3] | **Yes** | **Yes (most open DC path)** — ROCm/HIP open-source | **Yes** (datacenter INT8 TOPS ≫ consumer) | **Yes** (buy the card, open stack) | **Done** — `src/hip/matmul_v4_accel.hip` (MFMA). Validate MI350/MI355X + re-measure. |
| **AMD MI400 / UDNA** (2026+) | **Likely yes** — CDNA-Next adds FP4/FP8 headline; INT8 MFMA expected to persist ⚠needs-confirm | Yes | Yes | Yes | Yes | HIP backend forward-compatible; confirm INT8 MFMA on UDNA |
| **Google TPU v5e/v5p** | **Yes** — native int8 mult + **true int32 accumulator** [4][5] | **Yes** (XLA static schedule + int accum) [6] | **Yes** — Pallas/Mosaic/JAX, INT8 custom kernels (+71 % vs bf16 on v5e) [7] | **Plausible** (systolic, high INT8 TOPS) — *unmeasured* | **No — Google Cloud only** | **New** Kind::TPU: Pallas kernel + remote host-bridge (heavier than in-process GPU) |
| **Google TPU v6e Trillium / v7 Ironwood** | **Yes** — 256×256 MXU, native BF16/FP8/**INT8** [8] | Yes | Yes (Pallas) | Plausible (unmeasured) | **No — cloud only** | Same as above; strongest cloud datacenter fit |
| **Google TPU v4 (legacy)** | **NO for this workload** — MXU accum is **FP32-mantissa bounded (2²⁴)**, not true int32 → **not bit-exact** at n=4096 [4] | **NO** (silent rounding >2²⁴) | Yes | — | No | **DO NOT onboard without the §3.4 accumulator-width gate** |
| **AWS Trainium2 / Trainium3** | **NO** — systolic Tensor Engine is **float-only** (FP8/BF16/MXFP8); INT8 only on non-matmul Vector Engine [9][10] | n/a (no int matmul unit) | **Yes** — NKI open (Apache-2.0, MLIR) | Would-be, but **no INT8 matmul primitive** | **No — AWS only** | **Blocked** unless exact-int-on-float (§3.3) — NKI kernel could host it, but that's a consensus change |
| **Apple M5 / M5 Pro / M5 Max** | **Yes** — Neural Accelerator per GPU core, INT8 with **INT32 output** [11][12] | Yes *pending* self-test (order-indep. in principle) | **Yes** — Metal 4 TensorOps / MPP `matmul2d` | **No** — retail/pooled tier (~130 TOPS M5 Max est.) | **Yes** | **Done** — `src/metal/matmul_v4_accel.mm` (pre-M5 int-ALU tile + M5 `tensor_ops::matmul2d`) |
| **Apple M6 / M7** (2027+, rumor) | Expected yes (N2 process) ⚠rumor, no matmul specifics | TBD | Yes | No (retail) | Yes | Metal backend forward-compatible |
| **Tenstorrent Blackhole** | **Yes** — Tensix matrix engine, INT8; **fully open ISA** [13][14] | Plausible (static dataflow) — needs self-test | **Best-in-class** — TT-Metalium open C++ kernels, open LLK/ISA docs | No (throughput tier modest today) | **Yes** (buy card, fully open) | **New** Kind::TT: TT-Metalium kernel; strong permissionless hedge, real effort |
| **Intel Gaudi 3** | **Yes** — 8× MME 256×256, INT8 supported [15] | Plausible — needs self-test | Yes (TPC C-like kernels) | Plausible (unmeasured) | Limited (Intel/cloud) | **New** backend; medium effort |
| **Groq LPU** | **Yes** (INT8, ~750 TOPS) & **deterministic by design** [16] | **Yes** (deterministic arch) | **No** — inference-compiler-locked, no general custom-kernel path | n/a | **No** (cloud only) | Impractical (locked stack) |
| **Cerebras / SambaNova** | **Weak/float-centric** (BF16/FP; SambaNova markets "no quantization") | — | Partial | — | No (cloud/appliance) | Not a near-term target |

Sources for the matrix: **[1]** [Tom's Hardware — Blackwell Ultra NVFP4 boost "at the cost
of INT8 and FP64"](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support);
[NVIDIA Blackwell Ultra blog](https://developer.nvidia.com/blog/inside-nvidia-blackwell-ultra-the-chip-powering-the-ai-factory-era/);
[Blackwell microbenchmark, arXiv:2512.02189](https://arxiv.org/html/2512.02189v1) (standard
Blackwell: INT8 3927 TOPS ≈ FP8 3851, FP4 7702). **[2]**
[NVIDIA Rubin platform blog](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/);
[Rubin, Wikipedia](https://en.wikipedia.org/wiki/Rubin_(microarchitecture)). **[3]**
[AMD Instinct MI350 blog](https://www.amd.com/en/blogs/2025/amd-instinct-mi350-series-and-beyond-accelerating-the-future-of-ai-and-hpc.html);
[Tom's Hardware MI355X](https://www.tomshardware.com/tech-industry/artificial-intelligence/amd-reveals-core-specs-for-instinct-mi355x-cdna4-ai-accelerator-slated-for-shipping-in-the-second-half-of-2025);
[STH Hot Chips CDNA4](https://www.servethehome.com/amd-dives-deep-on-cdna-4-architecture-and-mi350-accelerator-at-hot-chips-2025/). **[4]**
[Architectural Limits of Cloud TPUs in Finite-Field Cryptography, arXiv:2605.25367](https://arxiv.org/html/2605.25367)
(v4 MXU accumulator is FP32-mantissa-bounded 2²⁴; v5e/v5p have a true int32 accumulator).
**[5]** [Google Cloud TPU architecture docs](https://docs.cloud.google.com/tpu/docs/system-architecture-tpu-vm). **[6]**
[Large-scale linear algebra on TPUs, arXiv:2112.09017](https://arxiv.org/pdf/2112.09017)
(XLA deterministic scheduling). **[7]**
[Pallas / custom TPU kernels (TDS)](https://towardsdatascience.com/the-rise-of-pallas-unlocking-tpu-potential-with-custom-kernels/). **[8]**
[TPU7x Ironwood docs](https://docs.cloud.google.com/tpu/docs/tpu7x);
[Inside the Ironwood stack](https://cloud.google.com/blog/products/compute/inside-the-ironwood-tpu-codesigned-ai-stack). **[9]**
[Trainium2 NKI architecture guide](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/guides/architecture/trainium2_arch.html). **[10]**
[Trainium3 overview](https://awesomeagents.ai/hardware/aws-trainium3/);
[NKI docs](https://awsdocs-neuron.readthedocs-hosted.com/en/latest/nki/index.html). **[11]**
[Zakharko — A19/M5 Neural Accelerators (INT8→INT32)](https://tzakharko.github.io/apple-neural-accelerators-benchmark/). **[12]**
[Apple ML Research — MLX on M5](https://machinelearning.apple.com/research/exploring-llms-mlx-m5);
[Metal tensors WWDC26 330](https://developer.apple.com/videos/play/wwdc2026/330/). **[13]**
[Tenstorrent Blackhole dev launch](https://tenstorrent.com/newsroom/tenstorrent-launches-blackhole-developer-products-at-tenstorrent-dev-day);
[tt-metal / TT-Metalium](https://github.com/tenstorrent/tt-metal). **[14]**
[tt-isa-documentation](https://github.com/tenstorrent/tt-isa-documentation);
[Tenstorrent RISC-V matmul, arXiv:2505.06085](https://arxiv.org/pdf/2505.06085). **[15]**
[Intel Gaudi 3 white paper](https://cdrdv2-public.intel.com/817486/gaudi-3-ai-accelerator-white-paper.pdf). **[16]**
[Cerebras/Groq/SambaNova comparison](https://intuitionlabs.ai/articles/cerebras-vs-sambanova-vs-groq-ai-chips).

**Reading of the matrix.** The permissionless + open + exact-INT8 + datacenter quadrant is
essentially **AMD ROCm/HIP alone** among the frontier parts (NVIDIA is open+permissionless
but is *deprioritizing* INT8; TPU/Trainium are cloud-gated). The permissionless retail tier
is **Apple + Tenstorrent**. The genuinely new cloud datacenter substrate is **TPU v5e+**,
gated behind Google Cloud and behind the §3.4 accumulator-width hazard. **Trainium, despite
open tooling (NKI), is disqualified from the exact-INT8 path by hardware** — the sharpest
single illustration of the industry shift.

---

## 3. The precision-format strategic analysis (the most important section)

### 3.1 The question, restated

Does binding the PoW to *exact-integer INT8* keep it on the AI-compute frontier, or will
future AI accelerators — which optimize for low-precision **float** (FP8/FP4/microscaling)
— diverge from an INT8-integer workload and undermine the "reward scales with AI compute"
thesis?

### 3.2 The honest assessment: the frontier is leaving INT8, on a measurable schedule

The spec's §K.4 argument ("INT8 loses nothing economically — dense INT8 = dense FP8 on
H100/B200") **was true for Hopper and base Blackwell and is already false at the leading
edge:**

| Generation | Dense INT8 vs the frontier low-precision format | Direction |
|---|---|---|
| Hopper H100/H200 | INT8 = FP8 = 1,979 TOPS (no FP4 unit) | INT8 *is* the low-precision frontier |
| Blackwell B200 | INT8 3,927 ≈ FP8 3,851; **FP4 7,702 (2× INT8)** [arXiv:2512.02189] | INT8 = half the frontier |
| **Blackwell Ultra B300** | **INT8 *reduced*** to fund NVFP4; NVFP4 +50 % dense [Tom's Hardware] | INT8 actively cut |
| **Rubin / Rubin Ultra** | 2× width **for FP4/FP8 only**; INT8 flat / unlisted | INT8 stagnates as FP4 doubles |
| **AWS Trainium2/3** | **No INT8 matmul unit at all** (float + MXFP8 systolic) | INT8 absent from a whole new class |
| AMD CDNA4 MI355X | INT8 retained, 2×/CU vs MI300 (with FP6/FP4 added) | INT8 still first-class *here* |
| Apple M5 | INT8→INT32 present; but MX scaling formats arriving OS 27 | INT8 present, float creeping in |

Two conclusions follow, both honest:

1. **The ordering survives today.** Absolute dense INT8 TOPS still rank datacenter above
   consumer (B200 4,500 ≫ 5090 838; even a de-rated B300 keeps a large absolute INT8 lead).
   The §K.2b GO/NO-GO can still pass on current silicon. Nothing here changes the *near-term*
   activation calculus.
2. **The thesis decouples on a 2–3 generation horizon.** The quantity the PoW rewards
   (dense INT8 TOPS) is being *deliberately frozen or cut* on the newest datacenter parts
   while the quantity that actually defines "AI compute" (dense FP4/microscaling TOPS)
   races ahead. A Rubin-class or Trainium-class part can be a top-tier AI accelerator and a
   middling (or absent) INT8 miner. Over enough generations this **inverts the design
   intent**: reward would scale with *legacy-INT8* compute, not *AI* compute.

This is the single biggest strategic risk in the whole v4.1 program, larger than any
single-backend determinism bug, because no amount of solver work on the INT8 path fixes a
frontier that has moved off INT8.

### 3.3 Determinism-preserving options if the frontier moves off INT8

The hard constraint never relaxes: **every backend must reproduce the CPU reference
bit-for-bit; no floating point on the consensus path** (FP add is non-associative and
diverges across vendors, spec §K.4, [arXiv:2511.00025](https://arxiv.org/pdf/2511.00025)).
Any migration must preserve exact, order-independent, cross-vendor-identical arithmetic.
The candidate paths, worst-to-best for BTX:

**Option A — INT4 integer (`s4×s4→s32`). REJECTED.** The frontier is *float* FP4, not
integer INT4. NVIDIA deprecated INT4 IMMA after Turing/Ampere; Blackwell/Rubin FP4 units
are floating point. There is no cross-vendor exact-integer INT4 matmul path to move to.
Dead end.

**Option B — Block-scaled / microscaling with *integer* mantissas. RESEARCH, high risk.**
MXFP8/NVFP4 store *float* mantissas and accumulate in float (non-deterministic). A
determinism-preserving analogue would be *integer mantissas + a shared per-block
power-of-two (integer) scale*, with **exact integer accumulation of the mantissa products
inside a block** and an exact shifted fold across blocks — structurally the *same trick*
v4.1 already uses in the **C-13 limb combine** (balanced base-2⁷ digits + a `Σ 2^{7(i+j)}`
mod-q fold). The problem is that commercial MX *hardware* accumulates mantissas in float;
to stay exact you must force integer accumulation, which either (a) is not what the MX unit
does, or (b) drops you back onto the plain INT8 path you were trying to leave. **Net: this
buys frontier-format *shape* without frontier-format *hardware acceleration* unless a vendor
ships an exact-integer-accumulate MX mode, which none has announced.** Consensus change;
park as research.

**Option C — Exact integer *via* float (Ozaki-scheme error-free transforms). RESEARCH, the
recommended escape hatch.** The Ozaki scheme computes an *exact* integer/`s32` matmul on
*float* tensor cores by splitting each operand into a fixed number of low-bit "slices" whose
pairwise products are exactly representable in the FP format's mantissa, then summing the
slice-products *exactly*. Recent work maps this onto FP16/FP8 tensor cores for exact/high-
precision GEMM. For BTX this is the **only known way to reproduce the identical bit-exact
integer product on float-only frontier hardware** — the Trainium class, and any future
NVIDIA part that keeps only float fast paths. Tradeoffs, all real:
  - **Determinism is recoverable but not free.** Exactness requires the slice count and the
    *summation order/method* to be **pinned in consensus** and performed in an exact
    (integer or compensated-and-proven-exact) accumulator — you cannot lean on the FP
    unit's own non-associative accumulation. That reintroduces int-ALU/VPU work off the
    tensor cores, partially eroding the very datacenter tensor lever (§K.2a-WT wall-time
    check would have to be re-cleared).
  - **Freivalds is unaffected in principle** — it verifies the *committed integer product*
    `C` over `q=2⁶¹−1` regardless of how the miner computed `C` (§D.3). The verifier does
    not care whether the miner used IMMA, MFMA, or an Ozaki-on-FP8 kernel, only that the
    committed integers are correct. **This is the key enabling fact: the escape hatch is a
    *miner-side* computation change, not a verifier change** — *provided* the committed
    object stays the exact integer `C`/`Ĉ`.
  - **But it is a consensus-critical *specification* change** the moment it becomes the
    normative fast path, because difficulty (§I.4) is calibrated to the marginal work unit
    and the ASERT rescale (ACTIVATION B2b) would move.

**Option D — Status quo + governance trigger + funded Option-C study. RECOMMENDED now.**
Keep exact-INT8 as the sole consensus baseline (it is the only shipping cross-vendor
bit-exact tensor path). Add the §5 monitoring trigger. Fund the Option-C feasibility study
so that if/when INT8 throughput on new datacenter parts stalls relative to FP4 by a
governance-set margin, BTX already knows whether an exact-int-on-float path can follow the
frontier without breaking determinism — *before* it is on the critical path.

### 3.4 Flag: what is a consensus change vs a miner-only optimization

| Change | Class | Why |
|---|---|---|
| Add a TPU/Trainium/Tenstorrent/Gaudi backend that reproduces the **same INT8 `Ĉ`** | **Miner-only** | Dispatcher verifies + falls back; digest byte-identical (`accel_v4.h` contract) |
| Ozaki-on-float kernel that still commits the **exact integer `C`/`Ĉ`** | **Miner-only** *iff* committed bytes are identical; but its *difficulty calibration* is consensus-adjacent | Verifier checks integers, not the method (§D.3) |
| Changing the committed object to a **float/MX** sketch | **CONSENSUS FORK** + determinism risk | FP non-associativity → cross-vendor split (§K.4) |
| Changing `q`, `n`, `b`, limb base, or the operand field to suit a new accumulator width | **CONSENSUS FORK** | Alters the verified object and every golden vector |
| Enforcing the §3.4 **true-integer-accumulator eligibility self-test** | **Not consensus** (backend gating) but **consensus-*protecting*** | Prevents a mis-accumulating device (TPU v4) from ever sealing a divergent block |

---

## 4. Architectural flaws found for future hardware (READ THIS)

### 4.1 FLAW (prominent): the exactness argument assumes a true ≥32-bit **integer** accumulator that several AI accelerators do not have

Spec §B.6-(1) asserts "`s8×s8→s32` MMA is exact … given B.4 no accumulator wraps." §B.4
sizes the accumulator against `2³¹−1` (peak `4096·125² = 6.4×10⁷` at n=4096). **This is
correct only on hardware whose INT8 matmul truly accumulates in ≥32-bit two's-complement
integer.** It is *false* on accelerators whose "int8" matmul path accumulates into an
**FP32-mantissa-bounded accumulator (2²⁴ = 16,777,216)**:

- **Google TPU v4's MXU accumulator is bounded by the IEEE-754 FP32 mantissa (2²⁴), not the
  full int32 range** ([arXiv:2605.25367](https://arxiv.org/html/2605.25367)). At n=4096 the
  base-matmul accumulator peak `6.4×10⁷ ≫ 2²⁴`, so a TPU-v4 backend would **silently round
  high-magnitude entries and produce a wrong `C` → a different digest → a chain split** if
  it were ever flagged mining-capable without the self-test.
- The **C-13 limb-tensor combine is even more exposed**: each limb-pair GEMM entry is
  `n·64²`, which is **exactly 2²⁴ at n=4096** and `3.35×10⁷ > 2²⁴ at n=8192` — i.e. the
  combine sits *at or past* the FP32-mantissa boundary precisely on the parameter range the
  spec targets (n = 4096–8192, `CheckCombineLimbBound` allows n ≤ 8589). The limb path is
  *less* portable than the base GEMM, not more.
- Only **TPU v5e/v5p and later provide a true int32 accumulator** (extending the safe degree
  to `d_max ≈ 16,448`), which is why v5e+ are marked eligible and v4 is not.

**This is a real cross-vendor bit-exactness hazard, not a throughput issue.** The
verify-and-fallback dispatcher (`accel_v4.h`) protects the *chain* — a wrong device digest
is rejected and recomputed on CPU — so a mis-accumulating backend "only loses throughput."
But that safety net exists **only if the backend is correctly marked and the determinism
self-test (`verify-backend.sh`) actually exercises the failing regime.** The current golden
vectors (ACTIVATION B2a) are generated on NVIDIA/AMD/Apple — all true-int32 — so they would
**not catch** an FP32-mantissa accumulator. **Mitigation (backlog C-1, consensus-protecting):**
(a) make "true ≥32-bit integer accumulator" an explicit, documented eligibility invariant in
§B.6 / §O.1; (b) add **adversarial golden vectors that force accumulations in `(2²⁴, 2³¹)`**
— specifically high-magnitude `C`, `P=U·A`, `Q=B·V`, and limb-pair entries near 2²⁴ — so any
FP32-mantissa device fails the self-test loudly instead of silently at some future block.

### 4.2 FLAW (moderate): the wide-XOF operand floor behaves differently on systolic / cloud accelerators

The spec's §K.2a-WT wall-time-majority requirement was measured on PCIe GPUs where the host
CPU expands operands and the tensor stage dominates. On **systolic, host-bridged
accelerators (TPU, Trainium)** three things differ and are **unmeasured**:
(i) **`B` is nonce-fresh** (n² = 16 MiB at n=4096 *per nonce*) and must cross the host↔device
link every nonce — on a cloud TPU the host↔TPU path and the XLA dispatch latency are a
different bottleneck than PCIe GEMM overlap; (ii) systolic arrays want *large static* shapes,
which the §K.2b batched combine provides, but the per-nonce `B`-expansion + transfer floor
does not amortize; (iii) the XOF (SHA-256 counter mode) runs on whatever host the cloud
assigns. **Consequence:** the datacenter-ordering *hypothesis* is validated (pending B2g) only
on NVIDIA-class PCIe parts; it is **entirely unvalidated on systolic/cloud parts**, and the
measurement harness (`measure-hardware.sh`, `matmul_v4_stage_bench`) has no systolic/cloud
stage model. This is not a bug in the chain; it is a **gap in the evidence base** for the
"multi-platform datacenter-favoring" claim. (Backlog M-1.)

### 4.3 FLAW (strategic, not a bug): the frontier substrates are cloud-gated

TPU and Trainium — the two most credible *new* datacenter substrates — are available
**only** from Google and AWS respectively. A permissionless PoW whose top hardware is
rentable from exactly two hyperscalers concentrates the frontier behind those two firms'
capacity and terms. Spec §0.7-(4) (price-independence) and §O.2 (pooling) blunt the
*economic* manipulation angle, and the *permissionless* frontier still exists via **AMD
ROCm/HIP (open, buyable)** and the retail tier (Apple, Tenstorrent). But it should be stated
plainly in §N.3 (risk register): "multi-platform" at the datacenter frontier increasingly
means "multi-*hyperscaler*," which is in tension with permissionlessness. The mitigation is
to **actively keep the open, buyable paths (AMD, Tenstorrent) first-class**, not to chase
the cloud parts.

---

## 5. Concrete further solver-work items (prioritized backlog)

Tags: **[CC]** consensus-critical / consensus-protecting · **[OPT]** optional throughput/
coverage · **[MEAS]** measurement/harness · **[GOV]** governance/monitoring. Each item notes
*why it advances the scaled-reward-by-AI-compute goal.*

### Priority 1 — do before onboarding any non-NVIDIA/AMD/Apple part

- **C-1 [CC] True-integer-accumulator eligibility invariant + adversarial high-magnitude
  golden vectors (2²⁴–2³¹).** Extend §B.6/§O.1 to require a true ≥32-bit integer accumulator
  and add golden vectors that force `C`, `P`, `Q`, and limb-pair entries into `(2²⁴, 2³¹)` so
  FP32-mantissa MXUs (TPU v4-class) fail `verify-backend.sh` loudly. *Why:* it is the single
  cheapest insurance against a future backend silently splitting the chain, and it is the
  precondition for safely adding TPU/Trainium/Tenstorrent/Gaudi at all. **Highest priority.**

- **G-1 [GOV] INT8-vs-frontier monitoring trigger.** Track, per new datacenter generation,
  dense-INT8-TOPS ÷ dense-FP4/FP8-TOPS and dense-INT8-TOPS growth vs the AI frontier. Define
  a governance escalation if INT8 decouples past a threshold (e.g. INT8 flat while frontier
  FP4 ≥2× over a generation, as already seen B200→B300). *Why:* the §3.2 decoupling is the
  top strategic risk; this makes it a watched, actionable signal instead of a surprise.

### Priority 2 — highest-value coverage for the permissionless frontier

- **A-1 [OPT] AMD CDNA4 (MI350/MI355X) + UDNA validation on the existing HIP/MFMA backend.**
  Build + run `verify-backend.sh hip` and `measure-hardware.sh hip` on MI350/MI355X; confirm
  INT8 MFMA int32-accumulate bit-exactness and the datacenter ordering. *Why:* AMD ROCm/HIP
  is the **only open, permissionless, exact-INT8 datacenter path** as NVIDIA deprioritizes
  INT8 — keeping it first-class is what keeps the frontier reachable without a hyperscaler.

- **R-1 [GOV/CC] Confirm INT8 IMMA survives on NVIDIA Rubin / Rubin Ultra.** NVIDIA's
  headline precision list for Rubin omits INT8; verify on real silicon (or NVIDIA docs) that
  `mma.*.s32.s8.s8.s32` remains present and its throughput. *Why:* if a future NVIDIA part
  drops fast INT8, the CUDA backend's competitiveness — and the whole datacenter thesis on
  the dominant vendor — is at stake; this is the earliest warning.

### Priority 3 — new backends (safe-by-construction under the verify+fallback contract)

- **T-1 [OPT] Google TPU backend (`Kind::TPU`) via a Pallas/XLA INT8 kernel + remote
  host-bridge.** Gated on v5e+ (true int32 accumulator, per C-1). Reproduce `Ĉ` byte-exactly;
  wire through `ComputeDigestsBatchedDispatched`. *Why:* adds a deterministic, high-INT8-TOPS
  cloud datacenter substrate and a second-vendor determinism cross-check. **Cloud-only
  caveat** (§4.3). Heavier than in-process GPU backends (needs a host↔TPU bridge).

- **TT-1 [OPT] Tenstorrent TT-Metalium backend (`Kind::TT`).** The only *fully open ISA*
  target; best long-term permissionless + custom-kernel hedge. Lower throughput today. *Why:*
  insurance that a permissionless, open, non-NVIDIA, non-cloud exact-INT8 path always exists.

- **GA-1 [OPT] Intel Gaudi 3 backend (MME, INT8).** Medium effort; adds a third independent
  datacenter vendor for the determinism cross-check. *Why:* vendor diversity de-risks any
  single-vendor INT8 deprecation.

### Priority 4 — the escape hatch and portability generalizations

- **O-1 [CC-research] Exact-integer-on-float (Ozaki-scheme) feasibility study.** Determine
  whether the exact integer `C`/`Ĉ` can be reproduced bit-for-bit on float-only tensor cores
  (Trainium; future FP-only NVIDIA) with the slice count and exact summation pinned in
  consensus, and quantify the int-ALU/VPU cost it re-adds (§K.2a-WT). *Why:* the **only known
  path to follow the AI frontier off INT8 without abandoning determinism** — and the only way
  Trainium ever becomes eligible. Consensus change if adopted; do the study *now*, while
  off-critical-path.

- **L-1 [OPT] Accumulator-width-parametric C-13 limb combine.** Generalize the balanced
  base-2⁷/4-limb decomposition so the limb base is chosen from the device's *actual*
  accumulator width (e.g. narrower limbs for a 2⁴⁻bounded/other-width unit) while the shifted
  mod-q fold still lands on the identical canonical residue. *Why:* lets devices lacking a
  full int32 tensor accumulator still hit bit-exactness, widening the eligible set without a
  consensus change (the committed `Ĉ` is unchanged; only the miner-side decomposition varies).

### Priority 5 — measurement / harness (feeds every GO/NO-GO)

- **M-1 [MEAS] Extend `measure-hardware.sh` / `matmul-v4-report` / `matmul_v4_stage_bench`
  to systolic + cloud backends.** Add TPU/Trainium/Tenstorrent/Gaudi stage models incl. the
  per-nonce `B`-expansion + host↔device transfer floor (§4.2), and a remote-runner mode for
  cloud parts. *Why:* the datacenter-ordering hypothesis is currently untestable on any
  systolic/cloud part; this closes the §4.2 evidence gap.

- **M-2 [MEAS/CC] Cross-vendor golden-vector expansion (ACTIVATION B2a superset).** Generate
  and pin identical golden vectors across H100/B200 + MI350 + M5 + **TPU v5e/v7 + Tenstorrent
  + Gaudi 3**, including the C-1 high-magnitude adversarial set. *Why:* bit-exact determinism
  across the *full* platform set is the precondition for ever flagging any of them
  mining-capable; a single divergent vector is a chain split.

---

## 6. Multi-platform determinism strategy

The consensus invariant is unchanged and non-negotiable: **every backend reproduces
`matmul_v4::ComputeDigest` byte-for-byte; a one-bit divergence is a chain split** (`accel_v4.h`).
The strategy to hold that across a widening platform set:

1. **The dispatcher's verify+fallback rule is the load-bearing safety net, and it already
   generalizes.** `ComputeDigestDispatched` / `ComputeDigestsBatchedDispatched` re-verify
   *every* device result with the O(n²) sketch-Freivalds check and fall back to CPU on any
   mismatch. **Adding a new `Kind` cannot split the chain** — the worst a buggy backend does
   is lose throughput. This is why new backends are safe-by-construction and why the
   determinism *test* burden (not the runtime risk) is the real gate.

2. **Make the true-integer-accumulator requirement explicit and *tested*, not assumed
   (C-1/M-2).** The §4.1 flaw shows the current determinism argument implicitly trusts every
   "int8 matmul" to accumulate in real int32. Codify the requirement in §B.6/§O.1 and, more
   importantly, *exercise the failing regime* in the golden vectors so non-conforming
   accumulators fail `verify-backend.sh` deterministically. A device only becomes
   mining-capable after passing bit-for-bit against the CPU reference on the **full**
   adversarial set (spec §N.3-v posture, extended).

3. **Expand the golden-vector cross-vendor set to every candidate platform (M-2).** Today:
   CUDA + Metal (gating) + HIP (optional). Target: add TPU v5e/v7, Tenstorrent, Gaudi 3, and
   the C-1 high-magnitude vectors. Golden vectors are generated on real silicon and pinned;
   a new platform is not "supported" until its vectors match byte-for-byte.

4. **Extend the tooling to non-NVIDIA/AMD/Apple silicon (M-1):**
   - `verify-backend.sh <backend>` gains `tpu`, `trainium` (only if O-1 lands), `tt`,
     `gaudi` targets, each building the backend and running
     `matmul_v4_backend_determinism_tests` incl. the high-magnitude set → PASS only on
     bit-for-bit identity to the CPU reference.
   - `measure-hardware.sh` / `matmul-v4-report` gain a **remote-runner** mode for cloud parts
     (TPU/Trainium) — the JSON contract is unchanged (device identity, B1 bit-exactness, B2b
     nonce/s, B2g stage split), but the runner executes on a rented instance and ships the
     JSON back, so the one-command aggregation across a datacenter part / consumer part /
     Apple part (ACTIVATION B2g) extends to a *cloud* datacenter part.
   - `matmul_v4_stage_bench` gains systolic/cloud stage boundaries so the §K.2a-WT / §K.2b
     wall-time-majority check can be evaluated on TPU/Trainium at all (§4.2).

5. **Keep the CPU reference the sole source of truth.** Every backend — GPU, systolic, or
   Ozaki-on-float — is validated *against* `matmul_v4::ComputeDigest` and never trusted over
   it. This is what lets BTX add and remove platforms freely without ever putting consensus
   at the mercy of a vendor's kernel.

---

## 7. Confidence & what could not be verified

| Claim | Confidence | Basis / caveat |
|---|---|---|
| Blackwell Ultra B300 *cut INT8* to fund NVFP4 | **High** | Explicit Tom's Hardware wording ("at the cost of INT8 and FP64"); NVIDIA's own blog stays silent on INT8 (consistent with de-emphasis). Exact B300 INT8 TOPS **not** published — could not verify the magnitude of the cut. |
| Rubin/Rubin Ultra double **only** FP4/FP8; INT8 flat/unlisted | **Medium-High** | NVIDIA Rubin blog + SemiAnalysis; INT8 IMMA presence on Rubin **not explicitly confirmed** (R-1 exists to close this). Treat "INT8 dropped on Rubin" as *not established* — the safe read is "flat, not doubled." |
| Trainium2/3 systolic Tensor Engine is float-only (no INT8 matmul) | **High** | AWS's own NKI Trainium2 architecture guide enumerates FP8/BF16/FP16/TF32/FP32 for the Tensor Engine and INT8 only on the Vector Engine. Trainium3 systolic = BF16+MXFP8 (secondary source). |
| TPU v4 MXU accumulator is FP32-mantissa-bounded (2²⁴); v5e/v5p+ true int32 | **High** | Peer-style arXiv:2605.25367 states both explicitly. Did not independently re-derive; the paper's numbers are internally consistent with the 128×128 MXU geometry. |
| TPU INT8 + XLA is bit-exact/deterministic | **Medium** | Determinism of XLA static scheduling + integer accumulation is well-supported in principle; **no BTX golden-vector run on real TPU exists** — must be proven by M-2, not assumed. |
| AMD CDNA4 keeps INT8 as first-class MFMA (2×/CU vs MI300) | **Medium-High** | AMD blog + STH; **exact MI355X dense INT8 TOPS and whether INT8 = FP8 rate not isolated in available sources** — could not pin the number. HIP/MFMA int32-accumulate path is established (existing backend). |
| Apple M5 INT8→INT32 exact path | **Medium-High** | Third-party microbench (Zakharko) + Apple Metal 4 TensorOps int8 tensors; Apple publishes **no first-party INT8 TOPS**, and bit-exactness is *pending* the self-test (spec §O.1 already flags this). |
| Tenstorrent fully open ISA + INT8 | **High** (openness), **Medium** (exact-INT8 determinism) | Open ISA docs + TT-Metalium confirmed; INT8 matmul determinism/accumulator width **not verified** — needs a self-test. |
| Groq deterministic + INT8, but inference-locked | **Medium-High** | Secondary sources; the "no general custom-kernel path" is an inference from its compiler-locked model, not a first-party denial. |
| Datacenter-favoring ordering holds on *systolic/cloud* parts | **Low (unproven)** | No measurement exists on any systolic part; §4.2 gap. Explicitly a hypothesis. |
| Ozaki-on-float can preserve bit-exact determinism for BTX | **Low-Medium (untested for this workload)** | The scheme is real and maps to FP tensor cores; whether it clears BTX's cross-vendor determinism + §K.2a-WT wall-time bar is exactly what O-1 must determine. |

**What I could not verify at all:** exact B300/Rubin INT8 TOPS magnitudes; whether Rubin
retains INT8 IMMA; MI355X isolated dense INT8 TOPS; any real-TPU/Trainium/Tenstorrent BTX
determinism run (none exist — this repo has no such hardware, consistent with ACTIVATION's
"hard dependencies this repo cannot satisfy"). All forward-looking magnitudes should be
re-confirmed on real silicon at activation time (spec §Q.21.2 / ACTIVATION B2a–B2g cadence).
