# BTX MatMul v4 — Huawei Ascend & ZTE Accelerator Feasibility (China-Domestic Silicon)

*Status: RESEARCH + DETERMINATION deliverable. NOT a code change, NOT a consensus change,
NOT an activation. Companion to `doc/btx-matmul-v4-multiplatform-roadmap.md` (the per-platform
feasibility-matrix methodology and the INT8→FP4 precision landscape — mirrored here),
`doc/btx-matmul-v4-accumulator-eligibility.md` (the true-≥32-bit-integer-accumulator
invariant / the 2²⁴ trap — the make-or-break gate for v4.1),
`doc/btx-matmul-v4-frontier-native-format.md` and
`doc/btx-matmul-v4-committed-object-redesign.md` (the BMX4 power-of-two-block-scale
requirement — the make-or-break gate for BMX4), and `doc/btx-matmul-v4-exact-int-on-float.md`
(the no-rounding determinism discipline). The design spec is authoritative and UNCHANGED by
this document. Written 2026-07-16.*

> **Posture (inherited, preserved).** Every throughput/ordering statement is
> **measurement-gated** (§K.2b GO/NO-GO, ACTIVATION B2g): peak-TOPS/PFLOPS figures below are
> **illustrative vendor or third-party numbers, never load-bearing** — two prior model
> estimates in this program were falsified by measurement, and this document makes no third.
> Per spec §0.7-(4) (PRICE-INDEPENDENCE), nothing here reasons from BTX or token market
> price; "availability" is a **distribution fact** (who can physically buy/rent the part),
> not price reasoning. Forward-looking hardware claims are cited and split into **confirmed
> vendor spec** vs **rumor/leak/roadmap/marketing**. Chinese-accelerator specs are
> disproportionately leaked, estimated, or marketing-sourced; they are flagged as such and
> the two consensus-critical facts (accumulator precision, cross-unit determinism) are
> **not stated in any vendor doc I could find** and become "must-test-on-real-silicon" items,
> not assumptions.

---

## 0. The two gates, restated (what each chip must pass)

The PoW is a dense matmul verified cheaply by Freivalds over `q = 2⁶¹−1`, with a HARD
requirement of cross-vendor **bit-exact determinism** — a one-bit divergence is a chain
split. There are two solver profiles:

- **v4.1 (current, INT8).** Needs an **exact `s8×s8→s32` integer matmul with a TRUE
  two's-complement ≥32-bit integer accumulator**. An FP32-mantissa-bounded (2²⁴) accumulator
  is **INELIGIBLE** (accumulator-eligibility doc §1: base `C`/`P`/`Q` peak `6.4×10⁷` and the
  C-13 limb combine hits exactly 2²⁴ at n = 4096). No floating point on the committed path.
- **BMX4 (v4.2 candidate, frontier-native).** Small exact-integer mantissas
  `{0,±1,±2,±3,±4,±6}` (E2M1, ×2-normalized) × a per-block **power-of-two (E8M0) scale**,
  run on FP4/FP8 microscaling tensor units as an EXACT integer matmul. Requires
  **power-of-two block scales** — a *fractional* scale (NVFP4's E4M3, or a mantissa-bearing
  top scale) rounds and is **INELIGIBLE** — plus an accumulator that is exact under the
  K′-blocked extract-and-promote schedule (the t=24 proof).

Both gates are backed by the same enforcement chain: the `accel_v4.h` verify-every-result-
and-fall-back-to-CPU dispatcher means a mis-accumulating/mis-rounding backend can only lose
throughput, never split the chain — **but no Ascend/ZTE backend exists in this repo**, so
every determination below is a paper determination pending a real-silicon self-test
(`verify-backend.sh` + the C-1 high-magnitude adversarial vectors + the §4.6 BMX4 boundary
vectors).

---

## 1. Feasibility matrix (mirrors roadmap §2 columns)

Legend — **Exact-INT8 + true int32 accum?** = is there an `s8×s8→s32` matmul unit with a
true two's-complement ≥32-bit integer accumulator (v4.1 gate)? **P2 microscale (BMX4)?** =
does a block-scaled FP4/FP8 matmul unit exist whose block scale is a **power-of-two (E8M0)**,
not fractional (BMX4 gate)? **Det?** = documented bit-exact / order-independent across
units & runs? **3P-prog?** = can an independent miner write a custom matmul kernel (open
SDK) vs a locked inference stack? **Permissionless?** = can a *global* miner buy/rent one
(export-control / China-domestic distribution)? **Perf tier** = illustrative INT8/FP TOPS &
bandwidth vs the NVIDIA baseline (B200 INT8 3,927 / FP4 7,702 TOPS; H100 INT8 1,979; RTX
5090 INT8 838 — from roadmap §2/§3, measurement-gated).

| Platform | Exact-INT8 + true int32 accum? | P2 microscale (BMX4)? | Det? | 3P-prog? | Permissionless? | Perf tier (illustrative) |
|---|---|---|---|---|---|---|
| **Ascend 910B** (Da Vinci, SMIC N+1/7nm) | **Yes** — Cube does `s8×s8` GEMM accumulating to **INT32** [C1][C2] ⚠accum-width not in *vendor* doc | **No** — no FP8/MX unit; INT8/FP16/BF16 only [C3] | ⚠ undocumented — must self-test | **Yes** — CANN / Ascend C / AscendCL / TIK, open C APIs + GitHub samples [C4] | **No — export-banned; China-domestic** [A1][A2] | ~512–640 INT8 TOPS, 64 GB HBM, ~1.2 TB/s [S1] — sub-H100 |
| **Ascend 910C** (dual-910B die, SMIC 7nm N+2) | **Yes** — same Da Vinci Cube, INT8→INT32 [C1][C2] ⚠accum-width not in vendor doc | **No** — BF16/FP16/INT8; **FP8/HF8 reportedly absent** on 910C [C5] | ⚠ undocumented | **Yes** — CANN/Ascend C [C4] | **No — export-banned; Huawei-cloud + China-domestic; CloudMatrix 384** [A1][A2][A3] | ~1,600 INT8 TOPS (est.), ~800 TF FP16, 96–128 GB HBM2e, ~1.8 TB/s [S2] — ≈H100-class INT8, < B200 |
| **Ascend 910D** (reported quad-die) | **Likely yes** (Da Vinci lineage) ⚠**rumor** — specs unconfirmed [R1][R2] | **Adds FP8** (reported) ⚠ scale format unknown — likely not P2-MX | ⚠ undocumented | Yes (CANN, if it ships) | **No — export-banned (named in the ban)** [A2] | Targets >H100 / Blackwell-class ⚠ **rumor/leak**, no benchmarks |
| **Ascend 950PR / 950DT** (2026, new SIMD+SIMT ISA) | **Presumed yes** — INT8 retained "on top of what 910C offers" ⚠**new ISA — INT8 int32-accum not re-confirmed** [C6] | **Yes (MXFP8/MXFP4 path)** — adds OCP **MXFP8 + MXFP4** = **E8M0 power-of-two** block scales [C6][C7]. HiF8/HiF4 do **NOT** qualify (see §2) | ⚠ undocumented; FP/MX accumulator exactness (t=24) unproven | **Yes** (CANN/Ascend C forward) ⚠ new-ISA toolchain maturity unknown | **No — export-banned; China-domestic; SuperPoD/homegrown HBM** [C6][A2] | 1 FP8 PFLOP, 2 FP4 PFLOPS/chip, 2 TB/s interconnect ⚠vendor peak [C6][C7] — DC-class, < B200/Rubin FP4 |
| **Ascend 960** (2027) | Presumed yes ⚠rumor | **Yes (MXFP4)** + **HiF4** (HiF4 fractional-scale ⇒ **ineligible**, §2) ⚠rumor | ⚠ undocumented | Yes (CANN) | **No — China-domestic** ⚠ | 2 FP8 / 4 FP4 PFLOPS ⚠vendor roadmap [C7][C8] |
| **Ascend 970** (2028) | Presumed yes ⚠rumor | Yes (MXFP4) ⚠rumor | ⚠ undocumented | Yes (CANN) | **No — China-domestic** ⚠ | 4 FP8 / 8 FP4 PFLOPS ⚠vendor roadmap [C7][C8] |
| **ZTE (any AI accelerator silicon)** | **Unknown — no public dedicated matmul accelerator with disclosed specs** [Z1][Z2][Z3] | **Unknown** [Z1][Z2] | **Unknown** | **Unknown** — no public kernel SDK for a ZTE accelerator | **No / N/A** — ZTE integrates domestic chips + was cleared to buy NVIDIA H200 [Z3] | **Cannot assess** — public info thin (§3) |

Sources for the matrix are collected in §6.

---

## 2. The BMX4 power-of-two-scale gate on Ascend 950-series formats (make-or-break)

The 950-series "add FP8, MXFP8, HiF8, MXFP4, HiF4" list is a **mix of eligible and
ineligible formats**, and the distinction is exactly the load-bearing one from the
frontier-native doc §2.1 (scale format decides, not element format):

| 950-series format | Scale discipline | BMX4 power-of-two-scale gate |
|---|---|---|
| **MXFP8 / MXFP4** (OCP MX) | **E8M0** — 8-bit pure exponent, 32-element block, value `2^(code−127)` [C7][OCP] | **PASS (structurally).** E8M0 dequant is an exact bit-shift; this is precisely the committed structure BMX4 targets. **The only Ascend path that clears the BMX4 scale gate.** |
| **HiF8** (Huawei HiFloat8) | **Per-value dynamic-mantissa / tapered** (3/2/1/0 mantissa bits by exponent magnitude) — NOT a per-block power-of-two scale [C9][C10] | **FAIL.** It is a floating element format with adaptive per-value precision, not microscaling with a power-of-two block scale. A committed HiF8 object would carry FP-mantissa values into consensus → non-associative → fork/split. Ineligible, same class as any fractional-scaled format. |
| **HiF4** (Huawei HiFloat4) | **Three-level hierarchical**: 64-elem block **UE6M2** (a *6-exponent, 2-mantissa fractional* top scale) + 1-bit sub-block factors + INT3 elements [C9] | **FAIL.** The UE6M2 top scale is **fractional** (has mantissa bits) — the exact analogue of NVFP4's rejected E4M3 scale (frontier-native doc §3a). Dequant is a real multiply, not an exponent-field add; not provably exact. Ineligible. |
| **FP8 (E4M3/E5M2, per-tensor)** | Per-tensor scale (not block) | Usable only via the exact **scale-folding into E4M3** fallback (frontier-native §4.4), 1 plain FP8 GEMM — needs the t=24 accumulator proof. Not a microscaling win. |

**Determination:** Ascend 950/960/970 are usable under BMX4 **only through their OCP
MXFP8/MXFP4 (E8M0) path**, and Huawei's own headline low-bit formats (HiF8, HiF4) are
**ineligible** for the committed object because their scales are tapered/fractional. This is
the single most important Ascend-specific finding: the marketing pushes HiF8/HiF4 (better
accuracy per Huawei), but BTX can only ever commit through the *standards-pure* MX path the
chip also happens to support.

**Two unproven sub-gates remain even on the MX path (must-test-on-silicon):**
1. **Accumulator exactness (t = 24).** BMX4 native-rate eligibility requires proving the
   block-scaled accumulate is exact to ≥2^t under the K′-blocked schedule (frontier-native
   §4.3/§4.6). Nominal "FP32 accumulate" is never trusted — the Hopper FP8 t≈14 surprise is
   the standing precedent. **No Ascend vendor doc states the MX/FP accumulator's exact
   significand width.** Fail-closed default t=14 ⇒ K′=0 ⇒ ineligible until proven.
2. **Committed (not data-derived) scale loading.** BMX4 commits the block scale exponents
   from the header seeds; the kernel must be able to *load an explicit committed E8M0 scale
   tensor* rather than deriving scales from the data (the same wrinkle flagged for
   Trainium's NKI `quantize_mx`). Whether Ascend C / CANN's MX matmul primitive accepts an
   externally supplied scale tensor is **unverified** and needs an Ascend C prototype.

---

## 3. ZTE — honest finding: no evaluable accelerator silicon in public

I could not find a **dedicated ZTE datacenter AI matmul accelerator with disclosed
architecture** (matrix-unit dimensions, INT8/FP8 support, accumulator, SDK). What is public:

- ZTE presents a **full-stack "AI Factory" / AI Booster** solution built on **heterogeneous
  mixed inference over *domestic* chip platforms** — i.e. ZTE is a systems/co-design
  integrator of *other vendors'* accelerators, not a disclosed-spec accelerator vendor
  [Z1][Z2].
- ZTE's chip-design subsidiary (Sanechips) is known for telecom SoCs/DPUs; **no public AI
  training/inference matmul accelerator product with specifications** surfaced in this
  research.
- Distribution-wise, ZTE was **cleared by the US to purchase NVIDIA H200** (joining Alibaba,
  Tencent, ByteDance) [Z3] — reinforcing that ZTE is a chip *consumer/integrator* here, not a
  merchant-silicon accelerator supplier.

**Determination (ZTE):** *insufficient public information to evaluate against either gate.*
Not "fails" — **unevaluable**. There is no documented programmable matmul unit, no stated
accumulator width, no stated FP4/FP8 microscaling scale format, and no public custom-kernel
SDK for a ZTE accelerator. If ZTE (or Sanechips) later discloses a matmul accelerator, it
re-enters this matrix; today it is out of scope of a hardware-feasibility determination.
(Where ZTE runs domestic Ascend/other silicon inside its "AI Factory," the relevant
determination is that of the *underlying* chip — e.g. the Ascend rows above.)

---

## 4. Verdicts per chip (with the two gates called out explicitly)

**Ascend 910B / 910C — the current datacenter parts.**
- **v4.1 (INT8): PLAUSIBLY USABLE, pending the accumulator self-test.** The Da Vinci Cube is
  a genuine `s8×s8` integer matmul that **accumulates to INT32** per multiple secondary
  descriptions [C1][C2] — architecturally the true-int32 path v4.1 requires, unlike a TPU-v4
  FP32-mantissa MXU. **Gate status: passes on available evidence, but the two's-complement
  ≥32-bit width is not stated in a Huawei vendor doc and cross-unit determinism is
  undocumented** — so this is a **must-test-on-silicon PASS-expected**, enforced by the C-1
  high-magnitude adversarial vectors (which force accumulations into (2²⁴, 2³¹)) before any
  mining-capable flag.
- **BMX4: NOT USABLE.** No FP8/MX microscaling unit (910B INT8/FP16/BF16 only; 910C
  reportedly lacks FP8/HF8) — the power-of-two-scale gate is moot (no scaled-FP unit exists).

**Ascend 910D (reported).**
- **v4.1: LIKELY USABLE** (Da Vinci lineage ⇒ INT8→INT32 expected) — but **rumor-tier**; no
  confirmed spec, no benchmarks. **BMX4: UNKNOWN** — adds FP8 (reported), scale format
  undisclosed; do not assume MX/E8M0. Treat entirely as leak until Huawei confirms.

**Ascend 950PR / 950DT / 960 / 970 (roadmap, Huawei Connect 2025 — vendor-announced).**
- **v4.1: PRESUMED USABLE but re-confirm.** INT8 is described as retained on top of 910C, but
  the 950 uses an **all-new SIMD+SIMT ISA** [C6] — the true-int32 INT8 accumulator behaviour
  must be re-verified on the new architecture, not carried over on faith.
- **BMX4: USABLE *iff* the MXFP8/MXFP4 (E8M0) path clears the accumulator proof.** The
  power-of-two-scale gate **PASSES** via OCP MXFP8/MXFP4 (this is the standout positive
  finding — Ascend 950+ is, on paper, an E8M0-native BMX4 host in the same class as Blackwell
  `mxf4`, MI355X OCP-MX, and Trainium3 Matmul-MX). **HiF8 and HiF4 FAIL the scale gate**
  (tapered / UE6M2-fractional — §2) and must not be used as the committed format. Remaining
  blockers: (i) prove t=24 exact accumulation on the block-scaled path via the §4.6 boundary
  vectors; (ii) prove CANN/Ascend C can feed a *committed* E8M0 scale tensor. Both are
  silicon/SDK tests, not assumptions.

**Cross-cutting determinism caveat (both gates, all Ascend parts).** No Huawei doc I found
states cross-unit/cross-run bit-exact determinism or the exact accumulator significand
width. These are the two facts Chinese vendor docs "rarely state" and they are **exactly** the
two BTX cannot assume. They convert to hard **must-test-on-real-silicon** gate items
(`verify-backend.sh` bit-for-bit vs the CPU reference, incl. the C-1 and §4.6 adversarial
sets). Until then the runtime safety net still holds: `accel_v4.h` verify+fallback means a
non-conforming Ascend backend loses throughput, never splits the chain — *but such a backend
does not yet exist in this repo.*

---

## 5. Programmability & permissionless-availability (the decisive practical caveats)

**Programmability — Ascend is genuinely third-party-programmable (a positive).** CANN exposes
a multi-layer stack: **AscendCL** (C APIs, callable from third-party frameworks or
encapsulable into third-party libraries), **Ascend C** and **TIK** (Tensor Instruction
Kernel) for **custom operators/kernels**, with public GitHub sample repos and an ONNX Runtime
CANN execution provider [C4]. An independent miner *can* in principle write a custom
`s8×s8→s32` (or MX) matmul kernel — this is **not** a locked inference-only stack like Groq.
Caveats: CANN/Ascend C toolchain maturity and documentation depth are widely reported as
rougher than CUDA/ROCm; the 950-series **new SIMD+SIMT ISA** implies a new kernel programming
surface whose openness/maturity is unproven; and none of this is exercised by BTX today.

**Permissionless availability — this is the disqualifier for a *global* PoW.** Every Ascend
datacenter part (910B, 910C, and explicitly the upcoming 910D) is **banned from use under US
export controls**, with a **worldwide** enforcement posture announced in 2025 [A1][A2].
Distribution is effectively **China-domestic**: sold into Chinese enterprises/telcos and
served via Huawei Cloud **CloudMatrix 384** (384-chip Ascend-910C clusters) [A3]. Supply is
further HBM-bottlenecked, and Huawei is moving to homegrown HBM for the 950 era [C6].

**Asymmetric-availability implication (a distribution fact, not price reasoning).** A
China-domestic-distribution, export-controlled accelerator is usable **in practice mainly by
China-domestic miners**. For a *permissionless* PoW this is the same structural concern the
roadmap raises for cloud-gated parts (§4.3), sharpened: rather than "multi-hyperscaler," the
Ascend frontier is "single-jurisdiction." It does not break determinism or the gates, but it
means an Ascend backend would **widen hardware access asymmetrically by geography** — the
opposite of vendor/geography neutrality. Keeping the **open, globally buyable** exact-INT8 /
E8M0-MX paths (AMD ROCm/HIP, NVIDIA, Tenstorrent) first-class remains the permissionless
hedge; Ascend is at best a *regional* addition, not a global one.

---

## 6. Performance assessment (illustrative, measurement-gated — no ordering claims)

Absolute peak figures only, to size "is it even datacenter-class," never to rank:

- **Ascend 910C** ≈ **1,600 INT8 TOPS (est.)**, ~800 TF FP16, ~96–128 GB HBM2e, ~1.8 TB/s
  [S2]. That is **≈H100-class on INT8** (H100 1,979 TOPS) and **well above** a consumer 5090
  (838), but **below B200** (3,927 INT8). On INT8 alone it is credibly datacenter-competitive
  in *absolute* terms; the CloudMatrix 384 rack-scale story is Huawei's actual competitive
  lever (scale-out to offset per-chip deficit), which is orthogonal to a single-nonce solver.
- **Ascend 910B** ≈ 512–640 INT8 TOPS, ~64 GB, ~1.2 TB/s [S1] — sub-H100; a mid-tier
  datacenter part.
- **Ascend 950 (2026)** ≈ **1 FP8 PFLOP / 2 FP4 PFLOPS per chip**, 2 TB/s interconnect
  [C6][C7]. For BMX4 the relevant lever is FP4: **2 PFLOPS ≈ 2,000 TOPS-class**, i.e. roughly
  **¼ of B200's dense FP4 (7,702)** and a small fraction of Rubin's vendor 35–50 PF class. So
  the 950 is a **real datacenter FP4 part but a generation-plus behind the NVIDIA frontier**
  on peak; 960/970 (2027/28) double each step (4/8 FP4 PFLOPS) but stay behind the
  contemporaneous NVIDIA/AMD parts on announced peaks.

**Verdict (perf):** **datacenter-class, not frontier-leading.** On the current INT8 workload
the 910C is roughly H100-tier (above consumer, below B200); on the future BMX4 workload the
950-series is a genuine E8M0-MX FP4 datacenter part but trails B200/Rubin/MI355X on peak
PFLOPS. **All of this is illustrative** — no BTX kernel has run on any Ascend part, the
§K.2a-WT wall-time majority is unmeasured on Da Vinci/SIMD+SIMT, and the program's
measure-don't-model rule forbids any ordering claim. Whether an Ascend part would be
"datacenter-competitive vs a B200/5090 baseline" *for this solver specifically* is a B2g
measurement obligation, not a number in a vendor slide.

---

## 7. Sources (confirmed vendor spec vs rumor/secondary marked)

**Ascend architecture / Cube / accumulator (secondary-technical):**
[C1] [Da Vinci Cube 16×16×16 / INT8 16×32 MAC, INT8→INT32 accumulation — Springer *Huawei
Atlas AI Computing Solution*](https://link.springer.com/chapter/10.1007/978-981-19-2879-6_6)
and [CUHK SEEM5730 Atlas platform notes](https://www1.se.cuhk.edu.hk/~seem5730/l22/06%20Atlas%20AI%20Computing%20Platform_ALEX.pdf)
(secondary/academic — **not** a Huawei datasheet; accumulator two's-complement width not
independently stated). [C2] [Huawei *DaVinci: A Scalable Architecture for Neural Network
Computing*](https://www.cmc.ca/wp-content/uploads/2020/03/Zhan-Xu-Huawei.pdf) (Cube = 4,096
FP16 / 8,192 INT8 MACs; **primary-ish**, first-party slides). [C3]
[Ascend 910B specs — WareDB](https://www.waredb.com/processor/ascend-910b) (INT8/FP16/BF16;
secondary). [C5] [Report that 910C lacks FP8/HF8 (BF16 only) — X/@YouJiacheng](https://x.com/YouJiacheng/status/1888743046264832457)
(**rumor/single-observer**).

**Ascend 950-series roadmap (vendor-announced, Huawei Connect 2025):**
[C6] [Huawei Connect 2025 keynote — SuperPoD / Ascend 950 / homegrown HBM (Huawei
official)](https://www.huawei.com/en/news/2025/9/hc-xu-keynote-speech) (**confirmed vendor
announcement**). [C7] [Tom's Hardware — Ascend NPU roadmap: 950PR/950DT/960/970, adds FP8,
MXFP8, HiF8, MXFP4, HiF4; 1 FP8 PFLOP / 2 FP4 PFLOPS; 2 TB/s](https://www.tomshardware.com/tech-industry/artificial-intelligence/huawei-ascend-npu-roadmap-examined-company-targets-4-zettaflops-fp4-performance-by-2028-amid-manufacturing-constraints)
(secondary reporting on a vendor announcement). [C8]
[RCR Wireless — Huawei Ascend roadmap](https://www.rcrwireless.com/20250922/ai-infrastructure/huawei-ai-chips);
[TechPowerUp — Ascend 950 + homegrown HBM](https://www.techpowerup.com/341123/huawei-unveils-homegrown-hbm-and-ascend-950-bets-on-massive-superclusters)
(secondary).

**Format semantics (the BMX4 scale gate — §2):**
[OCP] [OCP Microscaling Formats (MX) v1.0 — MXFP8/MXFP4 = 32-elem block, **E8M0** power-of-two
scale](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf)
(**standard**). [C9] [*Unleashing Low-Bit Inference on Ascend NPUs: HiFloat evaluation*,
arXiv:2602.12635](https://arxiv.org/html/2602.12635v1) (HiF8 = per-value dynamic mantissa;
HiF4 = 3-level hierarchical with **UE6M2** top scale + INT3 elements — the fractional-scale
finding). [C10] [*Ascend HiFloat8 Format for Deep Learning*, arXiv:2409.16626](https://arxiv.org/html/2409.16626v1)
(HiF8 tapered-precision definition, first-party Huawei authors).

**Software stack / programmability (§5):**
[C4] [AscendCL overview — Huawei CANN docs](https://support.huawei.com/enterprise/en/doc/EDOC1100191897/8ebada29)
(third-party callable C APIs); [Ascend/samples GitHub](https://github.com/Ascend/samples)
(custom-operator samples); [CANN ONNX Runtime EP](https://onnxruntime.ai/docs/execution-providers/community-maintained/CANN-ExecutionProvider.html).

**Availability / export controls (§5):**
[A1] [SemiAnalysis — Huawei CloudMatrix 384 / Ascend 910C](https://newsletter.semianalysis.com/p/huawei-ai-cloudmatrix-384-chinas-answer-to-nvidia-gb200-nvl72);
[A2] [Tom's Hardware — US worldwide crackdown on using Huawei Ascend chips (910B/910C/910D
banned)](https://www.tomshardware.com/tech-industry/artificial-intelligence/u-s-issues-worldwide-crackdown-on-using-huawei-ascend-chips-says-it-violates-export-controls);
[A3] [SiliconANGLE — Huawei CloudMatrix 384 launch (384× Ascend 910C)](https://siliconangle.com/2025/07/27/huawei-launches-cloudmatrix-384-server-alternative-nvidias-ai-infrastructure-stack/).

**Perf figures (§6, illustrative):**
[S1] [Ascend 910B — WareDB / Awesome Agents](https://awesomeagents.ai/hardware/huawei-ascend-910b/)
(secondary/estimated); [S2] [Ascend 910C — Awesome Agents](https://awesomeagents.ai/hardware/huawei-ascend-910c/) /
[XPU.pub — 910C & CloudMatrix](https://xpu.pub/2025/04/22/huawei-ascend/) (secondary/estimated).

**910D (rumor):** [R1] [TrendForce — 910D test as early as May 2025](https://www.trendforce.com/news/2025/04/28/news-huawei-reportedly-set-to-test-new-ascend-910d-ai-chip-as-early-as-may-aiming-to-challenge-nvidia/);
[R2] [Tom's Hardware — Ascend 910D vs Blackwell/Rubin](https://www.tomshardware.com/tech-industry/artificial-intelligence/huawei-ascend-ai-910d-processor-designed-to-take-on-nvidias-blackwell-and-rubin-gpus)
(**rumor/leak**).

**ZTE (§3):** [Z1] [The Register — ZTE full-stack AI infrastructure / co-design](https://www.theregister.com/2026/03/02/zte-unveils-full-stack-ai-infrastructure);
[Z2] [The Register — ZTE TCO-optimal AI factory (heterogeneous mixed inference on domestic
chips)](https://www.theregister.com/ai-and-ml/2026/06/25/zte-builds-a-tco-optimal-ai-factory-to-fuel-token-economy/5262082);
[Z3] [Tom's Hardware — US allows ZTE to buy NVIDIA H200](https://www.tomshardware.com/tech-industry/artificial-intelligence/us-govt-allows-chinese-telecom-giant-zte-to-purchase-nvidia-h200-ai-chips-firm-joins-alibaba-tencent-and-bytedance-in-access-to-hopper-tech).

---

## 8. Confidence table & what could not be verified

| Claim | Confidence | Basis / caveat |
|---|---|---|
| Da Vinci Cube does `s8×s8` GEMM **accumulating to INT32** (910B/910C) | **Medium-High** | Multiple secondary/academic descriptions [C1][C2] consistently say INT32 accumulation; **no Huawei datasheet I found states the two's-complement width or saturation behaviour** — the v4.1 gate is *expected-pass*, not proven. Must clear the C-1 high-magnitude vectors on real silicon. |
| 910B/910C have **no FP8/MX microscaling unit** (⇒ BMX4 N/A) | **Medium-High** | 910B INT8/FP16/BF16 [C3]; 910C FP8 "reportedly absent" [C5] (single-source rumor). Consistent with the roadmap wording that 950 *adds* FP8/MXFP8 "on top of what 910C offers" [C7]. |
| Ascend 950-series **adds OCP MXFP8/MXFP4 (E8M0 power-of-two scales)** ⇒ clears the BMX4 scale gate | **High (format), Medium (silicon detail)** | MXFP8/MXFP4 are OCP-standard E8M0 by definition [OCP]; Huawei-announced for 950 [C6][C7]. **Not** verified: whether the MX matmul accepts a *committed* (externally supplied) scale tensor, and the exact accumulator width. |
| **HiF8 and HiF4 FAIL the power-of-two-scale gate** (ineligible as committed format) | **High** | HiF8 = per-value tapered mantissa; HiF4 top scale = **UE6M2 fractional** [C9][C10]. Fractional/tapered ⇒ not an exact exponent-field shift ⇒ non-deterministic if committed. |
| Ascend FP/MX **accumulator exactness (t=24)** on the block-scaled path | **Unverified (must test)** | No vendor doc states it; Hopper's t≈14 surprise is the precedent. Fail-closed until §4.6 boundary vectors pass on real silicon. |
| Ascend **cross-unit/cross-run bit-exact determinism** | **Unverified (must test)** | Not stated in any Huawei doc found. The single largest open question for *any* Ascend backend; enforced only by an on-silicon `verify-backend.sh` run vs the CPU reference. |
| Ascend is **third-party-programmable** (custom matmul kernel possible) | **Medium-High** | CANN/AscendCL/Ascend C/TIK are open C APIs with public samples [C4]; **but** toolchain maturity vs CUDA/ROCm is weaker, and the 950 new-ISA kernel surface is unproven. Not a locked inference stack (unlike Groq). |
| Ascend datacenter parts are **export-banned / China-domestic** | **High** | US worldwide crackdown names 910B/910C/910D [A2]; distribution via Huawei Cloud CloudMatrix 384 [A1][A3]. Asymmetric availability by jurisdiction. |
| 950D reports / 910D specs | **Low (rumor/leak)** | Sampling dates, die counts, node (5nm vs SMIC 7nm) conflict across sources [R1][R2]; no benchmarks. Do not rely on for any gate. |
| Perf figures (910C ≈1,600 INT8 TOPS; 950 = 1 FP8/2 FP4 PFLOPS) | **Low-Medium (illustrative)** | 910C INT8 is an *estimate* from FP16 scaling [S2]; 950 PFLOPS are vendor peaks [C6][C7]. Measurement-gated; no BTX kernel has run on Ascend. |
| **ZTE has an evaluable AI matmul accelerator** | **Could not verify (assessed absent)** | No public dedicated-accelerator spec; ZTE is an integrator of domestic chips + cleared to buy NVIDIA H200 [Z1][Z2][Z3]. Unevaluable, not failing. |

**What could not be verified at all (the must-test-on-real-silicon set):** (1) the Ascend
INT8 accumulator's true two's-complement ≥32-bit width and saturation behaviour (the v4.1
gate); (2) the MX/FP accumulator's exact significand width `t` and the K′ schedule's
exactness (the BMX4 accumulator sub-gate); (3) cross-unit/cross-run bit-exact determinism on
any Da Vinci or SIMD+SIMT part; (4) whether CANN/Ascend C can load a *committed* E8M0 scale
tensor for the MX matmul; (5) any BTX golden-vector / `verify-backend.sh` run on real Ascend
silicon (none exists — this repo has no Ascend hardware, same posture as ACTIVATION's
"hardware dependencies this repo cannot satisfy"); (6) **all** ZTE accelerator internals
(no public silicon). None of these can be assumed from Chinese vendor documentation; each is
a hard gate item before any Ascend/ZTE backend could ever be flagged mining-capable.
