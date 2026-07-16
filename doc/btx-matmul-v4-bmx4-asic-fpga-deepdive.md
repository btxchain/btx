# BTX MatMul v4.2 / BMX4 — ASIC & FPGA Hardware-Economics Deep Dive (FINAL Residual Bound)

*Status: STUDY deliverable (silicon-economics analysis). NOT a code change, NOT a spec
edit, NOT an activation input by itself. Companion to
`doc/btx-matmul-v4-frontier-native-format.md` (the BMX4 object definition),
`doc/btx-matmul-v4-committed-object-redesign.md` (the security determination and its
first-pass "~2–3×" residual estimate, §4.3), `doc/btx-matmul-v4-design-spec.md`
(§S.1/§S.2/§S.2.2 residual methodology, §L.4 capacity-gate impossibility, §K.2a-WT/§K.2b
measurement discipline, §E.3 marginal work unit — all authoritative and UNCHANGED), and
`doc/btx-matmul-v4-multiplatform-roadmap.md` (per-platform silicon numbers). Per spec
§0.7-(4) no token/market price is used anywhere; all hardware framing is
throughput-, energy- (J/nonce), and silicon-area-based. Every figure is tagged
**[C] confirmed-cited** or **[M] modeled**; per this program's posture (two prior
model-based ordering claims falsified by measurement, §K.2b) nothing here upgrades a
model to a result. Written 2026-07-16.*

---

## 0. Executive answer

**FINAL residual bound (energy- and area-normalized, per unit of honest exact-matmul
nonce throughput, marginal v4.1 work unit, n = 4096 / b = 4 / Q ≥ 32):**

| Adversary | BMX4 residual vs commodity FP4 datacenter GPU | s8 baseline (same model) | Spec's prior disclosure |
|---|---|---|---|
| Bespoke mining-only tensor ASIC, realistic (one node behind frontier, merchant-fab, NRE-burdened) | **≈ 1.5–2.5×** | ≈ 1.4–2.4× | ~1.5–2× (§S.2.2) |
| Bespoke ASIC, credible worst case (frontier node, full-custom mod-q datapath, E2M1-U/V co-change adopted) | **≈ 2–3.5×, ≤ ~4×** | ≈ 2–3× | ~2–3× first-pass (redesign §4.3) |
| FPGA (best AI-hardened flagship, granting a 2–4× LUT dividend on the 4-bit alphabet) | **≥ 13× BEHIND** a B200-class GPU (typically 15–30× on the marginal unit); ~3–6× behind an RTX 5090; worse J/op | ≥ 13–31× behind | ≥ ~13× behind (§S.2.1, redesign §4.3) |
| **Cliff condition** (the one real cliff, silicon-testable): commodity FP4 block-scaled accumulate proves only t≈14, not t=24 → commodity loses the native path (K′=0, §4.3 of the frontier doc) while a bespoke exact-integer array is unaffected | **≈ 6–14×** (residual × the commodity 4× slice tax) | n/a (s8 is INT8-native everywhere) | not previously quantified |

**Headline findings, in one paragraph.** The first-pass "~2–3×" estimate survives as the
central band, but **its assumed mechanism was wrong, and correcting it is the main
content of this document**: the cheap {0,±1,±2,±3,±4,±6}×2^e multiplier is NOT what a
bespoke ASIC monetizes, because the commodity FP4 tensor pipe (E2M1 significand multiplier
+ E8M0 exponent-add scale) already **is** — to within ~1.2–1.5× — the optimal circuit for
exactly this alphabet; NVIDIA/AMD ship that circuit at frontier nodes at 2× their own INT8
rate (B200 measured FP4 7,702 vs INT8 3,927 TOPS [C]). What a bespoke chip actually
monetizes is (a) the generic domain-specific strip (empirically ~1.5–2.5× at iso-node —
the TPU-v4-vs-A100 anchor [C]), and (b) a dedicated wide-integer mod-q datapath for the
**C-13 limb combine, which is ~80 % of the marginal unit's tensor MACs and is completely
alphabet-independent** — the same lever, at the same magnitude, that already exists
against the s8 object. Consequently **BMX4 widens the ASIC residual over s8 by at most
~1.2–1.3× multiplicative, not by the naïve 3–4× MAC-density ratio.** The XOF is *not* the
hardware-cost floor (<0.1 % of a bespoke miner's energy and <1 % of its area at n = 4096
— §4.4); operand bandwidth is not a wall for anyone (AI_opt = 2,048 ops/byte — §4.5). The
real ASIC-resistance floor is: exact wide-integer reduction + the mod-q combine
(format-independent, ~80 % of the work) + the fact that the frontier already mass-produces
the BMX4 multiplier. The single factor that decides between "bounded ~2–3×" and a genuine
cliff is **whether commodity block-scaled FP4 accumulation proves t = 24 exact** (§4.6
boundary vectors of the frontier doc) — a silicon test, not a design choice.

---

## 1. The question, and the honest limit of any answer

**Question.** BMX4 (v4.2 candidate) commits operands as small exact-integer E2M1
mantissas {0,±0.5,±1,±1.5,±2,±3,±4,±6} (×2-normalized: {0,±1,±2,±3,±4,±6,±8,±12}) times a
per-32-block power-of-two scale 2^e, e ∈ {0..4}; the committed object stays an exact
integer matmul verified by Freivalds over q = 2⁶¹−1, unchanged in form. The redesign doc
(§4.3) estimated the "mining-only tensor chip" residual widens from ~1.5–2× (s8, spec
§S.2.2) to ~2–3× because "narrower multipliers cheapen bespoke MAC arrays." This
document converts that estimate into a defensible bound by actually decomposing the
per-nonce work and costing each component on ASIC, FPGA, and commodity silicon.

**The honest limit, stated first.** Nobody tapes out a miner to test a PoW. There is no
empirical BMX4 ASIC and there will not be one before an activation decision. "Final"
therefore means: a silicon-economics model whose **assumptions are explicit, whose inputs
are cited real-silicon parameters wherever such parameters exist, whose outputs are
ranges with sensitivity analysis, and whose falsifiable predictions are enumerated**
(§9). This program has twice had peak-based models falsified by measurement (§K.2b);
accordingly every load-bearing number below carries a [C]/[M] tag and the §7 sensitivity
table says which assumption moves the bound how far. The bound is an *envelope*, not a
point; anyone claiming a point value for an untaped chip is overclaiming.

**Price-independence note.** All comparisons are in J/nonce (physical, price-free — the
same basis as spec §S.4.6's joules/nonce ranking) and nonce/s per mm² of silicon at a
stated node (a capex *proxy* that avoids market prices). NRE dollar figures appear only
as already-disclosed context from spec §S.2.2 ([SemiEngineering](https://semiengineering.com/big-trouble-at-3nm/):
$0.5–1.5 B-class at 3 nm) and never enter the ratio arithmetic.

---

## 2. The honest per-nonce work unit under BMX4 (what must be costed)

The enforced unit is the **v4.1 marginal batched-sketch unit** (spec §E.3/§K.2b): A, U, V
and P = U·Ā are template-scoped (amortized across the nonce sweep); per nonce the miner
must (S1) expand nonce-fresh B from the XOF, (S2) compute Q = B̄·V, (S3) combine
Ĉ = P·Q mod q, (S4) serialize + digest. Difficulty is calibrated to exactly this unit
(§E.3), so this — not the naïve full n³ GEMM — is what an ASIC must be cheaper *at*.

**Two object profiles must be carried, because they differ at the hardware level:**

- **Profile P-A ("BMX4 as specified"):** U/V remain balanced-s8 (entries ≤ 125), per the
  frontier doc §4.5 (the E2M1-U/V co-change is explicitly deferred). Then B̄ entries
  (≤ 192, i.e. 9-bit) meet s8 V entries in S2: on INT8 hardware B̄ needs a 2-slice
  (2 GEMMs); V (≤125) is **not** E4M3-exact (125 needs a 7-bit significand), so S2 is
  *not* a 1-GEMM FP4-rate operation on commodity MX hardware either. S2 runs as 2 s8
  GEMMs on the INT8 pipe.
- **Profile P-B ("E2M1-native U/V co-change adopted"):** U/V drawn from the E2M1/𝓜
  alphabet (the redesign doc's F\* instantiation does exactly this — |u|,|v| ≤ 6). S2
  becomes one block-scaled FP4-rate GEMM on MX hardware; P/Q magnitudes shrink to < 2²³.
  This is the profile under which the frontier doc's "≈1×, tax removed" table applies to
  the *marginal* unit and not only to the committed object C̄ = Ā·B̄.

**Exact op counts per marginal nonce (n = 4096, b = 4, m = 1024) [C — arithmetic from the
pinned spec formulas §E.3, frontier doc §4.1]:**

| # | Stage | s8 object (today) | BMX4 P-A | BMX4 P-B |
|---|---|---|---|---|
| S1 | XOF expand B (SHA-256 counter mode, 32 B out/compression) | n²·(256/251) B ≈ 17.1 MB → **535 k compressions** | n²·4 bits·(16/15) + n²/32 scales·4.8 bits ≈ 9.26 MB → **290 k compressions** | same 290 k |
| S2 | Q = B̄·V | n²m = **1.72×10¹⁰ s8 MACs** (1 GEMM) | **3.44×10¹⁰ s8 MACs** (B̄ 2-sliced, 2 GEMMs) | **1.72×10¹⁰ 4b×4b MACs** (1 block-scaled GEMM) |
| S3 | combine Ĉ = P·Q mod q | 16·n·m² = **6.87×10¹⁰ s8 MACs** (C-13 limb-tensor) *or* n·m² = 4.30×10⁹ mod-q wide MACs (ALU-direct) | identical | identical (limb count unchanged: P,Q entries still ≫ s8 → 4×4 limb pairs; base-2⁶ limbs possible per redesign §4.4, same 16 pair-GEMMs) |
| S4 | serialize + digest (8m² = 8 MiB payload) | **262 k compressions** | 262 k | 262 k |
| — | streamed bytes (B in + payload out + Q traffic) | ~34 MB | ~26 MB | ~26 MB |

Three structural facts fall straight out of this table and govern everything below:

1. **The combine (S3) is ~80 % of the tensor MAC volume in every profile, and it is
   100 % alphabet-independent** (it multiplies int-magnitude P/Q entries, not committed
   operands). The BMX4 alphabet touches only S2 — ~20 % of tensor MACs (P-B) or 0 % of
   them at reduced efficiency (P-A, where BMX4 makes S2 *heavier* on INT8 hardware).
2. **The SHA volume is 552–797 k compressions per nonce** — µJ-scale on any silicon
   (§4.4) against mJ-scale matmul; SHA cannot be the cost floor at n = 4096.
3. **Arithmetic intensity stays ≈ AI_opt = 2n/b = 2,048 ops/byte** (spec §K.2a) —
   far above every device ridge; memory bandwidth is binding for no one (§4.5).

---

## 3. Research anchors (cited inputs to the model)

| Parameter | Value used | Status | Source |
|---|---|---|---|
| B200 dense INT8 / FP8 / FP4, measured | 3,927 / 3,851 / 7,702 TOPS | **[C]** | [Blackwell microbenchmark, arXiv:2512.02189](https://arxiv.org/abs/2512.02189) (also pinned in roadmap §3.2) |
| B200 TDP | 1,000 W | **[C]** | [Runpod B200 specs](https://www.runpod.io/articles/guides/nvidia-b200), [Verda B200/B300](https://verda.com/blog/nvidia-b300-vs-b200-complete-gpu-comparison-to-date) |
| B300 dense NVFP4 / TDP | 15 PFLOPS dense, 1.1–1.4 kW | **[C]** (vendor-class specs) | [Verda](https://verda.com/blog/nvidia-b300-vs-b200-complete-gpu-comparison-to-date), [Spheron B300 guide](https://www.spheron.network/blog/nvidia-b300-blackwell-ultra-guide/) |
| RTX 5090 dense FP4 / INT8 / TBP | ~1,676 / 838 TOPS / 575 W | **[C]** | [RTX Blackwell whitepaper](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf) (repo-pinned, redesign §4.3) |
| Rubin NVFP4 (context only) | 35–50 PF vendor peak | **[C]** (vendor claim, unmeasured) | [NVIDIA Rubin blog](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/) |
| Best shipping SHA-256 ASIC efficiency (2026) | S23 Hyd ≈ 9.5 J/TH; S21 XP ≈ 13.5 J/TH air | **[C]** | [Mineshop J/TH rankings 2026](https://mineshop.eu/blog/asic-miner/most-efficient-bitcoin-asic-miners-2026-ranked-jth), [BT-Miners rankings](https://bt-miners.com/most-energy-efficient-bitcoin-miners-in-2026-full-j-th-rankings-across-every-model-bt-miners-carries/), [D-Central](https://d-central.tech/best-bitcoin-miners/) |
| → energy per SHA-256 compression, bespoke, ~5 nm class | **≈ 5–7 pJ** (9.5–13.5 pJ per SHA256d ÷ ~2 effective compressions with midstate reuse) | **[M]** derived from [C] | derivation this doc; midstate reuse per [AsicBoost, arXiv:1604.00575](https://arxiv.org/pdf/1604.00575) |
| SHA-256 pipelined core complexity | ~15–30 kGE at 7 nm, > 50 Gbps; 14,273 µm² @ Intel 14 nm (3-pipe, 1.53 GHz) | **[C]** | [Custom ASIC Design for SHA-256 (Computers 13(1):9, incl. EPI 7 nm survey)](https://doi.org/10.3390/computers13010009) |
| Datapath energy at 45 nm, 0.9 V (canonical) | int8 MAC 0.2 pJ; int8 add 0.03 pJ; int32 add 0.1 pJ; int32 mult 3.1 pJ; FP32 MAC 4.6 pJ | **[C]** | [Horowitz, ISSCC 2014](https://gwern.net/doc/cs/hardware/2014-horowitz-2.pdf), [tabulated](https://www.researchgate.net/figure/Energy-consumption-of-multiply-accumulations-Horowitz-2014_tbl1_301848151) |
| 45 nm → 4/5 nm datapath scaling | ÷ ~5–7 energy | **[M]** (standard scaling envelope; used only for *ratios*, never absolutes) | — |
| Generic domain-specific-ASIC-vs-GPU strip at iso-node (dense tensor workload) | perf/W ≈ **1.5–2.5×** | **[C]** (anchor) | [TPU v4 vs A100: 1.2–1.7× faster at 1.3–1.9× less power, Jouppi et al., ISCA 2023](https://arxiv.org/abs/2304.01433) (both ~7 nm-class) |
| HBM3/HBM3E energy | ~0.5–4 pJ/bit (≈ 4–32 pJ/byte; sources disagree on what is included) | **[C]** (range) | [Micron HBM3E brief](https://assets.micron.com/adobe/assets/urn:aaid:aem:b710d8f2-7f66-44c1-a234-456e2b986347/renditions/original/as/hbm3e-product-brief.pdf), [faceofit HBM3 vs GDDR7](https://www.faceofit.com/hbm3-vs-hbm4-vs-gddr7/) |
| FPGA flagship dense INT8 | Versal VC1902 133 TOPS; Stratix 10 NX 143 TOPS @ ~1 TOPS/W | **[C]** | spec §S.2.1 (repo-pinned, vendor whitepapers) |
| FPGA 4-bit multiplier cost | ~11 LUTs + 2 CARRY4 (7-series-class) | **[C]** | [arXiv:2510.21533](https://arxiv.org/html/2510.21533v1); DSP packing per [arXiv:2203.11028](https://arxiv.org/pdf/2203.11028), [arXiv:2606.11065](https://arxiv.org/html/2606.11065) |
| Leading-node NRE | ~$542 M @ 5 nm; $0.5–1.5 B-class @ 3 nm | **[C]** (context only) | [SemiEngineering](https://semiengineering.com/big-trouble-at-3nm/) (spec §S.2.2 pinned) |
| OCP MX format facts (E2M1 value set, E8M0 scale) | as frontier doc §2 | **[C]** | [OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) |

Whole-chip commodity energy per op used throughout, derived from measured TOPS at TDP
[M from C]: **B200 INT8 ≈ 0.255 pJ/op; B200 FP4 ≈ 0.130 pJ/op** (1,000 W ÷ measured
dense TOPS; "op" = TOPS convention, 2 ops per MAC). GPU SHA-256 throughput is taken as
~20–25 G compressions/s per flagship card at TBP (hashcat-class figure) → **≈ 5 nJ per
compression on GPU [M]** — ~10³× worse than a SHA ASIC, which matters below only in that
it *still* doesn't matter (§4.4).

---

## 4. Component-by-component: what an ASIC CAN and CANNOT cheapen

### 4.1 The multiplier cell — big saving in isolation, already commoditized

The ×2-normalized mantissa alphabet factorizes: every μ ∈ {0,1,2,3,4,6,8,12} is
(0, 1 or 3)·2^{0..2}. A bespoke mantissa multiplier is therefore a 2-bit×2-bit odd-part
lookup ({1,3}×{1,3} → {1,3,9}) plus a 2+2-bit exponent add plus sign logic — and the
per-block E8M0 scale 2^{e_A+e_B} is applied **once per 32-element block sum**, not per
MAC. Gate-model comparison (NAND2-equivalents, standard-cell synthesis-class estimates —
**[M]**, cross-checked against the Horowitz energy ratios [C]):

| MAC cell | Multiplier | In-cell accumulation | Total (with pipe regs) | Density vs s8 cell | Energy vs s8 MAC |
|---|---|---|---|---|---|
| s8×s8→s32 (baseline; the v4 IMMA object) | ~400–500 GE (Booth 8×8) | 19–24 b CSA + int32 column add | ~700–900 GE | 1× | 1× (0.2 pJ @45 nm [C]) |
| **BMX4 4b×4b exact** (P-B) | ~30–60 GE (LUT + exp-add) | 12 b CSA (block sums ≤ 1152 < 2¹¹) + **amortized** ⅟₃₂ share of 32 b shift-promote | **~200–300 GE** | **~3–3.5×** | ~4–6× less |
| BMX4 4b×8b (P-A: B̄-mantissa × s8 V) | ~150–250 GE | ~16 b CSA + promote | ~450–550 GE | ~1.5–1.7× | ~2× less |
| Commodity FP4 E2M1 FMA w/ E8M0 scale + FP32 accumulate | 2b×2b significand mult (trivial) + exponent add | FP32 alignment + 24 b add + TMEM | (proprietary) | **revealed: 1.96× vs its own INT8** (7,702/3,927 [C]) | 1.96× less |
| Freivalds/mod-q wide MAC (24b×24b → mod 2⁶¹−1, Mersenne shift-add reduction) | ~3–4 kGE | 61–64 b CSA | ~4–5 kGE | — | ~0.7–0.9 pJ @5 nm [M] |

**Reading.** Yes, the bespoke BMX4 cell is ~3–3.5× denser than a bespoke s8 cell — the
redesign doc's premise is arithmetically right. But the comparison that sets the residual
is bespoke-vs-**commodity-FP4**, and the commodity FP4 pipe already implements a 2-bit
significand multiplier with an exponent-add scale — i.e. **the frontier already ships the
cheap multiplier, at 2× its own INT8 rate, on the best nodes on Earth, in volume**
(that is the entire premise of the tax-inversion design). The bespoke cell's residual
edge over the commodity FP4 cell is confined to replacing the FP32 accumulate/alignment
machinery with a right-sized exact fixed-point path and deleting unused FP semantics
(rounding modes, NaN/inf, subnormal logic): **modeled 1.2–1.5× at the cell level [M]** —
not 3–4×. And this applies only to S2's ~20 % of MACs (P-B), or not at all (P-A).

One further bespoke-only crumb: zero-skipping. P(μ=0) = 1/15 ≈ 6.7 % under the uniform
15-code sampler [C — frontier doc §4.1]; clock-gating on zero operands buys a bespoke
array ≤ ~7 % energy (commodity dense pipes don't skip) — included in the §5 ranges, and
bounded exactly as the redesign doc's §4.2 zero-mass condition anticipated. Similarly a
single Strassen level fits a 10-bit bespoke datapath under BMX4 (operand sums ≤ 384),
saving ≤ ~12.5 % of S2 multiplies at O(n²) add cost — a ≤ 1.1× nibble on 20 % of the
work, absorbed in the ranges (spec §A.6 disposition unchanged).

### 4.2 The exact wide-integer accumulation datapath — the floor, tested

The claim to test: the cross-block reduction to exact int32-class accumulators is
invariant work the alphabet cannot shrink. The honest answer is **"mostly invariant —
shrinkable ~1.3–1.6× at the cell level, and the shrink saturates":**

- **In-block reduction narrows with the alphabet:** s8 partial products are 14-bit and a
  32-deep in-block reduction needs ~19-bit carry-save; BMX4 mantissa products are ≤ 36
  (6-bit ×4-grid) and a 32-block sum is ≤ 1152 < 2¹¹ → ~12-bit carry-save. Reduction-tree
  area/energy scales ≈ linearly in width → **~1.6× saving on the reduction share** [M].
- **The block structure amortizes, not eliminates, the wide path:** one 2^{e_A+e_B}
  shift (≤ 2⁸) + one ≥ 24-bit add per 32 MACs (K′-blocked promotion per frontier doc
  §4.3). Per-MAC cost of the wide path ≈ (32-bit shift-add)/32 ≈ a few GE — small but
  **irreducible**: the committed object's entries reach 1.51×10⁸ ≈ 2²⁷·²; every correct
  miner, bespoke or commodity, must land every one of the n²m products in an exact
  ≥ 2²⁷ container. No alphabet choice removes that; BMX4 only lets the *narrow* part of
  the reduction be narrow.
- **Why the shrink saturates:** as operands narrow, the MAC cell becomes
  accumulation- and operand-delivery-dominated (multiplier ~450→~45 GE is a 10× shrink,
  but the cell shrinks only ~3× — the reduction+regs floor). Chip-level, the MAC array is
  itself only ~30–50 % of a real accelerator's energy (the rest is SRAM/reg-file operand
  delivery, clock, control, DRAM — Horowitz's own point [C]); even a *free* multiplier
  would cap the chip-level gain near ~1.4–1.7×. **Diminishing returns protect the
  design**: the narrower the alphabet, the more the workload is accumulation, and
  accumulation is the invariant.
- **And the commodity side already banks half of it:** the 2× FP4-vs-INT8 commodity rate
  is precisely NVIDIA monetizing the same multiplier shrink; the FP32 accumulator it
  keeps is *wider than BMX4 needs* (24 b vs the 12 b + promote that suffices), which is
  exactly the bespoke 1.2–1.5× cell edge counted in §4.1 — provided the FP32 path is
  actually exact (t = 24). If it is not, the commodity part falls off the native path
  entirely, which is the §7 cliff scenario, and *that* — not the multiplier — is where a
  real ASIC gap would come from.

### 4.3 The combine stage — the dominant, alphabet-independent term (the real crux)

S3 is 4.30×10⁹ multiply-accumulates of ~2²¹–2²⁴-magnitude integers into q = 2⁶¹−1
residues per nonce — **~80 % of the marginal unit's tensor-MAC volume in the C-13 limb
form (6.87×10¹⁰ s8 MACs), in every profile, for every operand format.** The options:

| Implementation | Who | Cost per nonce [M from §3 anchors] |
|---|---|---|
| C-13 limb-tensor: 16 s8 pair-GEMMs | commodity GPU (its only tensor option) | 1.374×10¹¹ ops × 0.255 pJ ≈ **35 mJ** (B200) |
| Same limb array, bespoke s8 systolic | ASIC | ≈ 35 / (1.5–2.5 generic strip) ≈ **14–23 mJ** |
| **Dedicated wide-int mod-q MAC array** (24b×24b→Σ mod 2⁶¹−1; Mersenne reduction is shift-add) | ASIC only | 4.30×10⁹ × ~0.9–2 pJ ≈ **4–9 mJ**; intrinsic bit-product count is 2× lower than the limb form (529 vs 1,024 bit-products/MAC), so this is the honest floor of the stage |
| int-ALU direct (CUDA cores, 64-bit mod-q) | commodity fallback | ~25 mJ energy but ~10–20× slower wall-time than its own tensor path [M] — not chosen |

**This is where the bespoke edge actually lives** — a 2–4× stage-level lever from
building the wide-integer arithmetic the GPU has no native unit for — and it is
**identical under s8 and BMX4**, because P/Q magnitudes are int-scale in both (P-A) and
the limb-pair count stays 16 even at the shrunken P-B magnitudes (redesign §4.4). Two
design-side notes follow, flagged for the v4.2 parameter owners rather than decided here:
(i) any future combine optimization that shrinks S3's share (E2M1-native U/V *plus* a
smaller limb base, or an int-ALU-competitive path on commodity) shrinks the bespoke
residual too — the combine is the ASIC's best stage; (ii) conversely nothing about BMX4
makes S3 worse — the alphabet is simply irrelevant to it.

### 4.4 The XOF floor — negligible in silicon cost; its value is freshness, not joules

Per nonce: 552 k (BMX4) / 797 k (s8) SHA-256 compressions (S1+S4). Costing both sides:

- **Bespoke ASIC:** at the 2026 Bitcoin-ASIC anchor (~5–7 pJ/compression [M from C]):
  **≈ 3–6 µJ/nonce — 0.02–0.05 % of the ~12–20 mJ matmul energy.** Area: a fully
  pipelined core (1 compression/cycle, ~15–30 kGE [C]) does ~1.5×10⁹ compressions/s at
  1.5 GHz; a chip running 2,000 nonce/s needs ~1.1×10⁹ compressions/s ≈ **one core,
  ≲ 0.01 mm² at 5 nm — < 1 % of die**. The XOF/matmul area-power question is settled:
  **the matmul (specifically S3) dominates a BMX4 mining ASIC's silicon by 3–4 orders of
  magnitude at n = 4096.**
- **Commodity GPU:** ~5 nJ/compression on shader ALUs [M] → 2.8–4.0 mJ/nonce ≈ 5–9 % of
  per-nonce energy (and a wall-time item when host-expanded — the known §K.2a-WT
  operational concern, not a silicon-economics one).

**Consequence for the ASIC-resistance thesis (honest correction):** the design should
not claim the XOF as a hardware-*cost* floor — a SHA ASIC block is the cheapest silicon
in this entire pipeline, and BMX4 halving the XOF bytes moves nothing material on either
side. The XOF's real, load-bearing role is **anti-amortization**: n² fresh bytes per
nonce with no nonce-invariant factor (invariants I1′/I3, redesign §4.1) is what forces
*every* miner — bespoke included — to run the full matmul per nonce instead of caching
it. It denies the shortcut; it does not tax the balance sheet. The floor the thesis
needs is §4.2+§4.3, and those hold on their own.

### 4.5 Operand memory bandwidth — no wall, for anyone

Streamed bytes/nonce ≈ 26–34 MB (§2) against ~1.7×10¹¹ ops → AI ≈ 2,048 ops/byte, ~3.5×
above the worst commodity ridge (spec §K.2a table). Energy: 30 MB × 4–32 pJ/byte (HBM3
range [C]) ≈ **0.1–1.0 mJ/nonce, ≤ 2 %** on the GPU. A bespoke chip generates B on-die
straight out of its XOF block and holds the ~36 MB working set (P: 16.8 MB int32, V,
buffers) in SRAM — eliminating external memory entirely — but since memory was ≤ 2 % of
the commodity budget, **on-die generation buys the ASIC almost nothing**; symmetrically
there is no bandwidth wall that could stop a bespoke design. Memory is neutral: it
neither protects the GPU nor opens an ASIC angle. (This is the §L.4 conclusion arriving
from the other direction — the workload's footprint is deliberately tiny and its
intensity deliberately high; the redesign doc §4.3 already noted BMX4 moves *further*
from any capacity/bandwidth gate, and this model concurs: packed operands halve, AI
doubles.)

---

## 5. The integrated model

**Method.** Per-nonce energy = Σ stages, commodity side priced at measured-TOPS-at-TDP
(§3), bespoke side = commodity ÷ (generic strip 1.5–2.5× [C-anchored]) ÷ (stage-specific
datapath factor from §4.1–§4.3 [M]), + SHA/memory terms priced directly. Area-normalized
throughput (nonce/s·mm² at iso-node) is modeled with the same factors (utilization-of-die
~2.5–3× for a miner ASIC × per-mm² array-rate parity-to-1.5×, capped by the empirical
TPU-class evidence that iso-node dense-tensor ASICs land within ~1.5–2.5× of GPUs, not
5×+ [C]). Node handicap where applied: ×1.3–1.5 energy, ×1.6–2 area for one node behind
[M, standard scaling].

**Per-nonce energy (mJ), B200-class commodity anchor [M from C]:**

| Stage | s8 GPU | s8 ASIC | BMX4 P-A GPU | BMX4 P-A ASIC | BMX4 P-B GPU | BMX4 P-B ASIC |
|---|---|---|---|---|---|---|
| S1+S4 SHA | 4.0 | 0.005 | 2.8 | 0.004 | 2.8 | 0.004 |
| S2 B̄·V | 8.8 (INT8) | 3.5–5.9 | 17.5 (INT8, 2-slice) | 5.5–9.2 (4b×8b cells) | 4.5 (FP4) | 1.5–2.5 (4b×4b exact) |
| S3 combine | 35.0 (limb s8) | 4–17 (mod-q array … limb array) | 35.0 | 4–17 | 35.0 | 4–17 |
| memory | 0.3–1.0 | ~0.1 | 0.3–1.0 | ~0.1 | 0.3–1.0 | ~0.1 |
| **Total** | **48–49** | **8–23** | **56** | **10–26** | **43** | **6–20** |
| **Residual (same node)** | | **2.1–3.1×** | | **2.2–3.5×** | | **2.2–3.5×** (worst-case tail to ~4× with zero-skip + Strassen crumbs and best-case mod-q array) |
| **Residual (ASIC one node behind)** | | **1.4–2.4×** | | **1.5–2.5×** | | **1.5–2.6×** |

Cross-checks: (i) the s8 row reproduces the spec's disclosed ~1.5–2× under the realistic
(node-behind) scenario and shows the same-node worst case was always nearer 3× once the
combine lever is credited — an honest tightening of §S.2.2, not a BMX4 effect; (ii) the
commodity BMX4-P-A row is *worse than s8 for the GPU* (B̄'s 9-bit width taxes the INT8
pipe 2×) — i.e. **as currently specified (s8 U/V), BMX4's marginal unit does not deliver
the frontier-native ≈1× on the sketch profile; only the committed-object stage C̄ is
FP4-native.** This is the §K.2a-WT re-measure obligation made concrete, and it is a
strong quantitative argument for adopting the deferred E2M1-U/V co-change (P-B) — which
the redesign doc's F\* already assumes — subject to its sketch-soundness re-derivation;
(iii) B300/Rubin move the commodity FP4 term down (15→~2× and 35–50 PF vendor-peak
class), shrinking S2's share further and leaving the residual even more combine-set.

**Throughput per die area (iso-node, nonce/s·mm², normalized) [M]:** bespoke
utilization-of-die (MAC array + SRAM ~70–80 % of a miner die vs ~25–35 % tensor-region
on a GPU) × cell density from §4.1, discounted by the empirical iso-node cap [C]:
**bespoke ≈ 1.5–3× per mm²** for BMX4 (P-B), ≈ 1.3–2.5× for s8. One node behind: the
advantage halves (0.8–1.6×) — a node-behind bespoke chip barely beats the commodity part
per wafer at all, which is why the *energy* residual (which survives node handicap
better) is the binding number, and why difficulty absorption (spec §I.4) + NRE
([SemiEngineering](https://semiengineering.com/big-trouble-at-3nm/) $0.5–1.5 B-class at
3 nm, disclosed in §S.2.2) keep the realistic case at the low end of the band.

---

## 6. The FPGA case

Same decomposition, FPGA-specific costing [M from C]:

- **S2 (the alphabet stage):** the 4-bit alphabet is genuinely LUT-friendly — a 4-bit
  multiplier is ~11 LUTs [C, arXiv:2510.21533], and the {0,1,3}×2^k structure reduces it
  further to a shift-add; DSP packing fits 2–4 such MACs per DSP slice
  [C, arXiv:2203.11028]. Granting the flagship AI-FPGAs (VC1902 133 / Stratix 10 NX 143
  dense INT8 TOPS [C]) a **generous 2–4× fabric dividend on 4-bit** → ~280–580
  TOPS-equivalent on S2. This is the *most* charitable BMX4 reading for FPGAs.
- **S3 (80 % of the work):** wide-integer accumulation and s8 limb GEMMs are exactly
  what the hardened DSP columns already do at their rated INT8 TOPS — **no 4-bit
  dividend applies**. S3 runs at ~133–145 TOPS-equivalent.
- **Marginal-unit wall-time (per device):** S2 3.44×10¹⁰ ops @ ~400 TOPS ≈ 86 µs +
  S3 1.374×10¹¹ ops @ ~140 TOPS ≈ 981 µs → **≈ 1.07 ms/nonce**, vs B200 ≈ 40–43 µs
  (P-B, peak-basis) → **≈ 25–27× behind a B200-class part; ≥ 13× holds with heavy
  margin even granting FPGA peak utilization and discounting the GPU to the §K.2b 60 %
  utilization gate (→ ~15–16×).** Against a consumer RTX 5090 (FP4 1,676 TOPS [C]) the
  gap is ~3–6×. Energy: ~1 TOPS/W fabric-class [C] vs B200's effective ~4–8 TOPS/W on
  this mix → **3–8× worse J/nonce.**

**Verdict: the prior "FPGAs stay ≥ 13× behind" claim is CONFIRMED and is conservative on
the marginal unit (typically 15–30×).** The small alphabet is the best thing that ever
happened to FPGAs on this workload and it still doesn't matter, because (a) the dividend
only touches the 20 % alphabet-dependent stage while the 80 % combine pins them to their
hardened-INT8 rate, and (b) the spec §S.2.1 structural point stands: the only reason
these FPGAs post triple-digit TOPS is hardened matmul blocks — there is no
reconfigurability dividend left to collect on a dense, regular, latency-insensitive
GEMM. FPGAs remain excluded on throughput, J/op, and (per §S.2.1) $/TOPS alike.

---

## 7. FINAL residual bound and sensitivity

**FINAL bound (restated from §0 with its conditions):** under the condition that
commodity block-scaled FP4 accumulation proves t = 24 (frontier doc §4.6 vectors), the
bespoke BMX4 mining-ASIC residual over a commodity FP4 datacenter GPU is
**≈ 1.5–2.5× realistic / ≈ 2–3.5× credible worst case (≤ ~4×)** per unit of honest
exact-matmul throughput (J/nonce basis; per-mm² basis is equal or tighter), versus
**≈ 1.4–2.4× / ≈ 2–3×** for the s8 baseline under the identical model. **BMX4 widens the
residual by ≤ ~1.2–1.3× multiplicative.** The first-pass "~2–3×" (redesign §4.3) is
confirmed as the central band — but for a different reason than it gave: the widening
comes almost entirely from the FP32-accumulator-vs-exact-fixed-point cell delta on the
S2 stage plus small bespoke-only crumbs (zero-skip, one Strassen level), NOT from the
raw 3–4× multiplier-density ratio, which the commodity FP4 pipe already captures. The
FPGA gap is ≥ 13× behind datacenter (confirmed; typically 15–30×), ~3–6× behind consumer
FP4, at worse J/op.

**Sensitivity of the bound to each assumption:**

| Assumption | Range explored | Effect on BMX4 residual |
|---|---|---|
| **Commodity t (proven exact accumulator width on the FP4/MX path)** | t = 24 vs t ≈ 14 (Hopper FP8 precedent [C]) | **THE swing factor.** t≈14 → K′ = 0 → commodity falls off the native path to INT8 2-slice/4-GEMM fallback (frontier doc §4.3) while a bespoke exact array is untouched → residual ×~4 → **6–14×: a real cliff.** Silicon-testable before activation; no other assumption comes close. |
| Combine share / implementation | S3 = 60–85 % of tensor ops; limb-tensor vs bespoke mod-q array (2–4× stage lever) | ±0.5× on the residual; any commodity-side combine improvement narrows the residual (the ASIC's best stage). Also the s8 baseline moves in lockstep — the *delta* BMX4−s8 is insensitive. |
| Generic strip factor | 1.5–2.5× (TPU-v4 anchor [C]) | Linear: sets the floor of the band. Below 1.5× contradicts no evidence but wastes the attacker's NRE; above 2.5× contradicts every published iso-node dense-tensor comparison. |
| Node gap | ASIC at frontier vs one node behind | ×0.65–0.75 on the residual (energy); ×~0.5 per-area. Frontier-node access is what separates "worst case" from "realistic," and frontier FP4 allocation is exactly what a mining chip cannot out-bid the AI industry for (§S.2.2 logic, unchanged). |
| XOF cost model | ±3× on all SHA numbers | Moves the residual by < 2 % (§4.4). The XOF is not a load-bearing cost anywhere at n = 4096. |
| Memory model | HBM 4–32 pJ/B; on-die vs external | < 3 % effect either way (§4.5). No wall, no lever. |
| U/V profile | P-A (s8 U/V, as specified) vs P-B (E2M1 U/V) | Residual band nearly identical; what changes is the *commodity* GPU's own efficiency on the marginal unit (P-A wastes the FP4 pipe on S2 — a design-side reason to adopt P-B, not an ASIC-side one). |
| Zero mass / Strassen crumbs | ≤ 7 % + ≤ 12.5 % of S2 | ≤ ~1.1× combined, inside the stated band. |
| B300/Rubin FP4 scaling (15 PF [C] / 35–50 PF vendor [C-claim]) | commodity S2 term ÷ 1.7–4 | Shrinks S2's share → residual *more* combine-determined and slightly tighter. The frontier out-scaling the attacker each generation is the difficulty-absorption backstop (§I.4), same as s8. |

---

## 8. Verdict

**Bounded and acceptable — conditional on one silicon proof; the small alphabet does NOT
open an ASIC cliff by itself.**

1. **The BMX4 residual is bounded at ~2–3× (≤ ~4× worst case)** because the two things a
   bespoke chip would need to run away with the workload are both denied: the cheap
   multiplier is already mass-produced by the frontier (FP4 tensor pipes at 2× INT8
   rate, on nodes and volumes no mining chip will match), and the majority of the
   marginal work (exact wide accumulation + mod-q combine, ~80 % of tensor MACs) is
   alphabet-independent integer reduction on which the bespoke lever is the same ~2–4×
   stage factor it already had against s8. The alphabet moves the residual by ≤ ~1.3×.
   This is within the §N.3-iv disclosed-centralization envelope and comparable to the
   ordinary iso-node spread between commodity accelerator vendors themselves.
2. **The single determining factor is the XOF/accumulation-floor question, answered
   precisely:** the XOF is a freshness floor, not a cost floor (µJ vs mJ, §4.4); the
   *cost* floor is the exact-integer reduction datapath — and it holds, because narrowing
   operands makes the workload accumulation-dominated and accumulation is invariant
   (§4.2). The cheap multiplier does NOT let an ASIC escape, because the commodity part
   ships the same multiplier. **What could let an ASIC escape is commodity silicon
   failing the exactness envelope:** if B200/B300/MI355X/Trn3 block-scaled FP4
   accumulation proves t ≈ 14 rather than t = 24, the commodity FP4 rate is unusable for
   the exact object, the GPU pays the 4× fallback, and the residual jumps to 6–14× — a
   real cliff, from the accumulator, not the alphabet. The same t = 24 proof is already
   the frontier doc's #1 risk (§8) and the redesign doc's condition 3; this analysis
   makes it the ASIC-residual gate as well.
3. **Versus the s8 baseline, the honest statement for the v4.2 §S.2.2 re-disclosure is:**
   "a mining-only chip's residual edge is ~1.5–2.5× realistic, up to ~3.5–4× for a
   frontier-node full-custom design (s8: ~1.4–2.4× / ~3×); the increase from the BMX4
   alphabet is ≤ ~1.3× because commodity FP4 silicon natively implements the BMX4
   multiplier; FPGAs remain ≥ 13× behind; participation by SHA farms, junk cards, and
   FPGAs stays closed; the capacity-gate impossibility (§L.4) is format-independent and
   unaffected." That supersedes the first-pass "~2–3× worst case" with the same central
   number and a stated mechanism and conditions.
4. **Design-side corollary surfaced by the model (flagged, not decided here):** as
   specified (s8 U/V), the marginal sketch unit does not itself become FP4-native — only
   the committed object does — so the tax-inversion benefit on real miner throughput is
   partly deferred to the E2M1-U/V co-change already queued behind sketch-soundness
   re-derivation. Both the commodity ≈1× goal and (mildly) the ASIC-residual tightness
   argue for completing that co-change before v4.2 parameter freeze.

---

## 9. What the model settles vs what needs real silicon

**Settled by this model (arithmetic + cited parameters; will not change on silicon):**
the per-nonce work decomposition and its shares (§2); the XOF's negligibility as a
silicon cost and the matmul/combine dominance of ASIC area-power at n = 4096 (§4.4);
the absence of a memory-bandwidth wall in either direction (§4.5); the saturation
argument for accumulation-dominated MAC cells (§4.2); the FPGA exclusion (§6 — every
input is a shipping-part number); the *structure* of the residual (generic strip ×
combine lever × cell delta) and its insensitivity to the alphabet.

**Needs real silicon (falsifiable predictions, in priority order):**

1. **t = 24 proof on every commodity block-scaled path** (B200/B300 `mxf4`-E8M0 TMEM
   accumulate; MI355X CDNA4; Trn3 Matmul-MX PSUM; TPU v7 FP8 fold) via the frontier doc
   §4.6 boundary vectors — decides bounded-2–3× vs cliff-6–14×. *Prediction: passes on
   CDNA4 and Trn3 (architected FP32 accumulate), genuinely uncertain on Blackwell TMEM
   (Hopper t≈14 precedent).*
2. **§K.2a-WT stage split on the BMX4 marginal unit** on a real FP4 part at Q ≥ 32 —
   the model predicts S3 ≥ ~70 % of marginal tensor wall-time under P-A and ~80 % under
   P-B; if measurement shows the combine share materially lower (e.g. a faster
   commodity combine path exists), the bespoke residual *tightens* below this bound.
3. **`mxf4`-E8M0 rate parity with NVFP4** on B200/B300 and its survival on Rubin
   (frontier doc R-1-class item) — sets the commodity denominator.
4. **GPU-side SHA/XOF wall-time at Q ≥ 32 with on-die expansion** — an implementation
   item (host-expansion is today's bottleneck, spec §S.2.2 row 2), not a silicon
   unknown, but it gates the honest commodity J/nonce measurement this model
   approximates from TDP.
5. What no measurement short of a tape-out settles: the bespoke cell/array numbers
   themselves (§4.1 gate model, §5 area rows). They are bounded above by the empirical
   iso-node ASIC-vs-GPU record [C] and below by revealed commodity ratios [C]; the
   residual band was deliberately built so that every unmeasurable quantity is bracketed
   by a measurable one.

---

## 10. Confidence

| Claim | Confidence | Basis |
|---|---|---|
| Work decomposition & op counts (§2), combine = ~80 % of marginal tensor MACs | **High** | Pinned spec arithmetic (§E.3, C-13), format arithmetic |
| XOF is a freshness floor, not a cost floor (< 0.1 % ASIC energy/area) | **High** | Bitcoin-ASIC J/TH [C] + count arithmetic; robust to ±3× |
| No memory-bandwidth wall either direction | **High** | AI_opt = 2,048 [C-spec] + HBM pJ/bit range [C] |
| Commodity FP4 pipe ≈ the optimal BMX4 multiplier (alphabet advantage pre-captured) | **High** (structural) | OCP MX / E2M1 format arithmetic [C]; measured FP4 = 1.96× INT8 [C] |
| Accumulation-floor invariance & saturation (§4.2) | **Medium-High** | Gate/width modeling [M] cross-checked to Horowitz [C]; not silicon-verified |
| Bespoke combine lever 2–4×; generic strip 1.5–2.5× | **Medium** | Intrinsic bit-product arithmetic [M] + TPU-v4 anchor [C]; the widest [M] inputs in the model |
| FINAL residual band (1.5–2.5× realistic / ≤ ~4× worst) and ≤ ~1.3× delta vs s8 | **Medium** | Product of the above; deliberately a range; conditional on t = 24 |
| Cliff quantification at t ≈ 14 (6–14×) | **Medium-High** (mechanism), **Low** (which chips) | K′ arithmetic is exact [C-spec]; per-device t is unmeasured — item 1 of §9 |
| FPGA ≥ 13× (typically 15–30×) | **High** | All shipping-part inputs [C]; the 4-bit dividend was granted at maximum |
| Any real-silicon nonce/s ordering | **Low by design** | No BTX kernel has run on any FP4 part; §K.2b posture inherited verbatim |

**References** (beyond the four companion docs and spec sections cited inline):
[Blackwell microbenchmarks, arXiv:2512.02189](https://arxiv.org/abs/2512.02189) ·
[OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) ·
[Horowitz, ISSCC 2014](https://gwern.net/doc/cs/hardware/2014-horowitz-2.pdf) ·
[Jouppi et al., TPU v4, ISCA 2023 (arXiv:2304.01433)](https://arxiv.org/abs/2304.01433) ·
[Mineshop ASIC J/TH rankings 2026](https://mineshop.eu/blog/asic-miner/most-efficient-bitcoin-asic-miners-2026-ranked-jth) ·
[BT-Miners J/TH rankings 2026](https://bt-miners.com/most-energy-efficient-bitcoin-miners-in-2026-full-j-th-rankings-across-every-model-bt-miners-carries/) ·
[D-Central best miners 2026](https://d-central.tech/best-bitcoin-miners/) ·
[Custom ASIC Design for SHA-256, Computers 13(1):9](https://doi.org/10.3390/computers13010009) ·
[AsicBoost, arXiv:1604.00575](https://arxiv.org/pdf/1604.00575) ·
[Micron HBM3E product brief](https://assets.micron.com/adobe/assets/urn:aaid:aem:b710d8f2-7f66-44c1-a234-456e2b986347/renditions/original/as/hbm3e-product-brief.pdf) ·
[faceofit HBM3/HBM4/GDDR7](https://www.faceofit.com/hbm3-vs-hbm4-vs-gddr7/) ·
[4-bit multiplier in 11 LUTs, arXiv:2510.21533](https://arxiv.org/html/2510.21533v1) ·
[DSP-Packing, arXiv:2203.11028](https://arxiv.org/pdf/2203.11028) ·
[Arithmetic packing in FPGA DSPs, arXiv:2606.11065](https://arxiv.org/html/2606.11065) ·
[RTX Blackwell whitepaper](https://images.nvidia.com/aem-dam/Solutions/geforce/blackwell/nvidia-rtx-blackwell-gpu-architecture.pdf) ·
[Verda B300 vs B200](https://verda.com/blog/nvidia-b300-vs-b200-complete-gpu-comparison-to-date) ·
[Spheron B300 guide](https://www.spheron.network/blog/nvidia-b300-blackwell-ultra-guide/) ·
[Runpod B200](https://www.runpod.io/articles/guides/nvidia-b200) ·
[NVIDIA Rubin platform](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/) ·
[SemiEngineering 3 nm NRE](https://semiengineering.com/big-trouble-at-3nm/) ·
[DeepSeek-V3 §3.3.2 (t≈14 precedent), arXiv:2412.19437](https://arxiv.org/pdf/2412.19437).
