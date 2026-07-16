# BTX MatMul v4.2 — Longevity, Long-Horizon Threat Model & Format-Migration Governance Framework

*Status: RESEARCH + FRAMEWORK deliverable. Not a code change, not a spec edit, not an
activation decision. Companion to `doc/btx-matmul-v4-design-spec.md` (authoritative,
UNCHANGED), `doc/btx-matmul-v4.2-consolidated-design.md` (the consolidated v4.2 design,
owned elsewhere), `doc/btx-matmul-v4-multiplatform-roadmap.md` (G-1, the trigger this
document generalizes), `doc/btx-matmul-v4-exact-int-on-float.md` (the miner-only Ozaki
bridge), `doc/btx-matmul-v4-committed-object-redesign.md` (the hard-fork classification
and conditions ledger this framework operationalizes), `doc/btx-matmul-v4-frontier-native-format.md`
(BMX4, the width-ratio law), `doc/btx-matmul-v4-bmx4-asic-fpga-deepdive.md` (residual
bound), `doc/btx-matmul-v4-bmx4-shortcut-cryptanalysis.md` (small-alphabet closure,
C-15 scope), and `ACTIVATION.md` (the B5/B6 activation discipline this framework
inherits). Written 2026-07-16.*

> **Posture (inherited, preserved).** Per spec §0.7-(4) (PRICE-INDEPENDENCE), no market
> price appears as an input anywhere below — every trigger, threshold, and cadence bound
> is defined on physical/measured quantities only. Per the program's measurement-gated
> honesty (two prior model-based ordering claims were falsified on real silicon, §K.2b),
> every forward-looking claim is tagged **[C] confirmed** (shipping silicon, published
> spec, or peer-reviewed result) or **[S] speculative** (roadmap, rumor, extrapolation).
> Nothing in this document upgrades a hypothesis to a result, and the verdict in §4 is
> explicitly conditional on the gates that remain open (ACTIVATION B2g, B4′/C-15).

---

## 0. Executive verdict (details in §4)

**The design can withstand the test of time — but only because of one architectural
fact, and only if one governance mechanism is built and exercised.** The fact: the
consensus verifier is **compute-path-agnostic** — it checks exact committed integers
over `q = 2⁶¹−1` and never observes how they were produced, so *every* digital
low-precision format shipped or credibly roadmapped through ~2030 admits a no-rounding
exact-integer evaluation path (§1), and most frontier shifts are absorbed **miner-side,
with zero consensus action**. The mechanism: a standing, published frontier-tracking
signal plus a versioned-operand migration discipline (§3) that lets the *committed
encoding* follow the frontier at most once per two hardware generations, behind
measurement gates and supermajority signaling, while the verifier layer never changes.

Time horizons, honestly stated: **5–8 years — HIGH confidence** the PoW remains
superior on its own terms (exact, cheaply verified, frontier-tracking), assuming the
open v4.1 gates pass. **8–15 years — MEDIUM confidence, conditional** on (i) the
low-precision frontier remaining *digital* (the only existential format threat is
non-digital compute, §1.5/§2a), and (ii) the migration mechanism being exercised
successfully at least once (v4.2/BMX4-class). The single biggest long-horizon risk is
not any one format: it is the **exactness premium** — the industry's decade-long drift
toward approximate arithmetic (narrow accumulators, stochastic rounding, analog) slowly
stripping the exact-integer envelopes the PoW's non-negotiable no-rounding requirement
lives in (§2f is the near edge of it; §2a is the far edge).

---

## 1. Forward hardware/format trajectory, 5–15 years

### 1.0 The eligibility test (the lens for everything below)

A future compute substrate/format **keeps tracking this PoW** iff it admits a
**no-rounding exact-integer interpretation with power-of-two scales**: (i) some exact
small-integer subset of its operand format; (ii) products formed exactly; (iii) a
*proven* exact accumulation envelope (2^t for FP-mantissa accumulators, 2^(w−1) for
integer ones) under which a blocked extract-and-promote schedule (K′) never rounds;
(iv) any scaling structure expressible as exact powers of two. This is the generalized
C-1 invariant (`btx-matmul-v4-accumulator-eligibility.md` §1, redesign §3) — and by the
width-ratio law (`btx-matmul-v4-frontier-native-format.md` §1) an eligible device pays
at most a `k² = ⌈W_obj/w⌉²` slicing tax, removable by versioning the committed operand
encoding down to the device's exact width. A substrate that fails the test — no exact
envelope at all — cannot mine *any* exact-integer committed object at *any* encoding,
which is the existential threat class.

### 1.1 Census: where low-precision AI compute goes after FP4/microscaling

| Substrate / format (5–15 yr) | Evidence & horizon | Exact-integer reducible (power-of-two scales)? | Verdict for the PoW |
|---|---|---|---|
| **FP4/FP8 microscaling (MXFP4/6/8, NVFP4)** — current frontier | **[C]** shipping (Blackwell/B300, MI355X, Trn3, TPU v7); Rubin doubles FP4/FP8 only ([NVIDIA](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/)) | **YES** — established by the Ozaki bridge (k² tax) and natively by BMX4 (E2M1 integer subset × E8M0 2^e scales) | **ELIGIBLE**, both bridge and native |
| **NVFP4-style fractional scales (E4M3 block scales)** | **[C]** shipping ([NVIDIA NVFP4](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/)) | **Scales NO, hardware YES** — fractional scales round; but 2^e values are exactly representable in E4M3 scale registers, so the *hardware* runs a power-of-two-pinned consensus object exactly (redesign §3.1) | **ELIGIBLE with the scale pin**; the consensus format must never adopt fractional scale *semantics* |
| **MX successors: MX+ outlier extensions, "nanoscaling" NxFP, asymmetric AMXFP4** | **[C]** MX+ published ([MICRO '25](https://dl.acm.org/doi/10.1145/3725843.3756118)); NxFP/AMXFP4 research ([arXiv:2411.09909](https://arxiv.org/pdf/2411.09909)) **[S]** as products | **YES in every variant examined** — all are block-structured integers-times-scales refinements; finer per-element scaling only shrinks the block length L (helps the K′ discipline) *provided* scales stay 2^e; fractional micro-scales re-raise the NVFP4 pin | **ELIGIBLE** (watch the scale semantics, not the block geometry) |
| **Sub-4-bit: MXFP2/INT2, "second-gen FP4"** | **[S]** — no shipped FP2 matmul unit found; 4-bit is the current commercial floor ([MXFP4 deployment](https://www.spheron.network/blog/mxfp4-microscaling-quantization-gpu-cloud/), MR-GPTQ ICLR 2026); Rubin FP4 second-gen **[S]** | **YES for eligibility** (a 2-bit exact pipe simply raises the k² tax on a wider committed object); **NO for native tax-inversion** — a committed alphabet at ≤2 bits violates the hardness floor (min-entropy ≥ ~3.4 bits/element, ternary categorically rejected — redesign §4.2, cryptanalysis §2.6/§4) | **ELIGIBLE as hardware; the committed object must NOT follow below w≈3.** If the frontier's fastest pipe drops below ~3 exact bits, the PoW rides it at k² ≥ 4 and the ladder flattens by that constant — bounded, not fatal |
| **Ternary/1-bit (BitNet b1.58 class) + LUT/popcount silicon** | **[C]** real for 2–8B edge models ([microsoft/BitNet](https://github.com/microsoft/BitNet)); **[S]** for frontier — largest native 1-bit model ≈8B (Apr 2026), no frontier lab has shipped a ternary frontier model ([status](https://marklaursen.com/blog/1-bit-llms-could-make-gpus-obsolete)) | **YES trivially** (±1/0 are exact integers) — but this is the **BNN/XNOR cliff**: at a ternary committed object the tensor-core-optimality argument fails and LUT fabrics/popcount win (cryptanalysis §4) | **ELIGIBLE but FORBIDDEN as a committed object** (hardness floor). If ternary silicon ever *dominates* the frontier, the PoW deliberately stays ≥3-bit and accepts a ladder gap — see §2a |
| **Log-number-system (LNS) / log-posit hybrids** | **[S]** — research only ([LPRE ISCAS 2025](https://arxiv.org/pdf/2503.01313)); no commercial matmul adoption found | **Multiplication YES (exponent add = exact), accumulation NO** — LNS addition requires Gaussian-log interpolation tables that round by construction; no known exact-integer accumulation path | **THREAT if it ever dominates** — but adoption evidence is nil; monitor only |
| **Posit (with quire)** | **[S]** commercial; **[C]** as a standard — Posit Standard 2022 mandates the **quire**, an exact fixed-point dot-product accumulator ([IEEE Spectrum](https://spectrum.ieee.org/floating-point-numbers-posits-processor)) | **YES, unusually cleanly** — small integers are exact posit values and the quire is *architecturally* an exact accumulator (no K′ discipline even needed) | **ELIGIBLE — ideal on paper**, irrelevant until silicon ships |
| **Analog / in-memory compute (AIMC): EnCharge EN100, Mythic, IBM AIMC** | **[C]** shipping at the *edge/client* (EnCharge 200-TOPS INT8 client part — [EE Times](https://www.eetimes.com/encharge-picks-the-pc-for-its-first-analog-ai-chip/)); **[S]** for datacenter frontier — precision is the open research problem ([npj Unconv. Comp.](https://www.nature.com/articles/s44335-025-00044-2)) | **NO — structurally.** Charge/current-domain MACs + ADC quantization have device-level stochastic and drift error; there is no rounding *function* to be the identity on representable values — the computation is not discrete. No exact-integer interpretation exists at any encoding | **THE EXISTENTIAL CLASS** (with optical). See §1.5 and threat §2a |
| **Optical/photonic matmul (Lightmatter Envise class)** | **[C]** photonic *interconnect* is what actually shipped — Lightmatter's 2026 commercial products are Passage CPO and NVLink-Fusion optics, not compute ([Lightmatter](https://lightmatter.co/press-release/lightmatter-joins-nvidia-nvlink-fusion/)); photonic *matmul* demos reach "near-electronic" precision on classification **[C]**, i.e. explicitly not bit-exact | **NO — same structural reason as analog** (interference/detection is continuous; precision is statistical) | **EXISTENTIAL CLASS**, but the market's own revealed preference (2020s photonic-compute startups pivoting to interconnect) says the frontier is not moving here soon |
| **Wafer-scale digital (Cerebras WSE-3/WSE-4)** | **[C]** WSE-3 has 16-way INT8 SIMD, dense PFLOP-class INT8 ([XPU.pub](https://xpu.pub/2024/03/18/cerebras-wse-3/)); appliance/cloud-gated | **YES** — digital integer datapath; needs the standard C-1 self-test (accumulator width unverified) | **ELIGIBLE in principle**; distribution-gated (same caveat as TPU/Trainium, roadmap §4.3) |
| **Structured sparsity (2:4 → higher ratios)** | **[C]** shipping since Ampere; ratios may grow **[S]** | Orthogonal to exactness — but the committed object is dense i.i.d. with ~9% zeros, so sparsity units get ≈nothing (cryptanalysis §3); if the frontier's *dense* throughput stagnates while sparse throughput races, the ladder flattens by the sparsity speedup | **Neutral to eligibility; a ladder-decoupling watch item** for the §3 monitor |
| **Hyperscaler custom silicon (TPU v8+, Trainium 4+, MTIA…)** | **[S]** direction: float/MX-only matmul engines continue (Trn2/3 precedent **[C]**) | **YES via Ozaki/BMX4** as long as engines are digital with documented-or-testable exact envelopes | **ELIGIBLE; cloud-gated** (decentralization cost, §2b/§2d, not an eligibility cost) |

### 1.2 The structural conclusion (why eligibility keeps holding)

Every *digital* MAC array — integer or float, any width — has an exact-integer envelope
by construction: a p-bit×p-bit significand product is exact, and bounded partial sums
below the accumulator's exact capacity are exact in any order under any rounding scheme
(the no-rounding theorem, exact-int-on-float doc §2). Vendors cannot remove this
property without removing digital arithmetic itself; they can only *narrow* it (threat
§2f). So the question "does the frontier keep an exact-integer-reducible path?" reduces
to "does the frontier stay digital?" — and every confirmed frontier roadmap through
2028 (Rubin/Rubin Ultra, Feynman **[S]** beyond 2028 — [Tom's Hardware roadmap](https://www.tomshardware.com/tech-industry/semiconductors/nvidia-enterprise-roadmap-rubin-rubin-ultra-feynman-and-silicon-photonics),
MI400/UDNA, TPU v7, Trn3) is a digital tensor machine. **[C]** for ≤2028; **[S]**
beyond.

Two independent tailwinds make the exact envelope *more* likely to stay documented and
fast, not less:

1. **The HPC industry now depends on the same trick.** Ozaki-scheme exact/high-precision
   GEMM on low-precision tensor cores is a growing vendor-promoted use case — FP64
   emulation on FP8/INT8 tensor cores ([arXiv:2508.00441](https://arxiv.org/abs/2508.00441),
   [Ozaki-II with FP8, arXiv:2603.10634](https://arxiv.org/pdf/2603.10634),
   [HPCwire survey](https://www.hpcwire.com/2025/04/17/have-you-heard-about-the-ozaki-scheme-you-will/)).
   A vendor that broke exact small-integer products on its tensor pipes would break its
   own HPC emulation story. The PoW free-rides on that constituency. **[C]** for the
   trend; **[S]** that it persists 10+ years.
2. **Microscaling standardized on power-of-two scales at the consortium level** — OCP MX
   E8M0 is powers of two by construction, backed by AMD/Arm/Intel/Meta/Microsoft/NVIDIA/
   Qualcomm ([OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf),
   [OCP announcement](https://www.opencompute.org/blog/amd-arm-intel-meta-microsoft-nvidia-and-qualcomm-standardize-next-generation-narrow-precision-data-formats-for-ai)).
   The industry's own interoperability layer is exactly the scale discipline the PoW
   requires. NVFP4's fractional scales are the vendor-proprietary exception, and even
   that hardware accepts 2^e scale values exactly (redesign §3.1).

### 1.3 Which future format is the biggest threat?

Ranked by (probability the frontier actually goes there) × (damage if it does):

1. **Analog in-memory compute displacing digital tensor engines at the datacenter
   frontier** — the only *shipping-today* substrate with NO exact-integer interpretation
   (EnCharge is real silicon, today at the client edge **[C]**). If, in the 2032–2040
   window, the marginal AI FLOP is analog, no committed-object version can follow it.
   Assessed likelihood over 15 years: **low-to-medium** (precision, programmability, and
   training requirements keep frontier training/serving digital in every current
   roadmap; analog wins edge inference first, where it does not threaten the ladder).
2. **Sub-3-bit dominance (ternary-weight frontier + popcount/LUT silicon)** — eligible
   but floor-forbidden; the PoW would deliberately decouple from the fastest pipe by a
   bounded k² rather than cross the BNN cliff. Damage is a flattened ladder, not a
   broken chain. Likelihood over 10 years: **low-medium** (BitNet remains unproven at
   frontier scale **[C]** as of 2026; the information-theoretic pressure against <2-bit
   *activations* is real).
3. **LNS/log-domain matmul** — ineligible accumulation, but zero commercial traction;
   **low**.
4. **Optical matmul** — ineligible, but the sector's own capital moved to interconnect;
   **low** on 10 years, re-examine at 15.

Everything else the frontier is confirmed to be doing (FP4/FP8 microscaling, finer
block scales, wafer-scale digital, custom hyperscaler silicon) is **eligible** — most
of it *more* natively than INT8 is today, via the BMX4-class encoding.

### 1.4 Fifteen-year eligibility statement

**[C→S]** Exact-integer matmul keeps tracking the frontier as long as the frontier is a
digital multiply-accumulate machine, and every confirmed product through ~2028 plus
every credible roadmap through ~2031 is one. Beyond that the statement is
probabilistic; the §3 monitor exists precisely because no committee in 2026 can pin
2035's silicon.

### 1.5 The honest failure scenario (stated plainly, as required)

The plausible 5–10-year failure is **not** a chain split and **not** a verifier break —
it is a *thesis* failure: NVIDIA (or a successor monoculture) ships a generation whose
marginal AI throughput lives in (a) an accumulator regime with a tiny proven-exact
envelope (t≈14-class everywhere, K′ collapse — the deepdive's 6–14× cliff), or (b) an
analog/optical co-processor doing the bulk MACs, while its digital pipes stagnate. The
PoW then rewards *legacy digital exactness*, not *AI compute*; difficulty keeps
integrating delivered work honestly, the chain keeps producing blocks, but "reward
scales with AI compute" quietly becomes "reward scales with a shrinking niche." The
mitigations are §2f (design the committed object inside the weakest plausible exact
envelope — BMX4's sub-2²⁴ discipline), §3 (detect the decoupling while it is one
generation old, not three), and the disclosure duty (never market the thesis beyond
what the monitor currently shows).

---

## 2. Long-term threat model

Ratings: **Likelihood** over ~10 years / **Impact** on (chain-fatal ▸ thesis-fatal ▸
degrading). "Chain-fatal" would break consensus or verification — note that **nothing
in this table is chain-fatal**: Freivalds soundness is information-theoretic and
format-blind (≤2/q per round, redesign §2), so every threat below attacks the *work*,
the *ladder*, or the *decentralization*, never the validity of accepted blocks.

| # | Threat | Likelihood | Impact | Net rating |
|---|---|---|---|---|
| a | Frontier moves to a format with NO exact-integer path (analog/optical/LNS) | Low (5 yr) → Low-Med (15 yr) | Thesis-fatal (chain survives on digital residue) | **The existential one — MEDIUM net, rising with horizon** |
| b | Hardware monoculture / single-vendor dominance / sanctioned-bloc split | High (already partial) | Degrading→thesis-risk (format dictation, supply gating) | **MEDIUM-HIGH** |
| c | Cryptanalytic break of matmul hardness (C-15 class) | Low (structural) / Med (constant-factor) | Degrading (difficulty miscalibration), NOT soundness | **MEDIUM** |
| d | Pool / mining centralization (incl. hyperscaler-gated frontier, mining-ASIC residual) | Medium | Degrading (censorship/51% surface) | **MEDIUM** |
| e | Availability/regulatory fragmentation (export controls splitting the miner base) | High (ongoing) | Degrading, partially self-hedging | **MEDIUM** |
| f | Accumulator-exactness narrowing the eligible hardware set | Medium | Degrading→thesis-risk (K′ tax growth, eligibility cliffs) | **MEDIUM-HIGH (nearest-term real risk)** |

### 2a. No-exact-path frontier (existential)

Covered in §1.3/§1.5. Rated **Low-Med × thesis-fatal**. Mitigations: (i) the §3 monitor
watches *exactness share of frontier throughput*, not just INT8-vs-FP4; (ii) the
committed object is versioned to always sit inside the *widest commodity exact
envelope* (BMX4 discipline: whole pipeline < 2²⁴ by bound); (iii) accepted residual: if
the frontier truly goes non-digital, the PoW anchors to the best digital tier — the
design should pre-commit (in disclosure, not consensus) to that honest narrowing rather
than chase an unverifiable substrate. A ZK-attested analog path is **not** a mitigation
on any current evidence: proving 10¹⁰ analog MACs is orders of magnitude past the §F.2
budget, and the analog result is not even well-defined bitwise.

### 2b. Monoculture / vendor dominance / bloc split

**Evidence [C]:** NVIDIA holds the overwhelming share of frontier AI compute; INT8 is
already being de-emphasized on its newest parts (B300 cut INT8 to fund NVFP4 — [Tom's
Hardware](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support));
NVFP4's fractional-scale semantics are a proprietary fork of the OCP discipline. A
monoculture vendor can, without malice, dictate the PoW's migration schedule (its
format choices decide which encodings are native) and, with malice or under pressure,
degrade it (undocumented accumulators — the Hopper t≈14 precedent [DeepSeek-V3,
arXiv:2412.19437 §3.3.2] was *discovered by a customer*, not disclosed).

The sanctioned-bloc split is the second face: US export controls now explicitly gate
which bloc gets which silicon (H20→H200 saga; 25% duty on China-bound H200s, Jan 2026;
extraterritorial application to Chinese firms abroad, Jun 2026 — [Tom's Hardware](https://www.tomshardware.com/tech-industry/semiconductors/nvidia-prepares-h200-shipments-to-china-as-chip-war-lines-blur),
[Al Jazeera](https://www.aljazeera.com/economy/2026/6/1/us-says-ban-on-ai-chip-shipments-applies-to-chinese-firms-outside-china),
[Brookings](https://www.brookings.edu/articles/ball-games-over-the-us-is-out-of-the-ai-chip-market-in-china/)).
A two-bloc hardware world (NVIDIA/AMD vs Ascend/domestic) risks two divergent format
trajectories.

**Mitigations (mostly already designed, must be kept funded):** the verifier is
vendor-neutral by construction — any silicon that reproduces the committed integers is
eligible, which makes the *chain* bloc-agnostic even when supply chains are not
(`btx-matmul-v4-china-accelerators.md` exists for exactly this reason; its
determinism-unknowns are self-testable, not political). Keep the open, buyable paths
first-class (AMD ROCm, Tenstorrent — roadmap A-1/TT-1); pin committed alphabets to
consortium-standard, GCD-across-vendors subsets (the BMX4 E2M1∩E4M3∩s8 discipline), never
to one vendor's proprietary semantics; require two independent vendor implementations
in the golden-vector set before any format version activates (§3.4 condition M4).
Residual honestly held: if one vendor is >~80% of eligible throughput, migration timing
is de facto hostage to its roadmap — a monitored, disclosed condition, not a solvable one.

### 2c. Cryptanalytic break of matmul hardness

Three distinct sub-risks, which must never be conflated:

1. **Soundness break — impossible by construction.** Freivalds error ≤ 2/q per round is
   Schwartz–Zippel over F_q, unconditional; no algorithmic advance forges a block with
   a wrong `Ĉ`. **[C]**
2. **Asymptotic matmul progress (ω).** State of the art is ω < 2.371339 ([SODA 2025 /
   arXiv:2404.16349](https://arxiv.org/abs/2404.16349); the 2024 laser-method advance
   [Quanta](https://www.quantamagazine.org/new-breakthrough-brings-matrix-multiplication-closer-to-ideal-20240307/)).
   These are galactic algorithms — astronomically large constants, irrelevant at
   n = 4096. Progress cadence (~0.0005/yr in the exponent) gives no plausible 15-year
   path to a practical sub-Strassen dense kernel at PoW sizes. **[C]** Practical
   bilinear-recursion gains (Strassen/AlphaTensor-class, and claimed
   practical-lower-complexity kernels, e.g. [FalconGEMM, arXiv:2605.06057](https://arxiv.org/pdf/2605.06057))
   are constant-factor, available to all miners, and difficulty-absorbed (§A.6 posture;
   cryptanalysis §3: ≤1 recursion level on the small-alphabet object).
3. **The real one: a marginal-unit shortcut (the C-15 "no known algorithm" risk).** The
   priced unit is `expand B + B·V + combine + digest` with template-fixed rank-m
   `M = U·A` and `V`. The claim "no sub-`n²m` evaluation of `M·Bᵢ·V` for dense
   pseudorandom Bᵢ" is **an assumption, not a theorem** (spec §C I1′, Appendix C-15).
   A break here does not forge blocks; it *underprices work* — the shortcut-holder
   mines at a discount until difficulty absorbs it, a centralizing windfall exactly as
   large and as long-lived as the shortcut is private. The small-alphabet review
   (cryptanalysis doc) closed every identified channel with ≥2 orders of margin, but
   the external adversarial review remains a **mainnet blocker** (ACTIVATION B4′) and
   its scope must be re-run at every format version (§3.4).

Rating: **Low (structural) / Medium (private constant-factor) × degrading.** Standing
mitigation: difficulty-vs-Epoch-envelope anomaly monitoring (§I.4.2 makes difficulty an
audit trail; a private shortcut shows up as unexplained difficulty growth), plus the
per-version external-review requirement.

### 2d. Pool / mining centralization

Channels: (i) hyperscaler-gated frontier substrates (TPU/Trainium are rentable from
exactly two firms — roadmap §4.3); (ii) the disclosed mining-only ASIC residual
(~1.5–2.5× realistic, ≤~4× worst case, 6–14× only under the t-cliff — deepdive §0),
which if realized concentrates block production in whoever taped out; (iii) ordinary
pool-protocol centralization. Mitigations already structural: Freivalds-verified shares
make pooling trustless and proportional (§O.2) — pool operators cannot fake or steal
work; the capacity-gate impossibility (§L.4) means no VRAM/bandwidth moat can exclude
consumer/retail participation; difficulty absorbs each commodity generation, capping
any ASIC's payback window; per-block memorylessness (I1/I1′ template granularity) keeps
rental bursts bounded (§I.4.2's one-time windfall arithmetic). Residuals honestly held:
nothing in-protocol prevents a 51% coalition of two hyperscalers plus a tape-out — the
defense is the same as Bitcoin's (economic, not cryptographic), *plus* the fact that
v4's hardware base is the general AI fleet, the least BTX-dependent capital stock any
PoW has ever had. Rating: **Medium × degrading.**

### 2e. Availability / regulatory fragmentation

**[C]** Already in motion (§2b citations): export controls, tariffs, bloc-specific
SKUs, and the plausible extension of controls to *compute rental*, not just chips.
Consequences for the PoW: the miner base fragments by jurisdiction; per-bloc hardware
efficiency diverges; a bloc-level ban on PoW mining (China 2021 precedent) can remove a
large miner population step-wise. Why it is only **Medium × degrading**: ASERT
re-equilibrates within hours (§I.4.2) with a bounded, symmetric emission transient; the
verifier's vendor-neutrality means excluded blocs can mine on domestic silicon that
passes the self-test (the chain does not care whose fab); and mining needs no *frontier*
part — the ladder rewards frontier parts more, but H100-class and consumer silicon
remain eligible for their proportional share, so no single regulator can exclude the
network's hardware class, only its own territory. Mitigation duties: keep ≥3
independent-jurisdiction backend targets in the golden-vector program; treat "share of
eligible TOPS manufactured under one export-control regime" as a published §N.3
monitoring metric (disclosure, never a consensus input — §0.7-(4)).

### 2f. Accumulator-exactness narrowing (the nearest-term real risk)

The established facts: nominal "FP32 accumulate" was already once discovered to be
t≈14 on shipping silicon (Hopper FP8 — [arXiv:2412.19437](https://arxiv.org/pdf/2412.19437));
TPU v4's "int8" MXU was FP32-mantissa-bounded (C-1's raison d'être); Blackwell TMEM
block-scaled accumulate exactness is **untested** (deepdive falsifiable prediction #1);
vendors have no AI-market incentive to document, guarantee, or keep exact envelopes wide
— AI training *tolerates* accumulation error, PoW consensus does not. The 15-year trend
risk: every generation shaves accumulator width/documentation a little; K′ shrinks; the
extract-and-promote tax grows; eventually whole device classes fall out of the eligible
set or pay a cliff tax (the deepdive's 6–14× scenario), and the miner population narrows
to whoever's silicon still proves t=24.

Rated **Medium × Medium-High** — the most *likely* of the serious threats, and the one
the program can actually engineer against:

- **Design rule (already adopted in the BMX4 candidate, keep forever):** size every
  committed pipeline stage below the *weakest plausible commodity exact envelope* —
  today 2²⁴ (FP32-mantissa class), re-assessed per version. Eligibility-by-bound beats
  eligibility-by-vendor-promise.
- **Boundary-vector discipline (C-1 generalized):** every backend proves its envelope
  empirically at qualification (partial sums at exactly 2^t; odd-step crossings); a
  datasheet is never a PASS. Regenerate the vectors at every format version — a vector
  set that never enters the new regime certifies nothing (redesign §3).
- **The t-question is a standing monitor input (§3.2-M2):** the first commodity
  generation whose *fastest* path cannot prove any usable exact envelope is the ARM
  signal for a format version (or, at the extreme, the §2a scenario beginning).
- **Tailwind:** the HPC Ozaki constituency (§1.2) pushes vendors the other way.

### 2g. (Noted for completeness) Quantum

Grover-class speedup on digest grinding halves effective security bits for *every*
hash-based PoW equally and is throttled by quantum clock rates; the consensus hash set
is already PQ-conservative (spec §R). Matmul itself has no known useful quantum
speedup at these sizes. Not a differentiating threat; no action beyond §R. **[C]**

---

## 3. The format-migration governance framework (the test-of-time engine)

### 3.0 Design goal

The frontier will move again — the whole of §1 says so. The engine that makes the PoW
survive is not any single format choice; it is a **standing mechanism** that (i) sees
the frontier move while the move is young, (ii) absorbs most moves with zero consensus
action, and (iii) when consensus action is genuinely needed, executes it as a
routinized, measurement-gated, supermajority-signaled version bump instead of a
contentious redesign. The enabling architecture is already built: **the verifier is
compute-path-agnostic** (spec §D.3), so the consensus surface of a format migration is
"new operands into the same machine" (redesign §6) — the machine itself never forks.

### 3.1 The three-layer model (what is FIXED, what VERSIONS, what is FREE)

| Layer | Contents | Change discipline |
|---|---|---|
| **L0 — FIXED FOREVER (the constitution)** | Verifier structure (`SketchFreivalds` algorithm and its O(n²) cost); `q = 2⁶¹−1`; R = 3; the **exact-integer commitment** (the committed object is always an exact integer matmul — no float/stochastic/analog sketch, ever); digest form `H(σ‖Ĉ)` and the Fiat–Shamir rule (challenges from `H(σ‖H(payload))`, σ nonce-fresh); the single-thread verify budget (<100 ms target / <1 s ceiling) that caps n; price-independence §0.7-(4); invariants I2, I3, I5, I6, I8 and the I7 residue; the §L.4 capacity-gate closure; the hardness floor (committed-alphabet min-entropy ≥ ~3.4 bits/element, ≥4 nonzero magnitudes, P(0) ≤ ~10%, power-of-two scales only, sign/ternary categorically rejected); §O.2 proportional pooling; the generalized C-1 rule ("no operation on the committed path may ever round") | Never. A proposal touching L0 is not a format migration — it is a different coin. This is what keeps migrations non-contentious: the parts people would fight over are non-negotiable in advance. |
| **L1 — VERSIONED (the operand encoding, `OperandFormat vN`)** | Mantissa alphabet 𝓜; block length L; scale set 𝓔/e_max/E_max; U/V derivation alphabet; XOF sampling rule + domain tags; limb-combine base and its bound (asymmetric-extreme discipline); n and b *within* the L0 verify budget; all golden/adversarial vectors; the one-time ASERT rescale `Num/Den` | Only via the §3.3 pipeline: trigger → candidate → measurement gates → external review → height + supermajority signaling. Each version is a hard fork with the full redesign-§6 migration surface, minus everything L0 (which is most of the machine). |
| **L2 — MINER-LOCAL (free, no governance)** | Compute path: INT8 IMMA vs FP8/FP4 Ozaki slices vs BMX4-native MMA; slice width/count, K′ block length, assumed t, limb-base variants, backend Kind, batching window Q | None needed — byte-identical committed objects are indistinguishable at every consensus surface. This layer absorbs *most* frontier motion (Trainium became mineable with zero consensus action via the Ozaki path). The verify+fallback dispatcher plus C-1-class self-tests keep L2 unable to split the chain by construction. |

The load-bearing property: **a frontier shift only requires L1 action when the L2 tax
it imposes is structural and large** (the width-ratio law's k² landing on the chips the
ladder wants to win). Everything smaller stays in L2 forever.

### 3.2 The standing monitoring signal (G-1 generalized → "G-2: the Frontier Exactness
Ratio")

Roadmap G-1 watched one ratio (dense INT8 vs dense FP4/FP8 TOPS per new datacenter
generation). Generalize it into a standing, published, two-component signal:

**M1 — FER (Frontier Exactness Ratio), the off-chain measured component.** For each new
datacenter-class generation g and the current committed format v:

```
FER(g, v) = max over L2 paths p [ measured marginal nonce/s on g via p ]
            ─────────────────────────────────────────────────────────────
            measured marginal nonce/s g would achieve if its FASTEST native
            low-precision pipe ran the committed object at tax 1 (k²=1)
```

i.e. "what fraction of the device's frontier throughput can the *current* committed
encoding actually harvest, using the best legal miner path." FER = 1 on a natively
matched format; FER ≈ 1/k² when only the Ozaki bridge exists; FER → small as the
frontier decouples. Measured, never inferred from peak TOPS (the instrument is the
pinned `contrib/matmul-v4/measure-hardware.sh` / `matmul-v4-report` JSON — the same
one-command harness as ACTIVATION B2g, extended per roadmap M-1), published quarterly
with timestamps exactly like the ρ disclosure (spec Appendix C-14 precedent). Publish
alongside it the **exactness-envelope register**: the proven t/K′ per commodity path
(§2f), because a K′ collapse is a FER collapse one generation early.

**M2 — the on-chain corroborator.** Consensus cannot observe hardware, but §I.4.1 makes
difficulty an *audit trail of delivered compute*: at ASERT's fixed point,
`D_eq ∝ TOPS_net/W_nonce`. So a persistent, multi-quarter divergence between the
chain's difficulty growth rate and the published AI-frontier compute-stock growth
envelope (Epoch-class, 3.4×/yr **[C]** as of the spec's citation), uncorrelated with
rental-market shocks, is an on-chain-observable *symptom* that the workload no longer
recruits frontier hardware. M2 can never fire an activation by itself (it is
confounded); it exists so that the community can verify from public chain data that M1
is being reported honestly — the same audit-trail philosophy as §S.4's monitoring, and
never a consensus input (§0.7-(4): the protocol *reads* neither M1 nor M2; humans do).

**Signal states (published with each quarterly report):**

- **GREEN** — FER ≥ ~0.5 on the newest datacenter generation.
- **WATCH** — FER < 0.5 on one generation, or any commodity fastest-path K′ collapse
  (t unprovable at any usable width). Action: fund/refresh the candidate next format
  (the shelf discipline — the redesign doc *is* this artifact for the current cycle).
- **ARM** — FER < ~0.25 across two consecutive datacenter generations **and** the
  measured (never peak) marginal nonce/s ordering has flattened or inverted against the
  design intent. Action: take the shelf candidate into the §3.3 pipeline (measurement
  gates + external review). ARM is roadmap G-1's original INT8-decoupling condition,
  generalized to any incumbent format.
- **FIRE** — ARM plus the candidate's own gates all green (§3.3). Action: set the
  height, run signaling, activate.

Thresholds 0.5/0.25 are governance defaults, not consensus constants — they may be
re-pinned by the same public process that publishes the reports, but only *before* an
episode, never retroactively during one.

### 3.3 The migration pipeline (activation discipline)

Inherited from the B5/B6 + G.1 precedent and the redesign's §6/§8 ledger; restated as
the standing rule for every `OperandFormat vN`:

1. **Shelf phase (during GREEN/WATCH):** the candidate format is fully specified,
   hardness-re-derived (redesign-doc-class analysis: entropy floor, ASIC residual
   re-disclosure, §L.4 re-check, accumulation bounds, C-1 vectors at the *new*
   boundaries), and CPU-reference-implemented — **before** it is needed. Cost is
   research-only; no consensus exposure.
2. **Measurement gates (ARM → FIRE):** the B2a–B2g analogues re-run on the new format
   on real silicon: cross-vendor golden vectors byte-identical on ≥2 independent
   vendors' hardware (M4 below); §K.2a-WT wall-time majority + §K.2b GO/NO-GO on
   frontier + consumer + legacy anchors; verify budget re-confirmed; marginal-unit
   nonce/s measured for the ASERT rescale. Peak-TOPS arguments are advisory only —
   two prior model-based claims were falsified; a migration must never be the third.
3. **External adversarial review (C-15 analogue) — a blocker every time.** Scope: the
   I1′ marginal-unit floor and batch-algebra channels *on the new alphabet* (the
   small-alphabet review showed why this is format-specific), plus the new format's
   boundary regimes. A format version without a fresh review is not activatable.
4. **Activation mechanics:** height-gated hard fork (`nMatMulV4xHeight`, G.1 pattern —
   no dual-algorithm grace period), height set with ≥2 release cycles of runway,
   **supermajority miner/version signaling as a readiness gate** (B5/B6: a flag-day
   with no adoption check risks a split — signaling converts "contentious fork" into
   "measured upgrade"); one-time ASERT rescale `Num/Den` from the *measured* marginal
   unit on the path rational miners actually run; pools/miners retooled against the
   published vectors before the height.
5. **Fallback rule (pre-committed):** if ARM fires but the candidate fails its gates,
   the honest fallback is the L2 bridge (Ozaki-class k² tax) plus difficulty absorbing
   it — a worse ladder, never a security regression (redesign §7.3). No gate-failed
   format may activate "because the frontier moved"; the frontier moving is the
   *trigger*, never the *evidence*.

**What makes this non-contentious, by construction:** (i) the fight-worthy layer (L0)
is constitutionally frozen, so a migration cannot smuggle in soundness, emission,
pooling, or price-coupling changes; (ii) the trigger is a published measured ratio with
pre-committed thresholds, not a faction's judgment call; (iii) the miner-only/consensus
classification table (roadmap §3.4, exact-int-on-float §5) removes ambiguity about what
even requires a fork; (iv) supermajority signaling means activation is an observed
fact about adoption, not a bet.

### 3.4 The cadence bound (how often migration may occur)

**Hard floor: at most one committed-object migration per two datacenter hardware
generations — in practice ≥ 4 years between activation heights** (hardware cadence
~2 yr **[C]** for NVIDIA's published rhythm), with these justifications, each
independently sufficient:

- **Security debt:** every migration re-opens the external-review surface (C-15-class),
  regenerates the entire golden-vector trust chain, and re-runs difficulty calibration
  — a fresh window for a private shortcut or a mis-set rescale. Reviews take ~6–12
  months; a cadence faster than the review pipeline means permanently unreviewed
  consensus surface.
- **Decentralization:** miner/pool/backend retooling amortizes over the version's
  lifetime. A fast cadence taxes small operators (who retool slowly) relative to
  hyperscale operators (who retool instantly) — i.e., frequent migration is itself a
  centralization vector.
- **Governance-capture surface:** each fork is a lobbying opportunity for a hardware
  faction (the format that is "native" wins the tax inversion). A rare, trigger-gated
  cadence with the ARM condition requiring *two consecutive generations* of measured
  decoupling makes single-generation vendor marketing (launch-slide TOPS) structurally
  unable to force a fork — the R-1 lesson (confirm on silicon, not slides) as
  governance.
- **Symmetry with the threat clock:** §1's threats move on multi-generation timescales;
  a 4-year minimum cadence tracks every eligible-format shift in §1.1 with at most one
  generation of bounded-k² lag, which the L2 bridge covers.

**The only exception class:** a determinism/chain-split defect (a consensus bug, not a
format preference) — handled as an emergency bugfix release under ordinary security
process, explicitly *outside* this framework. There is no soundness-emergency path
because soundness is L0-unconditional; no format event can create one.

**Version co-existence rule:** exactly one `OperandFormat` is live at any height (G.1
precedent: no dual-algorithm grace period). Multi-format acceptance windows are
rejected — they would fragment difficulty semantics (which format's marginal unit does
`nBits` price?) and hand the fastest format's miners a within-window monopoly.

### 3.5 Standing obligations ledger (who must keep doing what, forever)

| # | Obligation | Cadence | Anchor |
|---|---|---|---|
| M1 | FER + exactness-envelope (t/K′) measurement & publication, per new DC generation | Quarterly report; per-generation deep run | §3.2; instrument = `measure-hardware.sh` JSON |
| M2 | Difficulty-vs-compute-envelope audit note | Quarterly, from public chain data | §3.2, §I.4.1 |
| M3 | Shelf candidate freshness (next-format spec + hardness re-derivation + CPU reference) | Reviewed at every WATCH; ≤ 1 generation stale | §3.3-1; today's artifact = the BMX4 doc-set |
| M4 | ≥ 2 independent silicon vendors + ≥ 3 jurisdictions represented in the passing golden-vector set for the live format | Re-affirmed per release | §2b, §2e |
| M5 | C-1-class boundary vectors regenerated at every format version's own magnitude boundaries | Per version | §2f, redesign §3 |
| M6 | External adversarial review per format version (C-15 scope, extended to the new alphabet) | Per version — activation blocker | §3.3-3 |
| M7 | ASIC-residual + §A.6 + entropy-floor re-disclosure per version | Per version | redesign §8 |
| M8 | §N.3 anomaly monitoring: difficulty spikes vs rental troughs; nonce-rate vs declared hardware; export-control share metric | Continuous | §2c, §2e |

---

## 4. Verdict — can v4.2 withstand the test of time?

**Yes, with a clock and conditions — and the honest framing is that "the test of time"
is passed by the governance engine, not by any format.**

**5–8 years: HIGH confidence**, conditional on the *already-known* gates: B2g measured
GO/NO-GO on real silicon, B4′/C-15 external review, and (for the v4.2 object) the
redesign's §8 conditions including the t=24 silicon test. Basis: every shipped and
confirmed-roadmap frontier substrate through ~2031 is digital and exact-integer
reducible (§1.1, mostly **[C]**); the Ozaki bridge means even a total INT8 deprecation
tomorrow costs a bounded k², not eligibility; Freivalds soundness is unconditional; the
capacity-gate closure and the ASIC residual bound are format-robust; and the migration
machinery needed for the first version bump is specified and (per the companion docs)
shelf-ready.

**8–15 years: MEDIUM confidence, explicitly conditional** on: (i) the low-precision
frontier remaining digital (assessed likely but not certain — §1.3 rates the analog/
optical displacement Low-to-Medium over 15 years); (ii) commodity silicon retaining
provable exact accumulation envelopes (§2f — Medium risk, engineerable-around via the
sub-envelope design rule, with the HPC-Ozaki constituency as tailwind); (iii) the §3
framework actually being staffed and exercised — a monitor nobody runs and a shelf
candidate nobody refreshes silently converts every threat in §2 from "detected at one
generation old" to "discovered three generations late."

**The single biggest long-horizon risk:** the **exactness premium** — the compounding
divergence between what the AI industry optimizes (approximate throughput: narrow
undocumented accumulators, stochastic rounding, eventually analog/optical MACs) and the
one property this PoW can never trade away (bit-exact, no-rounding-ever arithmetic).
Its near-term face is §2f (accumulator narrowing; the deepdive's t≈14 cliff — the first
thing real silicon must be made to answer); its far face is §2a (a non-digital
frontier, thesis-fatal though never chain-fatal). It is the one risk no committed-object
version can engineer away, because it attacks the eligibility *test* itself rather than
any encoding — which is precisely why the framework's monitor (§3.2) is defined on
exactness share, and why the design must keep pre-committing, in public disclosure, to
the honest degraded mode: anchor to the best exact digital tier, absorb the tax in
difficulty, and never chase an unverifiable substrate.

**Confidence per major claim:**

| Claim | Confidence | Basis |
|---|---|---|
| All confirmed frontier silicon through ~2028–2031 is exact-integer reducible | **High [C]** | §1.1 census; every entry digital; Ozaki/BMX4 paths machine-checked at the CPU reference |
| Analog/optical does not take the datacenter matmul frontier within 10 yr | **Medium [S]** | Edge-first commercial pattern (EnCharge), photonic pivot to interconnect (Lightmatter), precision literature; explicitly a judgment, monitored not assumed |
| No practical cryptanalytic threat to the *work* at n = 4096 within 15 yr; soundness unconditional forever | **High (soundness) / Medium (marginal-unit floor)** | Schwartz–Zippel; ω-progress galactic; C-15 review still open — the Medium is exactly that open item |
| Accumulator-exactness narrowing is real and engineerable-around | **Medium-High** | Hopper t≈14 + TPU-v4 precedents [C]; sub-2²⁴ design rule is arithmetic; Blackwell TMEM t untested — the named falsifiable prediction |
| The migration framework prevents contentious forks | **Medium** | Mechanism design (frozen L0, measured trigger, signaling) + BTX's own B5/B6 precedent; ultimately a social claim — no mechanism *proves* humans won't fork |
| 4-year cadence floor is the right bound | **Medium** | Review-pipeline and retooling arithmetic (§3.4); a governance default, revisable in the open, never mid-episode |

---

## References

Repo (authoritative context): `btx-matmul-v4-design-spec.md` §0.7, §C, §D.3, §G.1,
§I.4, §K.2b, §L.4, §N.3, §O.2, §Q.21–22, §R, §S, Appendix C-1/C-13/C-14/C-15;
`ACTIVATION.md` B2a–B2g, B4′, B5, B6; `btx-matmul-v4-multiplatform-roadmap.md` (G-1,
O-1, R-1, M-1/M-2, §3.2–3.4, §4); `btx-matmul-v4-exact-int-on-float.md` (§2 no-rounding
theorem, §5 classification); `btx-matmul-v4-committed-object-redesign.md` (§2–§8);
`btx-matmul-v4-frontier-native-format.md` (width-ratio law, §4.6 boundary vectors);
`btx-matmul-v4-accumulator-eligibility.md` (C-1); `btx-matmul-v4-bmx4-asic-fpga-deepdive.md`
(§0 residual bound, §9 falsifiable predictions); `btx-matmul-v4-bmx4-shortcut-cryptanalysis.md`
(§0 verdict, §2.6 cliff, §7.3 conditions); `btx-matmul-v4-china-accelerators.md`.

External (forward-looking; [C]/[S] as tagged in-text):
[OCP MX v1.0](https://www.opencompute.org/documents/ocp-microscaling-formats-mx-v1-0-spec-final-pdf) ·
[OCP narrow-precision standardization](https://www.opencompute.org/blog/amd-arm-intel-meta-microsoft-nvidia-and-qualcomm-standardize-next-generation-narrow-precision-data-formats-for-ai) ·
[NVIDIA NVFP4](https://developer.nvidia.com/blog/introducing-nvfp4-for-efficient-and-accurate-low-precision-inference/) ·
[NVIDIA Rubin platform](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/) ·
[NVIDIA roadmap incl. Feynman (Tom's Hardware)](https://www.tomshardware.com/tech-industry/semiconductors/nvidia-enterprise-roadmap-rubin-rubin-ultra-feynman-and-silicon-photonics) ·
[B300 INT8 cut (Tom's Hardware)](https://www.tomshardware.com/pc-components/gpus/nvidia-shares-blackwell-ultras-secrets-nvfp4-boost-detailed-and-pcie-6-0-support) ·
[MXFP4 production deployment (Spheron)](https://www.spheron.network/blog/mxfp4-microscaling-quantization-gpu-cloud/) ·
[MX+ (MICRO '25)](https://dl.acm.org/doi/10.1145/3725843.3756118) ·
[AMXFP4 (arXiv:2411.09909)](https://arxiv.org/pdf/2411.09909) ·
[microsoft/BitNet](https://github.com/microsoft/BitNet) ·
[1-bit frontier status assessment](https://marklaursen.com/blog/1-bit-llms-could-make-gpus-obsolete) ·
[Posits & the quire (IEEE Spectrum)](https://spectrum.ieee.org/floating-point-numbers-posits-processor) ·
[Log-posit edge engine (arXiv:2503.01313)](https://arxiv.org/pdf/2503.01313) ·
[EnCharge EN100 (EE Times)](https://www.eetimes.com/encharge-picks-the-pc-for-its-first-analog-ai-chip/) ·
[Analog IMC precision limits (npj Unconv. Comp.)](https://www.nature.com/articles/s44335-025-00044-2) ·
[IBM AIMC LLM research (SemiEngineering)](https://semiengineering.com/llms-on-analog-in-memory-computing-based-hardware-ibm-research-eth-zurich/) ·
[Lightmatter × NVLink Fusion](https://lightmatter.co/press-release/lightmatter-joins-nvidia-nvlink-fusion/) ·
[Lightmatter Passage L200](https://lightmatter.co/press-release/lightmatter-announces-passage-l200-the-fastest-co-packaged-optics-for-ai/) ·
[Cerebras WSE-3 INT8 (XPU.pub)](https://xpu.pub/2024/03/18/cerebras-wse-3/) ·
[ω < 2.371339 (arXiv:2404.16349, SODA 2025)](https://arxiv.org/abs/2404.16349) ·
[Laser-method breakthrough (Quanta)](https://www.quantamagazine.org/new-breakthrough-brings-matrix-multiplication-closer-to-ideal-20240307/) ·
[FalconGEMM (arXiv:2605.06057)](https://arxiv.org/pdf/2605.06057) ·
[FP64-on-FP8 Ozaki-II (arXiv:2603.10634)](https://arxiv.org/pdf/2603.10634) ·
[FP64 emulation on FP8 tensor cores (arXiv:2508.00441)](https://arxiv.org/abs/2508.00441) ·
[Ozaki scheme survey (HPCwire)](https://www.hpcwire.com/2025/04/17/have-you-heard-about-the-ozaki-scheme-you-will/) ·
[DeepSeek-V3 t≈14 accumulation (arXiv:2412.19437)](https://arxiv.org/pdf/2412.19437) ·
[H200-to-China shipments (Tom's Hardware)](https://www.tomshardware.com/tech-industry/semiconductors/nvidia-prepares-h200-shipments-to-china-as-chip-war-lines-blur) ·
[Extraterritorial chip controls (Al Jazeera)](https://www.aljazeera.com/economy/2026/6/1/us-says-ban-on-ai-chip-shipments-applies-to-chinese-firms-outside-china) ·
[US exit from China AI-chip market (Brookings)](https://www.brookings.edu/articles/ball-games-over-the-us-is-out-of-the-ai-chip-market-in-china/) ·
[China AI chip deficit (CFR)](https://www.cfr.org/articles/chinas-ai-chip-deficit-why-huawei-cant-catch-nvidia-and-us-export-controls-should-remain) ·
[Epoch AI chip production](https://epoch.ai/data-insights/ai-chip-production).
