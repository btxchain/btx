# BTX MatMul v4.2-D — the compute-bound redesign (ENC-BMX4C-D)

Status: **DESIGN + CPU-reference landed; activation-disabled on every network
(mainnet + all public testnets at `nMatMulBMX4CDHeight = INT32_MAX`).** This is
a staged, parameter-frozen L1 encoding profile. Nothing here flips activation.

Author track: lead designer/implementer, worktree
`claude/matmul-v4-design-spec-af23sj`. Companion docs:
`btx-matmul-v4-design-spec.md` (§0.7, §E.3, §K.2, §L.4), `btx-matmul-v4.2-bmx4c-spec.md`
(L0/L1/L2 §7.1, M-t24), `btx-matmul-v4-frontier-native-format.md` (tax inversion,
width-ratio law), `btx-matmul-v4-committed-object-redesign.md` (full-C axis),
`btx-matmul-v4.2-audit-hardness.md` (F2 Strassen),
`btx-matmul-v4.2-external-audit-round2-remediation.md` (measured findings).

---

## 0. TL;DR

The mandate: make the PoW **genuinely tensor-COMPUTE-bound** (so absolute TOPS
win and datacenter throughput can lead), **functional across architectures** with
a vendor-agnostic consensus object and vendor paths as pure optimizations, and
realize the **emergent-throughput reward ladder** — all without touching L0 or
price-independence.

The honest ground truth (design-spec §L.4, verified against source): for a
**linear** commitment `Ĉ = U·C·V` with an **O(n²)** Freivalds verifier, the
miner's `(U·A)(B·V)` factoring shortcut and the verifier's cheap check are the
**same property** ("verifier-linearity collapse"). You cannot make the enforced
work strictly `Θ(n³)`-bound while keeping O(n²) integer-exact verification via
any linear-sketch trick. The **only** lever that moves both the enforced work
*and* the shortcut factor, while preserving O(n²) integer-exact verification, is
to **commit more of C** — grow the sketch rank `m = n/b` (shrink the tile `b`),
paying sketch payload `8·m²` for enforced tensor work.

**This document picks the concrete operating point `b = 2` (m = n/2 = 2048 at
n = 4096)** and specifies it as a clean, versioned L1 profile **ENC-BMX4C-D**.
It is byte-for-byte ENC-BMX4C on the operand encoding and the determinism/M-t24
axis; it changes exactly one L1 parameter (the tile) and the domain tags.

| quantity (n=4096) | ENC-BMX4C (b=4) | **ENC-BMX4C-D (b=2)** | change |
|---|---|---|---|
| sketch rank m = n/b | 1024 | **2048** | 2× |
| sketch = fraction of C committed | rank m²=n²/16 (16× compression) | **rank m²=n²/4 (4× compression)** | commits 4× more of C |
| enforced marginal tensor MACs `n²m + 16nm²` | 1.25 n³ | **4.5 n³** | **3.6×** |
| combine share of the marginal unit | ~80% | **~89%** | more tensor-dominant |
| `(U·A)(B·V)` shortcut speedup vs per-nonce full recompute | ~4.2× | **~2.3×** | halved |
| sketch payload `8·m²` | 8 MiB | **32 MiB** | 4× (needs relay ext.) |
| verifier | O(n²), ~0.1–0.28 s | **O(n²), ~+25%** | unchanged order |
| every accumulator / M-t24 bound | 2304n / 288n / 1024n | **identical (m-independent)** | none |

What is **proven/analytic**: the enforced-MAC counts, the payload sizes, the
shortcut-factor arithmetic, the byte-identity of the three miner schedules at the
D rank, and M-t24 preservation (all machine-checked in
`src/test/matmul_v4_bmx4d_tests.cpp`). What remains a **measurement-gated
hypothesis**: whether 3.6× more tensor-dominant enforced work + squarer shapes
actually flips the datacenter-vs-consumer ordering — that needs real DC silicon
(runbook §4; no accelerator exists in this environment). What is a **real,
disclosed cost**: the 32 MiB payload exceeds the 16 MiB P2P / 24 MiB block
ceiling and **requires the P1/P3 relay-extension** before it can activate.

We do **not** claim to beat the L1 theorem. We move as far along the only
available axis as the transport budget allows, and we are explicit about the
residual.

---

## 1. The L1 tension, stated plainly

### 1.1 The theorem (design-spec §L.4, lemma L1)

> **L1 — verifier-linearity collapse.** Anything the verifier can evaluate in
> O(n²) … or any succinct *linear* structure … composes with the linear
> commitment/Freivalds check into an O(n²m) miner evaluation, forcing no
> materialization and no residency. Conversely, any *nonlinear, incompressible*
> derivation that defeats the miner's shortcut also defeats the verifier's: to
> run `A·(B·r)` the verifier must materialize A's n² entries, so if each costs
> more than O(1) the budget dies.

Consequences (all in the design docs, all verified):

- The current sketch `Ĉ = U·C·V` (b=4, m=1024) enforces a marginal per-nonce
  unit of `n²m` (form `B·V`) `+ 16·n·m²` (the C-13 limb-tensor combine) ≈
  **1.25 n³** int-MACs; the optimal miner never forms the full `n³` product C.
- **(a)** Any operand structure the O(n²) verifier can evaluate → the miner
  shares the same shortcut (collapse). **(b)** Any nonlinearity that blocks the
  miner → forces the verifier to O(n³) (self-defeating; blows the <100 ms /
  <1 s budget). **(b′)** A non-linear function of C that blocks factoring ALSO
  forces O(n³). **(c)** "One big dense combine GEMM" is Strassen/LCMA-reducible
  at exactly m=1024, n=4096 (audit F2). **(d)** Linear chains re-factor;
  nonlinear chains are self-defeating. **(e)** Reverting the I1′ amortization
  doubles enforced marginal work and restores memorylessness but does not close
  the structural shortcut.
- The only escape the spec itself names that preserves O(n²) integer-exact
  verification is **commit more of C** (larger m, up to full-C, 64 MiB), or a ZK
  proof of full evaluation (out of scope; ZK residency proofs take ≈ a block
  interval each, six orders short).

### 1.2 Why "commit more of C" is the one knob that moves both

The miner's cheapest schedule is `cost_factored = 2n²m + m²n`; forming C then
sketching costs `n³ + n²m + m²n`. Factored is cheaper by exactly `n²(n − m)`.
So:

- As `m → n`, the factored advantage `n²(n−m) → 0`: the shortcut **vanishes**
  (both paths cost ~3n³). The linear commitment can never drive the shortcut
  factor below 1 while the verifier stays O(n²) — but growing m walks it toward
  1 monotonically.
- Simultaneously, the enforced marginal tensor work `n²m + 16nm²` grows
  (dominated by the **quadratic-in-m** limb-combine term `16nm²`), and the GEMM
  shapes get **squarer** (m=2048, n=4096 vs the skinny m=1024), directly
  attacking the measured ~25% utilization ceiling.

The cost is **payload `8m²`** and a proportional rise in the O(m²) verify terms
and the payload SHA. That is the entire tradeoff. There is no free lunch here and
we do not pretend otherwise.

### 1.3 The measured problem this fixes (round-2 external review)

On real silicon (RTX 5090 / H100 / B200), at n=4096/8192 with the wide XOF and
C-13 combine: on-device tensor utilization tops out **~25% of INT8 peak**; the
combine is **bandwidth/launch-bound (~60–70% of wall-time)** and operand-gen is
**SHA/memory-bound (~13–26%)**, both favouring high-clock consumer parts; a
**consumer 5090 beats an H100 ~2–2.5×/card (~11×/rental-dollar)**. Verdict:
*"the datacenter-favouring goal is not delivered by the current sketch
construction."* Growing m attacks all three: bigger, squarer tensor GEMMs (raise
utilization), a combine that grows quadratically in m (raise the tensor:non-tensor
ratio in absolute terms), and less shortcut headroom for a fast-clock part to
skip work.

---

## 2. The chosen construction: ENC-BMX4C-D

**One parameter changes: the sketch tile `b`, 4 → 2, so `m = n/b` doubles.**
Everything else is ENC-BMX4C, unchanged and byte-identical:

- Mantissa alphabet `M11 = {0, ±1, ±2, ±3, ±4, ±6}` (exact-integer E2M1 subset).
- E8M0 power-of-two block scales, block length L = 32, S = 3, `E_max = 6·2³ = 48`.
- Scale-free M11 projectors U (m×n), V (n×m).
- Wide counter-mode SHA-256 XOF, mantissa/scale plane domain bytes.
- Base-2⁶ remainder-top limb combine (4 balanced digits, 16 limb-pair GEMMs).
- Soundness field `q = 2⁶¹−1`, `R = 3`, digest `H(σ‖Ĉ)`, Fiat-Shamir rule.
- Every magnitude/accumulator bound: `|C| ≤ 2304·n`, `|P|,|Q| ≤ 288·n`,
  `|S_ij| ≤ 1024·n` — **all m-independent** (see §4).

The only other change is **domain separation**: distinct V4.2-D tags
(`BTX_MATMUL_SEED_V42D`, `BTX_MATMUL_V42D_SKETCH_U/V`) so a seed can never
produce correlated C-profile / D-profile operand streams; the two profiles are
cryptographically independent objects.

**L-layer accounting (per bmx4c-spec §7.1):**
- **L0 (never changes):** the SketchFreivalds verifier structure and its O(n²)
  cost, q=2⁶¹−1, R=3, exact-integer commitment, digest form, Fiat-Shamir,
  C-1′ ("no committed-path op may ever round"), price-independence §0.7-(4),
  the single-thread verify budget that caps n. **ENC-BMX4C-D touches none of
  these.**
- **L1 (versioned — this profile):** §7.1 lists *"n and b within the L0 verify
  budget"* as L1. ENC-BMX4C-D re-versions **b (4→2)** and the domain tags, and
  regenerates golden vectors. This is the exact surface the redesign doc's §6
  "does NOT migrate" line (`sketch shape m=n/b … 8 MiB payload`) reserved — we
  are deliberately reopening it, and paying for it with payload (§6 here).
- **L2 (miner-local):** INT8 vs native FP4 vs Ozaki slices, K′, promotion
  cadence, backend Kind, batch window Q, Strassen/LCMA schedule for the combine
  — all byte-identical committed objects, no governance.

### 2.1 Why b=2 and not b=1 (full-C)

`n = 4096` has power-of-two divisors only, so the sketch options above b=4 are
b=2 (m=2048, 32 MiB) and b=1 (m=4096, `8·n² = 128 MiB` — worse than shipping C
raw at `4n² = 64 MiB`). The full-C endpoint (b=1 / raw C) is where the shortcut
factor is smallest (~1.5×) but its 64–128 MiB payload is far outside any
plausible near-term transport budget. **b=2 (32 MiB) is the maximal move along
the axis that a bounded relay extension can carry**, delivering 3.6× the enforced
tensor work and halving the shortcut factor. It is the recommended operating
point; b=1/full-C is documented as the theoretical endpoint gated on a larger
transport redesign, not adopted here.

If `n` is ever retargeted (e.g. to 8192), `b` retargets to **hold m = 2048**
(b=4 at n=8192), mirroring the ENC-BMX4C "hold m=1024" discipline, so the payload
stays 32 MiB across the dimension window.

---

## 3. Quantified tradeoff

All numbers at n = 4096, per nonce, marginal (B nonce-fresh; A/U/V
template-scoped under I1′, so `P = U·A` amortizes across the nonce sweep and the
batched miner fuses the window's combines into one big dense GEMM).

**Enforced tensor MACs** `= n²m + 16·n·m²` (form `B·V` + the 16 base-2⁶
limb-pair GEMMs of the combine):

| b | m | `n²m` (B·V) | `16nm²` (combine) | total | combine share |
|---|---|---|---|---|---|
| 4 | 1024 | n³/4 | n³ | **1.25 n³** | 80% |
| **2** | **2048** | n³/2 | 4 n³ | **4.5 n³** | **89%** |
| 1 | 4096 | n³ | 16 n³ | 17 n³ | 94% |

The combine term is **quadratic in m**, so it dominates and grows fast; that is
precisely the tensor-resident work we want to enlarge. (These are s8-MAC counts on
the limb path — the width tax of representing int32 P/Q as 4 base-2⁶ digits — and
they are cheap, high-rate tensor ops, which is the point.)

**Shortcut factor** = (per-nonce full recompute)/(enforced factored):

| b | full recompute `n³ + n²m + m²n` | enforced factored `n²m + m²n` (P=U·A amortized) | speedup |
|---|---|---|---|
| 4 | 1.31 n³ | 0.31 n³ | **4.2×** |
| **2** | 1.75 n³ | 0.75 n³ | **2.3×** |
| 1 | 3 n³ | 2 n³ | 1.5× |

**Payload / verify:**
- Sketch payload `8·m²`: **8 MiB → 32 MiB** (4×). Digest is SHA-256 over the
  payload (grows 4×, still negligible vs a GEMM).
- Verifier stays **O(n²)**: dominated by the two dense n² matvecs
  `A·(B·(V·y))`; the O(m²) left side `xᵀĈy` and the O(nm) projections grow with
  m (m²: 1M→4M per round; nm: n·1024→n·2048) but stay sub-dominant. Estimated
  **~+25% verify** (still well under a second at n=4096, ~0.1–0.28 s baseline).
- Freivalds soundness unchanged: per-round ≤ 2/q, `R=3` → ≤ 2⁻¹⁸⁰ (the larger m
  does not change the degree-2 Schwartz-Zippel bound).

**Effect on the `(U·A)(B·V)` shortcut:** the factoring still *exists* (b=2 is not
full-C), but its advantage over a per-nonce full recompute is halved (4.2×→2.3×)
and, crucially, the enforced work it cannot avoid — the committed m×m object — is
3.6× larger and 89% tensor. The miner's only remaining freedom is the *schedule*
(L2), not the *object*.

---

## 4. Determinism / M-t24 preservation (the clean property)

The single cleanest fact about this redesign: **growing m touches no
accumulator bound**, so M-t24 determinism is byte-for-byte identical to
ENC-BMX4C.

- Base product `|C̄| ≤ E_max²·n = 2304·n` (< 2²⁴ at n=4096; the F-L1 note's
  n=8192 caveat applies to a *direct-C FP-native* evaluation only — ENC-BMX4C-D
  never forms C̄ on the committed path, it factors).
- Projections `|P|,|Q| ≤ 6·E_max·n = 288·n` (< 2²¹ at n=4096).
- Limb-pair GEMM `|S_ij| ≤ 32²·n = 1024·n` (2²² at n=4096, 2²³ at n=8192).

**None of these contains m.** The sketch rank enters only the *output* dimension
(m×m) and the payload, never a contraction length or a per-MAC magnitude. So the
§5.3 t-discrimination / boundary-pin vectors, the odd-target near-2²⁴ probe, and
the whole native-vs-INT8 admissibility classification are **inherited verbatim**.
This is pinned mechanically in `d_profile_accumulator_bounds_are_m_independent`.

Consequence for the frontier tax-inversion (width-ratio law `k²=⌈W_obj/w⌉²`):
because the operand encoding is unchanged, the D profile keeps `E_max=48 ≤ 127`,
so **INT8 hardware still runs the object as one s8 GEMM (k²=1) on pre-shifted
operands, and frontier FP4 runs it as one block-scaled FP4 GEMM (k²=1)** — the
tax inversion is preserved. Growing m enlarges *both* those GEMMs equally; it
does not re-introduce a width tax.

---

## 5. The reshaped combine and Strassen-aware calibration

### 5.1 Landing the combine on tensor units (C-13 limb path)

The consensus combine is `Ĉ = P·Q mod q` (`ComputeCombineModQ`). The
tensor-landing form is the **C-13 base-2⁶ limb-tensor combine**
(`ComputeCombineLimbTensorBMX4C`, byte-identical, pinned by
`d_profile_all_schedules_are_byte_identical`): decompose each exact-int32 P/Q
entry into 4 balanced base-2⁶ digits (remainder-top), run the **16 limb-pair
m×m×n s8→s32 GEMMs** on native IMMA/MFMA/TensorOps, then one O(m²) shifted mod-q
fold `Ĉ = Σᵢⱼ 2^{6(i+j)}·S_ij mod q`. Under §K.2b batching the 16 GEMMs take the
stacked **m × Q·m × n** shape — one big dense GEMM per limb pair. At b=2 that
fused GEMM is `2048 × 32768 × 4096` (Q=32) per limb pair: exactly the fat,
tensor-saturating shape the DC-ordering goal wants, and 4× the m=1024 area.

This is why we **keep I1′** (A/U/V template-scoped): it enables the cross-nonce
combine fusion that keeps the device busy. Reverting I1′ (lever (e)) would double
enforced work and restore memorylessness but kill the fusion that helps DC
utilization — a worse trade for the compute-bound goal. We keep I1′ and buy
enforced work with m instead.

### 5.2 Strassen-aware difficulty calibration (audit F2 — REQUIRED)

Growing m makes the combine a **larger square-ish GEMM** (m×m output, contraction
n), which is **more** Strassen/LCMA-reducible, not less (FalconGEMM surpasses
vendor GEMM by up to 17.85% at n≥1024 — exactly this regime). The honest
consequences:

- The `nMatMulBMX4CDAsertRescale{Num,Den}` one-time difficulty rescale **MUST be
  calibrated against a measured LCMA/Strassen-accelerated combine cost**, not the
  schoolbook `16·n·m²` count. Otherwise the enforced work is overpriced and
  whoever runs the LCMA is underpriced. This is codified as an activation gate
  in `params.h` and mirrors audit F2 §3.4.
- Strassen/LCMA is **non-uniform across the ladder** (FP4-frontier parts get
  d=0 levels, wider-datapath/bespoke parts get d≥1), which slightly **flattens**
  the very ladder we engineer. We disclose this: the D profile does not claim a
  Strassen-free combine; it claims a *larger, calibrated* combine whose residual
  advantage is bounded by the tensor:wide-ALU throughput ratio and priced by a
  Strassen-aware ASERT rescale.
- The bespoke-ASIC residual widens (redesign §4.3 estimates ~2–3× worst case for
  the narrower committed object family); growing m does not change the alphabet,
  so this is inherited from ENC-BMX4C, not amplified by the tile change.

---

## 6. Payload / relay honesty (P1/P3) — the real cost

The 32 MiB sketch payload is the price of the enforced work, and it is a genuine
transport problem, disclosed here in full:

- **P1:** a 32 MiB sketch → a block well past the **16 MiB P2P message limit** and
  the **24 MiB consensus block ceiling**. ENC-BMX4C already sits at 8 MiB (24 MB
  block > 16 MB P2P is an OPEN item even there); ENC-BMX4C-D makes it
  unavoidable. **Activation is BLOCKED on a relay extension**: either a consensus
  reduction to a negotiated transport ceiling, or an extended block-transfer /
  authenticated proof sidecar with request/retry/fallback semantics.
- **P3:** compact-block relay cannot carry the mandatory proof; a 32 MiB proof
  needs a proof-aware compact-relay extension with full-network propagation
  measurement. This is a prerequisite, not a nicety.
- **P2 (storage):** proofs are 4× larger (~8 MiB → 32 MiB each), so the
  disclosed ~2.9 TiB/yr of C-profile proof data becomes ~11.6 TiB/yr. This
  makes **proof-aware pruning** (`nMatMulProofPruneDepth`, currently
  NON-FUNCTIONAL/RESERVED) a hard prerequisite, not a reserved field.

Recommended relay plan (sketch, for the follow-up track): ship the header +
digest on the normal path; carry the 32 MiB sketch as an **authenticated sidecar**
keyed by the digest, fetched on demand with retry/fallback to full-block, and
**pruned below a rolling depth** once buried. None of this is implemented here;
it is the named precondition that keeps `nMatMulBMX4CDHeight = INT32_MAX` until
built and measured.

**This is the intellectually honest core of the deliverable:** there is a real
payload/verification tradeoff; b=2 is the recommended operating point because it
is the largest enforced-work gain a bounded relay extension can carry; and the
relay extension is a hard, disclosed prerequisite.

---

## 7. The vendor-agnostic native path

### 7.1 The problem being fixed

Today the only library-locked path is the CUDA native MXFP4 GEMM
(`RunMxf4Gemm`): a single `cublasLtMatmulAlgoGetHeuristic` with
`CUDA_R_4F_E2M1` + `CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0`. cuBLASLt returns
**zero algorithms** for this on every tested NVIDIA card/toolkit (5090, B200;
12.8/13.0/13.5), so the native tier silently drops to INT8 everywhere — the
committed object is vendor-neutral (OCP-MX E2M1/E8M0) but its *fast execution*
exists only as cuBLASLt enums. Yet the raw
`mma.sync.aligned.kind::mxf8f6f4.block_scale…e2m1.e2m1.f32.ue8m0` instruction
**works on a 5090** (compiles with `compute_120a`) and passes M-t24 — the
hardware is capable, only the *library* refuses.

### 7.2 The portable contract (consensus object = OCP-MX, execution = anyone's)

The consensus object is **already vendor-neutral**: byte-identical to the CPU
reference (`ComputeDigestBMX4D` / `VerifySketchBMX4D`), built from shared
primitives (`ExpandOperandA/B`, `ExpandProjectorBMX4C`, `ComputeProjectedLeft/
Right`, `ComputeCombineModQ`/`ComputeCombineLimbTensorBMX4C`, `SerializeSketch`,
`ComputeSketchDigest`). The backend contract is the 3 fixed signatures per vendor
namespace, weak-stubbed, and the dispatcher **re-verifies every device digest**
via `VerifySketch*` and falls back to CPU on any mismatch — a wrong device digest
can never win a block, only lose throughput.

The portable **block-scaled MX-FP4 GEMM contract** every backend implements as a
pure L2 optimization:

```
Inputs (all host-derived, byte-exact vs CPU reference):
  E2M1 mantissa planes (2 nibbles/byte) for the P=U·A and B·V operands,
  E8M0 per-32-block exponents (unit 0x7F where the object is scale-free),
  logical (M, N, K) with K = n the contraction dim.
Output: exact int32 (M×N), then folded into the base-2⁶ limb accumulator.
Contract: the accumulation MUST be a TRUE ≥32-bit integer accumulator
  (or an FP-mantissa accumulator PROVEN t≥24 by M-t24); NEVER fast-accum.
  The kernel is byte-identical to the CPU reference or it is not used.
Fallback: the hand-written INT8 s8→s32 path (1 GEMM on pre-shifted operands,
  E_max=48≤127), available on every IMMA/MFMA/TensorOps device.
```

The native path is realized as **hand-written kernels, NEVER a library
dependency**:
- **CUDA:** a hand-written `mma.sync…mxf8f6f4…e2m1.e2m1.f32.ue8m0` kernel behind
  the existing tier-select (`compute_120a`), reachable without cuBLASLt. See §7.3.
- **CDNA:** MFMA `f8f6f4` block-scaled path (contract stub consistent with the
  CUDA kernel; qualification via the same M-t24 vectors).
- **Metal:** Apple has **no FP4 tensor unit**, so the "native" tier on Metal is
  the **hand-written INT8 TensorOps s8→s32 path** (M5-class Metal 4), which is
  the universal fallback anyway — the contract degrades gracefully.

Everywhere the fallback is the hand-written INT8 path, so **the object is
functional across architectures** even where no FP4 unit exists.

### 7.3 The DEVICE_HIGH_MAGNITUDE_PASS marker (G1)

`verify-backend.sh` requires a `DEVICE_HIGH_MAGNITUDE_PASS:<backend>:<device-id>`
marker that no backend emits (G1 OPEN). The contract: a backend emits this marker
**only after** the device reproduces the M-t24 / high-magnitude golden vectors
bit-for-bit against the CPU oracle (odd-target near-2²⁴ probe + the mixed-value
packing/layout cross-check), with device/driver/algorithm identity and a
no-CPU-fallback attestation. This document specifies the emit point as the
success tail of the per-device qualification (`RunMxf4Qualification` for the
native tier; the INT8 self-test for the fallback tier), keyed by the physical PCI
id (`DevicePhysicalKey`). See the CUDA implementation notes in
`src/cuda/matmul_v4_bmx4_accel.cu` for the concrete emit site.

---

## 8. What is proven vs hypothesis vs measurement-gated

**Proven / analytic (machine-checked in `matmul_v4_bmx4d_tests.cpp`):**
- D payload = 4× C payload; enforced marginal tensor MACs strictly > 3× C.
- The three miner schedules (factored / full-C / limb-tensor) are byte-identical
  at the D rank — the shortcut-closure invariant.
- M-t24 accumulator bounds are m-independent (determinism preserved).
- Honest proof verifies; perturbed-but-digest-consistent proof fails Freivalds;
  0-rounds fails closed; D digest ≠ C digest (profile independence).
- The construction touches no L0 invariant (verified by inspection: q, R,
  verifier structure, digest form, C-1′, price-independence all untouched).

**Hypothesis (the central open question):** that 3.6× more tensor-dominant
enforced work + squarer shapes flips the datacenter-vs-consumer ordering. The
round-2 review measured the *C* profile consumer-favouring; whether *D* flips it
is a utilization question that **only real DC silicon can answer**. We do NOT
assert datacenter ordering as fact — it is a measurement-gated hypothesis, per
the mandate.

**Measurement-gated (needs real hardware; none in this environment):**
- M-t24 PASS/FAIL on Blackwell TMEM / MI355X / Apple M5 (native FP4 vs INT8
  fallback classification).
- The combine's tensor-stage majority on a real instruction mix (modeled
  ~70–80%; could come in a minority and flip GO/NO-GO).
- The Strassen/LCMA-aware ASERT rescale ratio (must be measured, not modeled).
- Full-network propagation of a 32 MiB proof under the relay extension.

**Residual risks (disclosed):**
- The linear commitment can never make the shortcut factor exactly 1 at any
  transport-feasible m; b=2 halves it, does not eliminate it.
- Growing m amplifies the Strassen concern and slightly flattens the ladder.
- The 32 MiB payload is a hard transport/storage cost; activation is blocked on
  P1/P3/P2.

---

## 9. Files changed (this worktree)

- `src/matmul/matmul_v4_bmx4.h` / `.cpp` — the ENC-BMX4C-D CPU reference
  (`kTileBMX4D`, V4.2-D tags, `DeriveOperandSeedBMX4D`,
  `DeriveProjectorSeedsBMX4D`, `ValidateDimsBMX4D`, `ComputeDigestBMX4D`,
  `VerifySketchBMX4D`), reusing every ENC-BMX4C encoding primitive unchanged.
- `src/consensus/params.h` — `MatMulEncodingProfile::ENC_BMX4CD`,
  `nMatMulBMX4CDHeight` (+ ASERT rescale), `IsBMX4CDActive`, and the
  `GetMatMulEncodingProfile` ladder ENC_S8 → ENC_BMX4C → ENC_BMX4CD.
- `src/pow.cpp` — verify dispatch (`VerifySketchBMX4D`) and a CPU-reference solve
  loop (`SolveMatMulV4BMX4D`), gated by the profile selector (dead at runtime
  while disabled).
- `src/kernel/chainparams.cpp` — construction invariant for the D height (must
  succeed C; positive ASERT ratio).
- `src/test/matmul_v4_bmx4d_tests.cpp` (+ CMake) — the invariant suite above.
- `src/cuda/matmul_v4_bmx4_accel.cu` — hand-written native MXFP4 path +
  DEVICE_HIGH_MAGNITUDE_PASS marker (see the CUDA notes; compile-guarded,
  verifiable only on a real toolchain).

Everything stays activation-disabled (`nMatMulBMX4CDHeight = INT32_MAX` on every
network). No price/market input anywhere. The datacenter ordering is framed as a
measurement-gated hypothesis, not a fact.
