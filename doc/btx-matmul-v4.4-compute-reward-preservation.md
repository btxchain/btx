# BTX MatMul v4.4 — ENC-SC and the Preservation of the Compute→Reward Curve

*Status: v4.4 RELEASE-CANDIDATE DESIGN MEMO (constructive synthesis; nothing in
this branch is deployed; every change herein activates at ONE height,
`nMatMulSCHeight`, default `INT32_MAX` = inert). Successor-synthesis of
`doc/btx-matmul-deterministic-nextgen-design.md` (the ENC-SC committed object)
with the v4.1/v4.2 economics program
(`btx-matmul-v4-design-spec.md` §I.4/§K.2b/§L,
`btx-matmul-v4.2-consolidated-design.md` §6,
`btx-matmul-v4.2-asert-calibration.md`,
`btx-matmul-v4.2-longevity-threat-model.md`,
`btx-matmul-v4.2-solver-evolution-design.md`,
`btx-matmul-compute-vs-data-decoupling-research.md`).
ENC-SC's cryptographic soundness (round-by-round soundness of the combined
sum-check + Circle-FRI protocol over F_{2⁶¹−1}, and the §2.4 grinding-immunity
argument) is under SEPARATE adversarial review; every claim below that begins
"provided ENC-SC is sound" depends on that review closing positively (§6).
Written 2026-07-18.*

---

## 0. One-line thesis

The property the prior work finally achieved — **progressively more block
rewards flow to progressively more powerful AI GEMM compute** — is carried by
four mechanisms (uniform difficulty on the digest lottery; the GEMM-dominant
work shape; ASERT as a price-free integrator of delivered compute; and
measurement-gated shape retargets), **none of which lives in the bytes ENC-SC
deletes**. ENC-SC changes only the digest *preimage* (`H(σ‖Ĉ)` →
`H(σ‖R_LDE)`) and the verifier, replacing the Θ(m²) relayed sketch
(8–32 MiB/block, 2.67–10.7 TiB/yr) with a 64–200 KB prunable proof and an
O(headers) archive — and in doing so it converts `m`, the primary AI-compute
knob, from a storage-priced knob into a **storage-free** one. The
compute→reward curve is preserved at activation (one ASERT rescale absorbs the
measured +≈1.4× per-nonce SHA floor) and **improved over time** (the m-ladder
that the D profile paid 4× storage for now costs +~10–20 KB of proof per
m-doubling). The single quantified risk to the frontier-GEMM thesis — the
hash-floor share of per-nonce wall time — is bounded, tunable (rate ρ, leaf
width), measurement-gated per the twice-burned §K.2b rule, and backstopped by
the zero-overhead digest-only recompute fallback.

---

## 1. What, exactly, delivered "progressive rewards to progressive compute" in the prior work

First, the negative statement, because it is consensus-critical: **there is no
reward tiering anywhere in BTX.** The subsidy is flat Bitcoin-style
(`GetBlockSubsidy` = 20 BTX halving every 525k blocks;
`src/consensus/params.h:517-519`; spec §11.4), and price-independence
(§0.7-(4)) *forbids* any tiered payout. As the round-3 audit remediation puts
it verbatim: *"The 'reward ladder' is an **emergent** property of throughput
under one uniform difficulty (there is no reward tiering)"*
(`btx-matmul-v4.2-external-audit-round3-remediation.md:48-52`). The
"progressive reward" property is therefore the composition of four concrete
mechanisms:

### M1 — The digest lottery: block wins ∝ nonce throughput

The only way to win a block is `matmul_digest = H(σ‖Ĉ) ≤ target(nBits)`
(`ComputeSketchDigest`, `src/matmul/matmul_v4.h:249-252`; target check in
`CheckMatMulV4SketchVerifies`, `src/pow.cpp:3543-3620`, final compare at
`:3617-3618`). σ = SHA256d(full header) binds `nNonce64`
(`DeriveSigma`, `matmul_v4.h:89-93`), so each lottery draw costs one full
per-nonce work unit **W = 4n²m + 2nm² ≈ 7.73×10¹⁰ MACs** at the mainnet point
n = 4096, b = 4, m = 1024 (spec §I.4; decoupling memo §1.1). Uniform target ⇒
a device class g with marginal nonce rate ν_g wins blocks in expectation at
share ν_g/ν_net. With 40 blocks/hr × 20 BTX = 800 BTX/hr, each class earns
`(BTX/hr)_g = 800·T_g/TOPS_net` — the **work-unit-neutrality theorem** (spec
§L.2.1): scaling the per-nonce work by any constant c rescales every ν by 1/c,
ASERT re-targets, and each class's *share* is unchanged. More AI FLOPs ⇒
proportionally more expected blocks, at every price, with price read nowhere.

### M2 — The work shape: making "nonce throughput" mean "frontier GEMM throughput"

M1 alone would reward whatever the bottleneck resource is. The prior work spent
three design generations forcing that resource to be **dense
exact-integer tensor GEMM at datacenter-favoring arithmetic intensity**:

- **b = 4, m = n/b = 1024** (`matmul::v4::kTileB`, `src/matmul/matmul_v4.h:61`;
  `nMatMulV4TranscriptBlockSize`, `src/consensus/params.h:385-392`): the v4.1
  batched-sketch profile (spec §K.2b, `doc:860-870`), adopted after the PR #89
  *measurement* falsified b = 8 (H100/5090 = 0.40× — consumer-favoring). b = 4
  plus cross-nonce batching turns the per-nonce combine into one large dense
  GEMM `P·[B₁·V|…|B_Q·V]` (`ComputeCombineLimbTensorStacked`,
  `matmul_v4.h:224-237`) — the shape datacenter INT8/FP4 pipelines are built
  for.
- **I1′ operand scoping** (`DeriveOperandSeed`/`DeriveProjectorSeeds`,
  `matmul_v4.h:109-135`): A/U/V template-scoped (amortized), **B and σ
  nonce-fresh** — so the marginal per-nonce unit (expand B + B·V + combine +
  digest) is unavoidable per lottery draw, and difficulty prices exactly it.
- **Arithmetic intensity AI_opt = 2n/b = 2,048** — above every device ridge
  (H100 591, B200 563, 4090 655; spec §K.2a/§L.2), so no eligible device is
  bandwidth-bound and ranking is strictly ∝ tensor TOPS; the §L.4 impossibility
  result deliberately renounces capacity gates in favor of this compute lever.
- **ENC-BMX4C encoding** (`MatMulEncodingProfile::ENC_BMX4C`,
  `src/consensus/params.h:96-166`; bmx4c-spec §2): exact-integer FP4/MX-native
  operands so the frontier's fastest pipes run it at tax ≈ 1× while every INT8
  part keeps one s8 GEMM — the ladder table in
  `btx-matmul-v4.2-consolidated-design.md:404-431`: *"Rubin ≫ B300 > B200 >
  MI355X/Trn3 > TPU v7 > H100 > 5090 > 40/30 > M-class-pooled … steepens toward
  the frontier purely through absolute frontier throughput."*
- **m as the deep-compute knob**: the parked ENC-BMX4CD profile (b = 2,
  m = 2048; `params.h:104-122,155-161,441-469`) raises enforced per-nonce
  tensor work ~3.6×, with the **measured** per-card result B200/5090 = **1.54×
  at D vs a 1.06× tie at C**
  (`btx-matmul-v4.2-solver-evolution-design.md:70-71`). m is the knob that
  makes datacenter parts *win harder* — and in the prior design it cost
  8·m² = 32 MiB/block of segregated storage (Θ(m²), the entire problem the
  decoupling memo diagnosed).

### M3 — ASERT: difficulty as a price-free integrator of delivered compute

`CalculateMatMulAsertTarget` (`src/pow.cpp:2189`; spec §I.4.1, `doc:743-751`)
reads *only* timestamps, heights, 90 s spacing, and the 3600 s half-life. At
its fixed point `D_eq ∝ TOPS_net/W_nonce`: difficulty is an affine read-out of
delivered physical compute. It tracks the frontier's ≈ 3.4×/yr compute-stock
growth with a 0.020 % cadence distortion (spec §I.4.2), which is precisely the
"progressive" dynamic over time: **a miner who stands still loses block share
exactly as fast as the frontier grows; a miner who upgrades to each frontier
generation keeps or grows it.** The one-time rescale fields
(`nMatMulV4AsertRescaleNum/Den` `params.h:393-402`,
`nMatMulBMX4CAsertRescaleNum/Den` `:430-440`,
`nMatMulBMX4CDAsertRescaleNum/Den` `:462-469`; methodology
`btx-matmul-v4.2-asert-calibration.md`) exist so that any change to the
per-nonce work unit is absorbed at the fork without a cadence/emission
transient — calibrated from *measured* marginal nonce/s, never from MAC
counts, and not safety-critical (ASERT self-corrects within ~1 half-life).

### M4 — Measurement-gated shape retargets: compute scaling over epochs

Continuous throughput growth is absorbed by M3; *work-shape* growth (n, m) is
an L1-versioned, measurement-gated fork (longevity doc §3.1/§3.3; decoupling
memo §5-8: "every ~2–4 years a shape retarget raises m or j … and, when
budgets allow, n"). The gates are on-silicon (`matmul_v4_stage_bench`, the
§K.2b GO/NO-GO (a)–(d)), because *two model-based orderings were falsified*
before measurement became the rule.

Supporting rails (not reward mechanisms, but load-bearing for "difficulty =
compute"): the header-PoW throttle (`nMatMulHeaderPoWDiscountBits`,
`params.h:470-502`) and the provisional-vs-authenticated chainwork split
(`btx-matmul-v4.2-chainwork-authentication.md`) prevent self-declared digests
from claiming unearned chainwork.

**Summary statement of the property.** At any instant, expected block rewards
are proportional to a participant's share of network GEMM throughput (M1 + M2);
across time, difficulty growth (M3) plus shape retargets (M4) re-denominate
that share in frontier-generation terms, so progressively more powerful AI
compute progressively wins more of the fixed emission. This is what v4.4 must
preserve.

---

## 2. Mechanism-by-mechanism: what ENC-SC preserves, changes, or improves

ENC-SC (nextgen memo §7) commits, per nonce, the Merkle root `R_LDE` of the
canonical rate-ρ circle-code low-degree extension of Ĉ, sets
`matmul_digest = H(σ‖R_LDE)` (same header field, same target rule, new
preimage), and carries a 64–200 KB (cap 256 KB) whole-object
sum-check + Circle-FRI proof in-block, prunable after burial. Verification is
the 4-step cascade of §7.3 (digest/target → FRI transcript → sum-check →
O(n² + nm) end-point evaluation from header seeds), ε ≈ 2⁻⁸⁰.

### 2.1 M1 (digest lottery) — PRESERVED, with one strictly necessary strengthening

- Target rule, nBits, ASERT, chainwork accounting: **unchanged**. The lottery
  is still `matmul_digest ≤ target` on the same header field.
- The preimage changes from `H(σ‖Ĉ)` to `H(σ‖R_LDE)`. Provided ENC-SC is
  sound, the D3/I-F property holds: `R_LDE` is a *function* of
  (header, nNonce64) — no salts, no blinding, no free positions — and the
  proof constrains **every** committed word to its unique value with error
  ≤ 2⁻⁸⁰ (nextgen §4.B, §7.6). Hence **one nonce → one valid ticket → one full
  W of GEMM**, exactly the property today's full-payload Freivalds gives via
  reading all m² words. This is not incidental: the §2.4 commitment-grinding
  break shows that any committed object with unconstrained bits converts the
  PoW into SHA-grinding and *destroys* M1 (block wins would track hash rate,
  not GEMM rate). ENC-SC is the unique candidate in the study that removes the
  Θ(m²) relay while keeping the lottery fully GEMM-priced.
- Work-unit neutrality (§L.2.1) carries over verbatim: ENC-SC multiplies every
  device's per-nonce cost by a device-dependent factor near 1 (see §2.2);
  what it must not do — and, per the analysis below, does not do outside the
  measured-risk band — is move *relative* T_g between classes.

### 2.2 M2 (GEMM-dominant work shape) — PRESERVED; the +1.4× floor is the one measured risk

**Unchanged bytes-for-bytes:** the GEMM solver path. The miner still computes
Ĉ = (U·A)(B·V) exactly as today (`ComputeSketchOptimal`,
`matmul_v4.h:161-179`; batched `matmul_v4_batch.{h,cpp}`; BMX4-C kernels and
the C-13 limb machinery; the CUDA/Metal backends and the C-1/M-t24
accumulator-eligibility framework). I1′ scoping is unchanged (nextgen §7.1:
"Seeds, σ, I1′ template scoping, nonce rules: unchanged"). W is unchanged.
AI_opt = 2n/b is unchanged. The BMX4-C encoding profile and its ladder
(consolidated design §6) are unchanged — ENC-SC composes with the encoding
layer; it replaces the *commitment* layer only.

**What is added per nonce:** the canonical commitment: circle-FFT of the m²
residues to the 2m²-point domain (ρ = 1/2) + Merkle tree.

| Per-nonce floor (n = 4096, m = 1024) | v4.2 today | v4.4 ENC-SC |
|---|---|---|
| XOF expand B (nonce-fresh) | 16.8 MB SHA ≈ 262k comp. | same |
| Commitment hashing | 8.4 MB (flat digest) ≈ 131k | 16.8 MB leaves + 2²¹ interior ≈ 295k |
| **Total non-GEMM SHA floor** | **≈ 393k comp.** | **≈ 557k comp. (×1.42)** |
| FFT integer-ALU work | — | ≈ 4.4×10⁷ mod-q mults ≈ **0.06 % of W** (overlaps tensor GEMM) |
| GEMM W | 7.73×10¹⁰ MACs | same |

(Nextgen §3, §4.B "Sizes and costs"; the winner-only prover — DEEP quotients,
FRI folding, sum-check — is ≪ 1 s GPU once per 90 s block and does not touch
the nonce loop.)

**Why the economics survive the floor (+1.4× risk, absorbed in three ways):**

1. **Difficulty absorbs the level.** The floor raises every miner's per-nonce
   cost; the one-time `nMatMulSCAsertRescaleNum/Den` (standard B2b procedure,
   §3.2 below) re-anchors cadence, and §L.2.1 guarantees the emission split
   depends only on *relative* rates. A uniform ×1.42 SHA increment is
   share-neutral by the theorem.
2. **The non-uniform residue is bounded and tunable.** SHA throughput per
   dollar is flatter across classes than tensor throughput, so a larger SHA
   share compresses the ladder slope; that is exactly the K.2b failure mode
   measured once already at b = 8. The knobs: rate ρ (ρ = 1/4 halves the query
   count and shrinks proofs to ~80–100 KB but costs ×1.9 hashing — a
   silicon-tuned trade), leaf width, and — newly free — **m itself**: raising
   m grows GEMM ∝ (4n²m + 2nm²) against a hash floor whose commitment part
   grows ∝ m², so within the practical window (below) the GEMM share is
   *restored by the same knob the design wants to raise anyway*. At m = 2048:
   W → 1.72×10¹¹ MACs (×2.22) vs floor → ≈ 1.31M comp. (×2.35) — ratio
   approximately preserved while absolute enforced tensor work doubles and the
   measured 1.54× per-card frontier margin (D-profile point) is engaged.
3. **Measurement gate (blocking).** Per the twice-burned rule (spec §K.2b;
   nextgen §7.7 gate (ii)), the v4.4 GO/NO-GO re-runs the wall-time-majority
   and ordering measurements on H100/B200 **with the ENC-SC floor included as
   a pinned bench stage** (FFT + leaf/interior hashing added to
   `matmul_v4_stage_bench`): (a) tensor share of marginal wall time strict
   majority at Q ≥ 32; (b) ≥ ~60 % tensor utilization; (c) H100/B200 above
   5090 by a price-surviving margin; (d) verify inside the < 1 s budget. No
   activation parameter is pinned before these pass. Hard fallback if they
   fail at every (ρ, leaf, m) point: Candidate A digest-only recompute (zero
   per-nonce overhead — the strongest possible floor — at the price of
   GPU-class tip verification), nextgen §4.A/§9.1.

**Honest structural note (same shape as the old design, better constants where
it matters):** the hash floor's commitment term is Θ(m²) in *compute* under
both the old flat digest and ENC-SC (ENC-SC ×2 at ρ = 1/2); what ENC-SC
removes is the Θ(m²) *bytes on the wire and disk*. The GEMM-to-hash wall-time
ratio therefore still closes as m grows at fixed n (crossover order
m ≈ 4–8k at n = 4096, vs 8–16k before), and the escape is the same as it
always was: retarget n upward (ratio ∝ n²/m in the leading term), which is
now also cheaper because n's verify cost is O(n² + nm) with **no payload
consequence at all**.

### 2.3 M3 (ASERT integrator) — PRESERVED UNCHANGED, plus one standard rescale

`CalculateMatMulAsertTarget`, the half-life, anchor logic, timestamp
hardening, and the price-free property are untouched (nextgen §7.4:
"Difficulty (continuous): unchanged ASERT on the digest target"). v4.4 adds
exactly one instance of the existing pattern: `nMatMulSCAsertRescaleNum/Den`
at `nMatMulSCHeight`, calibrated per `btx-matmul-v4.2-asert-calibration.md`
from measured marginal nonce/s on the rational path (now including FFT + tree),
with 1/1 safe in the interim and residual error absorbed within ~40 blocks.
`D_eq ∝ TOPS_net/W_nonce` continues to hold with W_nonce the ENC-SC marginal
unit; M2's on-chain corroborator (longevity doc §3.2 — difficulty growth vs
the 3.4×/yr Epoch envelope) continues to function as the audit trail.

### 2.4 M4 (epoch scaling) — IMPROVED: the m-knob loses its Θ(m²) price

This is the headline synthesis. In the prior work, raising m meant the
D-profile bargain: ×3.6 enforced tensor work for 32 MiB/block segregated
storage, a chunked relay protocol (BIP324 24-bit ceiling workaround), a
consensus-coupled proof store, and 10.7 TiB/yr archives — the reason D was
parked behind `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY = false`
(`params.h:186-225`). Under ENC-SC:

| m (n = 4096) | W MACs/nonce | Old relay/archive cost | ENC-SC relay cost | ENC-SC verify |
|---|---|---|---|---|
| 1024 | 7.73×10¹⁰ | 8 MiB/blk, 2.67 TiB/yr | 64–200 KB | 150–400 ms |
| 2048 | 1.72×10¹¹ (×2.2) | 32 MiB/blk, 10.7 TiB/yr | +~10–20 KB | +O(nm) ≈ +15–30 % |
| 4096 | 4.12×10¹¹ (×5.3) | 128 MiB/blk (never shippable) | +~20–40 KB | ≈ ×1.5 today |
| 8192 | 1.10×10¹² (×14.2) | 512 MiB/blk (absurd) | +~40–60 KB | ≈ 1.5–2× today, sub-second |

Proof size grows O(log² m) (+1 tree level ×2 and ~1 FRI layer per doubling);
verify grows only through the O(nm) end-point term; **relay and archive are
flat in the required sense at every rung**. Combined with n: 4096 → 8192
(W ×4 at fixed m, within the L0 verify budget), the shape headroom is ×32
before any further idea (depth-chain D2 held in reserve) is needed — every
step of it storage-free.

---

## 3. The v4.4 scaling discipline: how compute grows over epochs, storage-free, reward-proportional

### 3.1 Two-track scaling (unchanged philosophy, unblocked mechanics)

- **Track 1 — continuous (throughput):** ASERT absorbs hardware-stock and
  generation-throughput growth indefinitely; no consensus action; blocks/hr
  and emission fixed; each participant's reward remains
  `800·T_g/TOPS_net BTX/hr`. A device that merely persists across a frontier
  doubling sees its expected reward halve — the progressive dynamic, priced
  continuously.
- **Track 2 — discrete (work shape, every ~2–4 years):** a measurement-gated
  L1-style fork raises m (primary — now free) and/or n (secondary), each with
  its own one-time ASERT rescale. Gates per retarget: on-silicon stage-bench
  wall-time majority + ordering (K.2b (a)–(d) with ENC-SC stages), verify
  budget re-bench, golden-vector regeneration, cross-vendor re-pin. No
  pre-pinned n(h)/m(h) ladder — forecasts here have been falsified twice;
  silicon decides (decoupling memo §5-8; nextgen §7.4).

Reward proportionality is invariant across both tracks by §L.2.1: shape
retargets change what a nonce *costs*, never what a unit of relative
throughput *earns*. The subsidy schedule (20 BTX, 525k halvings, 21M cap) is
untouched — "progressively more rewards" is always progressively more *blocks
won* out of a fixed, price-independent emission.

### 3.2 Activation (ONE height)

At `nMatMulSCHeight`, simultaneously: (i) digest preimage → `H(σ‖R_LDE)`;
(ii) verifier → the §7.3 cascade (dispatched where
`CheckMatMulV4SketchVerifies` routes by profile today, `src/pow.cpp:3543`);
(iii) proof carriage → in-block `matrix_c_data`, hard cap 256 KB
(`GetMatMulProofSizeCap` → constant); (iv) segregated relay/proof-store
machinery deleted-at-height; (v) `nMatMulSCAsertRescaleNum/Den` applied, then
ASERT re-anchors; (vi) `MatMulProfileParams` gains
`commitment ∈ {FLAT_SKETCH, LDE_SUMCHECK}`, `fri_rate`, `fri_queries`,
`fri_fold_arity`, `grind_bits`, `proof_size_cap`, and retires
`sketch_payload_bytes`/`proof_segregated` (nextgen §7.7). Below the height,
nothing changes; the branch is inert exactly like ENC-BMX4C/BMX4CD today.

### 3.3 Archive = O(headers), at every epoch

Nodes hold proofs for a rolling window (tip validation + reorg depth; 2016
blocks ≈ 0.4–0.5 GB at the 200 KB point); past burial depth even archives
drop them, because **every proof byte is recomputable from the 182-byte
header forever** (regenerate Ĉ at W MACs, re-encode, re-derive the identical
FS transcript), and any deep block is directly re-auditable by digest-only
recompute (ms on GPU, ~1–2 s CPU at m = 1024). Steady-state PoW data:
**60.8 MiB/yr of headers vs 2.67–10.7 TiB/yr today — a 10⁴–10⁵× reduction —
and the figure is m-invariant and n-invariant forever** (nextgen §7.5;
decoupling memo §6). Shape retargets change the *cost* of historical
re-audit (W grows), never the *bytes*; deep history additionally rides
assumevalid-class policy with the stronger re-derivability property.

---

## 4. Kept vs. replaced (the v4.4 delta, exhaustively)

### KEPT (byte-identical or mechanically extended)

| Component | Anchor |
|---|---|
| GEMM solver + all backends: `ComputeSketchOptimal`, batched miner, BMX4-C/M11 encoding + kernels, C-13 limb combine, CUDA/Metal accel, C-1/M-t24 accumulator eligibility, verify+fallback dispatcher | `src/matmul/matmul_v4*.{h,cpp}`, `matmul_v4_bmx4*`, `accel_v4.h`, `params.h:96-166,503-513` |
| I1′ operand scoping: nonce-fresh B and σ; template-scoped A/U/V; 182-byte header; seed rules | `matmul_v4.h:89-142`; nextgen §7.1 |
| Difficulty machinery: ASERT formula/half-life/anchoring, rescale pattern (one new instance), timestamp/timewarp hardening | `src/pow.cpp:2189`, `params.h:548-588` |
| Reward machinery: subsidy schedule, empty-block penalty, price-independence §0.7-(4) | `params.h:517-532` |
| Header-PoW throttle + provisional/authenticated chainwork split (C1 posture unchanged; ENC-SC's ms-fast fail cascade strictly improves body-verify DoS) | `params.h:470-502`; chainwork-authentication doc |
| PQ posture end-to-end: SHA-256-only consensus proof system; BIP324 v2 + hybrid ML-KEM-768 rekey transport — now *sufficient without modification*, since 256 KB ≪ the 16 MiB v2 packet ceiling that broke the 32 MiB relay | `src/bip324.h:43-52`; relay-hardening doc §1 |
| L0 survivors: q = 2⁶¹−1 (the M61 circle group, order 2⁶¹, is what makes Circle-FRI fit), exact-integer committed path ("no rounding, ever"), verify budget < 1 s, hardness floor, pooling rule | longevity doc §3.1; nextgen §2.5 |
| DoS verify budgets/framework (values re-tuned to the new cascade) | `params.h:403-410` |

### REPLACED / DELETED at `nMatMulSCHeight`

| Prior component | v4.4 replacement |
|---|---|
| Committed object relayed as the full Θ(m²) sketch (8·m² B in `matrix_c_data`, 8 MiB C / 32 MiB D) | 32 B `R_LDE` in the digest preimage + 64–200 KB ENC-SC proof in-block, prunable |
| Digest preimage `H(σ‖Ĉ)` | `H(σ‖R_LDE)` (same field, same target rule) — an L0 amendment, ratified openly as such |
| `SketchFreivalds` full-payload verifier (`matmul_v4.h:254-271`; O(n²) + 8·m² digest recompute) | §7.3 cascade: FS/FRI/sum-check replay + verifier-computed end-points from header seeds; 150–400 ms; ε ≈ 2⁻⁸⁰ (Freivalds' role as full-object binder is inherited by proximity + evaluation binding; digest-only recompute retained as the archival fallback) |
| Entire segregated relay subsystem: `MatMulProofStore` as consensus dependency, `getmatmulproof`/`matmulproof`/`mmproofchunk`, Stage 2b/2c/2d chunking, pending-byte budgets, `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY`, payload-sized `GetMatMulProofSizeCap` | **deleted**; proof rides ordinary in-block carriage under every existing message limit |
| ENC-BMX4CD as a storage-priced profile (m = 2048 ⇔ 32 MiB) | m becomes an ENC-SC *parameter*: the D-profile's measured 1.54× frontier margin is available at +~10–20 KB |
| `sketch_payload_bytes`/`proof_segregated` in `MatMulProfileParams` | `commitment`, `fri_rate`, `fri_queries`, `fri_fold_arity`, `grind_bits`, `proof_size_cap` |

---

## 5. The compute→reward curve, restated quantitatively for v4.4

For device class g with marginal ENC-SC nonce rate ν_g (GEMM W + ×1.42 SHA
floor + 0.06 % FFT), at any epoch (n, m):

- Expected blocks/day: `960 · ν_g / ν_net`; expected BTX/hr: `800 · T_g/TOPS_net`.
- Cost of a coin: `ρ·TOPS_net/800` — invariant to the work-unit size (§L.2.1),
  so neither ENC-SC's floor nor any m/n retarget moves it; only *relative*
  efficiency does, which is exactly what the frontier ladder orders.
- Over time: TOPS_net tracks the ≈ 3.4×/yr frontier envelope through ASERT
  (0.020 % cadence distortion); shape retargets raise W per nonce to keep the
  workload GEMM-dominant on each new generation — now at zero bytes.
- Archive: 60.8 MiB/yr, all epochs, forever.

Provided ENC-SC is sound, acceptance of a block still implies (except w.p.
≈ 2⁻⁸⁰) that the full mandated W was performed for the winning nonce, and no
GEMM-free grinding channel exists — so "blocks won" remains a faithful,
manipulation-resistant measurement of AI compute, which is the entire content
of the progressive-reward property.

---

## 6. Open dependencies (blocking, tracked; none design-internal)

1. **ENC-SC adversarial review** (separate track): round-by-round soundness of
   the exact combined sum-check + Circle-FRI protocol; Circle-FRI-over-M61
   parameter cryptanalysis (proven Johnson-bound regime only — conjectured
   capacity settings are not relied on); the §4.B grinding-immunity argument
   as normative text. Every preservation claim in §2.1 is conditional on this.
2. **Silicon measurement** (v4.4 B2g analogue): the ×1.42 floor and the
   ordering (K.2b (a)–(d) + ENC-SC stages) on H100/B200 before any activation
   parameter is pinned; ρ/leaf/m tuned on measurement, not models.
3. **Inherited open reviews that v4.4 does not alter:** I1′ anti-amortization
   external review (spec §C); C-15 marginal-work-floor review (round-3 P1-5 —
   the Ω(n²)-proven vs Θ(n²m)-claimed gap is unchanged by ENC-SC, which
   enforces the *committed object*, not a work lower bound); chainwork C1
   full authentication.
4. **Constitutional process:** the digest-preimage/verifier change is an L0
   amendment (longevity doc §3.1); v4.4 ratifies it openly with the flat-data
   requirement recorded as the new constitutional input, per nextgen §2.5/§9.5.

---

## 7. Sources

**Code:** `src/consensus/params.h` (:96-225 profiles/constants, :385-513
b/rescales/gate, :517-532 subsidy, :548-588 ASERT, :793-841
GetMatMulEncodingProfile/GetMatMulProfileParams); `src/matmul/matmul_v4.h`
(:43-80 kTileB/limbs, :89-142 σ/seeds/I1′, :161-237 optimal/batched solver,
:239-271 serialize/digest/Freivalds); `src/pow.cpp` (:2189 ASERT, :3543-3620
verify dispatch + target check, :3620-3660 in-block carriage/size cap);
`src/bip324.h` (:43-90 hybrid ML-KEM-768).
**Docs:** `btx-matmul-deterministic-nextgen-design.md` (§1-§4, §7, §9);
`btx-matmul-compute-vs-data-decoupling-research.md` (§1-§3, §5-§6);
`btx-matmul-v4-design-spec.md` (§I.4-I.5, §K.2a/b, §K.3, §L, §L.2.1, §L.4);
`btx-matmul-v4.2-consolidated-design.md` (§1, §6-§8);
`btx-matmul-v4.2-bmx4c-spec.md`; `btx-matmul-v4.2-asert-calibration.md`;
`btx-matmul-v4.2-longevity-threat-model.md` (§3.1-§3.3);
`btx-matmul-v4.2-solver-evolution-design.md` (§2, measured C-vs-D ordering);
`btx-matmul-v4.2-relay-hardening-design.md`;
`btx-matmul-v4.2-chainwork-authentication.md`;
`btx-matmul-v4.2-external-audit-round3-remediation.md` (P1-5, P1-6);
`btx-matmul-v4-frontier-native-format.md`.
