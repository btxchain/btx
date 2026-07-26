# BTX Threat Model and the Defensible Minimum Soundness Bound q* for the Succinct Proof

Date: 2026-07-26. Status: ANALYSIS (no code changes). Companion to
`btx-matmul-v4.6-stage3-global-composition-reconciliation-2026-07-25.md` (blocker #3 grinding
accounting, field-bounds lift, shared-commitment dual-lane) and the arity-4 extractor bridge doc.

## 0. What this document fixes

The composed FRI-lane soundness floor (field-bounds + shared-commitment work, with **A2
lane-independence now PROVEN** under ROM + Poseidon-binding — audit-input, not flag-flipped)
is

```
F(q) = min(  308 − 2q       # FIELD pair (dual-lane, rests on A2; m_f ≈ 154)
          ,  288 − q        # QUERY pair (Π_JQ joint squeeze, taxed: 2·m_Q + g − q)
          ,  256 − 2q )     # SHARED-COLLISION: one Poseidon collision in the shared
                            #   row tree equivocates BOTH lanes — UNPAIRED single term
```

parameterized by `q = log2(Q_H)` — the adversary's hash-oracle query budget **against one
target block's proof transcript** (for the shared-collision term, the *lifetime* collision
budget; see §3.5). Shipped package: **Q136 + enforced per-squeeze tax g=40
(`Fri3AlgCheckSqueezeGrind`) + 256-bit digests + A2 dual-lane (proven)**.

Two structural facts about this floor:

- The **shared-collision term 256−2q is the binding constraint at every q** (the field pair
  sits +52 bits above it uniformly; the query term 288−q exceeds 256−2q for all q ≥ 0). The
  collision floor is a *single* term, not a lane-pair: because both lanes open the same
  shared row tree, one collision equivocates both — the 2c-style pairing (512−…) applies only
  to lane-prefixed fold trees, which this package does not rely on.
- These are **probability-at-fixed-budget exponents, NOT work factors**. E.g. the untaxed
  field rounds carry ~2^155 *work* per meaningful attempt; 308−2q is the success-probability
  exponent for an adversary who has already spent budget 2^q. The two metrics must not be
  mixed (that mixing is what invalidated the old 101.20 union).

Every prior "clears 64 by ~29" / "sub-64 at q=100" statement was parameterized by an
**assumed** q. This document derives q from BTX's actual consensus reality — where the mining
anchor is a datacenter-scale tensor workload, not SHA — and sets the defensible minimum **q***.

## 1. Threat model

**Asset.** Acceptance of a false episode statement: a block whose succinct proof (GKR +
recursive STARK, PR-89 mandatory authority) verifies although the committed tensor episode was
not computed. Success = fake PoW = free blocks / inflation / reorg leverage.

**Adversary interfaces.** Three attack surfaces against F(q):

1. **Offline collision search** against the shared 256-bit Poseidon row-tree digest — the
   `256 − 2q` shared-collision term. It is the **only** term that amortizes across blocks and
   years: a collision found offline transfers to any future proof (fixed hash function), and
   one collision equivocates both lanes. Its q is therefore the adversary's *lifetime
   Poseidon-evaluation* budget, not a window-boxed budget — quantified in §3.5.
2. **Per-block FS transcript grinding** — the pair terms `308−2q` (field) and `288−q`
   (taxed query). The
   Fiat–Shamir transcript is bound per block: the FS preimage commits `sigma` (episode
   commitment) and `claimed_digest` (`matmul_v4_rc.cpp:765–780`, tag `kRCFsTag`, V8 role byte
   `0xF5` via `domain_sep::Sha256dFsPreimage`); the stage3 aggregation seed is
   domain-separated by role and binds `(node_id, slot_index)` (bridge blocker #5, closed); the
   consensus carrier is bound to the **block target** (commit `d6b4457`). Queries spent on
   block A's transcript are worthless against block B. Grinding is therefore
   **per-block-context, inside a window**.
3. **Algebraic / protocol attacks** not counted in q (list-decoding, batching correlation,
   transport). These are the per-term screens (field rounds 151–168 bits each, transport
   183.6 dual-α, statement-decomposition bridge 341·κ + 2⁻¹²⁸ + 2⁻⁸⁸) — all ≥ the F(q) floor
   at realistic q, handled in the reconciliation doc.

**The window.** PR-89 makes succinct verification **mandatory and immediate** on the relay hot
path (≤900 ms budget; 330 ms measured M4 Max). A forged-proof candidate must be built on the
current tip and win propagation before the chain advances, so the grind window per context is
the **90 s block interval** (`nPowTargetSpacing = 90`, `kernel/chainparams.cpp:537`), not a
dispute window. The deferred-verification alternative is analyzed (and rejected) in §3.4.

## 2. The tensor-mining anchor (code-cited)

BTX's PoW is the datacenter RC episode, not SHA hashing. `MakeDatacenterRCEpisodeParams()`
(`matmul_v4_rc.cpp:805`) at the frozen constants (`matmul_v4_rc.h:93–116`):

| Parameter | Value | Source |
|---|---|---|
| rounds × L_lyr | 8 × 24 (N = 200 sampleable units, λ exhaustive) | `kRCRoundsDC`, `kRCLayersDC` |
| d_model / d_ff | 4096 / 16384 (4× FFN expansion) | `kRCModelDim`, `kRCFfnDimDC` |
| b_seq | 87 552 = 2736·32 | `kRCBatchSeqDC` |
| n_ctx | 786 432 — **hard-pinned to epoch-0** (hash-bound guardrail assert) | `matmul_v4_rc.cpp:824` |
| T_leaf | 4096 B | `kRCTileLeafBytesDC` |
| **MAC/episode** | **MAC_dc = 2³⁷·16422 = 2 257 022 493 917 184 ≈ 2⁵¹·⁰ INT8 MAC** | `matmul_v4_rc.h:103` |
| Working set | ~48 GiB (V2 expanded int8) / ~51 GiB (V3 packed), device-resident | `matmul_v4_rc_residency_plan.h:19–20`, `matmul_v4_rc_datacenter.h:57–61` |
| Resident-class floor | 64 GiB VRAM (`kRCResidentVramFloorBytes`); RTX 5090 (32 GB) excluded | `matmul_v4_rc_residency_plan.h:38–51` |

Even under a *total* break of the STARK, the consensus carrier layer independently forces
tensor work per candidate: the sampled carrier (8 FS-drawn spot checks,
`kRCSpotCheckQueries = 8`) plus the FVT terminal-round full recompute
(`RecomputeRCRoundRoot`, ≈2.8·10¹⁴ ≈ **2⁴⁸ MAC**, ~1/8 episode) bound to the block target
(commits `7ab6db8`, `d6b4457`, `cb389c7`). Caveat, stated honestly: FVT is a **pre-activation
gate** (`sampled_terminal_round_fvt_executable = false`; breaks the 900 ms budget below
datacenter HW — see `fvt-terminal-round-budget`), so today the anchor's per-context floor is
the header-target requirement itself, which at network difficulty equals the full expected
block work.

**Consequence.** An *attackable context* = a self-mined candidate block meeting the tensor
target. Contexts are produced at the attacker's tensor rate ÷ network difficulty — **not** at
their hash rate. This is the structural difference from the naive Bitcoin model.

## 3. Deriving q

### 3.1 Per-context grind budgets: q_ctx = log2(rate × window)

| Adversary hash rate | 90 s | 1 h | 24 h | 7 d | 30 d |
|---|---|---|---|---|---|
| Large ASIC-farm class, 2⁵⁰ H/s | **56.5** | 61.8 | 66.4 | 69.2 | 71.3 |
| Extreme nation-state, 2⁶⁰ H/s | **66.5** | 71.8 | 76.4 | 79.2 | 81.3 |

**Why the rates are already generous.** Bitcoin SHA256d ASICs are fixed-function on the
80-byte-header / fixed-midstate / rolling-32-bit-nonce datapath. The BTX FS preimages are
tagged, variable-length, multi-block SHA256d (`kRCFsTag ‖ σ ‖ claimed_digest ‖ ctr`, role byte
0xF5; stage3 seeds are statement-hash-derived). **Commodity Bitcoin hashpower cannot be rented
or repurposed for this grind.** Realistic general hardware: ~2³³ H/s per GPU, so 2⁵⁰ H/s
already means a ~100k-GPU dedicated cluster; 2⁶⁰ H/s (≈1.15 EH/s ≈ 0.2 % of Bitcoin's 2026
network) requires **purpose-built custom silicon** for this preimage format. We keep both
tiers as deliberate over-estimates.

### 3.2 Multi-context and campaign amplification — why concentration wins

The binding terms in F(q) are birthday-pair terms, ~2^(2q−2c'). Splitting a fixed per-window
budget across N parallel contexts gives N · 2^(2(q−log₂N)−2c') = 2^(2q − log₂N − 2c') —
**strictly worse than concentrating on one context**. (The linear query term 288−q is
split-neutral and takes the full +log₂W campaign surcharge, but even at the extreme —
q_w = 66.5 + 18.4 = 84.9 — it sits at 203 bits, nowhere near binding.) Parallel
context-farming (which the
48–51 GiB resident working set makes expensive: 1000 parallel contexts ≈ 50 TB of 64 GiB-class
VRAM) therefore does not help the pair attack at all; memory-hardness additionally prices the
contexts themselves.

What the adversary *can* do is repeat the single-context attack every window (budget is
rate-limited in time and cannot be concentrated across windows). Over W windows the union is
W · 2^(2q_w − 2c'), i.e. an effective

```
q_eff = q_ctx + log2(W)/2 .
```

W is capped by the **tensor anchor**: one attackable context per window requires meeting the
tensor target, so even an attacker owning 100 % of network tensor power gets at most
W = 86 400·365/90 = 350 400 ≈ 2¹⁸·⁴ contexts/year (fraction f of network power ⇒
2¹⁸·⁴·f). Hence the campaign surcharge is at most **+9.2 bits of q_eff per year**, assuming
total network capture.

- Nation-state, 1-year total-capture campaign: q_eff = 66.5 + 9.2 = **75.7**
- ASIC-farm class, 1-year: q_eff = 56.5 + 9.2 = **65.7**

### 3.3 Why the Bitcoin-annual 2⁹⁴ figure is the wrong model

Bitcoin's annual network output (~7·10²⁰ H/s × 3.15·10⁷ s ≈ 2⁹⁴) is an *amortized,
single-target* budget. In BTX it fails on all three axes:

1. **No transferable target.** Pair-grind queries are per-block-transcript (FS binding, §1).
   2⁹⁴ hashes spread over a year of 90 s windows is 2⁹⁴ − 2¹⁸·⁴ … i.e. only 2⁷⁵·⁶ per window
   — and that presumes the entire Bitcoin network re-tooled onto non-existent
   custom FS-grind silicon.
2. **Contexts cost tensor work.** Each additional attackable block context costs the full
   expected block work at 2⁵¹ MAC/episode on 48–51 GiB-resident hardware (≥2⁴⁸ MAC even for a
   carrier-forger once FVT activates). Context count enters q_eff only as +log₂(W)/2 and is
   anchor-capped at +9.2/yr.
3. **The only offline-amortizable term is the shared-collision term — and it is not a SHA
   target.** A digest collision does transfer, but the digest is Goldilocks Poseidon2, i.e.
   field arithmetic, not commodity SHA silicon. Bitcoin's 2⁹⁴ annual figure is SHA256d ASIC
   output and does not convert (§3.5 prices the real Poseidon budget at ~2⁷²–7⁶/yr for
   extreme adversaries). Even granting SHA-rate silicon for Poseidon, 2⁹⁴ queries give
   success 2^(2·94−256) = 2⁻⁶⁸ — still ≥64.

### 3.4 Deferred verification would break the model (why immediate verify is load-bearing)

If the succinct proof were verified with delay (days-scale dispute window), q_ctx rises to
76.4–81.3 (table §3.1) and F_shipped drops to 103.2 → 93.4 **before** campaign surcharge —
the ≥100 target is lost (≥64 still holds comfortably). Mandatory ≤900 ms hot-path
verification is therefore not just a scalability feature; it is what boxes the grind window at
90 s. Any future "optimistic/dispute" relaxation must re-run this derivation.

### 3.5 The shared-collision term: lifetime Poseidon budget, not a window

Because a Poseidon2 collision transfers across blocks, the 256−2q binding term must be
evaluated at the adversary's **lifetime** collision-search budget q_col, and window-boxing
does not protect it. What protects it is (a) the 256-bit width and (b) the cost of a Poseidon2
evaluation — Goldilocks field arithmetic (t = 12, R_F = 8, R_P = 22, x⁷), not a Bitcoin ASIC
datapath:

- Measured GPU rate (RTX 5060 Ti, from-scratch kernel, exact verifier params): **1.96·10⁸
  perms/s ≈ 2²⁷·⁵ per device**.
- 10⁶-GPU fleet, one year: 2²⁷·⁵ · 2¹⁹·⁹ · 2²⁴·⁹ ≈ **2⁷²·³**.
- Extreme custom-silicon uplift (~100× per-die, nation-state fab run): ≈ **2⁷⁹**; a
  still-generous defensible ceiling is **q_col ≈ 76** (≈2.4·10¹⁵ perm/s sustained for a
  year ≈ 12 M top-end GPUs equivalent).

So the collision reading of q lands in the **same ≤78 region** as the per-block grind
reading: 256 − 2q_col ∈ [98, 112] for q_col ∈ [72, 79], and ≥100 iff q_col ≤ 78. Honest
caveat (**M2 audit line**): the 256−2q exponent assumes generic-birthday-optimal collision
search against Poseidon2 — a **non-standard algebraic-hash binding assumption** (the frozen
R_F = 8/R_P = 22 schedule was dimensioned for a 128-bit algebraic security level, so no claim
above ~128 should be made on this term regardless; irrelevant at the 100-bit target but it is
a separate, open audit item, not a theorem).

## 4. The recommended minimum bound: q* = 76 (stress ceiling 78)

**q\* = 76**, and it holds under BOTH readings of q:

- **Per-block grind reading** (field + query pair terms): extreme nation-state (2⁶⁰ H/s on
  custom FS-grind silicon, ~0.2 % of Bitcoin's network re-imagined as bespoke hardware),
  sustained for a full year, owning 100 % of network tensor power → q_eff = 75.7 (§3.2).
- **Lifetime collision reading** (shared-collision term): extreme-adversary Poseidon2
  evaluation budget ≈ 2⁷²–2⁷⁶/yr (§3.5).

Stress ceiling **q = 78** adds ~4× headroom in window-count, rate, or fleet size. The
realistic ASIC-farm-class figure is 57–66; q* sits ~10–19 bits above it. (q is oracle-capped
at ~126–128 regardless; irrelevant here.) **q\* ≤ 78 is confirmed** — the boundary the
shipped 256-bit + A2 package needs for ≥100.

### F(q*) under the shipped package — min(308−2q, 288−q, 256−2q)

| q | field 308−2q | query 288−q | shared-collision 256−2q | **F(q)** | ≥64? | ≥100? |
|---|---|---|---|---|---|---|
| 64 | 180 | 224 | **128** | **128** | ✓ +64 | ✓ +28 |
| 66.5 (nation-state, single window) | 175 | 221.5 | **123** | **123** | ✓ +59 | ✓ +23 |
| **76 = q\*** | 156 | 212 | **104** | **104** | ✓ +40 | ✓ +4 |
| 78 (stress ceiling) | 152 | 210 | **100** | **100** | ✓ +36 | ✓ exactly |
| 96 | 116 | 192 | **64** | **64** | boundary | ✗ |

The **shared-collision term is the binding constraint at every row** — the field pair (A2)
never binds (+52 above uniformly) and the taxed query pair never binds (+84 and widening).
**Verdict: F(q\*) = 104 ≥ 100 with 4 bits of headroom, bound by the shared 256-bit Poseidon
collision term; the defensible minimum ≥64 clears by 40 bits and survives to q = 96** — a
budget requiring ≈2⁸⁹·⁵ H/s for 90 s, or the 2⁶⁰-adversary grinding one context for ~2 000
years, or ~10⁶× the extreme Poseidon fleet of §3.5.

**Honest global qualifier.** The within-proof union over FS sites (ledger site count
37 488 397 ≈ 2²⁵·²; count currently UNSTABLE vs 66.5 M) charges ~25 bits against the
composed figure: globally ≥100 holds only for q ≤ ~65 (covers the ASIC-farm class, not the
nation-state ceiling), and ≥64 holds for q ≤ ~83 (still clears q* by ~15 bits at F_g(76) ≈
79). The ledger's own conclusion stands: the **only sub-100 global term is the single-lane
FRI screen ~92.6** → the global 100-bit target needs multi-lane/batched FRI plus a settled
site count. The **minimum defensible bound (≥64) is met at q\* under every accounting.**

## 5. Classification: NECESSARY vs PARANOID-MARGIN at q* = 76

### NECESSARY (the 64/100 claims at q* rest on these)

1. **A2 lane-independence — now PROVEN** (under ROM + Poseidon-binding; audit-input, not
   flag-flipped). It remains maximally load-bearing: the dual-lane field pair 308−2q rests on
   it, and if the audit rejected it the field term reverts to single-lane
   **m_f − q = 154 − 78 = 76 at q = 78** (fails 100 by 24; under the within-proof site union
   ≈ 51 < 64). Classification: NECESSARY, status proven-pending-audit — keep it on the
   external-audit ledger, but it is no longer open construction work.
2. **Enforced per-squeeze grinding tax g = 40 + Π_JQ joint-query squeeze**
   (`Fri3AlgCheckSqueezeGrind` fused into `Fri3AlgJointQBatchCommit/Verify`, verifier cost
   1 hash). The 288−q query term *presumes both*: without them the query round reverts to the
   regrindable per-lane pair ≈ 216−2q, which undercuts the shared-collision term by 40 bits
   and binds at **64.0 at q = 76, 60 at 78** (fails the minimum at the stress ceiling). The
   old `kRCFriGrindingBits = 40` was arithmetic fiction (no verifier nonce check,
   `fri.cpp:694,1291`); only the enforced tax counts.
3. **Full 256-bit untruncated digests.** The shared-collision term 256−2q is the binding
   constraint at every q and the only offline-amortizable term; any sub-256 truncation
   collapses the floor linearly and is unbounded by windows.
4. **Field-bounds lift m_f ≈ 154** (unique-decoding, BKS2018/BCIKS2020/Haböck2022 —
   corrected the misapplied Johnson constant 126.93). At the old value the field pair
   253.9−2q would bind ~2 bits **below** the shared-collision term: F(78) = 97.9 < 100 at the
   stress ceiling. The lift moves it to 152–156 at q ∈ [76, 78], safely non-binding.
5. **Per-block context binding + immediate verification**: carrier→block-target binding
   (`d6b4457`), FS domain separation + (node_id, slot) binding, and the mandatory ≤900 ms
   hot-path verify. These are what make the pair-term q per-block (window = 90 s). §3.4: a
   days-scale deferred-verify design forfeits the 100-bit claim.
6. **H1 independent batching, steps 1–2** (`Fri3AlgReplayBatchCoefficients` + child-input
   threading — built, air_recurse 20/20, currently dormant behind
   `Fri3AlgQ192IndependentBatching() = false`). Lifts the internal-node lane from ~64.5
   (sub-64 exposure) to the 78.5 union. Cheap gating flip; required.
7. **A6 backend pin**: production must use MultiRow **V2** post-claim order (V1 per-column
   OOD adaptive-bug shape).
8. **For the GLOBAL ≥100 target only**: multi-lane/batched FRI to lift the single-lane 92.6
   screen, plus site-count stabilization (37.5 M vs 66.5 M decides the union charge).

### PARANOID-MARGIN (optional hardening; do not gate the production candidate on these)

1. **B384 / 384-bit re-dimensioned permutation**. Would lift the binding shared-collision
   term from 256−2q to 384−2q — which matters only if q > 78, above the q\* ceiling under
   both readings (per-block grind 75.7; lifetime Poseidon budget 72–76). Honest
   double-caveat: as built, B384's true floor is still min(192-bit birthday, ~128 algebraic)
   = 128 until R_F/R_P are re-dimensioned, so today it buys ~0 bits anyway. Keep as a
   selectable mode for a future q\* revision.
2. **DEEP64 retirement (H1 step 3)** — invasive parent-codec surgery, off the
   FRI-query-dominant path once steps 1–2 are gated on.
3. **FVT on the hot verify path as a grind defense** — buys ~37 bits at O(episode/rounds)
   verifier cost (breaks 900 ms below datacenter HW); the enforced g = 40 tax delivers 40 bits
   at 1 hash. FVT's residual value is the carrier/tensor anchor (dispute-only / async /
   pre-activation gate), not proof-grind defense.
4. **Q192 dual lanes** — overflows the 24 M block-weight proof-size gate; Q136/Q144 already
   saturates the min() at q ≤ 96 (the binding term is the shared-collision slope, not query
   count).
5. **Per-round tax nonces** (tax currently at the joint query round only) — the untaxed
   field rounds are covered by 308−2q = 156 at q\* (and carry ~2^155 *work* per attempt);
   extend only if q\* is revised upward.

### Separate audit lines (assumptions the floor is conditioned on — not construction work)

- **M2 — Poseidon binding.** The shared-collision exponent 256−2q assumes
  generic-birthday-optimal collision search against Poseidon2, a **non-standard
  algebraic-hash assumption** (unlike SHA-256's maturity); the frozen R_F=8/R_P=22 schedule
  is dimensioned for a 128-bit algebraic level, consistent with — but not a proof of — the
  claims made here (all ≤ 128).
- **A2 lane-independence** — proven under ROM + Poseidon-binding; the proof itself is
  audit-input.
- **A-FS-INST** — the per-level Fiat–Shamir instantiation heuristic (same assumption
  Plonky2/RISC0/Boojum ship).
- **Global-composition ledger** — certified_bits is still 0 until the composition-theorem
  constructions land: SHA-FS chip edges 2–4 (challenges are still host-extracted), the
  extractor-bridge β_node fix, M-LINK audit of Codex's stage3 CTL, site-count
  stabilization, and the external-audit ledger. F(q\*) = 104 is the *analytic*
  probability-at-budget floor of the shipped construction; the theorem work is what converts
  it to certified bits.

## 6. Bottom line

- **q\* = 76** (stress ceiling 78, and **q\* ≤ 78 is confirmed under both readings of q**):
  per-block grind — nation-state custom-silicon FS grinding (2⁶⁰ H/s) × 90 s windows × a
  year-long total-network-capture campaign = 75.7, with the tensor anchor (2⁵¹·⁰
  MAC/episode, 48–51 GiB resident, 64 GiB-class device floor) capping context amplification
  at +9.2 bits/yr; lifetime Poseidon-collision budget — 2⁷²–2⁷⁶/yr for an extreme fleet.
  Bitcoin-style amortization (2⁹⁴) is the wrong model: pair terms are window-boxed and the
  amortizable collision term is Goldilocks field arithmetic, not SHA silicon.
- **Shipped package (Q136 + enforced g=40 + 256-bit digests + A2 proven):
  F(q\*) = min(156, 212, 104) = 104 ≥ 100 with 4 bits of headroom, bound by the
  SHARED-COLLISION term 256−2q at every realistic q; ≥64 clears by 40 bits and survives to
  q = 96.** These are probability-at-budget exponents (not work factors), conditioned on M2
  + A-FS-INST. Globally (within-proof site-union charged) the 64-bar still clears by ~15
  bits; the global 100-bar is the one open lift (multi-lane FRI + settled site count).
- The production-required list is short and concrete: keep the enforced tax + Π_JQ +
  full-width digests + per-block binding/immediate verify, gate on H1 steps 1–2, pin V2,
  settle the site count, land the composition-theorem constructions, and put A2 + M2 on the
  external-audit ledger. The 384-bit permutation, DEEP64 retirement, hot-path FVT and Q192
  are paranoid margin.
