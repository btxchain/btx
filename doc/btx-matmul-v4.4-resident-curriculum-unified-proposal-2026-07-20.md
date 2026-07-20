# BTX "Resident Curriculum" (ENC_RC) — Unified Next-Generation PoW Proposal

*Date: 2026-07-20. Status: consolidated design proposal (hard fork). Non-normative except §R, which is written as normative spec text. Consensus changes are expected and permitted — this is a clean cutover.*

## Implementation status — WIP MatMul v4.5 (2026-07-20)

Branch tip tracks PR #89 (`claude/matmul-v4-design-spec-af23sj`). **Public activation remains NO-GO** (`nMatMulRCHeight = INT32_MAX`).

**Final-form index:** Stages A–I status, activation checklist, and Definition of Done live in
`doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md` (three-axis Stage F scaffolding inert;
Stage G silicon-gated; Stage E owner-owned). Do not raise height from this proposal alone.

| Surface | Status |
|---|---|
| §R CPU int64 episode oracle (`matmul_v4_rc.*`) | **Landed** — Phase 1–3 + tile-tree + ExtractMX |
| `ENC_RC=5` + `IsMatMulRCActive` + ASERT rescale fields | **Landed** — inert sentinel |
| `CheckMatMulProofOfWork_RC` / `SolveMatMulV4RC` / validation dispatch | **Landed** — toy dims via `fMatMulRCUseToyDims` (regtest only) |
| ExactGemm inject + `ProbeRCSelfQual` fail-closed | **Landed** — `native_mx*` stay false until device RC MX self-qual |
| P1.2 MX contraction layouts + Phase-2 ExactGemm device wire | **Landed** — `doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md` + packed helpers; S·V/bwd/wgrad native MX residual |
| Merkle spot-check + Fiat–Shamir q=8 | **Landed** — R1 reject still requires full CPU recompute |
| P2.1 validation model (shrink vs fraud-proof) | **Evidence** — `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md` (owner decides; segments/growth stay PARKED) |
| FINAL-FORM Stages F/H/I + master spec | **Landed (inert)** — `doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md`; `matmul_v4_rc_scale_axes.*` (`kRCThreeAxisScheduleEnabled=false`); Stage H test scaffolds |
| `matmul-v4-rc-harness` + `rc-gate.py` | **Landed** — real CPU timings; toy → PARTIAL (never raise-height) |
| Unit tests `matmul_v4_rc_tests` | **green** on CPU CI builds (incl. P1.2 layout + device-probe skip + Stage H scaffolds) |
| Silicon G2 residency / G3 k≥1.3 @ 24GB / G4 consensus dims | **Open** — measurement-gated before any height |

This document synthesizes a full multi-agent design cycle (six hardware-economics research passes, a grounding critique, a five-design synthesis, and a five-part build fleet) into one next-generation proof-of-work for BTX. It supersedes the framing of the earlier `btx-matmul-v4.4-hardware-economics-inversion-2026-07-20.md` study by carrying its grounded conclusions forward into a concrete, buildable design.

---

## 0. Executive summary

The **Resident Curriculum (RC)** replaces the single-GEMM ENC-DR-LT workload with a per-nonce **cognitive-workout episode** of three phases on the *existing* exact-MX integer-GEMM substrate:

1. **Associative Recall** — softmax-free FlashMX attention over a ~192 MiB resident, **per-nonce** KV state (cache-residency lever).
2. **Micro-Training Page** — an exact integer forward/backward pass whose 2 GiB activation footprint forces small-memory machines to checkpoint+recompute or host-offload (capacity/bandwidth lever).
3. **Consolidation** — a wide/shallow SHA256d Merkle tile-tree (<5% of work) that seeds the next round and forms the streamable verification transcript.

Design philosophy, in one sentence: **a machine with more memory capacity, memory bandwidth, and concurrency finishes the episode in fewer seconds and thereby earns proportionally more, while any machine — down to an 8 GB laptop — still completes and verifies every episode.** The gradient is purely economic; there is no admission gate.

**What it achieves (honestly):** it prices the **pre-2025 hardware tail** (RTX 3090, H100/H200, first-gen datacenter parts) out of rental viability by ~2.5–3× on cost-per-attempt (8–13× slower wall-clock), while a flagship consumer 5090 stays competitive and owner-operated hardware on cheap power is never fully excluded. It does **not** let the biggest datacenter chip dominate per-dollar — the B200 remains a ~2× cost-efficiency loser to its own rental premium; the thin cost-efficiency winner is the cheap-cache-per-dollar AMD MI355X (~1.0–1.3×). The security-relevant win is removing the cheap, abundant legacy-GPU fleet from the profitable-miner set, raising an attacker's cost floor — not concentrating reward in one vendor.

**Key structural facts established this cycle:**
- Sequential phases **average** their strong-vs-weak separations (time-weighted), they do **not** multiply — so the design collapsed from a five-phase relay to three phases on one substrate, with the two lever-bearing phases holding ~95% of episode time.
- Separation **multiplies within one phase** via `k(work-inflation) × b(bandwidth-deficit) × q(precision-tax)`.
- Phase 2's compute-inflation `k` is only **~1.33–2×** (host offload always caps it); its real separation is **bandwidth**, not compute — the reward model is tuned accordingly.
- The design is sound **conditional on three assumptions** (B0 cross-rung determinism, B1 nonce-bound state, B2 non-collapsibility), all three of which the normative spec §R closes by construction but which must be *proven* before ship.

---

## 1. Design philosophy: separation averages across phases, multiplies within one

This is the intellectual core and the reason the episode has three phases, not five.

**Averaging across phases.** Phases run in sequence, so episode time is a sum. If a weak machine runs phase *i* at ratio `rᵢ` and the strong machine spends time-fraction `wᵢ` there, the episode ratio is `Σ wᵢ·rᵢ` — a **time-weighted average**, bounded above by `max rᵢ` and dragged *down* by every low-separation phase. Piling on heterogeneous phases *dilutes* the advantage; every second the strong machine spends in a phase where it is not dramatically better is shelter granted to the weak machine.

**Multiplying within a phase.** Inside one phase, three deficits interact multiplicatively because they apply to the same operation stream: **work-inflation** (a memory-starved machine performs *more* operations — recompute, re-stream) × **bandwidth-deficit** (each operation's data arrives slower) × **precision-tax** (~2× per rung down FP4 > FP8 > INT8 > emulated). A machine short on all three pays the product, not the sum.

**The collapse to three phases.** Keep only phases that engage multiple deficit-multipliers, and give them nearly all the time. Phase 1 (residency: bandwidth × precision) ~30%; Phase 2 (capacity: work-inflation × bandwidth × precision) ~60–65%; Phase 3 (hash, weak separation) held to <5% and kept solely for commitment + transcript. Everything else from the five-phase relay (MoE, graph, prefix scan) was cut: MoE's required perfect balance removes the very scheduling irregularity it was meant to exploit and it carries the largest verification surface; prefix scan's serial fraction *hurts* strong machines.

**Roofline discipline (answered inside the phases, not by phase count):** keep every op **low arithmetic intensity** (rank-limited updates, small head dim, quantize-between-GEMMs) so all machines stay bandwidth-bound, where the strong machine's HBM ratio (4.5–8×) is realized — never let the workload drift compute-bound, where the strong machine's high roofline ridge point *shrinks* its lead.

---

## 2. Reconciliation & corrections (where the build-fleet sections adjusted each other)

The five sections are mutually consistent once three reconciliations are applied. They are stated here explicitly so downstream readers understand the final positions.

**C1 — Phase 2 separates on bandwidth, not compute.** The threat model (§5) proved Phase 2's compute-inflation `k` is bounded to ~1.33–2× for any rational miner, because √L / recursive checkpointing caps recompute at ~1.33× FLOPs and host-RAM offload always caps compute at ~1× (paying PCIe bandwidth instead). Therefore Phase 2 is **not** a large compute separator and **not** a hard capacity wall; its economic teeth are the **offload/cache-miss bandwidth penalty**. Phase 2 still earns its dominant time-share (it is the phase where capacity *forces* the extra bandwidth traffic), but the reward model (§7) is tuned to bandwidth, and the "steepest separation" language is corrected to "the phase that converts a capacity deficit into a bandwidth tax." To keep the RevNet O(1)-memory/2× bypass closed, Phase-2 layers MUST be non-invertible — which the spec's non-affine per-layer ExtractMX (§R.3) provides.

**C2 — B1 (nonce-bound state) is closed by the spec's seeding, not open.** The threat model's most dangerous attack is batching B nonces against a shared KV/weight state, which amortizes both levers to zero if the state is round-fixed and only the query is nonce-derived. The spec closes this: `seed₀ = SHA256("BTX_RC_ROUND_V1" ‖ sigma ‖ 0)` with `sigma = SHA256d(header)`, and *all* per-round operand seeds (Q, **KV**, W, Extract keys) descend from it — so the entire working set is **per-nonce distinct**. A miner cannot share KV across attempts because every attempt has a different header→sigma→KV. Generation cost G (one 192 MiB fill) is dominated by consumption C: each KV entry is re-read `n_q = 512×` in attention, so C/G ≈ 512 ≫ the required 64–256 threshold. "Template-scoped" in §R.2 refers to *within-round* streaming, not cross-nonce reuse.

**C3 — B2 (non-collapsibility, "C-16") is closed by non-affine ExtractMX, and is elevated to a named consensus assumption.** Softmax-free attention is linear, and linear attention collapses: `(QKᵀ)V = Q(KᵀV)`, with `KᵀV` computable once and shareable across nonces — simultaneously a shortcut and a total amortization. The *only* thing preventing collapse is the **nonlinear ExtractMX between S and Z** (`ExtractMX(QKᵀ)·V ≠ (QKᵀ)·V`). The spec makes ExtractMX non-affine by construction (ChaCha20 mantissa mix). This is now a load-bearing named assumption — **C-16 (non-collapsibility):** *no associative reordering of ExtractMX or the Phase-2 per-layer nonlinearity yields the exact episode digest with asymptotically less work.* It MUST be proven, not assumed; if ExtractMX were ever a linear rescale, Phase 1 is worthless.

Consistent across sections without conflict: the accumulator ruling (§R.1.4), the verification design (§R.5 + threat §5), and the reuse-vs-replace map (§6).

---

## 3. The three-phase architecture

**Phase 1 — Associative Recall (~30% of strong-machine time).** Softmax-free, exact-integer attention: `S = ExtractMX(Q·Kᵀ)`, `Z = ExtractMX(S·V)`, over a **per-nonce** KV state of ~192 MiB, sized to sit resident in a 256 MB Infinity Cache (MI355X) but overflow a 96 MB L2 (5090), which then re-streams from GDDR. Access pattern is round-seeded, so the working set cannot be compressed, partitioned once, or precomputed. Taxes on-chip cache capacity → bandwidth.

**Phase 2 — Micro-Training Page (~60–65%).** Exact integer forward-then-backward over a 16-layer, 4096-wide stack with a 2 GiB activation footprint. A big-memory part holds all activations; a 24 GB card checkpoints a subset and recomputes (or host-offloads) the rest. Nothing fails — the small machine pays a bandwidth tax (per C1, not a compute blow-up). The forward/backward dependency spine is what makes activation *memory* matter; a pure streaming kernel could tile its way out, a backward pass cannot.

**Phase 3 — Consolidation (<5%).** A wide/shallow SHA256d Merkle tile-tree over the round's tensors; the root seeds the next round (sequential round dependency) and is the streamable transcript. Kept tiny (Amdahl bound on the SHA-ASIC seam) and realized as a **tree, never a chain** (the serial-latency seam that sank the "Remembered Palace" memory-hard design — serial hashing favors CPUs/ASICs, which is the wrong hardware).

---

## §R — Normative exact-integer specification

*Ground truth: the int64 CPU reference of §R.5. All committed arithmetic is exact integer; no floating-point value may enter a committed reduction, an Extract input, or a serialized byte. Every conforming implementation MUST reproduce the episode digest byte-for-byte.*

### R.0 Notation, constants, structural parameter set

Operand alphabets inherited unchanged from the ENC-BMX4C / ENC-DR-LT substrate:
- **M11 mantissa** `μ ∈ {0,±1,±2,±3,±4,±6}`, `max|μ|=6`, no −0 (canonical signed magnitude). (`bmx4::kAlphabetM11`.)
- **E8M0 block scale** `e ∈ {0,1,2,3}`, factor `2^e`, one shared scale per **L=32**-element contraction block.
- **Dequantized operand bound** `E_max = 6·8 = 48`; every MX operand and every Extract output has `|value| ≤ 48`, fits int8.
- **Per-MAC product bound** `≤ 48² = 2304`.
- **FP32-mantissa exactness ceiling** `T24 = 2^24` (the boundary at which an FP32-accumulate "t=24" unit silently rounds).
- **SHA256d** = double SHA-256; tagged seed derivations `SHA256(tag ‖ …)`.

**Structural parameters (consensus constants, fixed by height, IDENTICAL for every nonce):**

| Symbol | Meaning | Value | Divisibility |
|---|---|---|---|
| `R` | rounds/episode | **4** | — |
| `d_head` | attention head dim | **128** | %32==0 |
| `n_q` | query rows/round | **512** | %32==0 |
| `n_ctx` | resident KV context | **786,432** (0.75 Mi) | %32==0 |
| `L_lyr` | training layers | **16** | — |
| `d_model` | training width | **4096** | %32==0 |
| `b_seq` | training activation rows | **16,384** | %32==0 |
| `T_LEAF` | tile-tree leaf | **1024 B** (32×32 int8) | — |
| `L` | MX block length | 32 | fixed |

Every value is a pure function of height, never of the nonce (§R.4.4). Resident KV footprint = `2·n_ctx·d_head` mantissa bytes + E8M0 scales ≈ **196 MiB** (the 180–240 MB band *is* the consensus quantity `n_ctx·d_head`). Training activation footprint = `b_seq·d_model·L_lyr·2` = **2 GiB**.

### R.1 ExtractMX — canonical exact semantics

Deterministic keyed requantization applied after every tensor stage; consumes an exact integer accumulator and emits an MX-block-scaled int8 operand. Because the Extract mantissa is a function of the **low-order bits** of the exact accumulator, any arithmetic error changes the output and is caught.

**R.1.1 Stage accumulator.** A stage is one GEMM (+ optional residual) producing `Y[i][j] = Σ_k A[i][k]·B[k][j] (+ residual)`. Evaluated in a two's-complement accumulator wide enough for the R.1.4 bound with zero wraparound; **consensus width is int64**. **HAZARD H1:** integer addition is associative/commutative, so any summation order yields identical `Y` **iff no intermediate re-quantization occurs**. Therefore **exactly one Extract per stage, on the completed `Y`**; re-quantizing/clamping/rounding a partial sum inside the k-reduction is **FORBIDDEN** (non-associative, would make tile order observable). This single rule makes every tiling produce identical bytes.

**R.1.2 The Extract map.** For element `(i,j)` in 32-column block `bj`, with stage-scoped `prf_key = DeriveMatExpandPrfKey(seed_stage)`:
1. `e = DeriveMatExpandMxScale(prf_key,i,bj) ∈ {0,1,2,3}` (position-only).
2. `μ = ExtractMatExpandMxTileMantissas(prf_key,i,bj,Y_tile32)[j mod 32] ∈ M11` — one ChaCha20 keystream per 32-cell tile, each accepted nibble XOR-mixed with the **exact two's-complement value of `Y[i][j]`**; rejection-sample into M11 (`SampleMantissaNibble`, accept 11/16).
3. `out[i][j] = μ·2^e ∈ [−48,48]`, one two's-complement int8.

Extract input MUST be the exact integer `Y` (never a float/rounded proxy; **H2**). Output canonical signed-magnitude int8, no −0 (**H8**). **ExtractMX is non-affine in `Y`** (the ChaCha mix) — this is what closes C-16 non-collapsibility (§2 C3). **Consequence:** the pre-Extract GEMM is not Freivalds-verifiable as a linear form; Extract stages are verified by recompute + tile-tree opening (§R.5), never a linear sketch.

**R.1.3 Fixed K-chunk promotion (t=24 eligibility).** A backend whose native accumulator is narrower than the stage's R.1.4 bound MUST promote the contraction into **balanced base-2⁶ limbs** (`kCombineLimbBase=64`, remainder-top), so each limb-pair partial stays `< 2^24`, recombining on a wide ALU; the digit identity `x = Σ 64^l d_l` is exact, so recombination is bit-identical to the oracle. A backend with a true ≥B-bit integer accumulator exceeding the stage bound MAY run natively. (**H3** closed.)

**R.1.4 Accumulator bounds — does 2^24 hold?** Per-element bound is `2304·K`:

| Stage | Contraction | Bound | vs 2^24 | vs 2^31 |
|---|---|---|---|---|
| P1 score `S=Q·Kᵀ` | 128 | 294,912 (2^18.2) | **holds** (57×) | trivial |
| P1 value `Z=S·V` | 786,432 | 1,811,939,328 (2^30.76) | **VIOLATED ×108** | fits, 1.18× (thin) |
| P2 fwd `W·X` | 4096 | 9,437,184 (2^23.2) | **holds** (1.78×) | trivial |
| P2 bwd `Wᵀ·G` | 4096 | 9,437,184 | **holds** | trivial |
| P2 wgrad `G·Xᵀ` | 16,384 | 37,748,736 (2^25.2) | **VIOLATED ×2.25** | trivial |

**Ruling.** The legacy `2^24` bound is a **per-GEMM FP32-mantissa property, not an episode invariant.** It holds for score + forward + backward (t=24-native OK); it is violated by `Z=S·V` (×108) and `G·Xᵀ` (×2.25), which MUST use **int64 or base-2⁶ limb promotion, never bare int32** (`Z=S·V` is only 1.18× under 2^31 — fragile). The episode-wide invariant replacing 2^24 is: **every stage accumulates in exact int64; each stage's `2304·K` is machine-checked `< 2^62`; a backend narrower than a stage's bound MUST limb-promote or fall back to the CPU oracle.** Headroom: `n_ctx` up to ~2×10¹⁸ before int64 overflow.

### R.2 Phase 1 — softmax-free FlashMX attention

`S = ExtractMX(Q·Kᵀ)` (`n_q × n_ctx`, contract `d_head`); `Z = ExtractMX(S·V)` (`n_q × d_head`, contract `n_ctx`). `Q` is round-seeded; `K,V` are the per-nonce resident KV state (§2 C2); the round seed perturbs `Q` and Extract keys, never shapes (C4).

**R.2.1 Index semantics.** Row-major; `Kᵀ` addressed by index arithmetic, never materialized: `S[i][t] = Σ_{d<d_head} Q[i][d]·K[t][d]`; `Z[i][d] = Σ_{t<n_ctx} S[i][t]·V[t][d]`. E8M0 blocks run along `d_head` for S, along `n_ctx` for Z. (**H12** closed.)

**R.2.2 Fixed tile schedule + tile-size invariance.** `S` (≈384 MiB) is never fully materialized; it is produced/consumed in ascending `n_ctx` tiles:
```
acc = 0                              # int64
for KV tile [t0,t0+ΔT):              # any ΔT partitioning n_ctx
    for t in [t0,t0+ΔT):
        s = ExtractMX_row(Q·Kᵀ)[i][t]   # exact; one Extract per S element
        acc += s · V[t][d]              # exact int64 add — NO re-quantization
Z[i][d] = ExtractMX(acc)             # exactly one Extract, at the end
```
**Tile-size invariance theorem.** Any two tilings of `[0,n_ctx)` yield identical `acc`, because each `S[i][t]` is Extracted from its own exact reduction (tiling-independent) and `acc` sums the same `n_ctx` exact integer terms (int64 add is associative/commutative). A machine forced to smaller tiles computes the identical `Z`. Holds **only** because softmax-free ⇒ no online rescale and no per-tile re-quantization (**H1'**). Any per-tile `Z` partial re-quant is non-conforming.

**R.2.3 Resident KV as a consensus parameter.** Stored `n_ctx × d_head` row-major (mantissa plane + E8M0 scale plane). Footprint ≈196 MiB fixed by `(n_ctx,d_head)`, retuned only at a fork height. A RAM-limited validator MAY stream/regenerate KV in tiles (invariance guarantees identical bytes). **KV size is a work/bandwidth knob, never a correctness knob.**

### R.3 Phase 2 — micro-training page

Per layer `l`, weights `W[l]` (`d_model × d_model`, round-seeded):
```
Forward:  X[l+1] = ExtractMX( W[l]·X[l] + X[l] )    # contract d_model; residual = X[l]
Backward: G[l]   = ExtractMX( W[l]ᵀ·G[l+1] )        # contract d_model
Wgrad:    D[l]   = ExtractMX( G[l+1]·X[l]ᵀ )         # contract b_seq
```
`X[0]`, `G[L_lyr]` round-seeded; `D[l]` is a transcript output.

**R.3.1 Bounds.** `W·X`,`Wᵀ·G` (K=4096) → `2^23.2 < 2^24` (t=24-native). `G·Xᵀ` (K=16,384) → `2^25.2 > 2^24` → int64/limb. All within int64.

**R.3.2 Residual rule.** Residual added **as exact integer to the pre-Extract accumulator**: `X[l+1]=ExtractMX((W·X)+X)`; pre-Extract value `< 2^24`. MUST NOT Extract `W·X` and residual separately (two Extracts = non-conforming; **H5**). **One Extract between two GEMMs; the residual is inside it.** The non-affine per-layer Extract is what makes each layer non-invertible (closes the RevNet bypass; §2 C1).

**R.3.3 Checkpoint output-invariance theorem.** For any checkpoint schedule `𝒞`, recomputed activations, gradients, and every `D[l]` are bit-identical. *Proof:* `X[l+1] = F_l(X[l])` with `F_l(x)=ExtractMX(W[l]·x + x)` a pure deterministic exact-integer function of `x` (W seed-fixed, GEMM exact + order-invariant, Extract deterministic); base `X[0]` seed-identical; induction gives identical `X[l]` from any stored checkpoint; backward mirrors it. ∎ **This is a memory↔time tradeoff, never a correctness difference (H9).** Sole requirement: recompute uses identical Extract semantics.

### R.4 Phase 3 — consolidation tile-tree + seeding + anti-grinding

**R.4.1 Canonical serialization.** Round byte stream, fixed order: `Z` → for `l=0…L_lyr−1`: `X[l+1]`,`G[l]`,`D[l]`. Row-major, one two's-complement int8 per element; no scales serialized (recomputable). (**H6/H10** closed.)

**R.4.2 Tile tree.** 1024-byte leaves (32×32 int8), last leaf zero-padded. `leaf_h = SHA256d(0x00 ‖ leaf)`. Binary tree `parent = SHA256d(0x01 ‖ left ‖ right)`; pad leaf count up to a power of two with a fixed sentinel `SHA256d(0x02 ‖ "BTX_RC_PAD")` (no duplicate-last rule; **H7**). `round_root_r` = root.

**R.4.3 Seeding.** `seed_{r+1} = SHA256("BTX_RC_ROUND_V1" ‖ round_root_r ‖ le32(r+1))`; `seed_0 = SHA256("BTX_RC_ROUND_V1" ‖ sigma ‖ le32(0))`, `sigma = SHA256d(header)` (binds nonce → closes B1). Per-round operand seeds derive from `seed_r` by distinct tags. **Episode digest** `= SHA256d("BTX_RC_EPISODE_V1" ‖ round_root_0 ‖ … ‖ round_root_{R−1})`, compared to `target(nBits)`.

**R.4.4 C4 anti-grinding invariant.** The nonce perturbs only **data values and Extract keys**. It MUST NOT influence `R, d_head, n_q, n_ctx, L_lyr, d_model, b_seq, T_LEAF, L`, tile counts, tree arity/depth, loop bounds, checkpoint-schedule *space*, or total MAC count. Every nonce performs identical total work over identically-shaped tensors. Any nonce-dependent shape/count/work-total is non-conforming, rejected at construction (compile-time asserts on the structural set). (**H4** closed.)

### R.5 The int64 oracle, self-qualification, winner reseal

**R.5.1 CPU int64 reference (sole ground truth).** `RecomputeResidentCurriculumReference(header,params,height)` — every GEMM exact int accumulation into int64 in fixed row-major ascending-k order; one ExtractMX per stage; serialize + tree-hash per R.4. MUST NEVER dispatch to an accelerated/FP backend (**R1 rule:** only the CPU reference may pronounce a block invalid). ε = 0 by construction.

**R.5.2 Self-qualification gate (fail-closed).** A native FP4/FP8/accelerated backend MAY serve **only after** proving **byte-identity to the CPU oracle at the consensus dimensions** `(d_head,n_q,n_ctx,d_model,b_seq)` — not toy shapes, because both accumulator regimes (`<2^24` and `>2^24`) only co-appear at full size. Qualification vectors MUST include partials (1) below 2^24, (2) across the 2^24 boundary (`Z=S·V` ×108), (3) near the int32 edge (`Z=S·V` ≈2^30.76). A backend that fails any vector or errors is **fail-closed**: fall back to CPU reference, clear `native_mxfp4_qualified`/`native_fp8_qualified`. Qualification is a performance fact, never a consensus prerequisite — the exact int8/int64 path is always available.

**R.5.3 Winner replay / reseal.** A solved block's nonce MUST be replayed through the CPU reference and its digest compared exactly to `header.matmul_digest`; mismatch aborts publication. On verify, the same recompute is the consensus predicate. The tile-trees form the streamable transcript: a spot-check verifier MAY, under Fiat-Shamir challenges seeded by `sigma`, open a bounded number of Merkle leaves and recompute only those stages as a DoS-bounded pre-filter — but a **reject** requires the full CPU int64 recompute (R1). Freivalds is admissible only as an optional accept-fast shortcut on a provably-affine sub-GEMM.

### R.6 Determinism-hazard register

| # | Hazard | Closure |
|---|---|---|
| H1 | Reduction order | single exact int64 reduction; no partial re-quantization (R.1.1) |
| H1' | Per-tile rescale in attention | softmax-free ⇒ one final Extract (R.2.2) |
| H2 | Extract fed rounded/float `Y` | Extract consumes exact int64 `Y` (R.1.2) |
| H3 | FP32 unit rounds past 2^24 | limb-promote or true ≥32-bit int (R.1.3/4) |
| H4 | Nonce grinds shapes | structural set height-fixed (R.4.4) |
| H5 | Residual Extracted separately | residual inside the single Extract (R.3.2) |
| H6/H10 | Endianness / concat order | row-major int8, fixed tensor order (R.4.1) |
| H7 | Odd Merkle promotion | fixed sentinel pad (R.4.2) |
| H8 | −0 / signed-byte | M11 no −0 (R.1.2) |
| H9 | Checkpoint changes activations | output-invariance theorem (R.3.3) |
| H12 | Transpose layout | index arithmetic pinned (R.2.1, R.3) |
| H13 | Block misalignment | all dims %32==0 asserted (R.0) |
| — | Accelerator rejects a good block | R1 + reseal (R.5) |

### R.7 Scheduled Scaling (future-proofing)

**Status.** PROVISIONAL control law + parameter surface. All growth constants below are **PROVISIONAL** (owner-set; monetary-adjacent) and MUST NOT be treated as final. Public activation remains **NO-GO** (`nMatMulRCHeight = INT32_MAX`). This section future-proofs the consensus shape so ENC_RC can track the durable AI resource profile for ~a decade without periodic governance size-refreshes; it does not schedule activation.

**R.7.1 Two scale dials + frozen ratios.** Split every absolute size from §R.0 into three classes:

| Class | Role | Members |
|---|---|---|
| **A — scheduled dials** | the *only* growing quantities | `W_res` (resident KV mantissa bytes; base ≈192 MiB), `W_cap` (activation bytes; base ≈2 GiB) |
| **B — frozen ratios/shape** | never scale | `d_head=128`, `L_lyr=16`, `d_model=4096`, `R=4`, `n_q/d_head=4`, phase-share targets (~30/65/<5%), C/G floor, `f3≤5%` |
| **C — eternal constants** | never scale, freeze forever | `L=32`, `T_LEAF=1024`, Fiat–Shamir `q=8`, all tags, SHA256d, soundness `2⁻⁶⁴`, **`kRCSegLen=32768`** (§R.7.4) |

Derived dims (recomputed from the dials each height; `round32` = nearest multiple of 32, then `%32==0` asserted — H13):

```
n_ctx = round32( W_res / (2 · d_head) )
b_seq = round32( W_cap / (2 · d_model · L_lyr) )
n_q   = 4 · d_head
```

At epoch 0 (`height == nMatMulRCHeight`) the dials equal the §R.0 base footprints, so the derived dims are bit-identical to today's frozen table (regression gate for any implementer).

**R.7.2 Pure schedule + ratchet + one-sided brake.** Growth is a deterministic pure function of the header chain up to `height` (like ASERT) — never of the nonce (C4). Per-epoch multipliers live in pre-committed Q16 tables (`nRCGrowthResTableQ16` / `nRCGrowthCapTableQ16`); they are **not** live floats. Control law sketch:

1. `epoch = (height − nMatMulRCHeight) / nRCScaleEpochBlocks` (inert while height unset / below activation).
2. Start from `(W_res, W_cap) = (W₀_res, W₀_cap)`; for each prior epoch `e`, multiply by the table entry **iff** the brake allows the step, then clamp to absolute hard caps (`nRCScaleHardCapResBytes` / `nRCScaleHardCapCapBytes`).
3. **Ratchet:** `W` is non-decreasing — a skipped (braked) step leaves the dials unchanged; dials never shrink.
4. **One-sided brake (pause-only):** compare smoothed chainwork-per-block over the closing epoch (`D_now`) to the trailing ~1 yr max (`D_ref`). Allow the step iff `D_now ≥ (1 − δ)·D_ref` with `δ = nRCBrakeDeltaPct` (PROVISIONAL default 20%). Growth can **only be paused**, never accelerated and never reversed. A miner cannot force growth (schedule is a hard cap) and can only pause it by withholding >δ of global hashrate for a full epoch — huge cost, pause-only payoff that *helps* small machines. No committee, no oracle, no miner-reported telemetry.

**OMITTED (FINAL-FORM Stage F6 / A3):** the chainwork brake is **not** active in code. `BrakeAllowsStep` always returns true; `ConsensusRCEpisodeParamsForHeight(..., CBlockIndex*)` ignores `pprev`. Growth is already parked via `kRCGrowthScheduleEnabled=false`. Reintroduce the brake only with full `CBlockIndex` threading + reorg-safe epoch-boundary caching — never half-wire.

PROVISIONAL schedule knobs (inert while `nMatMulRCHeight==INT32_MAX`): epoch length ≈90 d at 144 blk/day (`nRCScaleEpochBlocks=12960`); decaying geometric starting ~`g_res≈1.40/yr`, `g_cap≈1.25/yr`, stepping down ~0.02 every 12 epochs (~3 yr); hard caps 4 GiB KV / 16 GiB activations; table length 40 (~10 yr of quarterly epochs).

**R.7.3 Format-blind ladder.** Consensus names **no** hardware format (FP4 appears nowhere; only the M11×E8M0 alphabet + int64 accumulator + one Extract/stage). Any future format (FP2 / MXFP-next / ternary) needs **zero governance**: write a backend, pass fail-closed byte-exact self-qual at the *live epoch* dims, mine faster. Do not narrow the committed M11 alphabet here (would fork + thin operand entropy + pressure C-16).

**R.7.4 Fixed segmentation (`kRCSegLen=32768`).** For every long reduction whose contraction grows with a dial — Phase-1 `Z=S·V` (`K=n_ctx`) and Phase-2 wgrad `G·Xᵀ` (`K=b_seq`) — partition into consensus-FIXED segments of length `kRCSegLen`. Each segment's exact int64 partial is committed as additional tile-tree leaves (append to the round byte stream before the final tensor; R.4.1 order). Final value = int64 sum of committed partials (associative/exact). The H1 single-Extract rule is **unchanged**: Extract still fires once on the completed sum; segmentation is consensus-fixed, never miner-chosen.

Effects: a Fiat–Shamir spot-check recomputes **one** segment — `O(kRCSegLen · d_head)`, **constant forever** regardless of `n_ctx`/`b_seq` growth (verification O(1) as a DoS pre-filter). Per-partial bound freezes at `2304·kRCSegLen ≈ 2^26.2` (still needs int64 / limb; assert `< 2^62`). Tree depth grows `O(log W)`; `T_LEAF` stays 1024. A REJECT still needs full CPU recompute (R1), which grows linearly with `W` — that is the verifier-floor limit (§R.7.6).

**R.7.5 Epoch asserts + fallback.** After deriving dims, machine-check every §R invariant (dims `%32==0`, `2304·kRCSegLen < 2^62`, C/G reuse-factor ≥ 64, `f3 ≤ 5%`, nonce-independence of dials). On **any** failure: fall back to the **previous epoch's** dims (skip the step) — never fudge values, never crash consensus. Unattended growth is safe iff every epoch that would break an invariant is simply not applied.

**R.7.6 Honest residual (verifier floor).** The question "can the smallest honest full node still replay one episode within a block interval as `W` grows?" is **not** trustlessly observable on-chain. It needs a ~4–5 yr human curve-fit review, and it is the load-bearing reason the **growth ceiling stays human-set** (`nRCScaleHardCap*`). The schedule tracks the durable resource profile mechanically; it does not remove that one human check, by design. All growth constants remain **PROVISIONAL** until that review (and an explicit owner ratification) lands.

---

## 4. Threat model, hardness, and soundness blockers

Adversary: can build heterogeneous farms, batch across nonces, reorder computation, substitute exact algebraic shortcuts — but must emit a digest the int64 oracle reproduces bit-for-bit.

- **Nonce-grinding (C4):** safe iff zero data-dependent control flow. No sparsity/routing/MoE/early-exit/dynamic schedules; ExtractMX is dense fixed-layout, never sparse compaction; operands are full-entropy PRG expansions. `Work(n)=const`. Closed by R.4.4.
- **Amortization (B1):** the levers exist only if the full working set (KV **and** Phase-2 weights/activations) is nonce-bound. Closed by the `sigma`-seeded per-nonce derivation (§2 C2), with generation cost G ≪ consumption C (n_ctx re-read n_q=512×). Recompute-on-read is not a free bypass (re-reads cost N×PRG > a VRAM fetch).
- **Capacity ceiling (bound on k):** compute-inflation `k ∈ [1.33, 2]` for any machine holding ≥O(√L) activations; host offload caps compute at ~1×. **Phase 2's separation is bandwidth, not compute** (§2 C1). Do not size the reward model expecting a large compute gap.
- **Shortcut attacks:** approximation killed categorically by the exact digest (C-15). Exact fast matmul (Strassen) self-blocked by per-block MX scales (confined below crossover, uniformly available). Low-rank operands closed by full-entropy PRG operands. **Associative collapse (C-16) closed only by non-affine ExtractMX** — the load-bearing assumption (§2 C3).
- **Verification DoS (C3):** full per-block replay is a DoS; the design is **optimistic** — Merkle-commit intermediates, Freivalds on affine sub-GEMMs, Fiat-Shamir spot-checks on nonlinear stages, full CPU replay only as fraud proof. Query count pinned so transcript-grinding ≥ 2⁶⁴ and total verifier work ≤ a small multiple of header validation, soundness ≤ 2⁻⁶⁴.
- **ASIC resistance:** honestly *commodity-AI-accelerator PoW won by frontier silicon* (hyperscaler-capture risk — disclosed as design intent), resistant only to bespoke single-function hashing ASICs. Phase 3 (SHA256d) is the ASIC-vulnerable seam: bounded by Amdahl to ≤2–5% of work, and realized as a wide/shallow **tree** (not a chain) to deny the serial-latency seam.

**Prioritized blockers (must close before ship):**
- **B0 — Cross-rung bit-determinism** (prerequisite to all): every precision rung emits integers identical to the int64 oracle; throughput only, never result.
- **B1 — Full-working-set nonce-binding** (closed by spec §R.4.3; must be verified in implementation).
- **B2 — C-16 non-collapsibility** (closed by non-affine ExtractMX + non-invertible layers; must be *proven*).
- **B3 — Optimistic verification, priced** (construction: commit + Freivalds + Fiat-Shamir; pin k,c,q).
- **B4 — Constant-shape invariant** (construction: R.4.4).
- **B5 — Phase-3 containment** (parameter: f₃ ≤ 2–5%, wide/shallow tree).

---

## 5. Hard-fork integration & reuse-vs-replace

RC is a re-composition of the existing exact-MX substrate, not greenfield. **Reuse everything that establishes bit-exact integer ground truth; replace only the lottery object and the work shape.**

| Existing component | Disposition |
|---|---|
| `matmul_v4_lt` MatExpand GEMM (`kMatExpandPanelW`) | **Reuse** as the P1/P2 GEMM primitive (called more times, against resident operands). |
| `ExtractDequantMatExpand` ChaCha20 path (M11/E8M0, `kMatExpandMxBlockLen=32`) | **Reuse verbatim** as the operand-derivation PRF and the non-affine Extract (this *is* the precision ladder). |
| `matmul_v4_exact_float` Ozaki slice / `MaxExactAccumBlock` | **Reuse** as the FP4/FP8 exactness contract (limb promotion for the >2^24 stages). |
| `backend_capabilities_v4` self-qual + `self_test_required` | **Reuse framework; CLOSE the gate** — make `self_test_required` fail-closed at runtime (consensus-relevant hardening). |
| `src/cuda/*mxfp4*`,`*fp8*` (`native_*_qualified=false`) | **Activate per-device at runtime, only after self-qual passes** (never by build config). |
| Q* Merkle seal (`ComputeSealDigest…`, `DeriveWindowSlotId`, `CommitWindowSlotLeaf`) | **Extend** — repoint leaves from Q* slots to episode tile-tree tiles; header lottery object becomes the RC episode seal. Segregated-proof relay already deleted in v4.4 → RC stays digest-only (transcript recomputed, never relayed). |
| Authenticated chainwork (`IsBlockAuthenticated`, `GetTrustAdjustedChainWork`) | **Unchanged** (only *what* is authenticated changes). |
| ASERT, header-PoW identity, compact relay | **Unchanged** + one one-time rescale/re-anchor at activation (same code path as prior re-anchors). |
| Freivalds (`nMatMulV4FreivaldsRounds=3`) | **Reuse** for the accept-fast path on affine sub-GEMMs. |

**Net new code:** one `matmul_v4_rc.{h,cpp}` (episode orchestration + tile-tree seal), one profile enum `ENC_RC=5` + `nMatMulRCHeight` + `IsMatMulRCActive` + `nRC*` constants in `params.h`, one `CheckMatMulProofOfWork_RC` in `pow.cpp` + one ASERT re-anchor, and the fail-closed `self_test_required` enforcement. Chainwork, difficulty core, and relay are untouched.

**Clean cutover.** Every MatMul activation height is currently `INT32_MAX`; no MatMul profile has ever gone live. RC can be the **first and only** profile activated — no migration, no proof-store to migrate. Height selects the ruleset before any digest is interpreted; a version bit provides BIP9-style pre-activation readiness signaling; flag-day fork with ~2-week grace + checkpoint at `h−1`.

---

## 6. Reward-scaling model & honest economics

Reward-per-dollar = (attempts/sec) ÷ (rental $/hr). RC shapes the episode so attempts/sec is **bandwidth × capacity × concurrency**-bound (Phase 1 residency + Phase 2 offload-bandwidth), while cost is rental price. The purpose is to steepen the pre-Blackwell tail out of viability, not to beat the flagship consumer card.

| Tier | Role | Reward-per-$ (rel.) | Why |
|---|---|---|---|
| **MI355X (thin config)** | **Cost-efficiency winner** | **1.0–1.3×** | 256 MB Infinity Cache holds the ~192 MiB KV resident; high HBM keeps activations resident. Thin win. |
| **RTX 5090** | Reference / uncatchable | ~1.0× | Native FP4 + 96 MB L2 dodge both levers. **Cannot be beaten by more than the thin MI355X margin.** |
| **B200** | Per-dollar loser | ~0.5× (**2× worse**) | Fast (4.5–6×) but rental (10–13×) scales faster. Absolute-throughput king, cost-efficiency poor. |
| **H200** | Marginal | <1× | FP8 (one rung down); ample capacity but uncompetitive $/attempt on this working set. |
| **RTX 3090** | Priced out | ~0.3–0.4× (**2.5–3× worse; 8–13× slower**) | 24 GB forces P2 checkpoint/recompute; 6 MB L2 can't hold KV → P1 at DRAM bandwidth; INT8-only (~4× precision tax). Both levers bite. |
| **Owner-operated (any tier)** | Never excluded | n/a | Zero $/hr rental → positive marginal reward even on a 3090. RC taxes *rented* cost-efficiency, never bricks owned hardware. |

**Honest bottom line:** RC delivers (a) a thin MI355X cost-efficiency win at the top, (b) a competitive, uncatchable flagship 5090, and (c) a **steep economic cliff for the pre-Blackwell tail** — the actual security-relevant outcome. It does *not* deliver "biggest datacenter chip dominates," and it cannot, soundly (§ hardware-economics-inversion study). The centralization it does create is toward *commodity frontier AI silicon*, which must be disclosed.

---

## 7. Graceful degradation (no hard exclusion)

Every tier completes the identical episode and produces the identical transcript; each degrades on a *different* axis; the penalty is always time.

| Tier | P1 recall (~192 MiB KV) | P2 training page (2 GiB activ.) | Precision path | Finish (illustrative) |
|---|---|---|---|---|
| MI355X / B200 | fully cache-resident | holds all activations | native FP4 | 1× |
| H200 | re-stream from HBM (4.8 TB/s) | holds all | FP8 (~2×) | ~1.5–2× |
| RTX 5090 | re-stream GDDR7 (1.8 TB/s), modest | holds ~all; light checkpoint | native FP4 | ~2–3× |
| RTX 3090 | full re-stream (0.94 TB/s), no cache shelter | checkpoint+recompute (k≈1.3–2×) | INT8 (~4×) | ~8–15× |
| M-series Mac | re-stream unified (0.4–0.8 TB/s) | large unified often holds activations | INT8/emulated | ~15–30× |
| CPU | streams from DDR | holds in DRAM; ~10²–10³× slower/op | emulated (bottom rung) | ~50–150× |

Different machines taxed on different axes; coping mechanisms (re-stream, checkpoint, offload, emulation) are honorable systems techniques; **no row says "cannot run."** Verification inherits the softness: checking ≪ producing, so even sub-viable earners remain viable auditors.

---

## 8. Prototype & measurement roadmap

Build minimum-verification-surface first; measure the decisive unknown (Phase 2 `k`) second; integrate last. Grounded in the existing `contrib/matmul-v4/measure-hardware.sh` / `verify-backend.sh` / gate-script idiom.

1. **ExtractMX qualification harness** — int64 reference + tensor kernels (B200/MI355X/5090/3090/M-series/CPU) + randomized episodes + high-magnitude boundary vectors with on-device runtime markers. **Gate G1:** byte-identical over ≥10⁴ episodes/platform incl. boundary vectors; fail → fail-closed to integer path. Reference divergence between two CPUs = design-killing.
2. **Phase 1 Associative Recall Maze** (first *workload*; the external "Phase 1 first" suggestion adopted as step 2, after ExtractMX). Working-set sweep 64→256 MB. **Gate G2:** byte-identical transcripts; resolvable residency cliff in 96–256 MB (≥1.5×); ≥40% STREAM-peak bandwidth utilization (confirms bandwidth-bound).
3. **Phase 2 k-curve** (the decisive unknown) — full-residency vs √L checkpoint vs host-offload, all byte-transparent; measure `k(M)` down through the 24 GB / 8 GB / 2 GiB caps. **Gate G3:** identical digests across strategies; k variance ≤5%; defensible k at 24 GB.
4. **Integrated 3-phase episode.** **Gate G4:** end-to-end byte-identical; verify ≤1% of episode cost; variance ≤5%; tier separation target met.
5. **Graph/MoE** only if a priced axis is left unpriced.

**Go criteria:** byte-exactness everywhere; **k ≥ 1.3** at 24 GB; cache cliff ≥1.5× in 96–256 MB; integrated tier separation ≥5× frontier-vs-previous-gen and ≥20× vs CPU; all 512 MiB/2 GiB/8 GiB cap runs byte-correct. **Kill criteria:** **k < 1.1** (Phase 2 dead → trigger graph phase); any fast-path byte-exactness failure unrepairable (fail-closed) or **int64 reference divergence between CPUs** (design killed); no cache cliff anywhere <512 MB; episode variance >10%; tier separation <2×.

---

## 9. Consolidated decision list — what must be true before ship

1. **B0 cross-rung determinism** proven (G1 harness, all platforms, consensus dimensions).
2. **B1 nonce-binding** verified in implementation (KV + weights descend from `sigma`; G ≪ C).
3. **B2 / C-16 non-collapsibility** proven for ExtractMX and the non-invertible Phase-2 layers.
4. **B3 optimistic verification** built and priced (k,c,q for ≤2⁻⁶⁴ soundness, ≥2⁶⁴ grinding, cheap verify).
5. **B4 constant-shape** enforced by construction (compile-time asserts on the structural set).
6. **B5 Phase-3 containment** (f₃ ≤ 2–5%, wide/shallow tree).
7. **Accumulator ruling** implemented: int64/limb for `Z=S·V` and `G·Xᵀ`; never bare int32.
8. **`self_test_required` fail-closed** enforced at runtime; `native_*_qualified` flipped per-device only after self-qual at consensus dimensions.
9. **Measurement gates** G1–G4 passed; **the decisive k ≥ 1.3** measurement confirmed on real 24 GB silicon.
10. **Fork parameters** finalized from measurement (KV size, R, layer/width, self-qual dims, ASERT re-anchor), activation height set.

### Honest limits (unmovable)
- The RTX 5090 (native FP4 + 96 MB L2) cannot be made uneconomical soundly; RC does not beat it by more than the thin MI355X margin.
- Owner-operated hardware on marginal power cost is never priced out (C2 / no hard gate).
- The biggest datacenter part is not the per-dollar winner (rental scales with capability); the B200 is a ~2× cost-efficiency loser.
- Phase 2's separation is bandwidth (not compute); total tail tax saturates ~10–30× wall-clock, ~2.5–3× cost — never the FP4-vs-3090 peak ceilings (127–141×).
- The design is **commodity-AI-accelerator PoW won by frontier silicon** — a disclosed centralization tradeoff, the opposite of egalitarian ASIC-resistance.

**Verdict:** the Resident Curriculum is the best available realization of "stronger machine decisively out-earns weaker machine, gracefully" — sound conditional on B0/B1/B2 (all closed by construction in §R, to be proven), built almost entirely on the existing exact-MX substrate as a clean first-activation hard fork, and honest about its ceiling: it ages out the pre-2025 tail without excluding anyone and without pretending to dominate the newest consumer card.
