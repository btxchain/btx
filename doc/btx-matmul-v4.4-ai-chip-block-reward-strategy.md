> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul — Long-term multi-arch PoW for AI-chip block rewards

*Research synthesis (2026-07-19). Parallel agents + web research + code audit.
Not an activation decision. Branch remains inert (`INT32_MAX`).*

## Desired outcome

Datacenter AI accelerators (H200 / B200 / MI350 / Rubin) win **more blocks** and preferably beat RTX 5090-class retail on **blocks-per-dollar**, across vendors, through the Rubin era — without NVFP4 lock-in.

## What current ENC-BMX4C structurally cannot do

| Fact | Evidence |
|---|---|
| Linear Freivalds sketch → optimal miner never forms full C; work is skinny `(U A)(B V)` | `m=1024`, ~25% INT8 util |
| B200 ≈ **2×** 5090 on those shapes vs **4–6×** on huge dense INT8 | PR #89 on-silicon |
| SHA/XOF floor is **class-flat** | redesign + exact-accel-lanes |
| Miner-local opts (Karatsuba, device loop, MXFP4) help util, **cannot close 15–20× $/TOPS gaps** | economics outside consensus |
| **Rubin kills INT8-primary PoW**: published **250 TOPS INT8** vs **17.5 PF FP8** / **35–50 PF NVFP4** | [NVIDIA HGX](https://www.nvidia.com/en-us/data-center/hgx/) |
| 5090 also has FP4 (sm_120); FP4 alone does **not** tilt DC | PR #89 measurements |
| ENC-DR makes deeper `m` **storage-free** (D’s 32 MiB veto is gone) | v4.4 tension resolution |

**Ceiling:** consensus bytes can force *work shape* and *alphabet*; they cannot force fleet economics. But the current shape still leaves most of the DC advantage on the table.

---

## Hardware constraints (2026–2028)

| Part | Memory | BW | Fast pipe | Slow / dead pipe |
|---|---|---|---|---|
| RTX 5090 | 32 GB GDDR7 | ~1.8 TB/s | FP4/INT8 (sm_120) | no tcgen05/TMEM |
| B200 | ~192 GB HBM3e | ~8 TB/s | FP4/FP8/INT8 | — |
| MI350X | 288 GB HBM3E | 8 TB/s | **OCP MXFP4/8**, INT8 | — |
| Rubin | 288 GB HBM4 | ~22 TB/s | **NVFP4 / FP8** | **INT8 250 TOPS** |

**Portability rule:** commit **OCP MX (E8M0) / INT8 / E4M3-exact digits** — never NVFP4 fractional scales as consensus semantics.

---

## Ranked hard-fork options

### Rank 1 — Flagship: Tensor-native expand + deep-`m` under ENC-DR + consensus Q\*

**Ship as the v4.4-LT consensus package.**

1. **Raise `m` under ENC-DR** (primary geometry lever)
   - Phase A: `b=4→2`, `m=1024→2048` → ~**3.6×** enforced MACs, verify O(n²)+~25%, **0 B** permanent sketch
   - Phase B (gated): `m→4096` (near full-C shortcut ~1.5×)
2. **Replace SHA operand XOF with MatExpand** (kill class-flat floor)
   - Nonce-fresh `B` (and optionally A) derived via dense exact-int GEMMs against a height-scoped public mixer `G`
   - SHA retained only for seeds / σ / digest seal
3. **Consensus-bound window `Q*`** (force fat GEMMs)
   - Lottery over a window of `Q*∈{64,128}` sketches (Merkle of digests or stacked commit)
   - Verifier Freivalds-checks `r∈{1,3}` random slots + Merkle — not all Q\*
4. **Keep path-agnostic integer Ĉ** + miner FP8/MXFP4 lanes (Rubin hedge without alphabet lock-in)

| Knob | Today | v4.4-LT |
|---|---|---|
| `n` | 4096 | 4096 launch → 8192 after soak |
| `b` / `m` | 4 / 1024 | **2 / 2048** then **1 / 4096** |
| Expand | SHA-256 XOF | **MatExpand** (tensor) |
| `Q*` | miner-only ~32 | **64–128** consensus |
| Commit | ENC-DR digest | unchanged (32 B) |
| Alphabet | M11+E8M0 | keep; FP8 digits miner-local |

**Why DC wins $/nonce:** tensor wall-time majority + fat tiles → utilization approaches dense peak ratios; SHA floor shrinks; ENC-DR removes the old 32 MiB activation veto.

**Risks:** MatExpand needs shortcut/cryptanalysis (C-15 class); ASERT must recalibrate from B200 **and** 5090 measured nonce/s; still may lose to a *fleet* of cheap 5090s if retail $/TOPS stays extreme — but this is the only consensus-feasible path that attacks the *measured* failure modes.

---

### Rank 2 — Aggressive: ENC-DR-CAP (HBM capacity barrier)

| Param | Value |
|---|---|
| `n` | **16384** |
| `b` | 4 → `m=4096` |
| `Q_min` | **128** (single-GPU normative schedule) |
| Working set | **W(Q) ≈ 55–65 GiB** |

5090 (32 GB) must spill → PCIe thrash → rate crater. B200/MI350/Rubin keep the batch resident.

**Verify:** Freivalds still O(n²) but ~16× n=4096 → tip **2–6 s** without help; needs sketch-cache + async pool + depth policy.

**Opinion:** powerful, but higher DoS/IBD risk than Rank 1. Prefer as **Phase C** after MatExpand+deep-m GO/NO-GO, or as runner-up **ENC-DR-DEEP** (`n=8192`, `Q_min=64`, W≈25–30 GB) if 16k verify is unacceptable.

---

### Rank 3 — j-chain (hash-light depth)

`j∈{2,3,4}` sequential dependent combines per nonce; final digest only. Grows MAC wall linearly; SHA stays flat. Good supplement to Rank 1; do not use alone.

---

### Rank 4 — Succinct deeper commit (ENC-SC class)

Only if measured **κ≈1.00–1.05** (prior draft κ=1.42–2.4 was disqualified for re-inflating SHA). Shelf successor if deep-m under DR still leaves $/nonce inverted.

---

## Explicitly reject

| Idea | Why |
|---|---|
| NVFP4 as committed format | Single-vendor; fractional scales break exactness |
| Betting on INT8 through Rubin | Published 250 TOPS — thesis failure |
| Ternary / &lt;~3.4-bit alphabet | BNN/LUT cliff |
| Growing SHA / FRI κ≫1 | Recreates consumer-favoring floor |
| Skinny GEMMs / tiny Q as the unit | Launch-bound; clocks win |
| Analog / optical commitment | No exact-integer path |
| Miner-only opts as the strategy | Cannot guarantee $/nonce |

---

## GO/NO-GO gates (silicon, before activation)

1. Tensor wall-time **majority** on B200 and 5090 at the new unit
2. B200/5090 nonce/s **≥ ~4×** on the fat shape (toward dense peak ratio)
3. **Nonce/$** proxies (rental + purchase) show B200 ≥ 5090 (honest: may still fail on fleets)
4. MI350 FER / exactness gate PASS on OCP MX path
5. MatExpand adversarial review (no linear collapse into Freivalds)
6. Tip verify budget with sketch-cache + async pool within policy
7. Header-PoW + authenticated chainwork blockers still required (unchanged)

---

## Implementation order (consensus track)

1. **Now (docs + params scaffolding, inert):** pin Rank-1 parameter sheet; MatExpand design + goldens plan
2. **Code (still inert):** `m` retarget plumbing under ENC-DR; `Q*` window digest rules; MatExpand reference
3. **Measure:** B200 / 5090 / MI350 / H200 soak on Rank-1 shapes
4. **Optional Phase C:** CAP/DEEP memory barrier if $/nonce still inverted
5. **Activate** only after gates + existing security blockers

---

## Bottom line

Consensus **has not** exhausted levers — but it has exhausted *miner-local* ones. The creative, multi-arch path that best delivers “AI chips win blocks” is:

> **ENC-DR + deeper `m` + tensor-native expand + consensus-bound fat Q\*, with exact FP8/MXFP4 miner lanes for Rubin — not another INT8 alphabet, not NVFP4 lock-in, not a SHA-heavier proof system.**

**Implementation status (this branch):** Rank-1 is scaffolded as **ENC-DR-LT** (`doc/btx-matmul-v4.4-lt-normative-spec.md`, adversarial: `doc/btx-matmul-v4.4-lt-adversarial-analysis.md`): nonlinear MatExpand (ChaCha20-PRF + M11 Extract candidate; C-15 OPEN), deep-m `b=2`, Q* fat miner windows (Phase A; seal-as-PoW Phase B), ASERT DRLT rescale hooks, `ComputeDigestsBMX4CLTDispatched`, CUDA/Metal/HIP surfaces, inert `nMatMulDRLTHeight=INT32_MAX`. See `scripts/matmul_lt_readiness.sh` / `contrib/matmul-v4/lt-gate.py` (G5 = external C-15 ack; not auto-pass).

A pure HBM capacity gate (Rank 2) is the nuclear option if geometry+expand still lose on dollars.
