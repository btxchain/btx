# BTX MatMul v4.6 ENC_RC — Verify-time budget, cost model & hardware baseline

**Date:** 2026-07-23
**Branch / PR:** `claude/matmul-v4-design-spec-af23sj` (PR #89)
**Status:** design spec for the profile-2 (datacenter) sampled-carrier **verify-time**
path. Activation remains OFF on every public network (`nMatMulRCHeight =
nMatMulRCCoupledHeight = INT32_MAX`, formal arbiter hard-disabled). This document
records (a) the 900 ms wall-clock verify budget and where it applies, (b) the
cost model of the sampled-carrier verifier — what is reducible and what is
irreducibly SHA-bound, (c) the design levers that brought the ARM reference to a
GO, and (d) the **validator hardware baseline decision: SHA-acceleration + int8
dot-product (SHA-NI/SHA-ext + VNNI/i8mm) is the supported floor.**

Companion docs: `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md` (what v4.6
is, soundness accounting, activation gates); `doc/btx-matmul-v4.5-rc-frozen-
production-dimensions-2026-07-21.md` (production dims); `doc/btx-matmul-v4.5-rc-
datacenter-advantage-defaults-2026-07-21.md` (profile-2 rationale).

---

## 1. What the budget governs

The consensus arbiter of record is **int64 exact CPU replay**
(`RecomputeResidentCurriculumReference` / `RecomputeCoupledPuzzleReference`); a
block is valid iff its claimed result byte-identically replays. The **sampled
carrier verifier** (`matmul_v4_rc_freivalds_sampled.cpp`) is the *relay-time*
sublinear check that lets a node accept-and-forward a profile-2 carrier without
paying the full O(N) replay on the network path. Its wall-clock time is what the
900 ms budget bounds — the time a validating node spends verifying one carrier
before relaying it.

The budget is a **relay-path liveness bound, not a soundness parameter.**
Soundness comes from k=U forced unit coverage (all ≈400 units checked; single-
fault detection is linear and non-amplifiable — no Freivalds amortization is
admissible because H is unpublished) and from exact int32 recompute. The budget
only decides *which hardware can keep up with block flow*; it never relaxes what
is checked.

---

## 2. The four-phase parallel verifier

The carrier verifier runs in four phases with a determinism invariant that is
consensus-critical:

1. **plan** — deterministic: derive the sampled unit set and per-unit operand
   addressing from the transcript.
2. **prewarm** — deterministic: regenerate the operands the sampled units read
   (the PRF/SHA-XOF cost).
3. **unit-check** — parallel: exact int32 recompute of each sampled unit
   (packed int8 dot-product), compared against the committed tiles.
4. **reduction** — deterministic: fold per-unit verdicts into one verdict+reason.

**Invariant (gate):** `par=1` and `par=N` must produce byte-identical
verdict **and** reason string. Parallelism is a scheduling detail; the decision
is not allowed to depend on thread count. This is enforced in the sampled-carrier
tests and is a hard consensus gate — a verifier whose verdict depends on its
thread pool is a consensus split.

---

## 3. Cost model — reducible vs. irreducible regen

The prewarm phase dominates on the budget-stop (cold-first-unit) path. The
operands split into two classes:

### 3.1 Reducible (row-block addressable)

- **X0** (`0.334 GiB` full). SV/FFN units read only a handful of 32-row blocks.
  X0 is generated in 32-row blocks, each seeded via
  `DeriveX0RowBlockSeed(seed_x0, block)` at `kRCX0RowBlockRows = 32` granularity,
  so the verifier regenerates only the sampled blocks — **2.67 GiB → ~2 MiB**
  across the sample set. Gated on `UseDatacenterRowBlockX0(p)`
  (`matmul_v4_rc.cpp`). This is byte-changing vs. the pre-row-block operand and
  was re-goldened for profile-2 (profile-2 is not active, so this is allowed).

### 3.2 Irreducible (contraction-bound — full operand required)

- **W_up / W_down** — contraction-bound; every output row reads the full weight
  matrix. **Config W** (below) makes these episode-wide (one pair, not R pairs),
  which is the ~5× structural cut, but each remaining pair is still regenerated
  in full.
- **V** — the SV attention output contracts over **all** `n_ctx = 786432` K/V
  rows (~96 MiB per operand). No matter which SV unit is sampled, the full K/V
  operand must be regenerated. **Row-block addressing does not help here** — the
  contraction domain is the whole context, so there is no sub-slice to skip.

Because §3.2 operands are regenerated through SHA-256 counter-mode XOF
(`ExpandMantissaStream`), the residual prewarm floor is **SHA-256 throughput on
~200 MiB of episode-shared K/V when SV units land in the sample set.** That is
the wall, and it is fundamental to the construction, not a kernel-quality
deficiency.

---

## 4. Design levers (what got ARM to GO)

| Lever | Phase attacked | Effect |
|---|---|---|
| **Config W** — episode-wide FFN weights (`sigma`-derived), X0 per-round chain-bound (`seed_r`-derived) | prewarm | weight-regen R pairs → 1 (~5×) |
| **Row-block-addressable X0** (`DeriveX0RowBlockSeed`, 32-row blocks) | prewarm | X0 regen 2.67 GiB → ~2 MiB; prewarm 0.84 s → 0.21 s |
| **Four-phase parallel unit-check** + **packed SMMLA / VNNI** exact int32 recompute | unit-check | unit-check 0.84 s → 0.12 s (ARM) |
| **Hardware SHA** (ARM SHA-ext) / **AVX2 8-way multibuffer SHA** (x86) | prewarm floor | the only lever on the §3.2 SHA floor |

### 4.1 Config W anti-collision (load-bearing)

Config W shares FFN weights across the episode but keeps **X0 per-round and
chain-bound**: `seed_r = hash(round_roots[r-1], r)`, and the verifier recomputes
X0's sampled rows against the committed `round_roots`. Without this binding, a
miner could force `X0_r == X0_r'` and collapse R rounds into one. The chain-
binding is what makes shared weights safe; it is enforced in code and tests.

### 4.2 Packed int8 recompute exactness

The SMMLA (ARM i8mm) / VPDPBUSD (x86 AVX-512-VNNI) packed paths compute exact
int32 because `k·127·127 < 2^31`. Both are self-test-gated (multi-vector scalar
self-test at init) with an exact scalar fallback that *initializes* output to
zero and accumulates exactly — never silent zeros. Byte-identity of the packed
path to the scalar reference is a consensus gate: an x86 VNNI path that is not
byte-identical to the ARM path is a split and must not land.

---

## 5. Measured cross-hardware results

| Machine | ISA features | Threads | Total | Verdict | Budget ratio |
|---|---|---:|---:|---|---:|
| **Apple M4 Max** (Mac Studio) | SHA-ext, i8mm (SMMLA) | 16 | **330 ms** | **GO** | 0.37× (2.7× margin) |
| Intel Xeon W-3245 (2019, Cascade Lake-W, Mac Pro) | AVX-512-VNNI, **no SHA-NI** | 16 | 1611 ms | NO-GO | 1.79× |
| Intel Xeon W-3245 | AVX-512-VNNI, **no SHA-NI** | 32 | 1148 ms | NO-GO | 1.28× |

On the W-3245 at 32 threads the split is roughly even — regen SHA ≈ 0.581 s,
recompute ≈ 0.566 s — and *neither drops under ~0.45 s alone at 32 threads*. The
recompute half is already near-optimal (VNNI packed int8, mirror of the ARM
SMMLA packing). The regen half is already near-optimal (AVX2 8-way multibuffer
SHA, the maximum software-SHA parallelism AVX2 allows). The residual ~250 ms over
budget is **software SHA-256 on the §3.2 K/V regen** — the W-3245 has no SHA
instructions, so every byte of that ~200 MiB goes through the vector unit. There
is no further structural lever on that silicon: row-block addressing does not
apply to the contraction-bound K/V operand (§3.2), and multibuffer SHA is already
maxed.

---

## 6. Hardware baseline decision (DECIDED 2026-07-23)

> **The supported validator hardware floor is any CPU with SHA acceleration and
> an int8 dot-product instruction: SHA-NI/SHA-ext + VNNI/i8mm.**

Rationale:

- Every CPU at or above this floor clears the 900 ms budget with margin. This
  includes **all Apple Silicon** (SHA-ext + SMMLA), **Intel Ice Lake / Rocket
  Lake and newer** (SHA-NI + VNNI), and **AMD Zen and newer** (SHA + VNNI).
  These parts span everything from laptops to servers shipped since ~2019–2021.
- The residual over-budget hardware is specifically **pre-SHA-NI x86** — the 2019
  Xeon W-3245 class (Cascade Lake-W / Skylake-SP server parts that got AVX-512
  but not the SHA extensions). This is a narrow, aging band: it is **below the
  baseline** and is not a supported validator target.
- The alternative — supporting a no-SHA-NI validator — would require either
  raising the budget (weakening the relay-liveness guarantee for everyone) or a
  non-SHA construction for the contraction-bound K/V regen, which is a genuine
  research problem because SV contracts over the entire context. Neither is
  justified to accommodate a six-year-old server part that is below the floor of
  every other modern CPU.
- The budget stands at **900 ms**. ARM at 330 ms is the reference GO.

This is a *baseline*, not a requirement that every node run at the floor: nodes
above the floor have headroom; nodes below it can still run the full int64 exact
replay (the consensus arbiter), they simply cannot keep up with the sublinear
relay-path check at block flow and should not be relied on as relay validators.

---

## 7. x86 status and gates before it lands

The x86 reference path (AVX-512-VNNI packed int8 recompute + AVX2 8-way
multibuffer SHA-256 XOF, CPUID-gated with scalar fallback and multi-vector self-
test) is the correct implementation for **in-baseline** x86 validators (SHA-NI +
VNNI parts clear the budget with it; the W-3245 measurement is simply a below-
baseline data point that proves where the floor is). It lands on the PR head only
after two consensus gates pass:

1. **`matmul_v4_rc_gkr_tests` green** on x86.
2. **ARM ↔ x86-VNNI byte-identity** — the VNNI packed-int8 recompute and the AVX2
   multibuffer SHA XOF must produce byte-identical operands and digests to the
   ARM SHA-ext / SMMLA path. A divergence here is a consensus split (§4.2). This
   is the single gating check for the x86 branch.

Until both pass, the x86 branch stays off the PR head. The ARM path (d3a6e4b) is
the reference GO and is on the branch.

---

## 8. Where this leaves activation-readiness

The verify-time NO-GO that opened this workstream (~18.57 s at the start) is
**resolved on the baseline**: ARM is GO at 330 ms with a 2.7× margin, and the
cost model shows the residual on below-baseline x86 is a known, bounded, SHA-
instruction-absence gap — not an open engineering risk.

Verify-time is therefore no longer a blocker to a finite activation height. The
gates that remain are the ones already listed in the characteristics doc §6
(external crypto audit, native-silicon qualification, ASERT calibration) plus, on
the code side, the two x86 byte-identity gates in §7 above. None of those relax
the mainnet `INT32_MAX` heights, which stay set until a deliberate cutover.
