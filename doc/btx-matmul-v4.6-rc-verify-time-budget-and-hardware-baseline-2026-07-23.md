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

The budget is a **relay-path liveness bound, not a soundness parameter.** The
budget only decides *which hardware can keep up with block flow*; it never
relaxes what is checked.

### 1.1 What the sampled carrier actually enforces (honest bound)

An earlier draft of this section claimed "all ≈400 units checked; single-fault
detection is linear." That was inaccurate on both counts and is corrected here.

The carrier is checked at two granularities:

- **Unit granularity — exhaustive, not sampled.** The sampleable units are the
  Λ streamed DOWN-projection outputs, `Λ = rounds · L_lyr = 8 · 24 = 192` at the
  production datacenter shape (`MakeDatacenterRCEpisodeParams`). The FS sample
  count is `kRCFreivaldsSampleCount = 512 ≥ Λ`, and `FreivaldsSampleLayers`
  draws `min(λ, Λ)` distinct units — so **every** streamed unit is checked. There
  is no unit-level sampling gap. (The "≈400" in the old text was the GKR *wire*
  count, a different quantity.)
- **Tile granularity — sampled.** Within each checked unit, the verifier opens
  `kRCFreivaldsSegOutTiles = 2` output tiles (each a `(row, col-segment)`) out of
  the layer's full tile space `T ≈ 1.1·10⁷`, and Freivalds-verifies each opened
  tile's int8·int8→int64 GEMM exactly (per-tile Freivalds false-accept ≤ 2⁻⁶⁴).
  The two tiles per unit are drawn from the **target-bound, unbiasable** SegPos
  coin (`kRCFreivaldsSegPosTag`), so a miner cannot see or steer which tiles will
  be opened before committing operands.

**Consequence — this is a work-skipping bound, not exact completeness.** A single
isolated wrong tile is *not* reliably caught: P(caught) ≈ `2/T ≈ 1.8·10⁻⁷` per
layer. What the carrier bounds is the *fraction of episode compute a miner can
skip and still be accepted*. Let a strategy corrupt fraction `φ_l` of layer `l`'s
tiles. Per layer, P(both opened tiles land in clean tiles) ≈ `(1−φ_l)²`. Across
the Λ checked units, `P(accept) ≈ Π_l (1−φ_l)²`. For a total skipped fraction `f`
the product is **maximized by spreading `f` uniformly** (`log(1−φ)` is concave),
giving the adversary's best case and hence the soundness bound:

> **P(accept | skip fraction `f` of the carrier's MACs) ≤ (1 − f)^{2Λ} = (1 − f)^{384}.**

Reading off the exponent (`2Λ = 384` at production):

| Skipped compute `f` | Max P(accept) |
|---|---|
| 0.18 % | 0.5 |
| 1 %    | 2.1 · 10⁻² |
| 5 %    | 2.8 · 10⁻⁹ |
| 10 %   | 2.7 · 10⁻¹⁸ |

So a miner who wants even a coin-flip chance of acceptance can skip at most
~0.18 % of the work; skipping 10 % is rejected except with probability ~10⁻¹⁸.
The only "undetectable" cheating (isolated tiles) saves a negligible fraction of
energy, so it does not undermine the PoW cost function. This is the property on
which launch acceptability rests: **not** that every wrong tile is caught, but
that no *economically meaningful* amount of skipped work survives.

**Scope of the bound.** It covers the FFN DOWN-projection MACs, which are the
episode's dominant arithmetic intensity; attention (QKt / AV) is deliberately
held sub-dominant by the `n_ctx` hash-bound guardrail (§, `MakeDatacenterRC…`),
so the bounded work is the work that matters economically. The DOWN-projection
matmul itself is enforced exactly per opened tile (recompute-before-open, the
#101 fix; §9). Exact int32 recompute of each opened tile remains the arithmetic
authority; the int64 CPU replay stays the sole consensus arbiter.

This is the FS-sampled carrier's **launch** soundness. Closing the tile-level gap
to exact completeness (every wrong tile caught) is the Stage C succinct-proof
upgrade — an eventual replacement, not a launch blocker.

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

## 7. x86 reference path — landed

The x86 reference path (AVX-512-VNNI packed int8 recompute + AVX2 8-way
multibuffer SHA-256 XOF, CPUID-gated with scalar fallback and multi-vector self-
test) is the correct implementation for **in-baseline** x86 validators (SHA-NI +
VNNI parts clear the budget with it; the W-3245 measurement is simply a below-
baseline data point that proves where the floor is). **It is on the PR head**
alongside the ARM GO reference.

Why landing it on this branch is safe — this is a draft RFC branch that activates
nothing (`nMatMulRCHeight = INT32_MAX`, arbiter hard-disabled):

- **The ARM reference is provably unaffected.** Every x86 fast path is behind
  `#if defined(__x86_64__)` / `defined(ENABLE_AVX2)`; on ARM (and any non-x86
  build) the code does not compile, so the 330 ms GO reference is byte-for-byte
  unchanged.
- **The x86 path is fail-safe.** Both the VNNI recompute and the AVX2 XOF are
  gated by multi-vector self-tests against the scalar CSHA256 / scalar-oracle
  reference; a mismatch disables the fast path and falls back to byte-identical
  scalar output. A byte-divergent path cannot silently activate (§4.2).
- **The x86 suites pass** at this tip (`matmul_v4_rc_datacenter_tests`,
  `_coupled_tests`, `_freivalds_sampled_tests`; CUDA episode digests match the
  int64 CPU reference on the 5060 Ti).

### 7.1 Cross-hardware confirmation — recorded 2026-07-23

The belt-and-suspenders confirmations for the activation audit trail (not
branch-landing gates; activation is separately gated behind `INT32_MAX` +
external audit) are now on record, measured on the W-3245 build at tip
`a8aca34`:

- **`matmul_v4_rc_gkr_tests` on x86: PASS** — 79/79 cases, 1010 assertions
  (`EXIT_GKR=0`).
- **ARM ↔ x86 episode-digest byte-identity** — coupled toy vector
  `MakeCoupHeader(42)`, digest
  `7a7ce1065c7881aa2bd2295c26778ebf88c22432e91326f98d098c11885579ee`, identical
  across: x86 fast paths on; x86 with the AVX2 multibuffer XOF forced off
  (`BTX_BMX4_XOF8_AVX2=0`, i.e. scalar CSHA256 XOF); and the ARM frozen toy
  golden (Mac Studio). `matmul_v4_rc_datacenter_tests` also PASS both ways (47
  cases, 7855 assertions each).

Coverage note: the digest run directly toggles the **operand-generation XOF**
(AVX2 multibuffer ↔ scalar CSHA256) and shows it is byte-identical, and the
cross-arch match pins the AVX2 path to the ARM SHA-ext path. The **VNNI packed
int8 recompute** is a verifier-path kernel (not part of the reference digest),
so the digest run does not exercise it directly; its byte-identity is enforced by
the `PackedFastPathSelfTest` multi-vector scalar-oracle gate at init
(auto-fallback to scalar on any mismatch) and exercised by the datacenter-suite
verify assertions passing.

### 7.2 Packed-recompute operator kill switch (`BTX_RC_PACKED_I8MM`)

`RCDensePackedI8mmAvailable()` — the single selection point for the packed int8
recompute, routed through by both the production carrier verifier
(`matmul_v4_rc_freivalds_sampled.cpp`) and the compute bench — now honours
`BTX_RC_PACKED_I8MM=0` as a **process-wide operator kill switch**. When set, both
the ARM SMMLA and x86 VNNI packed paths are forced off and every recompute takes
the non-packed transposed exact path (`RCDenseRowBlockTransposedExactI8` /
`RCDenseTwoRowsBlockTransposedExactI8`). The switch is read once and cached (no
per-block `getenv`, no mid-process flip).

This is **consensus-safe**: the packed and transposed paths are byte-identical
(the verdict is unchanged; only throughput differs), so a validator running with
the switch either way reaches the same result. Its purposes:

- **Escape hatch** — disable the packed kernels in the field if a SMMLA/VNNI
  defect is ever found, without losing the (slower) correct verification.
- **Direct A/B** — run the suite twice, once with the var unset and once with
  `BTX_RC_PACKED_I8MM=0`; the episode digests and every verify verdict must
  match. This is the whole-suite complement to the kernel-level
  `PackedFastPathSelfTest`.

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

---

## 9. FFN matmul enforcement — soundness item #101 (RESOLVED)

An earlier tracking item flagged a soundness concern: *the profile-2 carrier
verifier does not enforce the FFN matmul* — i.e. that a miner might commit a
self-consistent but fabricated FFN output and have it accepted without the
verifier recomputing `X·W_up·W_down`. Reviewed against the current verifier
(`matmul_v4_rc_freivalds_sampled.cpp`), this is **closed in code**:

- The fused-FFN is sampled as its **DOWN** layer `GemmPhase2Fwd`
  (`X[l+1]=Extract(H·W_down+X[l])`). The **UP** projection
  `H=Extract(X·W_up)` (`GemmPhase2FfnUp`) is internal and *not* streamed — the
  verifier **recomputes it on the fly** when a Fwd tile is checked. So checking
  one sampled Fwd tile exercises **both** FFN matmuls.
- The recompute uses an **anchored input** (X-row opened against `round_roots`,
  or PRF-regenerated X0 at `l=0`) and **PRF-derived weights** (`W_up`/`W_down`
  from the operand seeds; the miner cannot choose them).
- The recomputed output is bound to the committed tile: `finish_tile` rejects on
  `eo != tile.extract_out` (`v7fs:recompute_mismatch`) **before** it opens
  `tile.extract_out` against `round_roots`. A fabricated FFN output fails the
  recompute check, not merely the Merkle opening.
- The layer's declared `kind` is itself cross-checked against the recomputed
  provenance (`e.kind == lp.kind`), so a miner cannot mislabel an FFN layer to
  dodge the FFN recompute path.

**Regression lock:** `matmul_v4_rc_freivalds_sampled_tests ::
frvs_ffn_matmul_is_enforced_101` builds an honest carrier with λ large enough to
cover every sampleable layer, asserts (non-vacuously) that a `GemmPhase2Fwd`
layer is actually sampled, then forges that layer's committed output and asserts
the verifier rejects with `v7fs:recompute_mismatch`. This guards the FFN
enforcement against regression, distinct from the pre-existing generic
`sampled[0]` tamper tests (which may land on an attention/SV layer).

This is a verifier-mechanism confirmation, not a substitute for the external
cryptographic audit (§8 / characteristics §6), which remains a gate.
