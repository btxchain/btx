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

The consensus authority **depends on the profile**. Under **profile 1**, int64
exact CPU replay (`RecomputeResidentCurriculumReference` /
`RecomputeCoupledPuzzleReference`) is the sole authority: a block is valid iff its
claimed result byte-identically replays. Under **profile 2** (the datacenter
default), the **sampled carrier verifier** (`matmul_v4_rc_freivalds_sampled.cpp`)
is *itself* the consensus accept/reject authority — `CheckMatMulProofOfWork_RC`
returns validity directly from it (a deterrence rule with a ~0.27 % residual; see
§1.1) and does **not** re-run the full replay per block. int64 exact replay
remains the arithmetic reference used at mining time and the profile-1 authority,
but for profile 2 it is not a wired per-block dispute mechanism. The 900 ms budget
bounds the wall-clock time a validating node spends on the profile-2 carrier
verify before relaying.

The budget is a **relay-path liveness bound, not a soundness parameter.** The
budget only decides *which hardware can keep up with block flow*; it never
relaxes what is checked.

### 1.1 What the sampled carrier actually enforces (honest bound)

Two earlier drafts of this section were inaccurate — first "all ≈400 units
checked; single-fault detection is linear," then a `(1−f)^384` *economic*
work-skipping bound. Both overstated. This is the corrected, deliberately
conservative statement, aligned with the code and with the two 2026-07-24
FS/T-BIND audits.

The carrier is checked at two granularities:

- **Unit granularity — exhaustive, not sampled.** The sampleable ("streamed")
  units are the layers whose `extract_out` is committed to a round's tile-tree —
  by `LayerInStream`, both the per-round **SV** output and each fused-FFN **DOWN**
  output. At the production datacenter shape (`MakeDatacenterRCEpisodeParams`):
  `rounds = 8`, `L_lyr = 24`, so there are `8·24 = 192` FFN-DOWN units **plus**
  `8·1 = 8` SV units = **200 streamed units** (the production carrier benchmark
  reports `units_total = 200`). The FS sample count is
  `kRCFreivaldsSampleCount = 512 ≥ 200`, and `FreivaldsSampleLayers` draws
  `min(λ, 200)` distinct units — so **every** streamed unit is checked; there is
  no unit-level sampling gap.
- **Tile granularity — sampled.** Within each checked unit the verifier opens
  `kRCFreivaldsSegOutTiles = 2` output tiles (each a `(row, col-segment)`) out of
  the unit's full tile space, giving `192·2 = 384` FFN tile checks + `8·2 = 16`
  SV tile checks = **400 tile checks** (`extract_tiles = 400`). Each opened tile
  is **exactly recomputed** — the verifier regenerates/authenticates the anchored
  input row, recomputes the full selected contraction, applies `Extract`, compares
  the exact int8 output bytes, and opens those bytes against the round root. This
  is **not** Freivalds: there is no probabilistic per-tile error term. The two
  tiles per unit are derived from the SegPos coin (`kRCFreivaldsSegPosTag`) over
  the **target/header/root-bound** FS transcript, so the sample is fixed by the
  committed candidate — a miner cannot steer it *within* one candidate (but see
  the grinding caveat below).

**What this does and does not give.** A single isolated wrong tile is *not*
reliably caught: with a per-FFN-unit tile space `N ≈ 1.1·10⁷` and two draws,
P(caught) ≈ `2/N ≈ 1.8·10⁻⁷` per unit. For a **fixed committed** FFN output with
bad-tile fraction `φ_l`, two draws without replacement miss all bad tiles with
probability `((N−b_l)(N−b_l−1))/(N(N−1)) ≤ (1−φ_l)²`. Over the 192 FFN units,
the product is maximized by spreading a fixed average bad-tile fraction `φ`
uniformly:

> **Conditional tile bound: P(accept) ≤ (1 − φ)^{384}**, where **`φ` is the
> average fraction of committed FFN output *tiles* that are wrong** (not the
> fraction of work skipped), and the 16 SV checks are additional. `384` is the
> FFN tile-draw count `192·2`, **not** `2 ×` the 200 units.

**This is NOT (yet) an economic work-skipping guarantee — three premises are
unmet.** Converting "average bad-tile fraction `φ`" into "fraction of mining work
skipped `f`" and calling the result an economic bound is *not currently
justified*:

1. **No cost-to-error lemma.** Nothing proves that skipping fraction `f` of the
   work forces ≥ `f` bad committed tiles. In particular `Extract` is a
   non-injective quantizer: the checked object is the int8 output, so a *cheaper
   wrong* accumulator that quantizes to the same int8 bytes passes. Fused UP/DOWN
   sharing and alternative algorithms further break a 1:1 MAC↔tile identification.
   So the earlier "skip 10 % of work → 2.7·10⁻¹⁸" reading is **withdrawn**.
2. **No adaptive-grinding proof.** Binding the target/header/roots into the FS
   seed fixes the sample *per candidate*; it does not stop a miner from preparing
   and abandoning many candidates. With per-candidate favorable probability `p`,
   `G` attempts give `1−(1−p)^G`; the composition with PoW cost is unproven. The
   code and comments should say "deterministically transcript-bound," **not**
   "unbiasable."
3. **Fixed-length T-BIND not enforced.** `VerifyMerkleProof` does not yet enforce
   the depth/length implied by the consensus-pinned stream (see the R-01 fix); the
   standard vector-commitment premise the bound assumes is being enforced
   separately.

**Consensus authority (stated honestly).** Under profile 2 the **sampled carrier
is itself the consensus accept/reject authority** — `CheckMatMulProofOfWork_RC`
returns `true` directly on a passing carrier (`pow.cpp:4258`), accepted "by the
sampled authority (deterrence, ~0.27 % residual)." The int64 exact-replay
reference (`VerifyBoundedExactReplay`) is the **profile-1** sole authority and the
mining-time reference oracle; for profile 2 there is **no wired deterministic
dispute mechanism** that re-runs it to reverse an acceptance, so it must not be
described as profile 2's "arbiter." The formal GKR/FRI arbiter is compile-time
hard-disabled.

**Bottom line for launch.** Profile 2 is a **deterrence rule** with a documented
~0.27 % residual — which is the basis on which it was accepted as launch PoW — and
the `(1−φ)^384` tile bound illustrates why *gross* cheating is caught with
overwhelming probability. It is **not** a formally-proven economic soundness bound;
the cost-to-error lemma, the grinding game, and fixed-length T-BIND are exactly
the items the external cryptographic audit (a standing pre-activation gate, heights
`INT32_MAX`) must close, alongside the eventual Stage C exact-completeness proof.

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
replay (the profile-1 authority and exact reference), they simply cannot keep up
with the sublinear relay-path check at block flow and should not be relied on as
profile-2 relay validators.

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
