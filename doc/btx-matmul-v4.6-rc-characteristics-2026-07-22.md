# BTX MatMul v4.6 (Resident Curriculum) — Characteristics & Status

**Date:** 2026-07-22
**Branch / PR:** `claude/matmul-v4-design-spec-af23sj` (PR #89)
**Status:** integrated on the PR head; **activation OFF on every public network**
(all heights `INT32_MAX`, formal arbiter hard-disabled). This document is the
short, honest characteristics summary of what v4.6 *is* and how it differs from
the single-matmul PoW currently live on `main`.

---

## 1. What "v4.6" names

v4.6 is the integrated result of PR #89: the **Resident Curriculum (ENC_RC)**
proof-of-work workload plus its **coupled puzzle (ENC_RC_COUPLED, V3
production)** and the in-circuit **G1–G5 arithmetization** (four reusable
finite-field constructions I–IV) verified over a **sound v5 FRI** backend. The
ENC_RC_COUPLED V3 production profile is the **default profile selection** for
the coupled selector (see §2 below for what "default" does and does not mean —
it does not mean activated).

It is a *release candidate*: the code, tests, and soundness accounting are in the
tree and green here, but three off-code gates remain before any finite
activation height is set (see §7).

---

## 2. The two-stage proof of work

The shipping ENC_RC v4.6 design is **two consensus encoding profiles**, selected
independently by two different consensus params, both wired and tested but
**both currently disabled** (`nMatMulRCHeight = nMatMulRCCoupledHeight =
INT32_MAX` on every public network):

- **Stage / Profile 2 — ENC_RC datacenter episode.** Selector
  `nMatMulRCProfile = 2` (the default; consensus asserts it is 1 or 2). This is
  the datacenter-scale transformer episode
  (`MakeDatacenterRCEpisodeParams`: `rounds`, `L_lyr`, and `b_seq` raised over
  the epoch-0 base — `rounds = 8` alone gives **≈15.9× MAC** vs. the base, the
  "~16×" figure carried through the ASERT rescale ratio `16422/1027`). Under
  profile 2:
  - The **FS-sampled sublinear carrier verifier**
    (`matmul_v4_rc_freivalds_sampled.cpp`) is the **relay-time accept/reject
    authority** — the check a validating node runs before forwarding a block,
    so it never pays the full O(N) replay on the network path. It is a
    **deterrence-based work-skipping soundness bound**, not a claim that every
    wrong tile is caught (see §2.1).
  - The **int64 CPU `ExactReplay` reference**
    (`RecomputeResidentCurriculumReference`) is retained as the **asynchronous,
    ε = 0 arbiter and dispute path** — it is the *ultimate* consensus reference
    that decides validity byte-exactly if a claimed result is ever disputed.
  - (Profile 1 of this same selector = epoch-0 base dimensions, with
    `ExactReplay` as the sole authority; it is retained but is not the
    default.)

- **Stage / Profile 3 — ENC_RC_COUPLED V3 production coupled puzzle.**
  Selector `nMatMulRCCoupledProfile = 3` (the default). This is the V3 coupled
  puzzle: **HBM-resident, ~48–51 GiB working set** (packed bank floor 48 GiB /
  packed ≈51 GiB at the frozen production dimensions). When both the ENC_RC
  episode and the coupled puzzle are configured live, the coupled profile is
  **preferred** (`GetMatMulEncodingProfile` selects ENC_RC_COUPLED over plain
  ENC_RC), and consensus asserts the coupled activation height is **at or above**
  the ENC_RC height (`nMatMulRCCoupledHeight >= nMatMulRCHeight`) — the coupled
  puzzle can only activate at the same height as, or after, the episode it
  couples to, never before. (Profile 2 of the *coupled* selector = the V2
  medium shape, retained only for explicit regression coverage; it is not the
  default and is not production.)

**A numbering subtlety worth stating precisely:** `nMatMulRCProfile` and
`nMatMulRCCoupledProfile` are **two different selectors** with **different**
default values — the episode selector defaults to **2**, the coupled selector
defaults to **3**. "Profile 2" and "profile 3" here name positions in two
separate enumerations, not two profiles of one selector. Read as a slogan: the
two-stage PoW is **"profile-2 episode + profile-3 coupled."**

### 2.1 The honest soundness bound (do not overclaim)

The FS-sampled carrier's guarantee is a **work-skipping bound**, derived in full
in `doc/btx-matmul-v4.6-rc-verify-time-budget-and-hardware-baseline-2026-07-23.md`
§1.1:

> **P(accept | a miner skips fraction `f` of the episode's checked MACs) ≤
> (1 − f)^(2Λ)**, where `Λ = rounds · L_lyr` is the number of exhaustively
> sampled streamed units (`Λ = 192` at the production datacenter shape, so the
> exponent is `2Λ = 384`).

This bound does **not** claim every wrong tile is caught — an isolated wrong
tile is essentially never caught by the sample (≈2/T per layer, with the tile
space `T ≈ 1.1·10⁷`), but catching an isolated tile would only save a
negligible sliver of work anyway. What the bound guarantees is that no
*economically meaningful* fraction of the episode's compute can be skipped and
still be accepted with non-negligible probability: skipping just 1% of the work
already caps acceptance at ≈2.1%, and skipping 10% caps it at ≈2.7·10⁻¹⁸. This
is **not** "formally sound" or "externally audited" — it is a deterrence
argument, and it is the property the launch design relies on.

Closing the remaining gap — catching *every* wrong tile, i.e. exact completeness
rather than a work-skipping bound — is the job of the **succinct proof upgrade
(Stage C)** described in §4 below. That upgrade is an *eventual* replacement for
the carrier's role, not part of what ships at launch.

---

## 3. The workload (what a miner actually computes)

Each ENC_RC episode is an **exact int64 GEMM substrate** — no floating-point in
the consensus object — composed of:

- **Attention (FlashMX)** over the resident context,
- **Micro-training** (forward / backward / weight-gradient passes),
- a **SHA tile-tree Merkle** commitment over the episode tiles.

The **coupled puzzle (V3 production)** binds the episode to a second, entangled
workload: per-lobe int8 GEMMs (`rows_per_lobe = 128`), page selection over a
`bank_pages = 1536` bank, a balanced permutation, a **material-exchange** phase
(`exchange_rows = 128`, `exchange_rounds = 4`), and per-lobe barrier roots
(`pages_per_barrier_lobe = 24`). The two workloads share a transcript so a miner
cannot compute one without the other.

The **int64 CPU reference** (`RecomputeResidentCurriculumReference` /
`RecomputeCoupledPuzzleReference`) is the **ultimate consensus authority**:
byte-identical replay under the reference is what validity is defined against,
and it is what the asynchronous dispute path uses to settle any claim. At
relay time under profile 2, the FS-sampled carrier (§2) stands in for full
replay as a sublinear accept/reject check; it does not replace the reference,
it defers to it on dispute. Everything else — GPU kernels, the succinct proof
below — is an acceleration or an audit aid, never the arbiter.

### 3.1 Acceleration is default-on, gated byte-exact to the reference

Mining is not required to run on CPU: the default acceleration policy
(`kRCAccelerationPolicyDefault = RCAccelerationPolicy::NativePreferred`) prefers
a native tensor lane (Ozaki MXFP4 / FP8), falls through to the exact-gated
dense-INT8 device path (CUDA IMMA / HIP MFMA / Metal tensor / Ascend Cube) when
native isn't available, and only falls back to the CPU oracle when no device
path self-qualifies. On CPU, the fast paths are SHA-NI/SHA-ext, AVX2, AVX-512-
VNNI, and ARM SMMLA/i8mm. None of this needs an experimental flag — it is
**on by default**.

What makes default-on safe is that **every** accelerated path — GPU native
MXFP4/FP8, GPU INT8 (CUDA IMMA / HIP MFMA / Metal), CPU SHA-NI/AVX2/AVX-512-
VNNI/SMMLA alike — is required to prove **byte-identical** output to the int64
reference via a runtime self-qualification (`BuildExactnessQualCacheKey` /
`PackedFastPathSelfTest`-style multi-vector scalar-oracle checks) before it is
used. A path that is not byte-exact on the running hardware is declined and
mining falls through to the next path down to the CPU oracle; a byte-divergent
path can never silently win a block — a device is used only when some path has
been proven byte-identical to the int64 oracle (see `matmul_v4_rc_accel_policy.h`).

---

## 4. The succinct proof (G1–G5 arithmetization)

The winner's episode is additionally attested by a succinct proof built from four
reusable finite-field constructions, wired into `VerifyWinnerProofV7`:

| Construction | Role | Cryptographic surface |
|---|---|---|
| **I** — multilinear-evaluation binding | eq-kernel sumcheck + batched opening | G1 / G2 / G5 |
| **II** — constraint system (Extract AIR) | ARX / SHA / sampler as low-degree polynomials | in-circuit ChaCha20 + SHA-256 |
| **III** — multiplicity-correct fixed-table lookup | Haböck log-derivative (LogUp), dual-α over Fp2 | G3 |
| **IV** — copy / permutation wiring | Schwartz–Zippel + Plonk grand-product | G4 |

Field stack: Goldilocks `p = 2^64 − 2^32 + 1`, `Fp2` (`x² − 7`), and an available
`Fp3` (`x³ − 2`) extension. The FRI backend is v5 (even/odd fold + terminal
constant-codeword check), `Q = 128` queries.

### Soundness (composed separation bound)

Computed in `RCGkrComposedSeparation` (`matmul_v4_rc_gkr.cpp`), the per-term
error budget composes (log-sum-exp of `2^-term`) to:

- **Composed bound ≈ 71.9 bits** (`ε_total ≤ 2^-71.9`), **FS-dominated**.
- Target `2^-64`; **margin ≈ 7.9 bits ⇒ adequate**
  (`kRCGkrAdequateMarginBits`; the earlier Q=116 configuration gave only ≈1.8
  bits and was rejected as inadequate).
- Per-term subtotals: FS subtotal **72** (absorbs Construction I's 74),
  Construction II **80**, Construction III **128**, Construction IV
  `min(equality, dual-permutation) = 83.19`, FRI proximity floor at Q=128
  **76.80** (field-independent), SHA256d **88**.
- **Single-challenge wiring (60 bits) is FORBIDDEN**; the dual-challenge
  permutation (mandatory) is what delivers the 83.19 wiring term.

A fuller **~76.8-bit** bound is reachable only with a full `Fp3`
Fiat–Shamir cutover, which requires a **proof-wire-format change** (algebraic
challenges are FRI-codeword-entangled; the cleanly-liftable challenges drive
prover-sent data, 16→24 bytes). That is a **documented follow-on**, not part of
v4.6. The shipped Q=128/Fp2 bound clears the target on its own.

> **The succinct proof is an accounting/audit artifact, not the consensus
> arbiter.** The formal arbiter is hard-disabled
> (`kRCGkrFormalSoundnessReady = false`): `EnvRCGkrArbiterEnabled` is ignored and
> the arbiter never gates consensus regardless of environment. int64 exact replay
> decides validity. This proof stack is the mechanism behind the eventual Stage C
> exact-completeness upgrade referenced in §2.1 — it is in-tree and green, but it
> is *not* part of what the two-stage design relies on at launch; the FS-sampled
> carrier's work-skipping bound is.

---

## 5. Defaults after this PR (the "V3 production is the default" policy)

| Knob | v4.6 default | Meaning |
|---|---|---|
| `nMatMulRCProfile` | **2** (datacenter episode) | selects the datacenter-scale episode dims; FS-sampled carrier is the relay authority under this profile (§2) |
| `nMatMulRCCoupledProfile` | **3** (was 2) | a finite coupled height alone selects **V3 production** — no hidden profile override |
| `RCCoupConsensusConfig{}.transcript_version` | **ENC_RC_V3** | aggregate default aligned to V3; domain tags map `V3 → COUP_*_V3` |
| `nMatMulRCHeight` | `INT32_MAX` | ENC_RC episode **OFF** on every public network |
| `nMatMulRCCoupledHeight` | `INT32_MAX` | coupled puzzle **OFF** on every public network |
| `kRCGkrFormalSoundnessReady` | `false` | formal arbiter **hard-disabled** |

On the **coupled** selector (`nMatMulRCCoupledProfile`), profile **2 (V2
medium)** is retained **only** for explicit regression coverage (selected via
an explicit `-regtestrccoupledprofile=2`) — this is a different "profile 2"
from the episode selector's default (§2). Profile **1 (V1 legacy)** remains
byte-identical to the pre-v4.6 legacy transcript. Mainnet parameter validation
asserts the coupled profile default is 3.

### Single-switch activation (wired, kept OFF)

v4.6 adds one control that turns the **entire RC family on at a single height**
with no staggered regime: setting the unified height assigns the **same** height
to both `nMatMulRCHeight` and `nMatMulRCCoupledHeight`, and the profile default
(3) selects V3 production automatically.

- Regtest / CI: `-regtestrcunifiedheight=<n>` (equivalent to setting both
  `-regtestrcheight=n` and `-regtestrccoupledheight=n`; a later per-component
  override still refines one leg).
- Mainnet: the switch exists but **no public network sets it** — both heights
  stay `INT32_MAX` until a deliberate cutover. Wiring the switch does **not**
  activate anything; it fixes *what* activates and *that it activates together*,
  not *whether*.

---

## 6. v4.6 (this PR) vs. v3-on-`main`

`main` today (merge `cc669ce`) runs the original MatMul PoW: **a single dense
integer matmul** (dimension 512) verified by **Freivalds' check over the
`2^31 − 1` field**. It is a compute-bound PoW but a *single* linear-algebra
operation with a probabilistic verifier and no episode structure, no coupled
puzzle, and no succinct proof.

| Dimension | v3-on-`main` (`cc669ce`) | v4.6-RC (PR #89, this branch) |
|---|---|---|
| PoW workload | one dense int matmul, dim 512 | multi-phase ENC_RC episode (attention + micro-training + Merkle) **coupled** to a V3 puzzle |
| Numeric substrate | int matmul over `2^31 − 1` | **exact int64** GEMM substrate |
| Verifier of record | Freivalds probabilistic check | **int64 exact CPU replay** (byte-identical) |
| Succinct proof | none | GKR/sumcheck v7 + batched dual-OOD DEEP FRI + LogUp + G1–G5, composed **≈71.9-bit** separation |
| Coupled second workload | none | per-lobe int8 GEMMs + page bank + material exchange + barrier roots |
| Hardware target | any int-matmul engine | frontier AI accelerators (tensor-core / FP4-Ozaki int64-exact paths) with a CPU reference floor |
| Activation | live on `main` | **OFF everywhere** (heights `INT32_MAX`), single-switch wired for a future clean cutover |

**Net:** v4.6 replaces a single probabilistically-verified matmul with a
structured, exactly-replayed AI-training episode plus a coupled puzzle and an
auditable succinct proof — a much larger and more AI-representative workload,
gated behind a fail-closed activation switch that no network has flipped.

---

## 7. What is done vs. what gates a finite activation height

**Done (in-tree, green here):**
- ENC_RC episode + coupled V3 production workload and int64 reference.
- G1–G5 arithmetization (Constructions I–IV) wired into v7 verify on sound v5 FRI.
- Composed soundness bound ≈71.9 bits (adequate margin), cross-reproduced.
- V3-production default policy (profile 3, aggregate default, domain tags).
- Single-switch activation wiring (kept OFF).
- **Profile-2 sampled-carrier verify-time: GO on the hardware baseline** — Apple
  M4 Max 330 ms (2.7× under the 900 ms relay-path budget) via Config W episode-
  wide weights, row-block-addressable X0, and a four-phase parallel verifier with
  packed int8 recompute. Baseline floor set at SHA-NI/SHA-ext + VNNI/i8mm; the
  residual on pre-SHA-NI x86 is a known below-baseline SHA-instruction gap. See
  `doc/btx-matmul-v4.6-rc-verify-time-budget-and-hardware-baseline-2026-07-23.md`.

**Still gating a finite activation height (off-code):**
1. **External cryptographic audit** of the succinct proof (the in-tree bound is
   our own accounting; the arbiter stays hard-disabled until an independent
   audit clears it).
2. **Native-silicon qualification** (frontier accelerator int64-exact paths).
3. **ASERT calibration** from measured silicon before any height is set.

Only after those does anyone set `nMatMulRCHeight = nMatMulRCCoupledHeight` to a
finite value (via the single switch) and pin the calibrated ASERT rescale.

---

## 8. Benchmarking (ENC_RC v4.6 only)

The legacy `matmul-v4-report` tool and the v4.1/v4.2/v4.4 benchmark binaries
(`btx-matmul-{cost,solve,metal}-bench`, the `src/bench/matmul_*`
microbenchmarks) measured superseded workloads and have been **removed** — they
reported "MatMul PoW" numbers that no longer reflect the shipping ENC_RC v4.6
workload. Bare `measure-hardware.sh cuda|cpu` is likewise refused without
`BTX_ALLOW_LEGACY_MATMUL_MEASURE=1`.

**Canonical entrypoint — `contrib/matmul-v4/run-full-benchmark.py`.** This is
the turnkey, verbose benchmark for current PoW performance: it describes the
full workload, states per-component which kernel is optimized vs. fallback on
your hardware, decides resident-vs-streamed from actual VRAM (against the
~48 GiB coupled resident working set) and explains why, and reports every
phase separately and combined. It is an observation-only tool — it never
changes consensus or activation heights — and drives the real episode harness,
`matmul-v4-rc-harness` (the same code path a miner runs):

```bash
# fast sanity pass (toy shape, no GPU needed)
contrib/matmul-v4/run-full-benchmark.py --quick

# the real thing (production dims)
cmake --build build --target matmul-v4-rc-harness
contrib/matmul-v4/run-full-benchmark.py --shape production --json report.json
```

For more granular workflows — Stage G CPU campaigns, the coupled V3 CI harness,
the production carrier verifier's 900 ms relay-time budget, and CUDA episode
digest/probe tests — `contrib/matmul-v4/measure-enc-rc-v46.sh` remains the
entrypoint:

```bash
contrib/matmul-v4/measure-enc-rc-v46.sh --help

# Stage G CPU campaigns → rc-gate.py
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile coupled
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile rc-medium

# Coupled V3 CI harness (v4.6 default coupled family)
contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --coupled-v3-ci

# Production Freivalds carrier verifier floor (900 ms budget) — see §2's
# relay-time authority and doc/btx-matmul-v4.6-rc-verify-time-budget-and-
# hardware-baseline-2026-07-23.md for the full derivation
contrib/matmul-v4/measure-enc-rc-v46.sh verify-carrier --threads 32

# CUDA episode context digest/probe tests (CUDA-built test_btx)
contrib/matmul-v4/measure-enc-rc-v46.sh cuda-episode-tests
```

Aggregate harness JSON with `contrib/matmul-v4/rc-gate.py`. Toy/PARTIAL never
raises `nMatMulRCHeight`. For CUDA mine→relay→ExactReplay on regtest and the
older B200/5090 protocol notes, see
`doc/btx-matmul-v4.5-v3-b200-5090-measurement-protocol.md` — cite only after
confirming the workload is ENC_RC (coupled / episode), not the retired v4.1
report tool.
