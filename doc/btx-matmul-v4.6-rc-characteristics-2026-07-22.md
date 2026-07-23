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
finite-field constructions I–IV) verified over a **sound v5 FRI** backend, with
the coupled **V3 production profile as the default activated path**.

It is a *release candidate*: the code, tests, and soundness accounting are in the
tree and green here, but three off-code gates remain before any finite
activation height is set (see §6).

---

## 2. The workload (what a miner actually computes)

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
`RecomputeCoupledPuzzleReference`) is the **sole consensus authority**: a block
is valid iff its claimed result byte-identically replays under the reference.
Everything else (GPU kernels, the succinct proof) is an acceleration or an audit
aid, never the arbiter.

---

## 3. The succinct proof (G1–G5 arithmetization)

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
> decides validity.

---

## 4. Defaults after this PR (the "V3 production is the default" policy)

| Knob | v4.6 default | Meaning |
|---|---|---|
| `nMatMulRCCoupledProfile` | **3** (was 2) | a finite coupled height alone selects **V3 production** — no hidden profile override |
| `RCCoupConsensusConfig{}.transcript_version` | **ENC_RC_V3** | aggregate default aligned to V3; domain tags map `V3 → COUP_*_V3` |
| `nMatMulRCHeight` | `INT32_MAX` | ENC_RC episode **OFF** on every public network |
| `nMatMulRCCoupledHeight` | `INT32_MAX` | coupled puzzle **OFF** on every public network |
| `kRCGkrFormalSoundnessReady` | `false` | formal arbiter **hard-disabled** |

Profile **2 (V2 medium)** is retained **only** for explicit regression coverage
(selected via an explicit `-regtestrccoupledprofile=2`). Profile **1 (V1
legacy)** remains byte-identical to the pre-v4.6 legacy transcript. Mainnet
parameter validation asserts the profile default is 3.

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

## 5. v4.6 (this PR) vs. v3-on-`main`

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

## 6. What is done vs. what gates a finite activation height

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

## 7. Benchmarking (ENC_RC v4.6 only)

**Canonical entrypoint** (do not use bare `measure-hardware.sh cuda|cpu` — that
is legacy v4.1/`matmul-v4-report` and is now refused without
`BTX_ALLOW_LEGACY_MATMUL_MEASURE=1`):

```bash
contrib/matmul-v4/measure-enc-rc-v46.sh --help

# Stage G CPU campaigns → rc-gate.py
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile coupled
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile rc-medium

# Coupled V3 CI harness (v4.6 default coupled family)
contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --coupled-v3-ci

# Production Freivalds carrier verifier floor (900 ms budget)
contrib/matmul-v4/measure-enc-rc-v46.sh verify-carrier --threads 32

# CUDA episode context digest/probe tests (CUDA-built test_btx)
contrib/matmul-v4/measure-enc-rc-v46.sh cuda-episode-tests
```

Aggregate harness JSON with `contrib/matmul-v4/rc-gate.py`. Toy/PARTIAL never
raises `nMatMulRCHeight`. For CUDA mine→relay→ExactReplay on regtest and the
older B200/5090 protocol notes, see
`doc/btx-matmul-v4.5-v3-b200-5090-measurement-protocol.md` — cite only after
confirming the workload is ENC_RC (coupled / episode), not v4.1 report.
