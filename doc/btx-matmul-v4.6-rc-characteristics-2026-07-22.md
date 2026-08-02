# BTX MatMul v4.6 construction — characteristics in the MatMul v4.7 roadmap

**Date:** 2026-07-22
**Status (updated for the proposed MatMul v4.7 integration PR):** implementation
and historical design summary; **activation is OFF on every public network**.
The canonical transition contract is
`doc/btx-matmul-v4.7-transition-roadmap.md`. If a dated statement below
conflicts with that roadmap, the roadmap controls.

---

## 1. How the v4.6 construction fits MatMul v4.7

**MatMul v4.7** names the complete transition architecture, not a proof
format number or one profile-selector value. It combines:

- the header-derived Resident Curriculum work statement and 182-byte
  digest-only header;
- Profile 1 as the interim, exactly replayable production workload;
- Profile 2 as the later, approximately 16-times-heavier workload;
- ExactReplay, accelerator qualification, scheduling, and admission machinery;
  and
- unfinished succinct-proof/Stage-3 research retained for future epochs.

Existing `V2`, `V3`, `V7`, coupled-profile, FRI, GKR, and Stage-3 labels are
internal or historical construction names. They do not identify a v4.7
network epoch and do not grant consensus authority.

---

## 2. The four consensus epochs

Every transition below requires its own reviewed activation height. The
implementation PR leaves all heights unreachable.

| Epoch | Workload | Consensus authority | Proof posture |
|---|---|---|---|
| A | Profile 1 | ExactReplay | optional shadow proof only |
| B | Profile 1 | ExactReplay **and** proof | mandatory durable proof, dual-validation burn-in |
| C | Profile 1 | proof | mandatory proof; replay is non-consensus audit |
| D | Profile 2 | proof | separate workload activation; replay is non-consensus audit |

Profile 1 is four rounds, 16 FFN layers, `b_seq=16,384`, and `T_leaf=1,024`.
It is the only ExactReplay launch candidate. Profile 2 is eight rounds, 24 FFN
layers, `b_seq=87,552`, and `T_leaf=4,096`; it is reserved for Epoch D after
succinct proof authority has already operated on Profile 1.

An optional Epoch-A proof cannot accept or reject a block, affect chainwork,
punish a peer, or replace replay. In Epoch B the proof becomes consensus data
but ExactReplay remains independently required. A mandatory proof must be
canonically serialized, committed, retrievable through relay/reorg/restart/IBD,
and may not live only in an ephemeral P2P sidecar or process-local cache.

The sampled/Freivalds carrier and unfinished Stage-3/GKR code are research,
benchmark, or optional precheck surfaces. They have no authority in Epoch A,
cannot substitute for either leg of Epoch B, and cannot become authoritative
through an environment flag or local relay state.

### 2.1 The honest soundness statement (do not overclaim)

The full, corrected derivation is in
`doc/btx-matmul-v4.6-rc-verify-time-budget-and-hardware-baseline-2026-07-23.md`
§1.1. In summary:

- **Unit coverage is exhaustive.** The streamed units are the per-round SV output
  **and** each fused-FFN DOWN output (`LayerInStream`): at production that is
  `8·24 = 192` FFN units **plus** `8` SV units = **200 units** (benchmark:
  `units_total = 200`). Since `kRCFreivaldsSampleCount = 512 ≥ 200`, every unit is
  checked.
- **Tiles are sampled and *exactly recomputed*.** Two tiles per unit are opened
  = `192·2 = 384` FFN + `8·2 = 16` SV = **400 tile checks**. Each opened tile is
  **exactly recomputed** (regenerate anchored input row → full contraction →
  `Extract` → byte-compare → Merkle-open); there is **no** Freivalds probabilistic
  error term on checked tiles.
- **The tile bound is conditional.** For a fixed committed FFN output with average
  bad-*tile* fraction `φ`, `P(accept) ≤ (1 − φ)^384` (the `384` is the FFN
  tile-draw count, not `2 ×` the 200 units; the 16 SV draws are additional). It
  does **not** claim every wrong tile is caught — an isolated wrong tile is caught
  with only ≈`2/N ≈ 1.8·10⁻⁷` per unit.

**Do not read this as an economic "skip X% of work" guarantee.** Turning "bad-tile
fraction `φ`" into "fraction of work skipped `f`" needs a cost-to-error lemma that
is **not proved** — and `Extract` is a non-injective quantizer (the checked object
is the int8 output, so a *cheaper wrong* accumulator that quantizes to the same
bytes passes). The earlier "skip 10% → 2.7·10⁻¹⁸" phrasing is **withdrawn**.
Likewise, the sample is deterministically bound to the target/header/root
transcript per candidate, but that is **not** proven "unbiasable" against a miner
who grinds many candidates, and the fixed-length Merkle T-BIND premise is being
enforced separately (opening-length checks).

**Current transition reading:** this is historical Profile-2 precheck analysis,
not the Epoch-A validity rule. Profile 1 ExactReplay is epsilon-zero authority
for Epoch A. Profile 2 is not an ExactReplay launch candidate. Stage 3 must
close the complete statement, recursion, soundness, durable carriage, and
production proving/verification gates before Epoch B, C, or D can activate.

---

## 3. The workloads

Each ENC_RC episode is an **exact int64 GEMM substrate** — no floating-point in
the consensus object — composed of:

- **Attention (FlashMX)** over the resident context,
- **Micro-training** (forward / backward / weight-gradient passes),
- a **SHA tile-tree Merkle** commitment over the episode tiles.

Historical coupled-puzzle research binds the episode to a second, entangled
workload: per-lobe int8 GEMMs (`rows_per_lobe = 128`), page selection over a
`bank_pages = 1536` bank, a balanced permutation, a **material-exchange** phase
(`exchange_rows = 128`, `exchange_rounds = 4`), and per-lobe barrier roots
(`pages_per_barrier_lobe = 24`). The two workloads share a transcript so a miner
cannot compute one without the other.

The portable int64 reference defines byte-identical replay. In Epoch A the
complete Profile-1 replay—normally accelerated by a byte-exact device
implementation—is the consensus authority. Profile 2 remains dormant until
Epoch D and is never authorized by the sampled carrier.

### 3.1 Acceleration is default-on, gated byte-exact to the reference

Mining is not required to run on CPU: the default acceleration policy
(`kRCAccelerationPolicyDefault = RCAccelerationPolicy::ProductionPreferred`) prefers
dense-INT8 device paths (CUDA IMMA / HIP MFMA / Metal tensor / Ascend Cube).
Correctness-qualified native Ozaki MXFP4 / FP8 remains an explicit measurement
mode until separately reviewed production-shape performance evidence makes it
eligible for automatic validation. The CPU oracle is used when no production
device path self-qualifies. On CPU, the fast paths are SHA-NI/SHA-ext, AVX2, AVX-512-
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

## 4. Succinct-proof research (G1–G5 and Stage 3)

Historical work sought to attest the winner's episode with four reusable
finite-field constructions wired into `VerifyWinnerProofV7`:

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

> **Update (2026-08-02):** the Fp3 Fiat–Shamir cutover described below as a
> follow-on has since SHIPPED (episode-v7 Fp3 challenges + Fp3-codeword FRI,
> `src/matmul/matmul_v4_rc_fri_ext3.{h,cpp}`). The current composed bound is
> **≈ 76.8 bits, FRI-query-dominated, margin ≈ 12.8** —
> `RCGkrComposedSeparationBits()` (`src/matmul/matmul_v4_rc_gkr.cpp:2959-2968`)
> with FS subtotal 135.5 / wiring 147.19/288 / Construction I 76
> (`src/matmul/matmul_v4_rc_gkr.h:876-899`), pinned by
> `gkr_integration_composed_separation_bound`. The ≈ 71.9 Q=128/Fp2 figures
> below are the v4.6 state at this document's date.

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
v4.6. That local Q=128/Fp2 accounting cleared its stated component target; it
does not close the unfinished end-to-end Stage-3 statement or authorize a
proof epoch.

> **No current succinct proof is a consensus arbiter.** The formal arbiter is
> hard-disabled
> (`kRCGkrFormalSoundnessReady = false`): `EnvRCGkrArbiterEnabled` is ignored and
> the arbiter never gates consensus regardless of environment. This stack is a
> historical basis for Epochs B–D, not evidence that those epochs are ready.
> Sampled/Freivalds acceptance is likewise not a proof and has no authority.

---

## 5. Proposed integration defaults

| Knob | Proposed state | Meaning |
|---|---|---|
| Epoch-A workload selector | **Profile 1** | interim exactly replayable workload |
| Epoch-B height | disabled | no mandatory proof until format and durable availability are frozen |
| Epoch-C height | disabled | no proof-only authority until dual-validation burn-in succeeds |
| Epoch-D height | disabled | no Profile-2 workload until proof authority is established |
| Stage-3 readiness gates | `false` | unfinished proof machinery remains fail-closed |
| Public activation heights | `INT32_MAX` | documentation and implementation merge do not activate consensus |

The integration branch retains older coupled selectors for regression work but
now selects Profile 1 by default while every public height remains disabled.
It must not collapse the four epoch heights into a single switch.

---

## 6. MatMul v4.7 Epoch A vs. v3-on-`main`

`main` today (merge `cc669ce`) runs the original MatMul PoW: **a single dense
integer matmul** (dimension 512) verified by **Freivalds' check over the
`2^31 − 1` field**. It is a compute-bound PoW but a *single* linear-algebra
operation with a probabilistic verifier and no episode structure, no coupled
puzzle, and no succinct proof.

| Dimension | v3-on-`main` (`cc669ce`) | v4.7 Epoch A candidate |
|---|---|---|
| PoW workload | one dense int matmul, dim 512 | Profile-1 multi-phase ENC_RC episode |
| Numeric substrate | int matmul over `2^31 − 1` | **exact int64** GEMM substrate |
| Verifier of record | Freivalds probabilistic check | complete epsilon-zero ExactReplay |
| Succinct proof | none | optional shadow-only in Epoch A; unfinished |
| Header | existing v3 format | 182-byte digest-only header; no mandatory proof bytes |
| Hardware target | existing v3 miners | qualified Metal/CUDA/tensor acceleration with portable oracle |
| Activation | live on `main` | **OFF everywhere**; separate epoch heights required |

**Net:** Epoch A replaces a single probabilistically checked matmul with a
structured, exactly replayed Profile-1 episode while preserving a digest-only
header. Later proof and Profile-2 transitions remain independent.

---

## 7. What is done vs. what gates a finite activation height

**Implemented candidate components:** Profile-1 ExactReplay, qualified
accelerator dispatch, near-tip scheduling/admission machinery, Profile-2
workload code, and unfinished proof research.

**Epoch-A activation remains separately gated by:** cross-backend golden parity;
at least 100 continuous dimension-bound runs per required accelerator;
back-to-back/reorg/admission/fault-retry tests; serialization and no-chainwork-
before-replay invariants; testnet soak; IBD/checkpoint disclosure; ASERT
calibration; and a separate reviewed activation-height change.

**Epochs B–D require additional proof gates:** complete statement coverage,
independent cryptographic review, frozen format/transcript/algorithm hash,
durable proof carriage and historical availability, adversarial verifier
vectors, sustained proving capacity, and a bounded dual-validation burn-in.

---

## 8. Benchmarking MatMul v4.7 Epoch A

The legacy `matmul-v4-report` tool and the v4.1/v4.2/v4.4 benchmark binaries
(`btx-matmul-{cost,solve,metal}-bench`, the `src/bench/matmul_*`
microbenchmarks) measured superseded workloads and have been **removed** — they
reported "MatMul PoW" numbers that do not measure the MatMul v4.7 Epoch-A
candidate. Bare `measure-hardware.sh cuda|cpu` is likewise refused without
`BTX_ALLOW_LEGACY_MATMUL_MEASURE=1`.

**Canonical Epoch-A entrypoint — `matmul-v4-rc-harness
--base-production`.** It drives the Profile-1 episode path and emits the
device-coverage and timing report used by the acceptance gate:

```bash
# fast sanity pass (toy shape, no GPU needed)
contrib/matmul-v4/run-full-benchmark.py --quick

# Epoch-A candidate: Profile 1 production dimensions
cmake --build build --target matmul-v4-rc-harness
build/bin/matmul-v4-rc-harness --base-production --episodes 100 \
  --backend metal --out profile1-metal-100.json
```

`run-full-benchmark.py --shape profile2-production` and the carrier benchmark commands
below are retained historical Profile-2/proof-development measurements. They
must not be cited as Epoch-A acceptance evidence or as authority:

```bash
contrib/matmul-v4/measure-enc-rc-v46.sh --help

# Stage G CPU campaigns → rc-gate.py
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile coupled
contrib/matmul-v4/measure-enc-rc-v46.sh cpu --profile rc-medium

# Coupled V3 CI harness (v4.6 default coupled family)
contrib/matmul-v4/measure-enc-rc-v46.sh cpu rc --coupled-v3-ci

# Historical Profile-2 Freivalds carrier precheck
contrib/matmul-v4/measure-enc-rc-v46.sh verify-carrier --threads 32

# CUDA episode context digest/probe tests (CUDA-built test_btx)
contrib/matmul-v4/measure-enc-rc-v46.sh cuda-episode-tests
```

The retained `contrib/matmul-v4/rc-gate.py` aggregates historical Stage-G
schema only; its GO label cannot raise any epoch height. For CUDA
mine→relay→ExactReplay on regtest and the
older B200/5090 protocol notes, see
`doc/btx-matmul-v4.5-v3-b200-5090-measurement-protocol.md` — cite only after
confirming the workload is ENC_RC (coupled / episode), not the retired v4.1
report tool.
