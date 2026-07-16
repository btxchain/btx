# MatMul v4 — Activation Readiness Tracker

This file tracks the path from the current reference implementation to a
mainnet hard-fork activation. **`nMatMulV4Height` is deliberately UNSET on
mainnet** — v4 is enabled only on regtest/testnet for testing. Two gates:

- **Gate A — merge to `main` (after public review).** The fork lands
  *disabled*; inert until a height is set. Near-term.
- **Gate B — activate on mainnet.** Gated on calibration + audit + testnet +
  coordinated upgrade. Weeks–months; some items require real GPU hardware
  this repo cannot provide.

Design source of truth: `doc/btx-matmul-v4-design-spec.md`. Per-backend
hardware runbook: `doc/matmul-v4-gpu-backends.md`.

### One-command hardware report (feeds B1 + B2b + B2g)

Anyone can run **one command** on their machine and send back a single JSON:

```
contrib/matmul-v4/measure-hardware.sh cpu     # any host (baseline)
contrib/matmul-v4/measure-hardware.sh cuda    # NVIDIA sm>=75
contrib/matmul-v4/measure-hardware.sh metal   # Apple M5-class
contrib/matmul-v4/measure-hardware.sh hip     # AMD CDNA
# forward tool flags, e.g. real-hardware calibration run:
contrib/matmul-v4/measure-hardware.sh cuda --n 4096 --window 32 \
    --device-peak-int8-tops 1979 --v3-hashrate 1200000
```

It builds only the `matmul-v4-report` target, resolves the backend + device
identity, and emits `matmul-v4-report-<hostname>.json` plus a human summary
carrying: **B1** bit-exactness (resolved backend's batched digests vs the CPU
reference, PASS/FAIL — a FAIL is a hard consensus-split signal); **B2b**
sustained MARGINAL nonce/s (+ an `nMatMulV4AsertRescaleNum/Den` suggestion when
`--v3-hashrate` is given); **B2g** the §K.2a-WT per-stage wall-time breakdown on
the STACKED window shapes, the tensor-stage share, and an implied INT8
tensor-utilization estimate (with `--device-peak-int8-tops`). The tool alone
cannot decide the datacenter-favoring **ordering** (that needs multiple
machines) — it prints each machine's inputs; aggregate the JSON across a
datacenter part, a consumer part, and an Apple M5 to settle §K.2b(c). This is
the shared measurement instrument named in B2g / B4′.

---

## Gate A — merge to main (disabled)

| # | Item | Status |
|---|---|---|
| A1 | CPU consensus core (`int8_field`, `matmul_v4`, `pow_v4`) — compiles | ✅ done |
| A2 | Height-gated dispatch + one-time ASERT rescale (`pow.cpp`, `validation.cpp`) | ✅ done |
| A3 | Chainparams: regtest/testnet v4 params; **mainnet unset** | ✅ done |
| A4 | GPU backends (CUDA/Metal/HIP) + dispatch + capabilities — host side compiles | ✅ done |
| A5 | Dispatch re-verifies every accelerated result vs CPU, falls back | ✅ done |
| A6 | Miner seals `header.matmul_digest` (mining-flow correctness) | ✅ done |
| A7 | Fix `matmul_v4_pow_tests` / `matmul_v4_determinism_vectors` digest-seal + field-const bug | ✅ done |
| A8 | CPU unit suite builds + **runs green** (all 5 v4 suites + regtest activation test) | ✅ done |
| A9 | Golden determinism vectors — CPU run-to-run byte-identity validated by green suite | ✅ done (hard-pin optional) |
| A10 | DoS verify-budget params + min/max dimension bounds (§G.2/§I.5) | ✅ done |
| A11 | Pooled-mining / challenge-header RPC paths made v4-aware | ✅ done |
| A12 | Optimal-miner `(U·A)(B·V)` path in CPU `ComputeDigest` (byte-identical to full-C; enforced by equivalence test) | ✅ done |
| A13 | Public code review of design spec + implementation | ☐ todo (PR #89) |
| A14 | **v4.1 batched-sketch profile (spec §A.2 v4.1 / §C I1′ / §K.2b, PR #89 wall-time fix):** b = 8 → 4; A/U/V template-scoped (template hash zeroes nNonce64 + §H.4 seed fields), B/σ nonce-fresh; CPU batched miner (`matmul_v4_batch.{h,cpp}`, one stacked combine GEMM per window) wired into `SolveMatMulV4` (window Q via `BTX_MATMUL_V4_BATCH`, default 8) with the winner re-derived through the single-nonce reference before sealing; C-13 limb-tensor combine CPU reference; per-stage bench (`matmul_v4_stage_bench`); golden vectors re-pinned; verifier UNCHANGED (O(n²), one nonce). All 6 v4 suites + regtest activation functional test green | ✅ done (code) — ⚠ security review B4′ + measurement B2g outstanding |

Exit criterion: A1–A11 done, CPU suite green, reviewed → merge to `main`
with `nMatMulV4Height` unset.

---

## Gate B — mainnet activation

### ⛳ Activation trigger (the go/no-go gate)

**Mainnet activation is READY as soon as both `cuda` AND `metal` (Apple
M-series) return PASS** from the on-hardware determinism verification below.
CUDA covers datacenter + consumer NVIDIA; Apple M-series covers the retail /
pooled path — together they are the minimum hardware coverage to activate.
HIP/ROCm and additional device classes are **follow-on coverage, not blocking**.

- **GO** ⟺ `verify-backend.sh cuda` = PASS **and** `verify-backend.sh metal` = PASS.
- On GO, execute the staged one-line flip in **§B6**.
- Everything else in this branch (code, tests, harness, release procedure) is
  already staged so that GO → activation is mechanical.

> Recommended-but-not-blocking for the CUDA+M-series bar (owner's call, §B3–B4):
> external audit and testnet burn-in address DoS/edge-case/economic risks that
> are *separate* from the bit-exact determinism risk the trigger closes. Skipping
> them trades those risks for speed — record the decision here.

### B1. GPU backend determinism — on-hardware (the trigger inputs)
The kernels are written bit-exact-by-construction and compile behind their
toolchain guards, but **cannot be run in this repo's CI environment** (no CUDA
toolkit, no macOS/Metal, no ROCm). On real hardware, run:

```
contrib/matmul-v4/verify-backend.sh cuda    # NVIDIA sm>=75 host  -> PASS/FAIL
contrib/matmul-v4/verify-backend.sh metal   # Apple M5-class host -> PASS/FAIL
contrib/matmul-v4/verify-backend.sh hip     # AMD CDNA host (optional coverage)
```

It builds the backend, runs `matmul_v4_backend_determinism_tests`, and returns
PASS only if the digest is **bit-for-bit identical to the CPU reference** (a
one-bit divergence is a chain split → hard FAIL). Record results here:

| Backend | Gate | Verify (`verify-backend.sh`) | Result |
|---|---|---|---|
| **CUDA** (Turing→Blackwell, sm≥75) | **GATING** | H100 / B200 / RTX 5090 / 4090 / sm_75 | ☐ pending |
| **Metal** (Apple M5-class) | **GATING** | M5 / M5 Max | ☐ pending |
| HIP/ROCm (CDNA MFMA) | optional | MI300X / MI250 | ☐ pending |

Details + per-backend build flags: `doc/matmul-v4-gpu-backends.md`.

### B2. Appendix-C calibration (consensus-critical)
| # | Item | Needs |
|---|---|---|
| B2a | Cross-vendor INT8 determinism golden vectors — generate on H100/B200/consumer/Apple-M5/CDNA and confirm identical | **real GPUs** |
| B2b | One-time ASERT rescale `Num/Den` — benchmark real v3→v4 throughput on reference hardware and set empirically | reference GPU |
| B2c | ~~b=8 roofline confirmation~~ superseded by B2g: the b=8 profile was MEASURED consumer-favoring (reviewer: H100/5090 = 0.40× at n=8192) — roofline-only confirmation is no longer accepted for any b | — |
| B2d | Operand XOF regen timing envelope (15–35 ms); s8 operand + U/V sampling vectors. **Note (PR #89 review): the 15–35 ms envelope is the VERIFIER's once-per-block cost — the MINER pays expansion on every nonce**, so the XOF is also gated by the §K.2a-WT wall-time check. The per-element-hash XOF (~38.5M SHA-256/nonce at n=4096, 62.9% of per-nonce time on a 5090) is replaced by the wide counter-mode XOF (~1.2M, ~32× fewer; spec §A.2/C-12); operand values and all digests changed | CPU/GPU |
| B2e | n=4096 verify-budget confirmation on reference CPUs (<1 s single-thread) | CPU |
| B2f | **Mod-q combine on tensor cores + batched-sketch device port (spec Appendix C-13, §K.2b)** — CPU reference LANDED (4-limb balanced base-2⁷, valid for n ≤ 8589, byte-identical to the direct combine, incl. the stacked cross-nonce form). Device port now LANDED on **all three backends**: `ComputeDigestsBatchedAccel` (template-amortized P=U·A, stacked B·V, one large dense limb-tensor combine) in CUDA (cuBLASLt IMMA), HIP (MFMA), Metal (pre-M5 integer-ALU tile + M5 `tensor_ops::matmul2d`), all bit-exact-by-construction (on-device `DecomposeLimbPlanes` ported statement-for-statement) and wired through the verify+fallback dispatcher (`ComputeDigestsBatchedDispatched`). Compile behind their toolchain guards; CPU-only tree links via stubs. REMAINING: build + re-measure on real GPUs (see B2g) | real-GPU build + re-measure |
| B2g | **v4.1 batched-sketch GO/NO-GO (spec §K.2b)** — run `contrib/matmul-v4/measure-hardware.sh <backend>` (the `matmul-v4-report` tool; same stage boundaries as `matmul_v4_stage_bench`, one-command + JSON) on physical H100/B200 (+ 5090 anchor) at n=4096, b=4, window Q ≥ 32: (a) tensor stages (S2+S3b) strict majority of MARGINAL per-nonce wall-time; (b) batched tensor utilization ≥ ~60% of peak INT8; (c) nonce/s ordering actually datacenter-favoring; (d) b=4 verify (8 MiB payload) inside the CPU budget. **The datacenter claim is a hypothesis until this passes — two prior model estimates were falsified.** Also feeds B2b (ASERT rescale must use the MARGINAL per-nonce unit, since U·A is template-amortized) | **real GPUs** |

### B3. Security audit
External consensus/security audit. Focus: verifier DoS surface (payload
parser fuzzing, oversized/malformed sketches), the ASERT rescale, the
v3→v4 dispatch boundary, and the GPU-vs-CPU verify/fallback path.

### B4′. External adversarial review of the I1′ anti-amortization relaxation (BLOCKING)
v4.1 deliberately relaxes v4.0's I1/I7: A, U, V are template-scoped so `U·A`
amortizes and per-nonce combines batch into one dense GEMM (spec §C I1′,
§K.2b). The security argument (soundness preserved; no pre-mining; symmetric
across miners; difficulty prices the marginal unit) is written in §C I1′ but
is **needs-review, not proven-safe** — specifically the marginal-work floor
assumption and the reopened projector-cache channel. Solicit adversarial
review (the PR #89 reviewer is invited; the stage-bench harness is the shared
measurement tool). Mainnet activation MUST NOT proceed without this review.

> **Lineage note — this re-treads the exact ground the v2 "e1" fix closed.**
> The height-125,000 nonce-bound seed rule (`nMatMulNonceSeedHeight`, doc/
> btx-matmul-nonce-seed-v2-125000.md) was created *specifically* because
> operands fixed across a nonce sweep let a miner "reuse one consensus work
> instance across many nonce attempts," underpricing the work — and it
> **forbids shared-A/B nonce windows** and GPU base-matrix caches that reuse a
> stale instance. I1′ **intentionally re-opens that channel for A/U/V** (the
> whole batched-GPU design caches A/U/V/P per template — the precise mechanism
> v2 banned). Two things make this a *scoped* re-opening rather than a
> regression to e1, and the review must confirm both:
> 1. **Operand `B` stays nonce-fresh and consensus-enforced.** Verified in code:
>    `SetDeterministicMatMulSeeds` derives `seed_a/seed_b` from the full
>    nonce+parent-MTP preimage and `ContextualCheckBlockHeader` recomputes and
>    rejects any mismatch (`bad-matmul-seeds`, validation.cpp:10011); operand B
>    is derived from the full header hash incl. `nNonce64`. So `B`, `B·V`, the
>    combine, and the digest are all still paid **per nonce** — unlike e1, where
>    *both* operands were fixed and per-nonce cost collapsed toward zero.
> 2. **The amortization is bounded to one operand, not total.** `P = U·A` is one
>    GEMM paid once per window; as the window grows its per-nonce share → 0, so
>    the maximum underpricing is a *bounded constant factor* (the P-share of
>    total work), not the e1-style collapse. **This bound is an argument, not a
>    theorem** — and it is empirically the SAME quantity B2g measures: S0
>    (template-amortized) vs the marginal S1b+S2+S3+S4. If S0 is not small
>    relative to the marginal total at window Q ≥ 32 on real hardware, the
>    amortization is underpricing the work and the ASERT calibration (B2b) is
>    wrong. B2g is therefore a dual check: hardware ordering *and* e1-underpricing.
>
> **The v3 gap (template-precomputation) is NOT reintroduced.** Verified:
> `ComputeTemplateHash` binds `hashPrevBlock` (→ height + parent chain) and
> validation fails closed if parent-MTP context is unavailable ("matmul parent
> context unavailable"), so nothing template-scoped is computable before the
> parent exists (§C I1 memorylessness survives at template granularity; a
> different parent = different `hashPrevBlock` = different template).

### B4. Public testnet burn-in
Deploy on testnet, mine across `nMatMulV4Height` with **diverse hardware**,
confirm zero splits over a sustained window. This is where determinism
problems surface in the wild.

### B5. Coordinated activation
- Choose a mainnet height with **weeks** of lead time (not days).
- Prefer a miner/version **signaling/readiness gate** so activation only
  proceeds once a supermajority has upgraded — a flag-day with no adoption
  check risks a split.
- Ship a release with the height set; drive node/miner/pool/exchange
  upgrades *before* the height.
- Rewrite mining guides + pool software (§N.2 — Freivalds-verified shares).

Exit criterion: B1–B4 green **plus B2g (batched-profile measurement) and B4′
(I1′ adversarial review)**, height set with lead time + signaling,
supermajority upgraded → activate.

---

### B6. Staged mainnet activation — the one-line flip on GO

Mainnet `nMatMulV4Height` is **UNSET** (disabled) in `src/kernel/chainparams.cpp`.
On GO (CUDA + Metal both PASS), activation is a single, pre-planned change:

1. **Pick the height with lead time.** `H_activate = current_mainnet_height +
   Δ`, where `Δ` gives **≥ 2 weeks** of blocks at 90 s spacing
   (`Δ ≥ 2·7·24·40 = 13,440` blocks). Longer is safer.
2. **Set it** in `CMainParams` (the only consensus change):
   ```
   consensus.nMatMulV4Height = <H_activate>;   // was disabled (INT32_MAX)
   ```
3. **Set the ASERT rescale** `nMatMulV4AsertRescaleNum/Den` from the §B2b
   throughput benchmark (must be calibrated before this step, not left 1/1).
4. **Release** a tagged build with the height set; publish node/miner/pool/
   exchange upgrade notices; rewrite mining guides + pool software (§N.2).
5. **Prefer a signaling/readiness gate** (miner/version signaling) so activation
   only proceeds once a supermajority has upgraded — a flag-day with no adoption
   check risks a split.

Until step 2 is committed and released, the network stays on v3. This branch
contains everything needed for steps 1–5 to be mechanical once GO is reached.

## Hard dependencies this repo cannot satisfy
- **Real GPUs** (H100/B200/RTX/Apple-M5/CDNA) for B1, B2a–B2b and B2f–B2g.
- **External audit** (B3) and the I1′ adversarial review (B4′).
- **Public testnet operators + time** (B4).

Everything else (Gate A, the code for B1, the calibration harnesses) is in
this branch.
