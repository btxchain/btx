# MatMul v4.7 — Activation Readiness Tracker

> **Current transition status (2026-07-30):** this file contains substantial
> historical v4/v4.1 gate material below. The proposed integration PR is now
> governed by
> [`doc/btx-matmul-v4.7-transition-roadmap.md`](doc/btx-matmul-v4.7-transition-roadmap.md).
> Profile 1 ExactReplay is the Epoch-A launch candidate. Profile 2 is reserved
> for a later, separately activated proof-authoritative workload.
>
> **Update — corrective fail-closed state:** mainnet, testnet, and signet keep
> `nMatMulV4Height`, `nMatMulBMX4CHeight`, and `nMatMulRCHeight` at
> `INT32_MAX`. The live RC ASERT ratio is `1/1` and the GPU-lifecycle
> ratification flag is false. The implementation and calibration remain staged;
> a later activation-only change must choose and reseal a fresh atomic tuple.

This file tracks the path from the reference implementation to a mainnet
hard-fork activation. **Mainnet Epoch A and every Epoch B–D height remain unset
on every public network.** Implementation review and activation review are
separate gates. The activation decision remains open until exact-final evidence
for a freshly selected tuple is reviewed.

The required order is:

| Epoch | Workload | Authority | Proof posture |
|---|---|---|---|
| A | Profile 1 | ExactReplay | optional shadow-only |
| B | Profile 1 | proof **and** ExactReplay | mandatory and durable |
| C | Profile 1 | succinct proof | mandatory and authoritative |
| D | Profile 2 | succinct proof | mandatory; separate workload fork |

Do not collapse these epochs or infer one activation height from another.
Epoch A is the only epoch eligible for the first activation-height PR.

CURRENT SOURCE: `nMatMulV4Height`, `nMatMulBMX4CHeight`, and `nMatMulRCHeight`
are `INT32_MAX`, the RC ASERT ratio is `1/1`, and the GPU-lifecycle flag is
false. The implementation and staged coefficient are non-authorizing until an
activation review selects `H_A` from the live tip and the unchanged result
passes the exact-final evidence gate.

The eventual Epoch-A activation must set one atomic tuple at a single height
`H_A`; it must never be a one-field flip:

| Parameter family | Required Epoch-A value |
|---|---|
| Core heights | `nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = H_A` |
| Withdrawn/intermediate paths | DRLT and coupled-RC heights remain `INT32_MAX` |
| Workload/authority | Profile 1, production dimensions, ExactReplay authority |
| Header admission | HeaderPoW remains disabled; Poseidon2 `rcadmit` is P2P policy |
| ASERT | v4 and BMX4C ratios remain inert `1/1`; the live RC branch owns the reviewed one-time policy coefficient, which must be reproduced by exact-final CUDA launch-cohort evidence |
| Authorization | `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` and `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED` are separate, explicit reviewed decisions |

Epochs B–D require new height-versioned proof-required, proof-authority, and
Profile-2 selectors. They must not be implemented by flipping the current
global Stage-3 readiness value or `nMatMulRCProfile`, because doing so would
reinterpret historical Epoch-A blocks under a later rule.

The older, pre-v4.7 tracker below describes two historical broad gates. Its
"disabled" wording describes the implementation-only state at that time, not
the finite-but-provisional values staged in the current release candidate:

- **Historical Gate A — merge to `main` (after public review).** The fork was
  to land *disabled* and remain inert until a later activation change.
- **Gate B — activate on mainnet.** Gated on calibration + audit + testnet +
  coordinated upgrade. Some items require real GPU hardware this repo cannot
  provide.

Transition source of truth:
`doc/btx-matmul-v4.7-transition-roadmap.md`. Epoch-A measurements and
acceptance gates: `doc/matmul-v4-exact-replay-launch-candidate.md`.
Per-backend hardware runbook: `doc/matmul-v4-gpu-backends.md`. The older
`doc/btx-matmul-v4-design-spec.md` is retained as historical design provenance,
not as the authority for the current epoch sequence.

### One-command hardware report (feeds B1 + B2b + B2g)

> **Tooling update:** the legacy `matmul-v4-report` tool and its bare
> `measure-hardware.sh cpu|cuda|metal|hip` invocation were RETIRED (commit
> `a645c3b4` — fully superseded by ENC_RC). `measure-hardware.sh` now only
> drives the ENC_RC harness (`rc` sub-mode or a `--profile rc-*`/`coupled*`
> campaign); a bare-backend invocation exits with a pointer to the RC tools.

Anyone can run **one command** on their machine and send back a single JSON:

```
# ENC_RC episode harness (any backend: cpu | cuda | metal | hip):
contrib/matmul-v4/measure-hardware.sh cpu rc --toy --out report.json
contrib/matmul-v4/rc-gate.py report.json --out summary.json

# Stage G campaign profiles (same-tip, multi-run, rc-gate schema):
contrib/matmul-v4/measure-hardware.sh cpu --profile rc-toy
contrib/matmul-v4/measure-hardware.sh cpu --profile rc-medium
contrib/matmul-v4/measure-hardware.sh cpu --profile coupled

# Full production-shaped workload measurement:
contrib/matmul-v4/run-full-benchmark.py --shape production --backend cuda
# RC-only measurement wrapper:
contrib/matmul-v4/measure-enc-rc-v46.sh
```

The gates the retired report used to serve now live in the RC path:
**B1** bit-exact backend determinism → `ProbeRCSelfQual` (byte-exact vs the
int64 CPU oracle) via the `matmul-v4-rc-harness` target the script builds;
**B2b** ASERT throughput calibration →
`contrib/matmul-v4/rc-stage-g-campaign.py` + `contrib/matmul-v4/rc-gate.py`;
**B2g** datacenter-vs-consumer go/no-go →
`contrib/matmul-v4/run-full-benchmark.py`. A single machine alone cannot
decide the datacenter-favoring **ordering** (that needs multiple machines) —
aggregate the JSON across a datacenter part, a consumer part, and an Apple M5
to settle §K.2b(c).

---

## Historical Gate A — implementation-only merge with activation disabled

This section records the superseded implementation-only merge plan, under
which code and documentation could be merged with all activation heights
unreachable. It does not describe the current release candidate, which stages
a finite provisional tuple but remains non-authorizing pending exact-final
evidence and release review. Neither state enables proof authority or Profile
2 by default.

| # | Item | Status |
|---|---|---|
| A1 | CPU consensus core (`int8_field`, `matmul_v4`, `pow_v4`) — compiles | ✅ done |
| A2 | Height-gated dispatch + one-time ASERT rescale (`pow.cpp`, `validation.cpp`) | ✅ done |
| A3 | Historical chainparams plan: regtest/testnet v4 params; **mainnet unset** | ✅ done at that stage |
| A4 | GPU backends (CUDA/Metal/HIP) + dispatch + capabilities — host side compiles | ✅ done |
| A5 | Dispatch verifies every full-payload accelerated result; ENC-DR-LT returns digest-only losing slots and CPU-reconstructs/verifies/reseals every potential winner; any device/winner failure falls back | ✅ done |
| A6 | Miner seals `header.matmul_digest` (mining-flow correctness) | ✅ done |
| A7 | Fix `matmul_v4_pow_tests` / `matmul_v4_determinism_vectors` digest-seal + field-const bug | ✅ done |
| A8 | CPU unit suite builds + **runs green** (all 5 v4 suites + regtest activation test) | ✅ done |
| A9 | Golden determinism vectors — CPU run-to-run byte-identity validated by green suite | ✅ done (hard-pin optional) |
| A10 | DoS verify-budget params + min/max dimension bounds (§G.2/§I.5) | ✅ done |
| A11 | Pooled-mining / challenge-header RPC paths made v4-aware | ✅ done |
| A12 | Optimal-miner `(U·A)(B·V)` path in CPU `ComputeDigest` (byte-identical to full-C; enforced by equivalence test) | ✅ done |
| A13 | Public code review of design spec + implementation | ☐ todo (PR #89) |
| A14 | **v4.1 batched-sketch profile (spec §A.2 v4.1 / §C I1′ / §K.2b, PR #89 wall-time fix):** b = 8 → 4; A/U/V template-scoped (template hash zeroes nNonce64 + §H.4 seed fields), B/σ nonce-fresh; CPU batched miner (`matmul_v4_batch.{h,cpp}`, one stacked combine GEMM per window) wired into `SolveMatMulV4` (window Q via `BTX_MATMUL_V4_BATCH`, default 8) with the winner re-derived through the single-nonce reference before sealing; C-13 limb-tensor combine CPU reference; per-stage bench (`matmul_v4_stage_bench` — since REMOVED as a superseded-workload bench, commit `7c76afa2`; use `contrib/matmul-v4/run-full-benchmark.py`); golden vectors re-pinned; verifier UNCHANGED (O(n²), one nonce). All 6 v4 suites + regtest activation functional test green | ✅ done (code) — ⚠ security review B4′ + measurement B2g outstanding |

Historical exit criterion: A1–A11 done, CPU suite green, reviewed → merge the
implementation with the complete Epoch-A height tuple disabled and
ratification false. The current release candidate instead follows the
exact-final requirements at the top of this document and in the canonical
transition roadmap.

---

## Gate B — Epoch-A mainnet activation

### ⛳ Activation trigger (candidate remains fail-closed until final evidence)

**Historical analysis (pre-activation).** The former “CUDA + Metal PASS ⇒ GO”
rule was superseded: backend determinism is necessary, but it does not close
the economic, batching, verification-budget, admission-DoS, or
external-review gates. At the time this verdict was written, all public
activation heights were `INT32_MAX` and
`BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` was false.

**Required closing basis:** the operator may finalize Epoch A only after three
revision-bound evidence sets pass on the exact final implementation: a
CUDA+Metal correctness-golden cohort, zero-fallback CUDA lifecycle soak, and
CUDA launch-cohort ASERT calibration (see
`doc/btx-matmul-v4.7-transition-roadmap.md` §4), and with multi-day
wall-clock soak, multi-peer public testnet topology, and released-binary
upgrade behavior either completed or explicitly dispositioned in the reviewed
activation decision. Historical artifacts cannot substitute for this
exact-final evidence. Items in the list below that are not covered by those
artifacts (for example AMD-path qualification and a B200-class measurement)
remain open unless that decision expressly waives them. This section is the
gate analysis of record, not a description of shipped state.

At minimum, a future GO requires all of the following evidence in one reviewed
release:

- bit-exact accelerator qualification on the intended NVIDIA, AMD, and other
  supported frontier paths;
- a silicon-comparable B200/5090 measurement from one device-resident consensus
  Q* batch with W generation and digest on-device and no per-nonce sync; the
  `1ca87fb` 118.92/77.08 wall rates are host/launch diagnostics, not a ratio or
  ASERT input;
- the LT G2/G3 ordering and nonce/$ gates, MI350 qualification, tip-verify soak,
  and an independently completed C-15 review;
- the Poseidon2 `rcadmit` policy, per-netgroup quotas, global caps,
  authenticated-tip reservation, and no-chainwork-before-ExactReplay invariant
  surviving sustained invalid-candidate load. HeaderPoW must remain disabled:
  its nonce is not carried by the fixed 182-byte header;
- testnet burn-in, external consensus/security audit, calibration, and explicit
  L0 ratification.

No single backend marker or one-line height flip constitutes authorization to
activate.

For the current Epoch-A decision, the blocking evidence is the complete set in
the canonical roadmap §4: corrected cross-backend golden parity, at least 100
continuous dimension-bound runs per required accelerator, bounded
back-to-back/reorg behavior, admission-starvation resistance, faulted-device
recovery through an alternate qualified provider or operator restart, final
serialization/no-chainwork invariants, multi-day testnet soak, IBD/checkpoint
disclosure, and an independently reviewed height change. Portable replay
remains an explicit pre-activation or diagnostic path, not an inline strict-
device retry.
The legacy B1–B6 and C sections below remain useful evidence provenance, but
any conflicting workload/default recommendation is superseded.

### B1. GPU backend determinism — on-hardware (the trigger inputs)
The kernels are written bit-exact-by-construction and compile behind their
toolchain guards, but **cannot be run in this repo's CI environment** (no CUDA
toolkit, no macOS/Metal, no ROCm). On real hardware, run:

> (`verify-backend.sh` was RETIRED in commit `a645c3b4`; the determinism
> harness itself is a test suite in `test_btx` — build with the backend
> enabled and run it directly, per `doc/matmul-v4-gpu-backends.md`.)

```
# after a backend-enabled build (see doc/matmul-v4-gpu-backends.md for flags):
build/bin/test_btx --run_test=matmul_v4_backend_determinism_tests \
  --log_level=warning
# plus the pinned golden vectors:
build/bin/test_btx \
  --run_test=matmul_v4_backend_determinism_tests,matmul_v4_determinism_vectors \
  --log_level=warning
```

The suite (`src/test/matmul_v4_backend_determinism_tests.cpp`) passes only if
the digest is **bit-for-bit identical to the CPU reference** (a one-bit
divergence is a chain split → hard FAIL). Record results here:

| Backend | Gate | Verify (determinism harness) | Result |
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
| B2g | **v4.1 batched-sketch GO/NO-GO (spec §K.2b)** — run `contrib/matmul-v4/run-full-benchmark.py --shape production --backend <backend>` (the retired `matmul-v4-report` / `matmul_v4_stage_bench` tools' designated successor, commit `a645c3b4`; one-command + JSON) on physical H100/B200 (+ 5090 anchor) at n=4096, b=4, window Q ≥ 32: (a) tensor stages (S2+S3b) strict majority of MARGINAL per-nonce wall-time; (b) batched tensor utilization ≥ ~60% of peak INT8; (c) nonce/s ordering actually datacenter-favoring; (d) b=4 verify (8 MiB payload) inside the CPU budget. **The datacenter claim is a hypothesis until this passes — two prior model estimates were falsified.** Also feeds B2b (ASERT rescale must use the MARGINAL per-nonce unit, since U·A is template-amortized) | **real GPUs** |

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
review (the PR #89 reviewer is invited; `run-full-benchmark.py` is the shared
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
- Select the release-final mainnet height from the live tip only after the
  exact-final code and evidence freeze, with **at least 96 hours of runway**;
  prefer a longer runway when release coordination permits.
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

### B6. Staged mainnet activation — atomic Epoch-A tuple

The current source keeps the Epoch-A tuple disabled, the live RC ratio neutral,
and GPU-lifecycle ratification false. Once every required exit criterion is GO
(with CUDA and Metal PASSes only two of the required inputs), a narrow
activation-only change must install the complete tuple, evidence-bound policy
coefficient, and ratification decision atomically:

1. **Pick the height from the live tip at source freeze.**
   `H_activate = current_mainnet_height + Δ`, where `Δ` gives **at least
   96 hours** of blocks at the measured live spacing. Prefer additional runway
   when release coordination permits; never reuse a decayed candidate height.
2. **Set all three Epoch-A heights to exactly the same value** in
   `CMainParams`:
   ```
   consensus.nMatMulV4Height = <H_activate>;
   consensus.nMatMulBMX4CHeight = <H_activate>;
   consensus.nMatMulRCHeight = <H_activate>;
   ```
3. **Keep superseded paths inert.** DRLT and coupled-RC remain disabled,
   Profile 1 and production dimensions remain selected, unfinished Stage-3
   proof authority remains off, and HeaderPoW remains disabled.
4. **Assign ASERT ownership once.** Keep both
   `nMatMulV4AsertRescaleNum/Den` and
   `nMatMulBMX4CAsertRescaleNum/Den` at `1/1`; set only
   `nMatMulRCAsertRescaleNum/Den` to the independently reviewed policy
   coefficient reproduced by the exact-final v3-to-Epoch-A CUDA calibration.
   The RC dispatch branch is live at the unified height and owns that one-time
   rescale. The signed consensus fields cap each term at `INT64_MAX`.
5. **Re-affirm ratification explicitly.** The activation release must record
   the reviewed L0 decision and set both required source constants as part of
   the same release-final change. Candidate values, a height, benchmark,
   merge, or backend PASS do not imply ratification.
6. **Release** a tagged build with the tuple set; publish node/miner/pool/
   exchange upgrade notices; rewrite mining guides + pool software (§N.2).
7. **Prefer a signaling/readiness gate** (miner/version signaling) so activation
   only proceeds once a supermajority has upgraded — a flag-day with no adoption
   check risks a split.

The release-final review must run
`contrib/matmul-v4/verify-epoch-a-activation-gate.py` with a reviewed schema-2
policy record and the exact six role-specific binaries it names. The ASERT and
golden CUDA harnesses are deliberately separate inputs; equal source does not
imply byte-identical builds across evidence hosts or build configurations. The
verifier binds the
release source separately from the ASERT, golden, and lifecycle source commits.
Each artifact commit must resolve exactly, be a reachable ancestor in the
golden/ASERT-to-lifecycle-to-release chronology, and reproduce its own declared
full build-relevant tree fingerprint. A second immutable implementation
fingerprint must match every role and the release; it normalizes only the three
release-final height/coefficient literals and two ratification booleans, and
excludes only the sealed production manifest. Per-role binary hashes are
explicit; the manifest-bearing lifecycle daemon and CLI must exactly match the
lifecycle artifact. This permits evidence, manifest, and final authorization
commits after pre-manifest goldens without accepting any other source-code
change or an arbitrary ancestor. The verifier also binds the compiled
height/coefficient, both source
ratification flags, a re-derived CUDA-only ASERT corpus, the separate sealed
CUDA+Metal correctness cohort, and a correlated strict-device two-node CUDA
lifecycle campaign. The lifecycle policy explicitly records its
minimum complete/contention samples and p99/max bounds; the tool does not
invent those values. The campaign itself never self-ratifies a source flag.
The lifecycle campaign emits schema 4. A steady observer measures from
immediately before the solve RPC through the receiving node reporting that
exact authenticated tip. A contention observer starts before concurrently
submitting sibling solve RPCs to disconnected nodes and stops only after both
local sibling accepts, winning-branch extension, reorg convergence, and the
next exact direct-tip child's authentication. Monotonic checkpoints prove that
ordering and reproduce the full observer endpoint. Sums of component counters
are not accepted as the observer wall. Bounded daemon telemetry must bind the
same measured-child hash to strict winner reseal/local-authority consumption,
authenticated relay, and receiving strict ExactReplay. Missing, cancelled,
cross-block, post-convergence-only, or sequentially mislabeled contention data
is incomplete. The winner record starts at the solve RPC dispatch, counts every
nonce attempt, and includes all solve/reseal scheduler waits. The scheduler's
independent latest-component summary remains
diagnostic and cannot substitute for these exact-block records.
Changing source, a binary, evidence bytes, the height, a flag, a provider
cohort, or a lifecycle bound requires a new exact-final campaign and policy
record.

Until the exact-final tuple, coefficient, and ratification decision are
committed in a reviewed release and that release reaches its selected height,
the public network stays on v3. The finite values in this development branch
are not deployment authorization. A partial tuple is invalid by construction.

---

## Gate C — historical ENC-BMX4C research tracker

> **v4.7 precedence:** The Epoch-A candidate activates BMX4C atomically with v4 and
> Profile-1 ExactReplay at `H_A`. It is not a later standalone mainnet fork.
> The material below is retained as design and measurement provenance; its old
> ordering and independent-height recommendations do not govern v4.7.

**Historical note:** before the Epoch-A candidate,
`nMatMulBMX4CHeight` was deliberately unset on every network. The candidate
stages it at the same release-selected height as v4 and RC, but the tuple is
not final or shipped until the current activation gates close. Design source
of truth for the historical encoding work:
`doc/btx-matmul-v4.2-consolidated-design.md`; normative encoding spec + profile
machinery: `doc/btx-matmul-v4.2-bmx4c-spec.md`; governance framework:
`doc/btx-matmul-v4.2-longevity-threat-model.md`. The verifier (q = 2⁶¹−1, R = 3,
b = 4, 8 MiB sketch, digest, Fiat–Shamir) is byte-for-byte UNCHANGED across
profiles — Gate C is "new operands into the same machine".

### C1. Build items (shelf phase — research-only, zero consensus exposure)

| # | Item | Status |
|---|---|---|
| C1a | Normative ENC-BMX4C spec + L0/L1/L2 profile-versioning design (`doc/btx-matmul-v4.2-bmx4c-spec.md`) | ✅ done (this branch) |
| C1b | Consensus params, inert (`src/consensus/params.h`): `MatMulEncodingProfile` enum, `BMX4C_*` profile constants, `nMatMulBMX4CHeight` (INT32_MAX), `nMatMulBMX4CAsertRescaleNum/Den`, `nMatMulBMX4CMinProvenAccumulatorBits`, `IsBMX4CActive` / `GetMatMulEncodingProfile` | ✅ done (this branch) |
| C1c | CPU consensus reference (`src/matmul/matmul_v4_bmx4.*`): §1.2 nibble sampler (identity-on-E2M1 bijection), §1.3 scale planes, exact-shift dequant, base-2⁶ remainder-top limb combine + `CheckCombineLimbBound` successor (pins 288·n ≤ 2²³−1) | ☐ foundation agent |
| C1d | Validation/pow wiring per spec §8.2 (profile-dispatched seeds `"BTX_MATMUL_SEED_V42"`/sketch tags, expander profile arg, full-C word bound 2304·n, ASERT rescale at the profile height); chainparams assignment + construction asserts (`nMatMulBMX4CHeight > nMatMulV4Height` when set) | ☐ later integration wave (design pinned in spec §8.2 — do NOT wire ahead of it) |
| C1e | ENC-BMX4C golden vectors + regenerated C-1′ adversarial vectors (spec §5.3 families 1–5: t-discrimination, boundary-pin, scale-exactness, alphabet-hole, promotion-cadence). **A replayed s8-era vector set is VOID** — the old HM-A/HM-B/HM-C regimes are unreachable under BMX4-C operands | ☐ after C1c |
| C1f | Backend kernels (CUDA mxf4/IMMA, Metal, HIP, + first FP4/FP8-path device) + determinism-harness (`matmul_v4_backend_determinism_tests`) / `measure-hardware.sh` (ENC_RC `rc` mode) profile support | ☐ after C1c/C1e |
| C1g | Spec-text debts due at fork time: §A.6 Strassen rewrite (one INT8-path level at E_max = 48, zero frontier levels); §S.2.2 ASIC-residual re-disclosure (halved t-cliff ≈ 3–5× under the 1-GEMM INT8 fallback); C-1 → C-1′ codification in code comments; ρ re-measured on FP4 rental centrals (disclosure only) | ☐ at fork time |

### C2. M-t24 — THE gating measurement (runnable NOW, in parallel with Gate B)

Proven **t = 24 exact accumulation** on the commodity block-scaled FP4/MX path,
via the spec §5.3 t-discrimination + boundary-pin vectors on real silicon. This
single measurement decides (a) native-path eligibility, (b) which side of the
ASIC-residual band applies (bounded ~1.5–2.5× vs the ~3–5× cliff), (c) whether
the FP8-fold tier exists. Registered prediction: passes on CDNA4/Trn3
(architected FP32 accumulate), genuinely uncertain on Blackwell TMEM (Hopper
t≈14 precedent). Datasheets are never a PASS; a log that never entered the
regime is not a PASS.

| Path | Hardware | Result |
|---|---|---|
| `mxf4`-E8M0 TMEM accumulate | B200 / B300 (rentable now) | ☐ pending |
| UE4M3-hosted-2^e FP4 path | RTX 5090-class (buyable now) | ☐ pending |
| CDNA4 OCP MX | MI355X | ☐ pending |
| Matmul-MX PSUM (NKI; incl. explicit committed-scale-tensor loadability) | Trainium3 | ☐ pending |
| FP8 MXU fold | TPU v7 | ☐ pending |

**ENC-BMX4C MUST NOT activate without M-t24 PASS on ≥ 2 independent vendors'
frontier parts.** A t≈14 outcome on a path is not a Gate C failure — that path
falls closed to its FP8 fold or the 1-GEMM INT8 fallback (spec §5.2); it moves
the ladder, not the chain.

### C3. Joint v4.1 + v4.2 C-15 external adversarial review (mainnet blocker — commission ONCE)

Extends B4′, commissioned once covering both objects (the I1′ relaxation is
common; one review is cheaper and more coherent than two). Scope MUST name
verbatim: the I1′ marginal-work floor; **small-alphabet batch algebra over fixed
(P, V)** with the cryptanalysis §2.6 opening condition (≤ ~1.5 effective
symbols) as the attack target; **𝓜-valued template-scoped U/V**;
difficulty-calibration gaming between template refreshes. If the review demands
entropy margin above the §7.4 floor, the pre-analyzed 𝓜₁₅@S=4 hardening reserve
exists — as a *different* profile with its own §2.1-documented costs (4× INT8
tax, lost sub-2²⁴ envelope), never a parameter tweak to ENC-BMX4C.

### C4. Activation trigger (both required) + remaining measurement gates

Activate ENC-BMX4C only when BOTH hold:

- **(a) G-1 decoupling trigger confirmed on SHIPPED silicon** (INT8 flat/cut
  while frontier FP4/FP8 ≥ 2× across a generation — confirm per R-1 on silicon,
  never launch slides), and
- **(b) measured GO/NO-GO passes**: C2 M-t24 on ≥ 2 vendors; §K.2a-WT marginal
  wall-time tensor-majority at Q ≥ 32 on a real FP4 part (model predicts the
  combine at ~70–80% — measure, don't trust); cross-vendor ENC-BMX4C golden
  vectors (B2a analogue, ≥ 2 vendors + ≥ 3 jurisdictions, incl. FP4/FP8
  devices); verify budget re-benched ≤ the v4.1 budget (B2e analogue; expected
  ~28% cheaper regeneration); C3 review closed; `nMatMulBMX4CAsertRescaleNum/Den`
  computed from the MEASURED marginal unit on the path rational miners actually
  run (B2b analogue — never ship 1/1 on a network with pre-fork history).

For v4.7, the independent activation mechanics in this historical section are
superseded by B6: BMX4C shares `H_A`, its own ASERT ratio stays inert, and the
live RC branch owns the atomic Epoch-A calibration. Any later encoding-profile
migration requires a new height-versioned selector and its own calibration; it
must not mutate the meaning of `H_A`.

### C5. Leapfrog clause (explicit, conditioned)

If C2 (M-t24) and C3 (joint review) complete **before** v4.1's own Gate B
clears, governance SHOULD consider activating v4.2 ENC-BMX4C directly as the
first fork — one fork instead of two, at no cost to the INT8 installed base
(which mines ENC-BMX4C at 1 s8 GEMM, ≈ unchanged throughput). The leapfrog MUST
NOT be taken on unmeasured FP-path assumptions: if the FP-silicon wall-time
split (C4-b) is still open, ship v4.1 and stage v4.2. Record the decision here.

### C6. Profile-migration governance (standing obligations — this and every future profile)

Per spec §7.5 / longevity doc §3 (the L1 pipeline; L0 is constitutionally
frozen; L2 needs no governance):

- **FER monitor (G-2)**: publish quarterly the Frontier Exactness Ratio per new
  DC generation + the exactness-envelope register (proven t/K′ per commodity
  path), measured with `measure-hardware.sh` JSON — never inferred from peak
  TOPS. States: GREEN (FER ≥ ~0.5) / WATCH (< 0.5, or any fastest-path K′
  collapse → refresh the shelf candidate) / ARM (< ~0.25 across two consecutive
  generations AND measured ordering flattened/inverted → run the pipeline) /
  FIRE (ARM + candidate gates green → set height, signal, activate). Thresholds
  are governance defaults, re-pinnable only in the open and never mid-episode.
  The difficulty-vs-compute-envelope audit note corroborates but can never fire
  an activation; the protocol reads neither signal (§0.7-(4)).
- **Cadence floor**: at most one committed-object migration per two DC hardware
  generations (≥ 4 years between activation heights). Sole exception:
  determinism/chain-split defects, handled as emergency bugfixes outside this
  framework.
- **Single-live-profile rule**: exactly one encoding profile live at any height;
  multi-profile acceptance windows are rejected (difficulty-semantics
  fragmentation + within-window monopoly).
- **Per-version invariants**: fresh C-15-class review (blocker), golden + C-1′
  vectors regenerated at the new magnitude boundaries, ≥ 2 vendors / ≥ 3
  jurisdictions in the passing vector set, ASERT rescale from measurement,
  §S.2.2/§A.6 re-disclosures, and the spec §7.4 floor checked BEFORE golden
  vectors are generated. Pre-committed fallback: a gate-failed candidate never
  activates — the honest fallback is the L2 Ozaki-class bridge plus difficulty
  absorbing the k² tax.

## Hard dependencies this repo cannot satisfy
- **Real GPUs** (H100/B200/RTX/Apple-M5/CDNA) for B1, B2a–B2b and B2f–B2g.
- **External audit** (B3) and the I1′ adversarial review (B4′, joint with C3).
- **Public testnet operators + time** (B4).
- **Real block-scaled FP4/MX silicon** (B200/B300, RTX 5090, MI355X, Trainium3,
  TPU v7) for the Gate C M-t24 measurement (C2) and the ENC-BMX4C vector set
  (C1e/C4-b).

The historical Gate-A implementation, the code for B1, and the calibration
harnesses are in this branch. Exact-final CUDA+Metal and ASERT evidence,
full-suite closeout, and live-tip height selection remain open release gates.
