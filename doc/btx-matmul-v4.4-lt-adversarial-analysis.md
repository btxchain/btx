# BTX MatMul v4.4-LT — Adversarial analysis & hardening status

*Status: MatExpand C-15 class has **implementation mitigations** (non-affinity tests) but **external review remains open**. Q* Phase B seal-as-PoW is implemented and inert (`nMatMulDRLTHeight = INT32_MAX`). Activation remains gated.*
*Companion: `doc/btx-matmul-v4.4-lt-normative-spec.md`. Hardening response: `doc/btx-matmul-v4.4-lt-hardening-response-2026-07-19.md`.*

## Threat model (LT-specific)

| ID | Attack | Disposition |
|---|---|---|
| LT-C15 | Freivalds reassociation through linear MatExpand fold (`B̂ = fold(GWH)` affine in panels) | **MITIGATED in code; EXTERNAL REVIEW OPEN** — `ExtractDequantMatExpand` = position-salted Mix + M11 rejection + scale `e∈{0..3}`; blocks the linear reassociation class tested in-tree. SplitMix64-style mixer is **not** a proved cryptographic PRF. No shortcut exceeding the measured threshold was found within explicitly tested algorithms/dimensions; general shortcut resistance remains an external-review assumption. |
| LT-Q1 | Skinny single-nonce launches under fat `Q*` schedule | **CLOSED (Phase B, inert)** — when `fMatMulLTSealAsPoW` + live DRLT, lottery object is the Q* window seal (`ComputeSealDigestBMX4CLT`); Phase A remains per-nonce digest when the toggle is off. Q* commits aggregate leaf digests — it does **not** prove classical GEMM, tensor-core use, or simultaneous slot execution. |
| LT-Q2 | Window-seal PoW without MTP-threaded sibling seeds | **CLOSED (Phase B, inert)** — EncDr / solve thread parent MTP into `SlotSeedFn` → `SetDeterministicMatMulSeeds` for every slot; sketch-cache `H(σ‖Chat)==matmul_digest` skipped in seal mode |
| LT-A1 | ASERT continuous across MatExpand/deep-m work shift | **CLOSED in code** — `nMatMulDRLTHeight` rescale + re-anchor; ratios default 1/1 until silicon calibration against the **fastest known exact** miner path |
| LT-V1 | Missing `n % 32` gate for `ENC_BMX4C_LT` | **CLOSED** — validation mirrors ENC-BMX4C |
| LT-P1 | Live DRLT with wrong tile/rank pin | **CLOSED** — construction asserts `b=2`, `m=BMX4C_LT_SKETCH_RANK_M` |

## MatExpand non-collapse argument (implementation)

Normative map (per entry `(i,j)`):

1. `Y = G·W`, `B32 = Y·H` — exact integer GEMMs (unchanged).
2. `salt = LE64(seed_W)`.
3. `mixed = Mix(B32[i,j], i, j, salt)` — SplitMix64-style avalanche.
4. Walk nibbles of `mixed` (remix on exhaustion) through `SampleMantissaNibble` → `μ ∈ M11`.
5. `e = Mix(...scale lane...) & 3`; output `μ << e` with `|μ<<e| ≤ 48`.

Why this blocks the linear shortcut class:

- A Freivalds probe that is linear in `B̂` cannot pull `G`/`W`/`H` through Mix/M11/table rejection.
- Position salts `(i,j)` and panel salt kill translation / panel-reuse collapses across A vs B.
- Legacy `FoldInt32ToEmax48` (`y % 97 → [-48,48]`) remains exported **only** for differential tests; it is not normative.

Tests: `matexpand_extract_range`, `matexpand_not_affine_in_raw`, `matexpand_position_salt_differential` in `src/test/matmul_v4_lt_tests.cpp`.

## Consensus Q* — Phase A vs Phase B

**Phase A (default when LT live, `fMatMulLTSealAsPoW = false`):**

- `nMatMulConsensusQStar ∈ {64,128}` pinned at construction when DRLT is live.
- Miner evaluates fat windows; lottery object remains **per-nonce** `H(σ‖Ĉ)` (ENC-DR cache auth intact).
- Seal helpers (`ComputeWindowMerkleRoot` / `SealWindowCommit`) remain available for harnesses.

**Phase B (IMPLEMENTED, inert on public nets):**

1. Mode toggle `Consensus::Params::fMatMulLTSealAsPoW` (default `false`). Active only via `IsMatMulLTSealAsPoWActive(height)` = `IsDRLTActive(height) && fMatMulLTSealAsPoW`. Public nets keep `nMatMulDRLTHeight = INT32_MAX`, so the mode is fail-closed regardless of the toggle. Regtest opt-in: `-regtestmatmulltsealaspow` with a live `-regtestdrltheight`.
2. Lottery object: `matmul_digest := SealWindowCommit(σ_anchor, Merkle(slot digests), Q*)` via `ComputeSealDigestBMX4CLT`.
3. Slot nonces: `DeriveWindowSlotNonce(σ_anchor, j)`. Sibling V3 seeds: `SlotSeedFn` → `SetDeterministicMatMulSeeds(..., parent_MTP)` in solve + EncDr recompute.
4. Sketch-cache / MMSKETCH: Phase-A `H(σ‖Chat)==matmul_digest` auth is **not** used in seal mode (prefetch/ingress ignored; tip verify is ε=0 seal recompute). Seal-auth helpers: `SealWindowProofMatchesCommitment` / `VerifySealWindowFreivalds`.
5. Async EncDr worker: `ClassifyMatMulEncDrRecompute` returns height + parent MTP
   when prev is known (including seal heights); `MatMulVerifyWorker::Job` carries
   `parent_median_time_past` into `CheckMatMulProofOfWork_V4EncDr`. Seal mode
   fails closed without MTP. Tip-verify pending/budgets height-select via
   `nMatMulLTMaxPendingVerifications` / `nMatMulLT{Global,Peer}VerifyBudgetPerMin`
   when `IsDRLTActive` (defaults 2 / 1 / 1; inert while DRLT is INT32_MAX).
6. External tip-verify budget soak + C-15 seal-binding review remain GO/NO-GO
   items before raising a public height (see soak protocol below).

### Tip-verify soak protocol (Phase B; no silicon numbers)

Before setting a public `nMatMulDRLTHeight` with seal-as-PoW, run a **protocol
soak** on representative tip-verify hardware — record wall times locally; do
**not** paste unverified silicon numbers into this doc:

1. Enable LT + seal on a private/regtest chain (`-regtestdrltheight`,
   `-regtestmatmulltsealaspow`); leave public nets at `INT32_MAX`.
2. Deliver near-tip seal blocks over P2P so the async EncDr path runs
   (`MatMulVerifyWorker` with parent MTP from Classify under `cs_main`).
3. Measure: seal recompute wall time, pending-slot occupancy vs
   `nMatMulLTMaxPendingVerifications`, global/peer defer rate vs
   `nMatMulLT*VerifyBudgetPerMin`, message-thread latency (g_msgproc_mutex).
4. Calibrate LT pending/budget knobs from those measurements; raise only after
   honest tip advance stays unpaced and attacker-forced seal flood is bounded.
5. Pair with external seal-binding / C-15 review before any public height raise.

## Silicon / ratification gates (unchanged)

Do **not** set public `nMatMulDRLTHeight` finite until:

1. Tensor wall-time majority on B200 and 5090 for MatExpand+deep-m shape.
2. Calibrated `nMatMulDRLTAsertRescaleNum/Den` from measured nonce/s.
3. MI350 / OCP MX exactness PASS where claimed.
4. `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` for any non-regtest live height.
5. Phase B tip-verify budget soak (protocol above) + external seal-binding review
   if seal-as-PoW is required for the launch package.

## Source map

- Reference: `src/matmul/matmul_v4_lt.{h,cpp}` (`ComputeSealDigestBMX4CLT`, seal-auth helpers)
- Dispatch: `src/matmul/accel_v4.cpp` (`ComputeDigestsBMX4CLTDispatched`)
- Consensus: `src/pow.cpp` (solve + EncDr seal recompute), `src/validation.cpp`, `src/kernel/chainparams.cpp`, `src/net_processing.cpp` (MMSKETCH skip)
- Params: `fMatMulLTSealAsPoW` / `IsMatMulLTSealAsPoWActive`,
  `nMatMulLTMaxPendingVerifications`, `nMatMulLT{Global,Peer}VerifyBudgetPerMin`
- Async: `src/node/matmul_verify_worker.*` (Job carries parent MTP)
- Tests: `src/test/matmul_v4_lt_tests.cpp` (`phase_b_seal_*`),
  `src/test/matmul_verify_worker_tests.cpp` (`seal_async_forwards_parent_mtp`,
  `lt_tip_verify_budget_knobs`)
