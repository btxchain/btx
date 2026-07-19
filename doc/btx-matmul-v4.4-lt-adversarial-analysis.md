# BTX MatMul v4.4-LT — Adversarial analysis & hardening status

*Status: MatExpand C-15 class has a **selected cryptographic extractor candidate**
(Lever-B logical MX/E2M1 block-scale Extract + M11; frozen goldens) with **implementation
mitigations** (non-affinity tests) but **external review remains open** — not
closed. Q* Phase B seal-as-PoW is implemented and inert (`nMatMulDRLTHeight =
INT32_MAX`). Activation remains gated.*

*Execution note: “logical MX” describes consensus mantissas/scales, not a
native MXFP4 hardware path. Current LT CUDA/HIP dequantize to dense INT8 and
use qualified IMMA/MFMA; native MXFP4 is not wired.*
*Companion: `doc/btx-matmul-v4.4-lt-normative-spec.md`. Hardening response: `doc/btx-matmul-v4.4-lt-hardening-response-2026-07-19.md`.*

## Threat model (LT-specific)

| ID | Attack | Disposition |
|---|---|---|
| LT-C15 | Freivalds reassociation through linear MatExpand fold (`B̂ = fold(GWH)` affine in panels) | **CANDIDATE SELECTED; EXTERNAL REVIEW OPEN** — normative `ExtractDequantMatExpand` = Lever-B MX-block Extract: E8M0 scales shared on 32-col blocks per row + one ChaCha20 M11 tile stream per `(i,bj)` (`prf_key = SHA256("BTX_MATEXPAND_MXPRF_V44LT"‖seed_W)`). Legacy per-cell ChaCha (`ExtractDequantMatExpandChaChaCell`) is differential-only. In-tree witnesses disagree with affine/low-degree surrogates on dense samples; that is **not** a Freivalds non-collapse proof. **Do not claim C-15 cryptographically closed.** Pre-Extract `rank(B32)≤w=1024` is by design; linearized Extract would reopen ~`n/w=4×` panel collapse. PRF/MX ≠ MatExpand work lower bound; ~32× PRF dilution ≠ closure. Falsifiable game: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1. |
| LT-Q1 | Skinny single-nonce launches under fat `Q*` schedule | **IMPLEMENTED, REVIEW PENDING (Phase B, inert)** — when `fMatMulLTSealAsPoW` + live DRLT, lottery object is the Q* window seal (`ComputeSealDigestBMX4CLT`); Phase A remains per-nonce digest when the toggle is off. **Q\* is aggregate work commitment only** — it commits leaf digests and does **not** prove classical GEMM, tensor-core use, or simultaneous slot execution. **Slot-id binding is consensus:** full 256-bit `DeriveWindowSlotId` folds into V3 seeds via `BindWindowSlotIdIntoSeeds` and into each Merkle leaf via `CommitWindowSlotLeaf`; duplicate slot ids fail closed. Low-64 `DeriveWindowSlotNonce` is only the header grinding field (`ReadLE64(slot_id)`). External seal-binding review still required before any public height that enables seal-as-PoW. |
| LT-Q2 | Window-seal PoW without MTP-threaded sibling seeds | **IMPLEMENTED, REVIEW PENDING (Phase B, inert)** — EncDr / solve thread parent MTP into `SlotSeedFn` → `SetDeterministicMatMulSeeds` for every slot, then consensus `BindWindowSlotIdIntoSeeds`; sketch-cache `H(σ‖Chat)==matmul_digest` skipped in seal mode. Code complete; independent review of MTP/seed binding still pending. |
| LT-A1 | ASERT continuous across MatExpand/deep-m work shift | **CLOSED in code** — `nMatMulDRLTHeight` rescale + re-anchor; ratios default 1/1 until silicon calibration against the **fastest known exact** miner path |
| LT-V1 | Missing `n % 32` gate for `ENC_BMX4C_LT` | **CLOSED** — validation mirrors ENC-BMX4C |
| LT-P1 | Live DRLT with wrong tile/rank pin | **CLOSED** — construction asserts `b=2`, `m=BMX4C_LT_SKETCH_RANK_M` |

## MatExpand non-collapse argument (implementation)

Normative map (per tile `(i, bj=j/32)` then cell `(i,j)`):

1. `Y = G·W`, `B32 = Y·H` — exact integer GEMMs (unchanged).
2. `prf_key = SHA256("BTX_MATEXPAND_MXPRF_V44LT" ‖ seed_W)` — 256-bit ChaCha20 key.
3. `e = SHA256("BTX_MATEXPAND_MXSCALE_V44LT" ‖ prf_key ‖ LE32(i) ‖ LE32(bj))[0] & 3`.
4. Mantissa tile = one ChaCha20 stream (`nonce_first = bj ⊕ 'MXBL'`,
   `nonce_second = (i<<32)|bj`, `counter = remix`); nibbles XOR-mixed with
   `((uint32(raw)*0x9E3779B9)>>28)` then `SampleMantissaNibble` until 32 μ.
5. Output **exact mul** `μ·2^e` with `|μ·2^e| ≤ 48` (never signed left-shift).

**Rationale (candidate selection):** MX/E2M1 block layout matches miner tensor
lanes and cuts MatExpand PRF blocks ~32× vs per-cell ChaCha while keeping the
`[-48,48]` alphabet. This is a **consensus digest hard fork** of the LT
transcript. **Not** a closed cryptanalysis. **PRF ≠ work lower bound.**

Why this is argued to block the linear shortcut class (not proven):

- A Freivalds probe that is linear in `B̂` cannot pull `G`/`W`/`H` through
  ChaCha/M11/table rejection **if** Extract has no useful affine/low-degree surrogate.
- Position salts `(i,bj)` and full `seed_W`-derived key kill translation /
  panel-reuse collapses across A vs B; B32-bound nibble mix keeps Extract non-XOF.
- Legacy Fold / SplitMix / ChaChaCell remain exported **only** for differential tests.

Tests: `matexpand_extract_range`, `matexpand_not_affine_in_raw`,
`matexpand_position_salt_differential`, `matexpand_chacha_prf_golden_vectors`,
`matexpand_mx_scale_partitioned_right_matches_dense`
in `src/test/matmul_v4_lt_tests.cpp`.

## Consensus Q* — Phase A vs Phase B

**Phase A (default when LT live, `fMatMulLTSealAsPoW = false`):**

- `nMatMulConsensusQStar ∈ {128,256,512}` pinned at construction when DRLT is live.
- Miner evaluates fat windows; lottery object remains **per-nonce** `H(σ‖Ĉ)` (ENC-DR cache auth intact).
- Seal helpers (`ComputeWindowMerkleRoot` / `SealWindowCommit`) remain available for harnesses.

**Phase B (IMPLEMENTED, inert on public nets):**

1. Mode toggle `Consensus::Params::fMatMulLTSealAsPoW` (default `false`). Active only via `IsMatMulLTSealAsPoWActive(height)` = `IsDRLTActive(height) && fMatMulLTSealAsPoW`. Public nets keep `nMatMulDRLTHeight = INT32_MAX`, so the mode is fail-closed regardless of the toggle. Regtest opt-in: `-regtestmatmulltsealaspow` with a live `-regtestdrltheight`.
2. Lottery object: `matmul_digest := SealWindowCommit(σ_anchor, Merkle(CommitWindowSlotLeaf(slot_id, digest)), Q*)` via `ComputeSealDigestBMX4CLT`.
3. Slot identity: `slot_id := DeriveWindowSlotId(σ_anchor, j)` (256-bit); `nNonce64 := ReadLE64(slot_id)`. Sibling V3 seeds: `SlotSeedFn` → `SetDeterministicMatMulSeeds(..., parent_MTP)` then mandatory `BindWindowSlotIdIntoSeeds` (LT-Q2 + full-id bind). Duplicate `slot_id` rejects the seal.
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
