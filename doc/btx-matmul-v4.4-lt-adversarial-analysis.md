# BTX MatMul v4.4-LT — Adversarial analysis & hardening status

*Status: MatExpand C-15 class has a **selected cryptographic extractor candidate**
(ChaCha20 PRF + M11 rejection; frozen goldens) with **implementation mitigations**
(non-affinity tests) but **external review remains open** — not closed. Q* Phase B
seal-as-PoW is implemented and inert (`nMatMulDRLTHeight = INT32_MAX`). Activation
remains gated.*
*Companion: `doc/btx-matmul-v4.4-lt-normative-spec.md`. Hardening response: `doc/btx-matmul-v4.4-lt-hardening-response-2026-07-19.md`.*

## Threat model (LT-specific)

| ID | Attack | Disposition |
|---|---|---|
| LT-C15 | Freivalds reassociation through linear MatExpand fold (`B̂ = fold(GWH)` affine in panels) | **CANDIDATE SELECTED; EXTERNAL REVIEW OPEN** — normative `ExtractDequantMatExpand` = domain-separated ChaCha20 PRF over `(prf_key, raw, i, j, remix)` + M11 rejection + scale `e∈{0..3}` (`prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT"‖seed_W)`). In-tree witnesses disagree with affine/low-degree surrogates on dense samples; that is **not** a Freivalds non-collapse proof. SplitMix path retained only for differential tests. **Do not claim C-15 cryptographically closed.** Pre-Extract `rank(B32)≤w=1024` is by design (`O(n²·w)` MatExpand, not `O(n³)`); linearized Extract would reopen ~`n/w=4×` panel collapse. ChaCha-as-PRF ≠ MatExpand work lower bound. Falsifiable game: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1. |
| LT-Q1 | Skinny single-nonce launches under fat `Q*` schedule | **IMPLEMENTED, REVIEW PENDING (Phase B, inert)** — when `fMatMulLTSealAsPoW` + live DRLT, lottery object is the Q* window seal (`ComputeSealDigestBMX4CLT`); Phase A remains per-nonce digest when the toggle is off. **Q\* is aggregate work commitment only** — it commits leaf digests and does **not** prove classical GEMM, tensor-core use, or simultaneous slot execution. **Slot-id binding is consensus:** full 256-bit `DeriveWindowSlotId` folds into V3 seeds via `BindWindowSlotIdIntoSeeds` and into each Merkle leaf via `CommitWindowSlotLeaf`; duplicate slot ids fail closed. Low-64 `DeriveWindowSlotNonce` is only the header grinding field (`ReadLE64(slot_id)`). External seal-binding review still required before any public height that enables seal-as-PoW. |
| LT-Q2 | Window-seal PoW without MTP-threaded sibling seeds | **IMPLEMENTED, REVIEW PENDING (Phase B, inert)** — EncDr / solve thread parent MTP into `SlotSeedFn` → `SetDeterministicMatMulSeeds` for every slot, then consensus `BindWindowSlotIdIntoSeeds`; sketch-cache `H(σ‖Chat)==matmul_digest` skipped in seal mode. Code complete; independent review of MTP/seed binding still pending. |
| LT-A1 | ASERT continuous across MatExpand/deep-m work shift | **CLOSED in code** — `nMatMulDRLTHeight` rescale + re-anchor; ratios default 1/1 until silicon calibration against the **fastest known exact** miner path |
| LT-V1 | Missing `n % 32` gate for `ENC_BMX4C_LT` | **CLOSED** — validation mirrors ENC-BMX4C |
| LT-P1 | Live DRLT with wrong tile/rank pin | **CLOSED** — construction asserts `b=2`, `m=BMX4C_LT_SKETCH_RANK_M` |

## MatExpand non-collapse argument (implementation)

Normative map (per entry `(i,j)`):

1. `Y = G·W`, `B32 = Y·H` — exact integer GEMMs (unchanged).
2. `prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W)` — 256-bit ChaCha20 key.
3. Mantissa stream = ChaCha20 keystream (`crypto/chacha20.h`, RFC8439 layout)
   with Nonce96 `(uint32(raw)⊕lane, pack(i,j)=(uint64(i)<<32)|j)`, `counter = remix`;
   take first 8 bytes LE (`ReadLE64`). Encoding pin: external C-15 packet §1.4.
4. Walk nibbles through `SampleMantissaNibble` → `μ ∈ M11` (remix++ on exhaustion).
5. Scale stream = independent ChaCha20 lane (`SCLE`); `e = stream & 3`;
   output **exact mul** `μ·2^e` with `|μ·2^e| ≤ 48` (never signed left-shift).

**Rationale (candidate selection):** in-tree ChaCha20 is a reviewed stream cipher
(RFC8439 / Bitcoin Core). Prefer over SplitMix64 (not a PRF) and over per-entry
SHA256 (heavier; same security class as existing seed tags). BLAKE3 is not in-tree.
This is a **candidate**, not a closed cryptanalysis. **ChaCha-as-PRF ≠ work lower bound.**

Why this is argued to block the linear shortcut class (not proven):

- A Freivalds probe that is linear in `B̂` cannot pull `G`/`W`/`H` through ChaCha/M11/table rejection **if** Extract has no useful affine/low-degree surrogate.
- Position salts `(i,j)` and full `seed_W`-derived key kill translation / panel-reuse collapses across A vs B; `U`/`V` are rank-transparent and do not hide `rank(B32)≤128`.
- Legacy `FoldInt32ToEmax48` (`y % 97 → [-48,48]`) and SplitMix
  `ExtractDequantMatExpandSplitMix` remain exported **only** for differential tests.

Tests: `matexpand_extract_range`, `matexpand_not_affine_in_raw`,
`matexpand_position_salt_differential`, `matexpand_chacha_prf_golden_vectors`
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
