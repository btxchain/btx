# BTX MatMul v4.4-LT — Adversarial analysis & hardening status

*Status: implementation closed for MatExpand C-15 class + Q* Phase B seal-as-PoW; activation still gated (`nMatMulDRLTHeight = INT32_MAX`).*
*Companion: `doc/btx-matmul-v4.4-lt-normative-spec.md`.*

## Threat model (LT-specific)

| ID | Attack | Disposition |
|---|---|---|
| LT-C15 | Freivalds reassociation through linear MatExpand fold (`B̂ = fold(GWH)` affine in panels) | **CLOSED in code** — `ExtractDequantMatExpand` = position-salted Mix + M11 rejection + scale `e∈{0..3}`; not affine in the GEMM accumulator |
| LT-Q1 | Skinny single-nonce launches under fat `Q*` schedule | **CLOSED (Phase B, inert)** — when `fMatMulLTSealAsPoW` + live DRLT, lottery object is the Q* window seal (`ComputeSealDigestBMX4CLT`); Phase A remains per-nonce digest when the toggle is off |
| LT-Q2 | Window-seal PoW without MTP-threaded sibling seeds | **CLOSED (Phase B, inert)** — EncDr / solve thread parent MTP into `SlotSeedFn` → `SetDeterministicMatMulSeeds` for every slot; sketch-cache `H(σ‖Chat)==matmul_digest` skipped in seal mode |
| LT-A1 | ASERT continuous across MatExpand/deep-m work shift | **CLOSED in code** — `nMatMulDRLTHeight` rescale + re-anchor; ratios default 1/1 until silicon calibration |
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
5. Async EncDr worker: `ClassifyMatMulEncDrRecompute` returns nullopt at seal heights so validation always has parent MTP.
6. External tip-verify budget soak + C-15 seal-binding review remain GO/NO-GO items before raising a public height.

## Silicon / ratification gates (unchanged)

Do **not** set public `nMatMulDRLTHeight` finite until:

1. Tensor wall-time majority on B200 and 5090 for MatExpand+deep-m shape.
2. Calibrated `nMatMulDRLTAsertRescaleNum/Den` from measured nonce/s.
3. MI350 / OCP MX exactness PASS where claimed.
4. `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` for any non-regtest live height.
5. Phase B tip-verify budget + external seal-binding review if seal-as-PoW is required for the launch package (code path exists; measurement/review still required).

## Source map

- Reference: `src/matmul/matmul_v4_lt.{h,cpp}` (`ComputeSealDigestBMX4CLT`, seal-auth helpers)
- Dispatch: `src/matmul/accel_v4.cpp` (`ComputeDigestsBMX4CLTDispatched`)
- Consensus: `src/pow.cpp` (solve + EncDr seal recompute), `src/validation.cpp`, `src/kernel/chainparams.cpp`, `src/net_processing.cpp` (MMSKETCH skip)
- Params: `fMatMulLTSealAsPoW` / `IsMatMulLTSealAsPoWActive`
- Tests: `src/test/matmul_v4_lt_tests.cpp` (`phase_b_seal_*`)
