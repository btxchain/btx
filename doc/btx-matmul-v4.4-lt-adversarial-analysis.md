# BTX MatMul v4.4-LT — Adversarial analysis & hardening status

*Status: implementation closed for MatExpand C-15 class; activation still gated.*
*Companion: `doc/btx-matmul-v4.4-lt-normative-spec.md`.*

## Threat model (LT-specific)

| ID | Attack | Disposition |
|---|---|---|
| LT-C15 | Freivalds reassociation through linear MatExpand fold (`B̂ = fold(GWH)` affine in panels) | **CLOSED in code** — `ExtractDequantMatExpand` = position-salted Mix + M11 rejection + scale `e∈{0..3}`; not affine in the GEMM accumulator |
| LT-Q1 | Skinny single-nonce launches under fat `Q*` schedule | **Mitigated** — Phase A miner windows; Phase B seal-as-PoW binds full Q* when `fMatMulLTSealAsPoW` (still inert: needs live DRLT height) |
| LT-Q2 | Window-seal PoW without MTP-threaded sibling seeds | **Mitigated (Phase B)** — `SlotSeedFn` + `SetDeterministicMatMulSeeds` threads parent MTP into every window slot |
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

**Phase A (shipped, inert until height raised):**

- `nMatMulConsensusQStar ∈ {64,128}` pinned at construction when DRLT is live.
- Miner evaluates fat windows; lottery object remains **per-nonce** `H(σ‖Ĉ)` (ENC-DR cache auth intact).
- Seal helpers (`ComputeWindowMerkleRoot` / `SealWindowCommit`) are available for measurement harnesses.

**Phase B (implemented, inert until DRLT height is live AND `fMatMulLTSealAsPoW`):**

1. ~~Redefine `matmul_digest := SealWindowCommit(...)`~~ — `ComputeSealDigestBMX4CLT`
2. ~~Thread parent MTP into sibling seeds~~ — `SlotSeedFn` / solve path
3. ~~Sketch-cache auth for seal~~ — `SealWindowProofMatchesCommitment` + `VerifySealWindowFreivalds` (no `H(σ‖Chat)==seal` requirement)
4. Tip verify cost at production `n` with `Q*` — still a silicon GO/NO-GO measurement
5. External C-15-class review of the seal binding + MatExpand surface — still required before raising height

Default: `fMatMulLTSealAsPoW = false` on all nets; regtest opt-in via `-regtestmatmulltsealaspow`.

## Silicon / ratification gates (unchanged)

Do **not** set public `nMatMulDRLTHeight` finite until:

1. Tensor wall-time majority on B200 and 5090 for MatExpand+deep-m shape.
2. Calibrated `nMatMulDRLTAsertRescaleNum/Den` from measured nonce/s.
3. MI350 / OCP MX exactness PASS where claimed.
4. `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` for any non-regtest live height.
5. Phase B items if seal-as-PoW is required for the launch package.

## Source map

- Reference: `src/matmul/matmul_v4_lt.{h,cpp}`
- Dispatch: `src/matmul/accel_v4.cpp` (`ComputeDigestsBMX4CLTDispatched`)
- Consensus: `src/pow.cpp`, `src/validation.cpp`, `src/kernel/chainparams.cpp`
- Tests: `src/test/matmul_v4_lt_tests.cpp`
