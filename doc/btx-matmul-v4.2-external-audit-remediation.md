# PR #89 — External Audit (0.33.2 NO-GO) Remediation Status

*Response to the external "Required Remediation Before Merge or Activation" audit
(audited head `f65be2b`, target `0.33.2`, verdict NO-GO for production). Each item
below was re-verified against current HEAD by an independent verification lens
before action — several audit items were already fixed on the branch or were
outdated. This document is the honest status map. Date 2026-07-16.*

**Overall posture (unchanged and reaffirmed):** PR #89 is **inert experimental
code**. All production activation heights are DISABLED (`nMatMulV4Height`,
`nMatMulBMX4CHeight` = `INT32_MAX` on mainnet/testnet4; the header-PoW throttle is
disabled and structurally un-enableable). This is **NOT an activation-capable
`0.33.2`** and must not be released as one until every CRITICAL/HIGH item is
closed and the activation-evidence program (hardware, testnet, calibration,
independent review) is complete.

## Critical / high consensus items

| ID | Audit claim | Verified disposition | This branch |
|----|-------------|----------------------|-------------|
| **C1** | Headers credit `nBits` chainwork before the body authenticates `matmul_digest` | **REAL-OPEN (architectural)** | Throttle improved (C2); true authentication is architectural — see below |
| **C2** | Header spam gate proves CONSTANT work vs variable `nBits` claim | **FIXED (as a throttle)** | Gate rebound to `nBits`: cost ∝ claimed work (`1733b44`) |
| **C3** | "Single activation" not operationally complete | **PARTIAL / process** | Mechanism correct; hardware/testnet/calibration open |
| **C4** | `56044aa` half-life anchor guard over-restricts | **FIXED (cleaner way)** | Monotonic `max()` anchor selector; over-restrictive guard removed (`1733b44`) |
| **C5** | ASERT cascade collisions silently skip the rescale | **FIXED** | Reject non-inert rescale colliding with an earlier branch (`1733b44`) |
| **C6** | Production ASERT rescale uncalibrated (`1/1`) | **OPEN (measurement)** | Needs on-hardware v3→BMX4C throughput measurement (Gate C) |

### C1/C2 — header work (the one genuine consensus/DoS surface)
C1 and C2 are **one weakness**: at v4 heights header work is forgeable
(`matmul_digest` is a self-declared field, checked ≤ target at Phase1 but only
proven when the body arrives), so an attacker can credit `nChainWork` from `nBits`
without doing the work. **What this branch fixed (C2):** the header-PoW gate now
binds its target to the block's own `nBits` target shifted by
`nMatMulHeaderPoWDiscountBits`, so forging a header claiming difficulty `D` costs
`~D/2^discount` header hashes — proportional to the claimed chainwork, not a fixed
constant. **What remains OPEN (C1):** a SHA-based header PoW cannot *authenticate*
matmul-calibrated chainwork (SHA ≈ 10⁷× cheaper than a matmul eval), so this is a
rate-limiting **throttle**, not authentication. Closing C1 is architectural —
either a header-verifiable matmul-work proof bound to `nBits`, or (recommended, and
likely smaller) a **chain-selection redesign that does not credit matmul chainwork
to `nChainWork`/best-header/IBD until the block body has verified**. Documented in
`doc/btx-matmul-v4.2-header-pow-gate.md`. The throttle is additionally
un-enableable until the `nNonce`-on-wire header-format change lands
(`BTX_HEADER_NONCE_ON_WIRE`, startup-asserted).

## Header-sync / resource

| ID | Disposition | Status |
|----|-------------|--------|
| **H1** | REAL-OPEN (moderate): synthetic ASERT ancestry retained via sparse `pprev` grows O(chain) on deep presync (`headerssync.cpp`; `MatMulRequiredSyntheticFloor` fixes a floor) | OPEN — recommend an explicit compact synthetic-anchor state (anchor height/target/time + recent window) instead of a long sparse `pprev` chain |
| **H2** | Gate must run before claimed-work credit (presync/redownload) | Tied to C1 activation; enforce in `CheckHeadersPoW`/presync when the gate is enabled |

## Block construction / P2P / proof carriage

| ID | Disposition | Status |
|----|-------------|--------|
| **P1** | REAL-OPEN (miner self-DoS) | **FIXED** (`1733b44`): `BlockAssembler` reserves the exact ~8 MiB v4 payload before tx selection |
| **P2** | REAL-OPEN (design gap): consensus block 24 MB > P2P message 16 MB, so a 16–24 MB v4 block is un-relayable | OPEN — decision required: reduce the effective v4 block limit to the relay-safe 16 MB (soft cap in the miner is an interim; a consensus reduction is the real fix), or a negotiated extended block-transfer / proof-chunk relay extension |
| **P3** | REAL-OPEN: compact blocks (BIP152) don't carry the mandatory proof → full-block fallback | OPEN — needs a proof-aware relay extension (`getmatmulproof`/`matmulproof` or a proof commitment) |
| **P4** | REAL (dead param): `nMatMulProofPruneDepth` has no consumer | OPEN — either implement proof-aware pruning or remove the param; storage claims corrected (D2) |

## GPU / backend

| ID | Disposition | Status |
|----|-------------|--------|
| **G1** | Audit's specific value is WRONG (actual boundary is `2^24`), and the report tool's M-t24 vectors are a CPU self-test that cannot false-pass. BUT the CUDA *device* qualification probe was 64-divisible and could false-pass at t≤23 | **FIXED** (CUDA device probe now uses the odd `16,777,145`, compile-unverified `1edd3c6`) |
| **G2/G3/G6** | CUDA device binding / Metal MPP const decls / CUDA OOM Q-adaptation | **FIXED** (compile-unverified `1edd3c6`) |
| **G4** | Backend verify greps CPU test names as device evidence | Verify script now requires a runtime `DEVICE_HIGH_MAGNITUDE_PASS` marker (`1edd3c6`); the test-side emitter is a tracked follow-up. (Note: existing eligibility/`SKIPPED-PENDING-HARDWARE` gating already prevented the naïve false-qualification) |
| **G5** | HIP native MXFP4 is a false-return scaffold | OPEN by design — needs AMD CDNA + ROCm hardware; the report tool correctly marks native-path qualification unavailable |
| **GPU CMake** | bmx4 accel sources absent from CMake; HIP guard-name mismatch | OPEN — documented precise fix; untestable without a GPU toolchain; consensus-safe (CPU fallback) |

## Config / RPC

| ID | Disposition | Status |
|----|-------------|--------|
| **I1** | Missing `nMatMulV4TranscriptBlockSize == kTileB` invariant | **FIXED** (`1733b44`) |
| **I2** | GBT/mining RPCs not fully height-aware | PARTIAL — `encoding_profile` + `nonce64` added (`85c5d0f`/`d4f5528`); proof-reserved-bytes / relay-limit fields recommended |
| **I3** | Service RPCs must use live profile consistently | FIXED-UPSTREAM (`48356e2`) |

## Documentation corrections (D1–D5) — done
- **D1 (no activation-ready language):** this doc and the findings doc state
  plainly that passing CPU tests, accepting equal heights, or the throttle do NOT
  close the activation blockers; the header throttle is labelled a throttle, not
  authentication.
- **D2 (storage):** the "~80 GiB rolling proof store" is **not** implemented —
  `nMatMulProofPruneDepth` is dead (no consumer), and on a default node every
  ~8 MiB proof is retained, i.e. **~2.9 TiB/yr of unbounded growth at 90 s
  spacing**. No rolling/archival split exists yet.
- **D3 (relay):** the 16 MB P2P message limit, the 24 MB consensus limit, the
  ~8 MiB mandatory proof, and the lack of compact-block proof carriage (full-block
  fallback) are stated (P2/P3).
- **D4 (backend qualification):** source-compile / runtime-compile / device-exec /
  native-tensor / ALU-fallback / CPU-fallback / bit-exact / calibration are
  distinct; a fallback PASS is never a native-path qualification (G4).
- **D5 (unified activation):** at `v4==bmx4c`, ENC-S8 is skipped, the live profile
  is ENC-BMX4C, the v4 rescale stays `1/1`, the BMX4C rescale carries the full
  conversion, and the header throttle stays disabled until its wire/design work is
  complete.

## Activation-evidence program (out of code scope — OPEN)
C3, C6, G5, T1–T5, CI1/CI2, and the §11 network-readiness snapshot require:
calibrated v3→BMX4C rescale from real-hardware measurement; two-vendor
device-executed bit-exact qualification; production-sized relay + external-pool
conformance tests; a full-node enforcing (`-matmulstrict`) unified-activation
functional test (blocked today only by the pre-existing test-harness v4-mining gap,
being fixed); public testnet burn-in; independent multi-domain review; a signed
release; and demonstrated supermajority adoption. **None of these are satisfied,
and production activation remains disabled until they are.**
