# PR #89 — Second External Audit (0.33.2 NO-GO) Remediation Status

*Response to the second external "Adversarial Security Review and Required
Remediation" (audited head `c324361`, target `0.33.2`, verdict: safe only while
completely inert, NOT activation-ready). Each item was re-verified against the
branch and, where code-fixable now, fixed and independently re-reviewed by a
separate adversarial lens before landing. This is the honest status map.
Date 2026-07-16.*

**Overall posture (unchanged and reaffirmed):** PR #89 is **inert experimental
code**. Mainnet AND every public testnet are DISABLED (`nMatMulV4Height`,
`nMatMulBMX4CHeight = INT32_MAX`); the header-PoW throttle is disabled and
structurally un-enableable. This is **NOT an activation-capable `0.33.2`** and
must not be released as one until every CRITICAL/HIGH item is closed and the
activation-evidence program (hardware, testnet, calibration, independent review)
is complete.

## Activation model / policy

| ID | Audit item | Disposition | This branch |
|----|-----------|-------------|-------------|
| **UA-1** | Public testnet still uses staged 200k→250k activation | **FIXED** | Testnet `nMatMulV4Height` and `nMatMulBMX4CHeight` set to `INT32_MAX` (staged schedule withdrawn); the unified `v4==bmx4c` requirement is documented for the eventual approved height |

The whole upgrade now activates as a **unified direct v3 → v4.2/ENC-BMX4C**
transition at one height where `nMatMulV4Height == nMatMulBMX4CHeight`; there is
no public ENC-S8 (v4.1) interval, and the single calibrated v3→v4.2 rescale is
carried by the BMX4-C rescale (the v4 rescale stays inert `1/1`).

## Architectural blockers (OPEN)

| ID | Audit item | Disposition |
|----|-----------|-------------|
| **C1** | MatMul header chainwork is not authenticated | **REAL-OPEN (architectural)** — the SHA throttle is a rate limiter, not authentication (SHA ≈ 10⁷× cheaper than a matmul eval). Closing it needs either a compact header-verifiable matmul-work proof bound to `nBits`, or a chain-selection redesign that does not credit matmul chainwork to `nChainWork`/best-header/IBD until the block body verifies. Documented in `doc/btx-matmul-v4.2-header-pow-gate.md`. |
| **C1-A** | Forged best headers relax verification budgets (≈200k/min in IBD-like state) | **REAL-OPEN** — tied to C1: do not derive relaxed budgets from unauthenticated headers; keep hard global CPU limits in IBD; separate authenticated-chain progress from advertised best-header work. Needs the C1 redesign to fully close. |

## Header throttle

| ID | Audit item | Disposition | This branch |
|----|-----------|-------------|-------------|
| **H1** | Throttle grinds `nNonce`, which is not on the header wire — enabling it now risks a reject-all fork | **Correctly DISABLED** | Un-enableable until `BTX_HEADER_NONCE_ON_WIRE` (startup-asserted); activation is a staged header-format change |
| **H2** | Discount ≥ 256 maps to `powLimit`, recreating a fixed-cost gate; the test blessed discount 256 | **FIXED** | Valid discount range is now **0..255** (`UINT32_MAX` = disabled only). `Consensus::Params::MATMUL_HEADER_POW_MAX_DISCOUNT_BITS = 255` + `IsMatMulHeaderPoWDiscountValid()`; rejected fatally at chain-parameter construction and fail-**closed** at runtime (never `powLimit`). The unit test that blessed 256 was replaced. |
| **H3** | 32-bit grinding nonce can be exhausted as `nBits` grows | **OPEN (design)** — disabled today; before activation, use a wider dedicated throttle nonce (or a rigorously specified rollover / another consensus-safe search dimension) and prove safety across the whole difficulty range. Tracked with H1's wire change. |
| **H4** | Target-binding regression test is probabilistic (nBits is inside `GetHash()`) | **FIXED** | Extracted a **pure** gate-target helper `DeriveMatMulHeaderPoWGateTarget(nBits, discount, powLimit)` (declared in `pow.h`) and added fixed-vector tests (`MatMulHeaderPoWGateTarget_pure_fixed_vectors`) covering discounts 0/1/8/255, the invalid 256 and `UINT32_MAX-1`, the disabled sentinel, `powLimit` saturation, and nBits-ordering — vectors a fixed-target implementation cannot reproduce. |

## Difficulty / ASERT schedule

| ID | Audit item | Disposition | This branch |
|----|-----------|-------------|-------------|
| **D1** | Invalid ASERT config fails **open** to `powLimit`, and future-fork params are checked every block (a malformed future config weakens CURRENT difficulty at startup) | **FIXED** | Immutable ASERT params are now validated **fatally at chain-parameter construction** (`AssertBMX4CConstructionInvariants → ValidateMatMulAsertParams`, for all 6 MatMul networks incl. signet/shieldedv2dev, and re-validated on regtest after the `-regtest*` ASERT overrides). The per-block runtime path now fails **closed** (hardest target) via `MatMulAsertFailClosedBits()`; `CalculateMatMulAsertTarget`'s error returns likewise fail closed. `ValidateMatMulAsertParams` is a pure function of params (height is log context only), so construction-validity implies validity at every height — the fail-closed path is an unreachable defence-in-depth backstop. |
| **D2** | Branch-collision validation incomplete (non-inert `retune==asert`, `retune2==asert`, `retune2==retune`) | **FIXED** | All ten ordered branch pairs among {asert, retune, retune2, v4, bmx4c} are now collision-checked: the v4/bmx4c-vs-earlier cases in the C5 block, and the retune-family equality collisions added in `ValidateMatMulAsertParams` (rejecting only when the shadowed op is non-inert). Unified `v4==bmx4c` stays intentional (v4 branch guarded out, v4 ratio forced `1/1`, BMX4-C rescale is the sole active adjustment). |
| **D3** | `ScaleTargetByTimespan` clamps num/den to `UINT32_MAX` independently, distorting large ratios (`2^40/2^39 = 2 → 1`) | **FIXED** | New `ReduceRescaleRatioToU32(num, den, …)` GCD-reduces the ratio and requires both reduced terms to fit `uint32`; used both in validation and in the v4/bmx4c rescale application. A large-but-exact ratio (e.g. `2^40/2^39`) now reduces to `2/1` exactly; an irreducible `> uint32` ratio is rejected at construction. The `retune2` ratio is already `uint32` (no distortion class). Exact vectors added (D4 tests). |
| **D4** | Need one ASERT re-anchor at unified `H` (`H-1/H/H+1`, no ENC-S8, no double rescale, no shadowing) | **PARTIAL** | The unified-activation mechanism is covered by `matmul_unified_activation_tests`; the pure-vector and boundary coverage is extended here. Full `H-1/H/H+1` production-height functional coverage is part of the activation-evidence program. |

## Transport / storage

| ID | Audit item | Disposition |
|----|-----------|-------------|
| **P1** | Consensus block 24 MB > P2P message 16 MB; a 16–24 MB v4 block is un-relayable by external miners | **OPEN (design decision)** — the miner/GBT already soft-cap to the relay limit; the real fix is a consensus reduction to the transport ceiling or a negotiated extended block-transfer, plus the 16/24 MB boundary tests. |
| **P2** | `nMatMulProofPruneDepth` has no consumer | **DOCUMENTED** — marked NON-FUNCTIONAL/RESERVED in `consensus/params.h` with the true storage cost (~2.9 TiB/yr of ~8 MiB proofs at 90 s spacing, unbounded, no rolling store). Implementing proof-aware pruning (reorg/reindex/assumeUTXO/RPC semantics) or removing the field is the real fix. |
| **P3** | Compact-block relay cannot carry the mandatory proof (full-block fallback) | **OPEN** — needs a proof-aware compact-relay extension or authenticated sidecar with request/retry/fallback semantics and full-network propagation measurement. |

## GPU / hardware qualification (OPEN — no toolchain/hardware here)

| ID | Audit item | Disposition |
|----|-----------|-------------|
| **G1** | `verify-backend.sh` requires a `DEVICE_HIGH_MAGNITUDE_PASS` marker no backend emits | **OPEN** — the marker gate exists; the device-side emitter (bit-exact vs CPU oracle, device/driver/algorithm identity, no-CPU-fallback) is a tracked hardware follow-up. |
| **G2** | CUDA qualification may test a different shape/algorithm than production; cache keyed on PCI identity | **OPEN** — qualify exact production shapes; pin/record the cuBLASLt algorithm; include device/driver/runtime/library/shape/algo in the cache key. |
| **G3** | "Mixed-GPU" qualification is still single-device (`selected_devices.front()`); no device arg / sharding | **OPEN** — add explicit device selection to the BMX4-C API and qualify every configured device through the production dispatch path. |
| **G4** | CUDA OOM adaptation incomplete (host/native allocations before the adaptive-Q retry) | **OPEN** — move all Q-dependent allocations inside the retry region; test host/device/native OOM and deterministic final fallback. |
| **G5** | Hardware matrix incomplete (CUDA/HIP runtime, Blackwell MXF4, mixed-GPU, M5 Metal, M-t24, stress/thermal) | **OPEN by design** — needs real multi-vendor hardware; consensus-safe (CPU re-verify) but not activation-performance evidence. |

## Documentation (audit §8) — done / in progress
All v4.2 docs are being made to consistently state: unified direct v3→v4.2/ENC-BMX4C
(`nMatMulBMX4CHeight == nMatMulV4Height`, no public ENC-S8); mainnet + all public
testnets DISABLED with no scheduled activation date; the withdrawn 200k/250k
testnet schedule; the header throttle does not close C1; backend qualification
incomplete until real device markers exist; `nMatMulProofPruneDepth` non-functional
with the true storage cost disclosed; compact-block relay does not transport the
mandatory proof.

## Merge / activation decision (reaffirmed)
- **Merge as activated production consensus:** NO.
- **Merge as inert experimental code:** acceptable only with mainnet + every public
  testnet disabled (regtest the only enabled integration network), experimental
  labelling, no scheduled activation height, and invalid ASERT config unable to
  weaken current difficulty (D1 — now enforced at startup).
- **Activate soon:** NO. Activation remains blocked by C1 authenticated chainwork,
  the unified direct-to-v4.2 transition evidence, the safe header nonce/wire design,
  ASERT calibration, consensus/P2P size coherence, proof relay/storage design,
  real per-device backend qualification, and completed cross-platform evidence.
