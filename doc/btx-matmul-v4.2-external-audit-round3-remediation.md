> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# PR #89 — Third External Audit (0.33.2 NO-GO) Remediation Status

*Response to the third external "Adversarial Security Review and Fix Handoff"
(target `0.33.2`, verdict: NO-GO — safe only while completely inert). Each item
was re-verified against the branch and, where code-fixable now, fixed and
independently re-reviewed (an emulated independent-reviewer lens, not a
rubber-stamp) before landing. This is the honest status map. Date 2026-07-16.*

**Overall posture (unchanged and reaffirmed):** PR #89 is **inert experimental
code**. Mainnet AND every public testnet are DISABLED (`nMatMulV4Height`,
`nMatMulBMX4CHeight = INT32_MAX`); every behavioral change is gated behind
`IsMatMulV4Active(height)` and is therefore un-reachable on any live network.
This is **NOT an activation-capable `0.33.2`**. NO-GO stands.

## Status map

| ID | Item | Disposition | Commit / where |
|----|------|-------------|----------------|
| **P0-1 / C1** | Header MatMul chainwork is forged-header inflatable (self-declared `matmul_digest` credited full `GetBlockProof` before the body verifies), which can relax the assumevalid script-skip and poison best-header selection | **FIXED** | `843aabd` — provisional vs **authenticated** chainwork (`nAuthenticatedChainWork`): a v4+ block contributes work only once its body + MatMul product proof verified (`BLOCK_VALID_TRANSACTIONS`, gated by `ContextualCheckBlock`); routed into the two security-relaxing decisions (assumevalid skip, presync reporting); header-download/anti-DoS intentionally stays on provisional work (defended by the header spam gate). 6 adversarial unit tests + 230 consensus cases + activation functional test green. Design: `doc/btx-matmul-v4.2-chainwork-authentication.md` |
| **P0-2** | ENC-BMX4C-D (v4.2-D) must be removed from the consensus state machine, not merely disabled | **FIXED** | `44aedec` — removed the `ENC_BMX4CD` enum value, `nMatMulBMX4CDHeight`/ASERT params, `IsBMX4CDActive`, the `GetMatMulEncodingProfile` D branch, both pow.cpp dispatch branches (verify + solve), and the D construction asserts. Pure arithmetic retained only as clearly-labeled non-consensus reference with no production caller. 230 cases + 5-network startup green |
| **P0-3A** | Activation functional test asserted the v3 segment carried the v4 dimension | **FIXED** | `a25ce2f` — split `V3_DIMENSION`/`V4_DIMENSION`, assert each side of the v3→v4.2 boundary correctly |
| **P0-3B/C** | `getblocktemplate` / `getmatmulchallenge` (+ `getmininginfo`, `getdifficultyhealth`, `getmatmulchallengeprofile`) emit fields not declared in their `RPCResult` schemas → `-rpcdoccheck` aborts the RPC | **FIXED** | `7e97a7c`, `8f45a19` — declared every emitted field (hysteresis/deferred-reorg counters, private-parent withholding, required-backend, GPU prehash counters, CUDA buffer-pool object, gbt `encoding_profile`); doc-check functional tests green |
| **P0-3D** | `p2p_large_block_transport.py` only built a ~5.2 MB block (below 16 MB) and connected the peer in the wrong direction, so it never exercised the P1-1 path | **FIXED** | `a2deeac` — a precise unit test (V1 header size ceiling, both bounds + boundaries) plus a functional test that builds a 17.8 MB block and proves an empty-mempool peer pulls it via IBD over the block-bearing path (fixed the inbound-only peer-direction stall) |
| **P1-1** | Raising the GLOBAL P2P message limit to 24 MB expands the per-message DoS envelope for every command | **FIXED** | `a25ce2f` — ordinary messages back to 16 MB (`MAX_PROTOCOL_MESSAGE_LENGTH`); only `block`/`blocktxn` get 24 MB (`MAX_BLOCK_MESSAGE_LENGTH`); compile-time static_assert + per-network runtime assert (`nMaxBlockSerializedSize <= MAX_BLOCK_SERIALIZED_SIZE`) |
| **P1.4** | (same class as P0-3B/C) RPC schema completeness | **FIXED** | `7e97a7c`, `8f45a19` |
| **P1.5** | ENC-BMX4C GPU backends never linked (sources missing from CMake); `BTX_ENABLE_HIP_EXPERIMENTAL` guard mismatch; PRIVATE backend defines caused the silent-CPU-fallback vanities flagged | **FIXED** | `571c706` — wired the bmx4 cuda/metal/hip sources + stubs; fixed the HIP guard; made backend defines PUBLIC; fixed a CUDA signed-shift UB (`negative << shift` → `* (1<<shift)`) and a Metal ODR/namespace clash. GPU behind toolchain guards; CPU build + 66 backend/bmx4 cases green |
| **P1-3** | `verify-backend.sh` matches `DEVICE_HIGH_MAGNITUDE_PASS:<backend>:` but the CUDA code emitted `...:cuda-native-mxf4:` (tier in the backend field), so a genuine on-device PASS was reported as FAIL | **FIXED** | `b4adf13` — emit `DEVICE_HIGH_MAGNITUDE_PASS:cuda:<tier>-<device-id>`; verified at the contract level (script grep now matches the new string and not the old) |
| **P1-4** | GPU dispatch CPU-verified the full 8 MiB Freivalds on EVERY nonce in a window, though at most one can win | **FIXED** | `92ceb81` — thread the solve target in; full-verify only potential winners (`digest <= target`); losers can't be sealed so they are skipped; winner stays doubly protected (dispatch verify + solve-loop reference reseal). CPU path byte-identical; 81 cases green |
| **P1-5** | "Enforced-work" honesty: the doc must not overstate the anti-amortization / marginal-work floor | **ADDRESSED (doc)** | The floor is an **assumption, not a theorem** — see below and the C-15 audit (`doc/btx-matmul-v4.2-audit-hardness.md`) and spec §K.2b (every hardware-ordering and enforced-work claim is measurement-gated; two model estimates were already falsified on real silicon) |
| **P1-6** | Proof storage / prune parameter honesty | **ADDRESSED (doc)** — see below | `nMatMulProofPruneDepth` remains documented non-functional/reserved (round-2 P2); storage is unbounded until a real prune/relay-extension lands, which is an activation precondition, not a live feature |
| **P1-2** | CUDA scalar/INT8 fallback must not masquerade as the native FP4 tier | **DOCUMENTED — toolchain-gated** (below) | No CUDA toolchain in this environment; not blind-patched |

## P1-5 — enforced-work honesty (statement of record)

The per-nonce "marginal work floor" that difficulty is meant to price is an
**assumption, not a theorem**. The enforced object is a fixed rank-`m` linear
operator applied to pseudorandom `B`; the *proven* lower bound is Ω(n²)
(Freivalds), while the *claimed* enforced work is Θ(n²·m). No single reviewer
can prove the marginal unit has no sub-Θ(n²·m) shortcut, and there is a real,
cited sub-cubic/LCMA advantage on the combine. Consequently:

- **No spec text infers hardware ordering or enforced work from MAC/byte
  counts.** §K.2b treats every such claim as measurement-gated; the vanities
  measurements (H100/5090 = 0.40× at n=8192; ~25% INT8 utilization) are the
  pinned anchors, and two prior model estimates were falsified on real silicon.
- Activation is gated on the external C-15 cryptographic review of the
  marginal-work floor and on the on-silicon datacenter-ordering program — both
  OPEN, both blocking. The "reward ladder" is an **emergent** property of
  throughput under one uniform difficulty (there is no reward tiering;
  price-independence §0.7-(4) forbids it), and is only realized if the ordering
  claim survives measurement.

## P1-6 — proof storage / prune (statement of record)

The MatMul sketch proof is carried **inside the block** (lead decision; not a
fetched sidecar). At the 8 MiB ENC-BMX4C payload this is ~2.7 TiB/yr of
unpruned proof data. `nMatMulProofPruneDepth` is present but **non-functional /
reserved** (documented round-2 P2): nothing prunes proof data yet. A working
prune (or a §P1/P3 relay/pruning extension) is therefore an **activation
precondition**, tracked here and in the params.h field doc, not a live feature —
and it does not gate the current inert posture.

## P1-2 — CUDA scalar-vs-native honesty (toolchain-gated)

Investigated and precisely scoped for a toolchain holder; **not blind-patched**
(there is no CUDA/Metal/HIP toolchain in this environment to compile- or
run-verify a change to the device path, and an unverifiable edit to deep CUDA
reporting is a worse outcome than a precise hand-off).

Findings:

- The native-vs-fallback signal an operator acts on — the measurement JSON's
  `native_path_eligible` / `mt24.native_path_reason` and the
  `DEVICE_HIGH_MAGNITUDE_PASS` marker — is **already honest**: the native (FP4)
  tier is marked eligible and the marker emitted ONLY after the on-device
  `RunMxf4Qualification` (the odd near-2²⁴ accumulator discriminator + the
  mixed-value layout cross-check vs an exact host int64 reference) PASSES, keyed
  by physical device id. The scalar/INT8 fallback cannot produce native
  eligibility or the native marker (`src/cuda/matmul_v4_bmx4_accel.cu`, the
  `use_native`/`g_mxf4_qualified` gate). Correctness is tier-independent: the
  committed object is bit-exact whichever tier runs (the scalar path is an exact
  INT32 GEMM), so a fallback never threatens consensus.
- Residual, precise fix for the toolchain holder: when the native tier is
  eligible but an individual GEMM within a window falls back to the exact scalar
  path (`RunGemmAuto` with `force_scalar`, or cuBLASLt declining the block-scaled
  MXF4 algorithm — which, per vanities, is *every* current NVIDIA card via
  cuBLASLt), the run still attributes its **throughput** to the native tier. This
  is a measurement-honesty defect (misleading nonce/s), not a correctness or
  eligibility defect. The fix is to track "did any GEMM in this window take the
  scalar fallback" and surface it in the measurement report's device identity
  (e.g. a `native_gemm_scalar_fallbacks` counter / a `tier_actually_ran` field),
  so a datacenter-ordering number can never be reported as native-tensor while a
  scalar loop produced it. This composes with the vanities finding that the
  cuBLASLt MXFP4 path is inert on all current NVIDIA silicon (the native tier is
  reachable only via CUTLASS/tcgen05 or a hand-written kernel), which is already
  documented as the integration target.

## Remaining OPEN (unchanged, all activation-blocking)

- **C1 residual / hardness**: the marginal-work floor is an assumption (P1-5);
  external cryptographic review OPEN.
- **On-silicon datacenter-ordering program** (B2g): measurement-gated on real
  H100/B200/MI355/M5; two model estimates already falsified.
- **P1-2 measurement-honesty** (above): toolchain-gated hand-off.
- **P1-6 proof prune / relay extension**: activation precondition.
- Two-vendor M-t24, testnet burn-in, calibration, CI with a GPU toolchain.

None of these are reachable on any live network in the current inert posture.
