# BTX MatMul v4.4-LT — Rank-1 normative specification (ENC-DR-LT)

*Status: staged / inert (`nMatMulDRLTHeight = INT32_MAX` on all public nets).*
*Implements the Rank-1 flagship package from `btx-matmul-v4.4-ai-chip-block-reward-strategy.md`.*
*Adversarial status: `doc/btx-matmul-v4.4-lt-adversarial-analysis.md`.*

## Package contents

| Lever | Normative value | Effect |
|---|---|---|
| Deep-`m` under ENC-DR | `b = 2`, `m = n/2` (2048 @ n=4096) | ~3.6× tensor MACs; **0 B** permanent sketch growth |
| MatExpand | `B̂ = Extract_PRF(G·W·H)`, `w=1024` | ExactGemm floor `O(n²·w)` (not `O(n³)`); C-15 candidate mixer; cubic floor is deep-`m` sketch/combine |
| Consensus `Q*` | `{128,256,512}` (default 256) | Fat stacked miner windows (Phase A); Phase B seal-as-PoW via `fMatMulLTSealAsPoW` (implemented; public default off / DRLT `INT32_MAX`; **regtest** finite DRLT + seal on) |
| Alphabet / Ĉ | Path-agnostic integer; M11 projectors; Extract to `[-48,48]` | Logical MX-compatible components are consensus-visible; **native FP8/MXFP4 execution is not currently wired for LT** |

## MatExpand (reference)

Domain tags (V44LT):

- `BTX_MATEXPAND_G_V44LT` ‖ template → `G ∈ M11^{n×n}` (template)
- `BTX_MATEXPAND_H_V44LT` ‖ template → `H ∈ M11^{w×n}` (template)
- `BTX_MATEXPAND_WA_V44LT` ‖ template → `W_A ∈ M11^{n×w}` (template; operand A)
- `BTX_MATEXPAND_W_V44LT` ‖ full-header hash → `W_B ∈ M11^{n×w}` (nonce-fresh; operand B)

```
Y = G · W          # s8×s8→s32, n×w, w=1024  →  O(n²·w) MACs
B32 = Y · H        # s32×s8→s32, n×n         →  O(n²·w) MACs; rank(B32)≤1024
prf_key = SHA256("BTX_MATEXPAND_MXPRF_V44LT" ‖ seed_W)
# Per row i, column-block bj=j/32 (kBlockLen=32; require n%32==0):
e[i,bj] = SHA256("BTX_MATEXPAND_MXSCALE_V44LT" ‖ prf_key ‖ LE32(i) ‖ LE32(bj))[0] & 3
μ[i, 32·bj .. 32·bj+31] = MX tile ChaCha20 M11 (nonce_first=bj⊕'MXBL',
  nonce_second=(i<<32)|bj; nibble XOR-mixed with B32 raw; remix on exhaustion)
B̂[i,j] = μ[i,j] · 2^{e[i,j/32]}   # exact mul; alphabet [-48,48] unchanged
```

**Byte-encoding pin (normative):** see external C-15 packet
`doc/btx-matmul-v4.4-lt-external-c15-packet.md` §1.4 (endianness of `prf_key`,
tile salts, remix termination, exact mul). Device twins must match bit-exactly.
Full-width `(i,bj)` (MUST NOT truncate): `doc/btx-matmul-v4.4-lt-matexpand-position-salt.md`.

`FoldInt32ToEmax48`, SplitMix `ExtractDequantMatExpandSplitMix`, and legacy
per-cell `ExtractDequantMatExpandChaChaCell` (`BTX_MATEXPAND_PRF_V44LT`) are
**non-normative** (differential / related-nonce tests only).

**Extractor status:** Lever-B **MX/E2M1 block-scale Extract** is the **selected
consensus candidate** under `ENC_BMX4C_LT` (~32× fewer MatExpand PRF blocks vs
per-cell ChaCha). It is **not** cryptographically closed — external C-15 review
remains required before any public activation height is raised.
**PRF-as-primitive ≠ MatExpand work lower bound.** Public `nMatMulDRLTHeight`
stays `INT32_MAX`. C-15 stays **OPEN**.

**Logical layout is not a native-hardware claim.** “MX/E2M1 block-scale” above
describes an exact integer representation: M11 mantissas plus shared powers of
two on 32-column blocks. It does not mean that CUDA or HIP issued an OCP-MXFP4
instruction. The CPU miner consumes those components directly and avoids a
dense `Bhat` allocation. CUDA/HIP default to the single dense-INT8 projection
on every architecture. SM100/SM120 and gfx950 retain a qualification-only
`BTX_MATMUL_V4_LT_LOGICAL_MX=1` lane that keeps `(mu, scale/32)` and computes
`Bhat·V` with four exponent-masked INT8 IMMA/MFMA GEMMs plus exact `2^e`
accumulation. That lane is not the default because, absent native block-scale
instructions or measured sparse acceleration, it schedules four dense GEMMs.
Neither path is native MXFP4; a CUTLASS/tcgen05 or ROCm MXFP4 kernel remains
unimplemented and fail-closed. `PlanLTAccel` reports design intent, not runtime
capability evidence.

**Scoping:** MatExpand is `O(n²·w)`; the honest cubic-ish MAC floor is deep-`m`
`B̂·V` / combine (`m=n/2`). Linearized Extract would reopen ~`n/w≈4×` panel
collapse vs dense `n×n`. Projectors `U`/`V` are **rank-transparent**.

Projectors use `BTX_MATMUL_V44LT_SKETCH_U/V`. Digest = `H(σ ‖ Chat)` with
`Chat = (U·Â)(B̂·V)` over `q = 2⁶¹−1`, tile `b=2`.

## Q* window

**Phase A (default when LT live):** miner evaluates a window of `Q*` per-nonce
digests; lottery object remains the per-nonce ENC-DR digest (sketch-cache auth
intact). `fMatMulLTSealAsPoW = false`.

**Phase B (IMPLEMENTED, inert while `nMatMulDRLTHeight = INT32_MAX`):** when
`IsMatMulLTSealAsPoWActive(height)` the lottery object is the window seal.
`Q*` is an **aggregate work commitment** over leaf digests — it does **not**
prove classical GEMM, tensor-core use, or simultaneous slot execution. Full
256-bit **slot-id binding** (seeds + Merkle leaf) **is** consensus:

```
slot_id_j     := DeriveWindowSlotId(σ_anchor, j)
              = SHA256("BTX_QSTAR_SLOT_V44LT" ‖ σ_anchor ‖ j LE32)   # 256-bit
nNonce64_j    := ReadLE64(slot_id_j)                                 # grinding field
v3_seeds_j    := SetDeterministicMatMulSeeds(slot_j, height, parent_MTP)  # LT-Q2
seed_a/b_j    := BindWindowSlotIdIntoSeeds(v3_seeds_j, slot_id_j)
              # seed_a := SHA256("BTX_QSTAR_SLOTSEED_A_V44LT" ‖ seed_a ‖ slot_id)
              # seed_b := SHA256("BTX_QSTAR_SLOTSEED_B_V44LT" ‖ seed_b ‖ slot_id)
digest_j      := ComputeDigestBMX4CLT(slot_j)                        # H(σ_slot ‖ Chat_slot)
leaf_j        := CommitWindowSlotLeaf(slot_id_j, digest_j)
              = SHA256("BTX_QSTAR_LEAF_V44LT" ‖ slot_id_j ‖ digest_j)
matmul_digest := SealWindowCommit(σ_anchor, Merkle(leaves), Q*)
```

Seal commit tag: `SHA256("BTX_QSTAR_COMMIT_V44LT" ‖ σ_anchor ‖ merkle ‖ Q* LE32)`.
Duplicate `slot_id` values fail seal construction closed (do not rely on low-64
`nNonce64` uniqueness alone).

EncDr verify recomputes the seal with parent MTP (`CheckMatMulProofOfWork_V4EncDr`);
Phase-A `H(σ‖Chat)==matmul_digest` cache auth / MMSKETCH are skipped in seal mode.
Regtest opt-in: `-regtestmatmulltsealaspow` (requires live `-regtestdrltheight`).

### Report measurement contract

`matmul-v4-report --profile bmx4c-lt` keeps two distinct evidence domains:

- `cpu_reference_tensor_share_pct` is computed from portable CPU-reference
  stage clocks. It describes reference composition only. The legacy ambiguous
  `tensor_share_pct` field is null in new reports. Neither proves IMMA/MFMA
  execution, device tensor residency, saturation, or G1 readiness.
- G1 requires `native_path_eligible=true`, independent device kernel timing,
  hardware-counter evidence, and a strict-majority
  `device_tensor_share_pct`. Missing device telemetry fails closed.
- the report's S5 Merkle + `SealWindowCommit` clock is a commit-only
  microbenchmark. Ordinary sequential headers, digest-only seed derivation, or
  a non-consensus Q cannot be called a Phase-B measurement. Phase-B evidence
  must prepare real slot IDs/nonces, bind the full slot ID into both seeds, use
  `Q* in {128,256,512}`, and match `ComputeSealDigestBMX4CLT` byte-for-byte.

Consequently, a commit-only S5 value never closes the Phase-B seal gate or
supports a throughput/readiness claim.

## Activation

| Param | Default |
|---|---|
| `nMatMulDRLTHeight` | `INT32_MAX` (public); regtest finite (Phase B live) |
| `nMatMulConsensusQStar` | `256` |
| `nMatMulLTTranscriptBlockSize` | `2` |
| `nMatMulDRLTAsertRescaleNum/Den` | `1/1` (calibrate from silicon) |
| `fMatMulLTSealAsPoW` | `false` on public (Phase B mode; inert without live DRLT); **`true` on regtest** |
| `nMatMulLTMaxPendingVerifications` | `2` (tip-verify pending; inert while DRLT INT32_MAX) |
| `nMatMulLT{Global,Peer}VerifyBudgetPerMin` | `1` / `1` (conservative; calibrate via soak) |

Profile enum: `ENC_BMX4C_LT = 4`. Live only when `IsDRLTActive(height)`.

## Multi-arch backends

| Backend | Entry | Status |
|---|---|---|
| CPU reference | `matmul::v4::lt::*` | **normative** |
| Dispatch | `ComputeDigestsBMX4CLTDispatched` | host-verified |
| Injectable GEMMs | `ExactGemmBackend` | device splice for MatExpand `G*W` / `(G*W)*H` |
| CUDA | `ComputeDigestsOnlyLTCuda` | qualified INT8 IMMA: direct s8 stages, four-radix `Y·H`, Karatsuba-9 combine; dense INT8 `Bhat·V` by default; SM100/120 logical-MX four-pass lane is opt-in; no native MXFP4 |
| Metal | `ComputeDigestsOnlyLTMetal` | exact MSL integer GEMMs via `ExactGemmBackend` (self-tested); CPU fallback if unavailable |
| HIP | `ComputeDigestsOnlyLTHip` | qualified INT8 MFMA: direct s8 stages, four-radix `Y·H`, Karatsuba-9 combine; dense INT8 `Bhat·V` by default; gfx950 logical-MX four-pass lane is opt-in; no native MXFP4 |

Planner: `PlanLTAccel(device_class)` reports intended lane taxonomy only; it
does not probe, dispatch, qualify, or attest native execution. After the BMX4C
axis correction, both its operand B and LT's `Bhat` use contraction-aligned
row-by-K-block scales `e(i,j/32)`; their derivations and transcripts remain
separate. Per-architecture implementation status:

| Backend | MatExpand Extract | `B̂·V` | Notes |
|---|---|---|---|
| CPU | MX-block (normative) | `ComputeProjectedRightMxBlockScaleLT` | Consensus + ExactGemm fallback |
| CUDA | Device MX twin + device scales | Dense IMMA/scalar by default; four exact exponent-masked INT8 IMMA passes on sm100/sm120 only with `BTX_MATMUL_V4_LT_LOGICAL_MX=1` | Qualification lane, not native MXFP4; re-measure |
| HIP | Device MX twin + device scales | Dense MFMA/scalar by default; four exact exponent-masked INT8 MFMA passes on gfx950 only with `BTX_MATMUL_V4_LT_LOGICAL_MX=1` | Qualification lane, not native MXFP4; re-measure |
| Metal | Host MX via miner/digest | Host scale-partitioned | ExactGemm inject only; no Extract shader |
| Ascend | Host MX via miner/digest | Host scale-partitioned | ExactGemm Cube self-qual; Fold = GEMM filler only |

Linker `*_stub.cpp` files remain only for builds with the corresponding `BTX_ENABLE_*=OFF`.

## GO/NO-GO (before raising height)

1. Native tensor execution strict majority on B200 and 5090, proven by a
   qualified native path plus independent device-side timing and hardware
   counters. CPU-reference stage composition is diagnostic only and does not
   pass this gate.
2. B200/5090 nonce/s ≥ ~4× on a **single device-resident consensus-Q* batch**;
   require device nonce-fresh W generation, device digest, and no per-nonce
   synchronization. Host-orchestrated single-nonce wall rates do not count.
3. Nonce/$ proxies: B200 ≥ 5090 using only the same silicon-eligible batched
   rates (honest: fleets may still invert)
4. MI350 FER / OCP MX exactness PASS
5. MatExpand adversarial review: Lever-B MX-block Extract selected (internal
   non-affinity + golden vectors); external C-15 still required — not closed;
   re-measure B200/5090 after Lever B — **do not claim ≥4×** without JSON whose
   Q* batching/device-W/device-digest/no-per-nonce-sync provenance passes
6. Tip verify budget with sketch-cache
7. Header-PoW + authenticated chainwork blockers unchanged
8. Phase B seal-as-PoW tip-verify budget soak + seal-binding review if Rank-1
   launch requires consensus-bound windows (async EncDr+MTP + LT pending/budget
   knobs implemented; run the soak protocol in
   `doc/btx-matmul-v4.4-lt-adversarial-analysis.md` — no unverified silicon
   numbers in-tree)

## Source map

- `src/matmul/matmul_v4_lt.{h,cpp}` — reference
- `src/matmul/accel_v4.*` — `ComputeDigestsBMX4CLTDispatched`
- `src/cuda|metal|hip/matmul_v4_lt_accel*` — backends
- `src/consensus/params.h` — `nMatMulDRLT*`, `ENC_BMX4C_LT`
- `src/pow.cpp` — verify / recompute / solve / ASERT DRLT rescale
- `src/validation.cpp` — LT `n % 32` gate
- `src/test/matmul_v4_lt_tests.cpp`
- `scripts/matmul_lt_readiness.sh`, `contrib/matmul-v4/lt-gate.py`
