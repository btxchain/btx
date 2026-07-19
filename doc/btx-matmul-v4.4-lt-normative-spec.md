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
| Alphabet / Ĉ | Path-agnostic integer; M11 projectors; Extract to `[-48,48]` | FP8/MXFP4 remain **miner-local** lanes |

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
| CUDA | `ComputeDigestsOnlyLTCuda` | exact device GEMMs via `ExactGemmBackend` (self-tested); CPU fallback if unavailable |
| Metal | `ComputeDigestsOnlyLTMetal` | exact MSL integer GEMMs via `ExactGemmBackend` (self-tested); CPU fallback if unavailable |
| HIP | `ComputeDigestsOnlyLTHip` | exact device GEMMs via `ExactGemmBackend` (self-tested); CPU fallback if unavailable |

Planner: `PlanLTAccel(device_class)`. After Lever-B, `ScalePartitionedMxfp4`
means MX Extract scales `e(i,j/32)` + partitioned `B̂·V` (not BMX4C row-block
scales). Per-arch reference optimization status:

| Backend | MatExpand Extract | `B̂·V` | Notes |
|---|---|---|---|
| CPU | MX-block (normative) | `ComputeProjectedRightMxBlockScaleLT` | Consensus + ExactGemm fallback |
| CUDA | Device MX twin + host scales | Prefer MX scale-partitioned on Blackwell/sm100/sm120/5090; else dense IMMA/scalar | Re-measure after Lever B |
| HIP | Device MX twin + host scales | Prefer MX scale-partitioned on MI350/MI355; else dense MFMA/scalar | Re-measure after Lever B |
| Metal | Host MX via miner/digest | Host scale-partitioned | ExactGemm inject only; no Extract shader |
| Ascend | Host MX via miner/digest | Host scale-partitioned | ExactGemm Cube self-qual; Fold = GEMM filler only |

## GO/NO-GO (before raising height)

1. Tensor wall-time majority on B200 and 5090
2. B200/5090 nonce/s ≥ ~4× on fat shape
3. Nonce/$ proxies: B200 ≥ 5090 (honest: fleets may still invert)
4. MI350 FER / OCP MX exactness PASS
5. MatExpand adversarial review: Lever-B MX-block Extract selected (internal
   non-affinity + golden vectors); external C-15 still required — not closed;
   re-measure B200/5090 after Lever B — **do not claim ≥4×** without new JSON
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
