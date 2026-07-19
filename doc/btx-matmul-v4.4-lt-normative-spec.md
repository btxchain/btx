# BTX MatMul v4.4-LT — Rank-1 normative specification (ENC-DR-LT)

*Status: staged / inert (`nMatMulDRLTHeight = INT32_MAX` on all public nets).*
*Implements the Rank-1 flagship package from `btx-matmul-v4.4-ai-chip-block-reward-strategy.md`.*
*Adversarial status: `doc/btx-matmul-v4.4-lt-adversarial-analysis.md`.*

## Package contents

| Lever | Normative value | Effect |
|---|---|---|
| Deep-`m` under ENC-DR | `b = 2`, `m = n/2` (2048 @ n=4096) | ~3.6× tensor MACs; **0 B** permanent sketch growth |
| MatExpand | `B̂ = Extract(Mix(G·W·H))`, `w=128` | SHA operand floor → dense exact-int GEMMs; C-15 non-collapse |
| Consensus `Q*` | `{64,128}` (default 64) | Fat stacked miner windows (Phase A); seal-as-PoW is Phase B |
| Alphabet / Ĉ | Path-agnostic integer; M11 projectors; Extract to `[-48,48]` | FP8/MXFP4 remain **miner-local** lanes |

## MatExpand (reference)

Domain tags (V44LT):

- `BTX_MATEXPAND_G_V44LT` ‖ template → `G ∈ M11^{n×n}` (template)
- `BTX_MATEXPAND_H_V44LT` ‖ template → `H ∈ M11^{w×n}` (template)
- `BTX_MATEXPAND_WA_V44LT` ‖ template → `W_A ∈ M11^{n×w}` (template; operand A)
- `BTX_MATEXPAND_W_V44LT` ‖ full-header hash → `W_B ∈ M11^{n×w}` (nonce-fresh; operand B)

```
Y = G · W          # s8×s8→s32, n×w
B32 = Y · H        # s32×s8→s32, n×n
salt = LE64(seed_W)
B̂[i,j] = ExtractDequantMatExpand(B32[i,j], i, j, salt)
# Mix (SplitMix64-style) → M11 rejection nibbles → e∈{0..3}; value = μ<<e ∈ [-48,48]
```

`FoldInt32ToEmax48` (`y % 97`) is **non-normative** (differential tests only).

Projectors use `BTX_MATMUL_V44LT_SKETCH_U/V`. Digest = `H(σ ‖ Chat)` with
`Chat = (U·Â)(B̂·V)` over `q = 2⁶¹−1`, tile `b=2`.

## Q* window

**Phase A (normative today):** miner evaluates a window of `Q*` per-nonce digests;
lottery object remains the per-nonce ENC-DR digest (sketch-cache auth intact).

Merkle/seal helpers (for harnesses / Phase B):

`SHA256("BTX_QSTAR_COMMIT_V44LT" ‖ σ_anchor ‖ merkle ‖ Q* LE32)`.

Verifier Freivalds-checks committed sketches and always reseals winners through
`ComputeDigestBMX4CLT`.

## Activation

| Param | Default |
|---|---|
| `nMatMulDRLTHeight` | `INT32_MAX` |
| `nMatMulConsensusQStar` | `64` |
| `nMatMulLTTranscriptBlockSize` | `2` |
| `nMatMulDRLTAsertRescaleNum/Den` | `1/1` (calibrate from silicon) |

Profile enum: `ENC_BMX4C_LT = 4`. Live only when `IsDRLTActive(height)`.

## Multi-arch backends

| Backend | Entry | Status |
|---|---|---|
| CPU reference | `matmul::v4::lt::*` | **normative** |
| Dispatch | `ComputeDigestsBMX4CLTDispatched` | host-verified; device host-exact today |
| CUDA | `ComputeDigestsOnlyLTCuda` | host MatExpand + exact miner; device GEMM soak next |
| Metal | stub → CPU | Apple bring-up |
| HIP | stub → CPU | MI350 bring-up |

Planner: `PlanLTAccel(device_class)`.

## GO/NO-GO (before raising height)

1. Tensor wall-time majority on B200 and 5090
2. B200/5090 nonce/s ≥ ~4× on fat shape
3. Nonce/$ proxies: B200 ≥ 5090 (honest: fleets may still invert)
4. MI350 FER / OCP MX exactness PASS
5. MatExpand adversarial review closed on Mix+M11 Extract (internal: done; external C-15 still required)
6. Tip verify budget with sketch-cache
7. Header-PoW + authenticated chainwork blockers unchanged
8. Phase B seal-as-PoW only if Rank-1 launch requires consensus-bound windows

## Source map

- `src/matmul/matmul_v4_lt.{h,cpp}` — reference
- `src/matmul/accel_v4.*` — `ComputeDigestsBMX4CLTDispatched`
- `src/cuda|metal|hip/matmul_v4_lt_accel*` — backends
- `src/consensus/params.h` — `nMatMulDRLT*`, `ENC_BMX4C_LT`
- `src/pow.cpp` — verify / recompute / solve / ASERT DRLT rescale
- `src/validation.cpp` — LT `n % 32` gate
- `src/test/matmul_v4_lt_tests.cpp`
- `scripts/matmul_lt_readiness.sh`, `contrib/matmul-v4/lt-gate.py`
