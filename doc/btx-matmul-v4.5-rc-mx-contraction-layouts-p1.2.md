# ENC_RC P1.2 — MX contraction-axis layouts (row-block vs col-block)

*Date: 2026-07-20. Status: design + scaffolding (first increment). Non-normative
except where it restates existing §R / Extract / MatExpand contracts.*

## Problem

OCP-style E8M0 block scales are shared on **L=32 consecutive elements of the
GEMM contraction axis K**. Current RC operand expansion
(`ExpandMxDequantInt8` in `matmul_v4_rc.cpp`) always applies **row-block**
scales (one `e` per row `i`, column-block `⌊j/32⌋`) — the same convention as
LT MatExpand Extract (`DeriveMatExpandMxScale(prf, i, bj)` +
`ExtractMatExpandMxTileMantissas` over B32 tiles along columns; see
`matmul_v4_lt.{h,cpp}` and `matmul_v4_rc_extract.h`).

Row-block is contraction-correct when K runs along **columns**. It is
**transposed relative to K** when the right operand (or a transposed left)
contracts along **rows**. The CPU oracle still materializes dense dequant int8
and discards `(μ, e)`, so those stages cannot use native block-scaled MX
tensor instructions without a packed layout that matches K.

Consensus digests for this increment remain the **row-block dequant int8**
oracle (toy golden unchanged). Col-block packed helpers are scaffolding for
device MX / a future digest-breaking operand-layout migration.

## Layout vocabulary

| Name | Scale index | Shared along | Typical role |
|---|---|---|---|
| **Row-block** | `e[i][⌊j/32⌋]` | 32 consecutive **columns** of row `i` | Left operand when K = cols; LT Extract / MatExpand B̂ |
| **Col-block** | `e[⌊i/32⌋][j]` | 32 consecutive **rows** of col `j` | Right operand when K = rows; BMX4C `ExpandOperandA` |

BMX4C already splits the two: `ExpandOperandA` = col-block (U·A contracts on
rows of A), `ExpandOperandB` = row-block (B·V contracts on cols of B)
(`matmul_v4_bmx4.cpp`). RC currently uses only the row-block schedule.

## Layout matrix (RC stages)

For `C = L · R` with L=`M×K`, R=`K×N` (row-major storage):

| Stage | Formula (code path) | K | L needs | R needs | Current expansion | Native MX ready? |
|---|---|---|---|---|---|---|
| P1 score | `S = ExtractMX(Q·Kᵀ)` — `Phase1AssociativeRecall` dots Q/K along `d_head` | `d_head` (cols of Q,K) | Row-block | Row-block (on K beforeᵀ / on stored K cols) | `ExpandMxDequantInt8` row-block | Yes (dequant or packed row-block) |
| P1 value | `Z = ExtractMX(S·V)` — streamed S tiles × V | `n_ctx` (cols of S / **rows** of V) | Row-block (S from Extract along `n_ctx`) | **Col-block** on V | V forced row-block → **axis mismatch** | No — needs col-block V pack |
| P2 forward | `X' = ExtractMX(X·Wᵀ + X)` — `ForwardLayer` / `ExactGemmS8S8(X, Wt)` | `d_model` | Row-block on X | Col-block on Wt ≡ row-block on W thenᵀ | W row-block → Wt OK | Yes via dequant ExactGemm |
| P2 backward | `G' = ExtractMX(G·W)` — `GemmWtS8S8Int32` | `d_model` | Row-block on G | **Col-block** on W | W row-block → **axis mismatch** | No — needs col-block W pack |
| P2 wgrad | `D = ExtractMX(G·Xᵀ)` — `GemmGXt*` / chunked `ExactGemmS8S8(Gᵀ_panel, X_panel)` | `b_seq` (rows of G,X) | Row-block on Gᵀ panel ≡ **col-block on G** | **Col-block** on X | Both row-block on feature dim → **axis mismatch** | No — needs col-block on batch |

ExtractMX itself (`ExtractMXTileInt64` / `ExtractMXMatrixInt*`) always emits
**row-block** scales on the output matrix columns — matching LT MatExpand.
That is correct for S (next K = `n_ctx` along cols) and for X'/G'/D as left
operands of later row-K GEMMs; it does **not** fix right-operand V / W / X
for S·V, G·W, or wgrad.

## Code map (current)

| Path | Role |
|---|---|
| `ExpandMxDequantInt8` | Consensus operand expand: μ stream + row-block E8M0 → dense int8 |
| `ExtractMX*` / `lt::DeriveMatExpandMxScale` | Post-GEMM requant; row-block on output cols |
| `ExactGemmS8S8Dispatched` | Phase-2 `<2^24` s8×s8 (forward / backward); optional device inject |
| `GemmGXtInt64` / chunked ExactGemm | Wgrad oracle / panels; still dequant int8 |
| `MakeResolvedExactGemmBackendForRC` | CUDA/HIP/Metal/Ascend ExactGemm + RC self-qual gate |

## Fix plan (increments)

1. **P1.2 (this landing):** document matrix; CPU packed helpers for row-block
   and col-block; keep oracle on row-block dequant; wire Phase-2 ExactGemm
   through existing CUDA/HIP `LaunchGemmS8S8` (digest-identical); keep
   `native_mxfp4_qualified` / `native_fp8_qualified` fail-closed.
2. **Next:** device kernels that consume packed col-block for V / W-as-right /
   wgrad panels; self-qual vs int64/CPU at live dims before flipping any
   `native_*` bit.
3. **Consensus migration (digest-breaking, separate fork):** optionally
   regenerate V / W / batch-axis operands with col-block scales so packed MX
   equals the oracle without a dense dequant detour.

## Residuals after P1.2

- Phase-1 S·V native MX (col-block V) — helpers only; still int64 dequant stream.
- Phase-2 backward native MX (col-block W) — helpers only; ExactGemm stays s8 dequant.
- Phase-2 wgrad native MX (col-block G,X on batch) — helpers only; int64 / chunked ExactGemm.
- Full resident episode kernels on-device (KV residency, Extract on GPU).
- §R.7 growth / segment leaves remain PARKED.
