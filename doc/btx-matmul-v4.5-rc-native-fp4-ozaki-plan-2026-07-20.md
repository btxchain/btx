# ENC_RC — Native FP4 via Ozaki / limb split (Amendment 1.B)

*Date: 2026-07-20. Tip: WIP. Status: **IMPLEMENTING** (honesty split ExactGemm panels ≠ native MXFP4).*
*`nMatMulRCHeight` remains `INT32_MAX`. This document does not raise height.*

## Why LT native FP4 does not carry to RC

LT MatExpand projected-right (`B̂·V`) self-qualifies native MXFP4 on Blackwell /
5090-class silicon under **bounds &lt; 2^24** (ExactGemm / IMMA int32 accumulator
regime). That admission is **LT-only**.

ENC_RC Phase-1 **Z = S·V** and Phase-2 **wgrad** sit far outside that regime:

| Stage | Contraction | Bound (magnitude) | Plain native FP4? |
|---|---|---|---|
| LT projected-right | panel `n` with 2304·n &lt; 2^24 | &lt; 2^24 | Yes after LT self-qual |
| RC Phase-1 Z = S·V | K = `n_ctx` = 786432 | 2304 · 786432 ≈ **2^30.76** | **No** |
| RC Phase-2 wgrad | K = `b_seq` = 16384 | 2304 · 16384 ≈ **2^25.15** (&gt; 2^24) | **No** |

A single native MXFP4 tensor GEMM with an FP32 / limited-int accumulator cannot
be claimed bit-identical to the RC **int64 oracle** at consensus dims. LT
`native_mxfp4_qualified` must never be copied into
`RCSelfQualStatus::native_mxfp4_qualified`.

## Ozaki / limb-split approach (RC-only)

Reuse the exact-integer idea behind `ExactGemmS32S8ViaRadix256`
(`src/matmul/exact_gemm_radix.h`): express a wide product as a weighted sum of
**bounded** sub-GEMMs whose partials fit ExactGemm’s &lt; 2^24 contract, then
**recombine with exact integer weights** (no rounding).

### Honesty split (required)

1. **ExactGemm K-panel Ozaki** (`IsRcOzakiExactPanelsQualified` /
   `TryRcOzakiExactPanelsGemmS8S8Int64`) — CPU ExactGemm or CUDA `LaunchGemmS8S8`
   IMMA panels. May accelerate mining. **Does NOT** set
   `ProbeRCSelfQual.native_mxfp4_qualified`.
2. **Native block-scaled MXFP4 Ozaki** (`IsRcOzakiMxfp4Qualified` /
   `TryRcOzakiMxfp4GemmS8S8Int64`) — only after a real device path that factors
   MX-dequant int8 → E2M1+UE8M0 and launches `rc_ozaki_mxfp4_panel_gemm`
   (backend `mxfp4_blockscaled_device`). **Must not** call `LaunchGemmS8S8` or
   fall back to CPU inside the native claim. SM120 and SM100 use separate
   qual latches (`g_qual_sm120` / `g_qual_sm100`).

### Qualification gate (before flipping RC `native_mxfp4`)

- Match the **int64 CPU oracle** at K ∈ {4095,4096,4097,8192} + thin production-K,
  max ±M11/E8M0 vectors, multi-seed; corrupted device output must fail equality.
- Toy/medium episode digests already match in `ProbeRCSelfQual` before the
  native bit is consulted.
- Until that gate passes: `ProbeRCSelfQual` keeps
  `native_mxfp4_qualified = IsRcOzakiMxfp4Qualified()` (false without device).

## Artifacts

| Artifact | Role |
|---|---|
| `src/matmul/matmul_v4_rc_mx_ozaki.h` (+ `.cpp`) | Exact panels vs MXFP4 APIs; CPU limb-split oracle |
| `src/cuda/matmul_v4_rc_mx_ozaki_native.{h,cu}` | Device ExactPanels + MXFP4 block-scaled kernel |
| `src/cuda/matmul_v4_rc_mx_ozaki_native_link.cpp` | Stub when `BTX_ENABLE_CUDA_EXPERIMENTAL=OFF` |
| Tests | `rc_ozaki_exact_panels_qualify_and_match_oracle`, `rc_ozaki_mxfp4_native_gate` |

## Explicit non-goals

- Do not reuse LT `g_native_mxfp4_qualified` / resident LT peak path for RC Z or
  wgrad.
- Do not raise `nMatMulRCHeight`.
- Do not claim silicon rates from toy CPU campaigns.
- Do not enable a GKR arbiter from this workstream.

## Pointers

- RC episode oracle: `src/matmul/matmul_v4_rc.cpp` (`Phase1AssociativeRecall`,
  `AccumulateSegmentedGemmGXt`, `GemmGXtViaChunkedExact`)
- Radix recombine precedent: `src/matmul/exact_gemm_radix.h`
- Layout prerequisites: `doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md`
- Finish tracker: `doc/btx-matmul-v4.5-rc-finish-to-production-status-2026-07-20.md`
