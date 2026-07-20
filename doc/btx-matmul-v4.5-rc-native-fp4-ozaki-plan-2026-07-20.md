# ENC_RC — Native FP4 via Ozaki / limb split (Amendment 1.B)

*Date: 2026-07-20. Tip: `ea9b167` + WIP. Status: **PARKED / scaffolded**.*
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

### Sketch

1. **Partition the contraction axis** (and/or digit limbs of scaled operands)
   so each sub-product satisfies `2304 · K_chunk < 2^24`
   (same floor as `kRCWgradExactChunk = 4096`).
2. Run each sub-GEMM on a **native MXFP4** (or ExactGemm s8×s8) path that is
   already self-qualified for that small bound — yielding exact int32 partials.
3. **Recombine** into int64 (segment leaves optional) with integer limb weights
   / panel sums — byte-identical to `GemmGXtInt64` / Phase-1 streamed int64 Z.
4. Apply **ExtractMX once** on Σ partials (H1), never per-limb Extract.

Col-block V / W / batch packs from P1.2
(`doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md`) are prerequisites for
native MX operand layout; Ozaki does not replace that work.

### Qualification gate (before flipping any RC `native_*` bit)

- Match the **int64 CPU oracle** at:
  - CI-safe toy / medium shapes, **and**
  - consensus epoch-0 dims (`kRCContextLen`, `kRCBatchSeq`, …) or a documented
    production-representative subset that covers the &gt; 2^24 and ~2^30.76 regimes.
- Self-qual entry must be the **same** Ozaki device path miners will call
  (no host D2H pack detour claiming “native”).
- Until that gate passes: `ProbeRCSelfQual` keeps
  `native_mxfp4_qualified = false` / `native_fp8_qualified = false`.

## Scaffolding (this landing)

| Artifact | Role |
|---|---|
| `src/matmul/matmul_v4_rc_mx_ozaki.h` (+ `.cpp`) | `TryRcOzakiMxfp4Gemm*` fail-closed; CPU limb-split reference; `IsRcOzakiMxfp4Qualified() == false` |
| Comments in `matmul_v4_rc.cpp` | Phase-1 Z / wgrad point here |
| Tests | Assert RC / coupled native MXFP4 flags stay false until Ozaki qualifies |

Device kernels, cuBLASLt/hipBLASLt FP4 limb launches, and RC self-qual flips
are **out of scope** for this scaffold.

## Explicit non-goals

- Do not reuse LT `g_native_mxfp4_qualified` / resident LT peak path for RC Z or
  wgrad.
- Do not raise `nMatMulRCHeight`.
- Do not claim silicon rates from toy CPU campaigns.

## Pointers

- RC episode oracle: `src/matmul/matmul_v4_rc.cpp` (`Phase1AssociativeRecall`,
  `AccumulateSegmentedGemmGXt`, `GemmGXtViaChunkedExact`)
- Radix recombine precedent: `src/matmul/exact_gemm_radix.h`
- Layout prerequisites: `doc/btx-matmul-v4.5-rc-mx-contraction-layouts-p1.2.md`
- Finish tracker: `doc/btx-matmul-v4.5-rc-finish-to-production-status-2026-07-20.md`
