> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

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
   `TryRcOzakiMxfp4GemmS8S8Int64`) — only after **one** selected backend passes
   its **complete** suite alone:
   - `SM120_MMA` — hand QMMA.SF m16n8k32 e2m1 (never labeled cutlass)
   - `SM100_CUBLASLT` — cuBLASLt `CUDA_R_4F_E2M1` + `VEC32_UE8M0`
   Scalar-decode (`mxfp4_blockscaled_device_scalar-decode`) and dense INT8
   **Must not** flip the native latch. SM120 ≠ SM100 — never cross-infer.
   Runtime dispatches **only** the selected backend (fail-closed).

### Qualification gate (before flipping RC `native_mxfp4`)

- Match the **int64 CPU oracle** at
  K ∈ {1,8,31,32,33,4095,4096,4097,8192,16384}, production-ish M/N,
  M11/E8M0 corners, scale transitions, both sides of 2^24; corrupted output
  must fail equality. Scalar-tail (K%32) is tracked separately and is **not**
  MMA evidence (`native_tensor_launches` must be > 0 for `SM120_MMA`).

### Rack commands (Workstream G — plain sm_120 vs sm_120a feature-qualified)

Two recipes (also documented in `contrib/matmul-v4/measure-hardware.sh`):

```bash
# Recipe 1 — plain sm_120 packaging (native SM120_MMA OFF / fail-closed):
cmake -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
      -DBTX_CUDA_ARCHITECTURES=120 \
      -DBTX_CUDA_SM120_MXFP4_NATIVE=OFF ...
ninja test_btx
./src/test/test_btx -t matmul_v4_rc_sm120_native_capability_tests

# Recipe 2 — sm_120a feature-qualified native MXFP4 MMA (dedicated object):
cmake -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
      -DBTX_CUDA_ARCHITECTURES=120 \
      -DBTX_CUDA_SM120_MXFP4_NATIVE=ON ...
# (Agent B: isolated -gencode=arch=compute_120a,code=sm_120a on
#  matmul_v4_rc_mx_ozaki_native_sm120a.cu — do NOT put 120a in ARCHITECTURES)
ninja test_btx
./src/test/test_btx -t rc_ozaki_mxfp4_native_gate,rc_ozaki_mxfp4_selected_backend_honesty,matmul_v4_rc_sm120_native_capability_tests

# After SM120_MMA qualifies on Recipe 2, confirm SASS contains QMMA.SF E2M1:
cuobjdump -sass src/libbtx_matmul_backend.so | rg -n 'QMMA|mma\.|E2M1|mxf8f6f4'
ncu --devices 0 --set full ./src/test/test_btx -t rc_ozaki_mxfp4_native_gate
```

Do **not** write “sm_120 qualified” for block-scaled MMA — that latch is
**sm_120a feature-qualified** (linked dedicated object + complete suite).
Plain Recipe 1 fatbins must keep `SelectedBackend=Unqualified` for SM120_MMA.

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
| Tests | `rc_ozaki_exact_panels_qualify_and_match_oracle`, `rc_ozaki_mxfp4_native_gate`, `matmul_v4_rc_sm120_native_capability_tests` (plain sm_120 vs sm_120a honesty) |

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
