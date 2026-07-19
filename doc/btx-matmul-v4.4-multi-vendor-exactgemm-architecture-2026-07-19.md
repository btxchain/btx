# Multi-vendor ExactGemm architecture notes (2026-07-19)

Living implementation notes for miner-local ExactGemm backends. Consensus remains the CPU integer transcript. Public activation stays `INT32_MAX`.

## Contract (all vendors)

- Byte-identical to `ExactGemmS8S8` / `ExactGemmS32S8` (or fail closed).
- Self-qualify at process start; sample-check during mining; reconstruct winners on CPU.
- Never label scalar ALU as IMMA / MFMA / Cube / TensorOps.
- Capabilities report: `exact_s8_s8_s32`, `exact_partitioned_s32_s8`, arch string, max K, device hashing.

## NVIDIA CUDA (5090 / H200 / B200)

| Arch | SM | Notes from PR #89 silicon |
|---|---|---|
| RTX 5090 | sm_120 | INT8 cuBLASLt available; MXFP4 via cuBLASLt **no algorithm**; hand PTX `mxf4` on sm_120a |
| H100/H200 | sm_90 | INT8 available; no MXFP4 MMA |
| B200 | sm_100 | INT8 available; cuBLASLt MXFP4 no algorithm; sm_100a rejects consumer mxf4 PTX |

**Implemented (this branch):**

1. **cuBLASLt `CUBLAS_COMPUTE_32I` IMMA** (`matmul_v4_lt_tensor_gemm.cu`): host + **device-pointer** s8xs8→s32; self-test vs `ExactGemmS8S8` (square + MatExpand panel). `IsLtImmaGemmAvailable()` is true only after that match.
2. **LT ExactGemmBackend / `LaunchGemmS8S8`**: IMMA first; scalar `DeviceGemmS8S8Tiled` only on decline. `LtLastS8S8UsedImma()` reports which path ran.
3. **Device-resident MatExpand** (`matmul_v4_lt_accel.cu`): when IMMA available, G\*W / U\*Ahat / Bhat\*V use `TryLaunchLtImmaGemmS8S8Device` on persistent buffers; Y\*H stays scalar s32xs8 (no IMMA recipe — never claimed). Scalar CUDA graphs remain the non-IMMA path.
4. **Arch probe**: `ProbeLtCudaArch` / `ProbeLtCudaExactGemmCapabilities` → `sm_*` + name class `hopper` / `blackwell_dc` / `blackwell_consumer`.
5. **Digest-only D2H gap (honest)**: resident path still copies full Chat to host for `ComputeSketchDigestFromFq`. `device_hashing=false` in capabilities. Persistent buffers reused; loser Chat traffic not yet eliminated.

**Honest stubs:** CUTLASS MXFP4 / device FP8 remain fail-closed until self-qual on named silicon. Hand-written MXFP4 scalar decode never sets `used_tensor_path`. sm_120a vs sm_100a PTX recipes must not be conflated (see `matmul_v4_bmx4_cutlass_mxfp4.h`).

## AMD ROCm / HIP (MI300 / MI350)

- Prefer hipBLASLt / rocBLAS integer GEMM with INT32 accumulate when linked.
- `IsLtMfmaGemmAvailable` must mean actual MFMA/hipBLASLt path executed + ExactGemm match — not scalar ALU self-test.
- Target arches via `BTX_HIP_ARCHITECTURES` (e.g. gfx942).

## Huawei Ascend 950 (昇腾)

Sources (Chinese CANN ecosystem):

- asc-devkit Matmul high-level API samples (Ascend 950PR/DT, `dav-3510`, CANN ≥ 9.1.0)
- `aclnnMatmul` / `aclnnMm` / `aclnnMatmulWeightNz` (ops-nn); INT8 weights via
  `aclnnCalculateMatmulWeightSize(+V2)` + `aclnnTransMatmulWeight`
- Cube unit: `int8_t` A/B → INT32 C; **KEEP_DTYPE only** — never HF32 / down-precision
- **only advertise exact if accumulator proven exact vs CPU** (`IsAscendExactGemmAvailable`)

**Shipped (fail-closed without SDK in CI):**

1. `BTX_ENABLE_ASCEND` CMake option; `BTX_HAVE_CANN` when `include/acl/acl.h` found.
2. `src/ascend/` host ExactGemm: real TU under `BTX_HAVE_CANN` (two-phase aclnn + optional
   TransMatmulWeight); else stub returns false.
3. Accel / backend `Kind::ASCEND` (`"ascend"` / `huawei` / `npu`) — `ResolveBackend` selects
   only when compiled + CANN + ExactGemmS8S8 self-qual (odd-K + max-|entry|).
4. `used_cube_path` / ExactGemmBackend adapters require that gate. S32S8 declines.
5. Doc checklist + known limits: `doc/btx-matmul-v4.4-ascend-950-cann-backend.md`.

## Apple Metal

Existing LT ExactGemm + MPP TensorOps stubs; keep M4/M5 records separate.

## Production wiring

`SolveMatMulV4LT` / seal path should inject device `ExactGemmBackend` when backend ≠ CPU, still CPU-reseal winners. CUDA `ComputeDigestsOnlyLTCuda` already prefers resident IMMA/scalar then injects `LaunchGemm*` into host fallback.
