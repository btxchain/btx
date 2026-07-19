# Multi-vendor ExactGemm architecture notes (2026-07-19)

Living implementation notes for miner-local ExactGemm backends. Consensus remains the CPU integer transcript. Public activation stays `INT32_MAX`.

## Contract (all vendors)

- Byte-identical to `ExactGemmS8S8` / `ExactGemmS32S8` (or fail closed).
- Self-qualify at process start; sample-check during mining; reconstruct winners on CPU.
- Never label scalar ALU as IMMA / MFMA / Cube / TensorOps.
- Capabilities report: `exact_s8_s8_s32`, `exact_partitioned_s32_s8`, arch string, max K, device hashing.

## Logical MX versus native MXFP4

Lever-B exposes exact M11 mantissas and E8M0-like power-of-two scales in a
32-column logical layout. That makes a future OCP-MXFP4 encoding possible; it
does not establish that a backend executed MXFP4. The optimized CPU projection
consumes these components without materializing dense `Bhat`. Current LT CUDA
and HIP kernels materialize dense INT8 `Bhat` and execute the projection with
qualified INT8 IMMA/MFMA. Neither LT backend has a native MXFP4 projection
kernel. Static `ProjectionLane::ScalePartitionedMxfp4` planner labels are design
intent only and are not runtime qualification evidence.

## NVIDIA CUDA (5090 / H200 / B200)

| Arch | SM | Notes from PR #89 silicon |
|---|---|---|
| RTX 5090 | sm_120 | INT8 cuBLASLt available; MXFP4 via cuBLASLt **no algorithm**; hand PTX `mxf4` on sm_120a |
| H100/H200 | sm_90 | INT8 available; no MXFP4 MMA |
| B200 | sm_100 | INT8 available; cuBLASLt MXFP4 no algorithm; sm_100a rejects consumer mxf4 PTX |

**Implemented (this branch):**

1. **cuBLASLt `CUBLAS_COMPUTE_32I` IMMA** (`matmul_v4_lt_tensor_gemm.cu`): host + **device-pointer** s8xs8→s32; process-persistent handle, NVIDIA-recommended **32 MiB workspace**, A/B/C scratch, and descriptors/heuristic result cached by `(M,N,K)`. Up to 16 heuristic candidates are inspected and only an algorithm whose numerical flags attest **IMMA + signed INT8 inputs + INT32 accumulator** is admitted. Multi-shape self-qual uses 128/256-scale square and panel cases, host and device pointers, then requires current Rank-1 geometries including `w=1024` MatExpand panels and deep-`m` projections.
2. **LT ExactGemmBackend / `LaunchGemmS8S8`**: IMMA first; scalar `DeviceGemmS8S8Tiled` only on decline. `LtLastS8S8UsedImma()` reports which path ran (never true for scalar).
3. **S32S8**: the direct `TryLaunchLtImmaGemmS32S8` API still honestly declines because cuBLASLt has no direct s32×s8 recipe. The LT resident MatExpand path now decomposes `Y` into four exact signed-byte radix-256 planes and runs four qualified IMMA products plus the column-bias correction. Do not report this lowering as a native s32×s8 instruction.
4. **Device-resident LT path** (`matmul_v4_lt_accel.cu`): qualified IMMA runs `G·W`, radix-lowered `Y·H`, `U·Ahat`, dense-INT8 `Bhat·V`, and nine exact Karatsuba combine products. MX scale derivation is on-device, but Extract dequantizes to dense INT8; no native MXFP4 instruction is issued. Scalar CUDA graphs remain the non-IMMA path. Chat still returns to the host for hashing.
5. **Arch probe**: `ProbeLtCudaArch` / `ProbeLtCudaExactGemmCapabilities` → `sm_*` + name class `hopper` / `blackwell_dc` / `blackwell_consumer`.
6. **Digest-only D2H gap (honest)**: resident path still copies full Chat to host for `ComputeSketchDigestFromFq`. `device_hashing=false` in capabilities until a bit-identical device digest exists. Persistent MatExpand + GEMM scratch reused.

**Honest stubs / fail-closed:** Generic BMX4 portable grouped “MXFP4” is
integer emulation and **never** sets `used_tensor_path`; LT does not dispatch it.
CUTLASS/tcgen05 native MXFP4 and device FP8 remain fail-closed until a real
kernel self-qualifies on named silicon. sm_120a consumer PTX and sm_100a
datacenter tcgen05 recipes must not be conflated.

## AMD ROCm / HIP (MI300 / MI355)

| Arch | ISA | Notes |
|---|---|---|
| MI300X / MI300A | gfx942 | CDNA3 MFMA i8→i32 via hipBLASLt `HIPBLAS_COMPUTE_32I` or rocBLAS `gemm_ex` |
| MI350 / MI355 | gfx950 | CDNA4; same integer ExactGemm path; set via `BTX_HIP_ARCHITECTURES` |

**Implemented (this branch):**

1. **hipBLASLt when its installed release supplies a qualifying integer heuristic, then rocBLAS `gemm_ex` I8II** (`matmul_v4_lt_tensor_gemm.hip`): both libraries can be linked simultaneously, descriptors/algorithms are cached by shape, and a failed hipBLASLt shape falls through to rocBLAS. Host and device-pointer s8xs8→s32 are self-tested against `ExactGemmS8S8`; `IsLtMfmaGemmAvailable()` is true only after that match. CDNA architecture naming alone is no longer sufficient for mining admission.
2. **LT ExactGemmBackend / `LaunchGemmS8S8`**: MFMA first; device ALU / pooled scalar tile on decline. `LtLastS8S8UsedMfma()` reports which path ran. `MakeResolvedExactGemmBackend` injects `LaunchGemm*` (not MFMA-only Try*).
3. **Device-resident MatExpand** (`matmul_v4_lt_accel.hip`): G\*W / U\*Ahat / Bhat\*V use the qualified INT8 library path. Y\*H is exactly radix-lowered into four signed-byte GEMMs plus a column-bias correction. The Fq combine is lowered into nine exact balanced-base-64/Karatsuba INT8 GEMMs. The scalar fallback GEMMs use shared tiles and remain honestly labeled ALU.
4. **CMake**: `BTX_ENABLE_HIP=ON` requires explicit `BTX_HIP_ARCHITECTURES` (e.g. `gfx942;gfx950`). hipBLASLt and rocBLAS are probed independently; without a library path, the registry rejects MFMA mining even if scalar HIP ALU kernels work.
5. **Fail closed when HIP off**: stubs keep `IsLtMfmaGemmAvailable` / `IsLtDeviceAluGemmAvailable` / `LaunchGemm*` false.

**Honest stubs:** native block-scaled MXFP4 on MI300/MI350/MI355 remains hardware-gated. Consensus remains CPU; activation stays `INT32_MAX`.

## Google Cloud TPU / PJRT

`src/tpu/` defines a versioned provider ABI rather than importing OpenXLA into the node. `BTX_ENABLE_TPU_PJRT` is OFF by default. A bridge must keep a PJRT/libtpu client, executables, and device buffers resident and attest that the TPU MXU—not a host fallback—executed.

The admitted floating lane is narrowly proven exact: S8 values are exactly representable in BF16, products are exact in FP32, and BTX checks `inner·max|A|·max|B| ≤ 2^24` before every provider call. Thus every possible integer partial sum is exactly representable regardless of reduction order. The inclusive `2^24` boundary is part of self-qualification; the first value above it is rejected before device invocation. S32S8 remains CPU-only.

Select a registered/self-qualified provider with `BTX_MATMUL_LT_EXACT_BACKEND=tpu`. This accelerates LT ExactGemm only; it does not make TPU a full v4 digest backend.

## AWS Trainium / Neuron NKI

`src/trainium/` provides the analogous OFF-by-default `BTX_ENABLE_TRAINIUM_NEURON` provider ABI for a version-pinned NKI NEFF/NRT bridge. The provider must convert S8→BF16 without scaling, keep accumulation/output in FP32 PSUM, validate exact FP32→S32 conversion, and attest native Tensor Engine execution.

The same host proof gate and boundary tests apply. This matches the documented NKI `nc_matmul` BF16 inputs and FP32 internal accumulation while avoiding any unsupported claim of native S8 GEMM. Select it with `BTX_MATMUL_LT_EXACT_BACKEND=trainium`; S32S8 remains CPU-only.

## Huawei Ascend 950 (昇腾)

**Implemented (fail-closed without a qualifying CANN SDK/device):**

1. The native lane now uses documented CANN 9.1 `aclnnQuantMatmulV5` raw
   `INT8×INT8→INT32` semantics, with the required persistent `FLOAT32(1)`
   `x2Scale`; ordinary `aclnnMm`/`aclnnMatmul` is not used for an undocumented
   integer dtype combination.
2. `aclnnCalculateMatmulWeightSizeV2` + `aclnnTransMatmulWeight` supplies the
   processor-affine NZ weight path used as native Cube evidence. Products whose
   documented contract is ND-only decline rather than being mislabeled Cube.
3. Device buffers, pinned host staging, one stream, and the largest workspace
   persist across calls. Async H2D/operator/D2H work has one terminal stream
   synchronization.
4. The capability registry initializes AscendCL once and classifies only the
   actual `aclrtGetSocName()` result. There is no environment override or
   guessed `dav-3510` default.
5. CMake links either the recommended split `opapi_nn + opapi_math` pair or
   generic `opapi`, never both; deprecated `ops_infer` is not used.
6. `used_cube_path` is exposed only after odd/rectangular/aligned/max-magnitude
   probes match CPU `ExactGemmS8S8`. S32S8 still declines. The detailed product
   matrix and qualification checklist are in
   `doc/btx-matmul-v4.4-ascend-950-cann-backend.md`.

## Apple Metal

| Class | Silicon | ExactGemm lane | Capability string |
|---|---|---|---|
| **M4-class** (pre-M5) | M1–M4 GPU / ANE | MSL integer ALU ExactGemm only (verification / pooled ALU) | `m4_class` — **never** advertise TensorOps |
| **M5-class** | M5 GPU Neural Accelerators | Metal 4 `mpp::tensor_ops::matmul2d` INT8→INT32 (MPP) | `m5_class` + `exact_s8_s8_s32` only after ExactGemmS8S8 self-qual |

**Implemented (this branch):**

1. **MPP TensorOps ExactGemm** (`metal/matmul_v4_lt_tensor_gemm.mm`): runtime metal4.0 compile of `matmul_v4_lt_s8_gemm_s32_tensor`; self-test vs `ExactGemmS8S8` (square + MatExpand panel). `IsLtTensorOpsGemmAvailable()` is true **only** after that match — never from ALU shaders alone.
2. **LT ExactGemmBackend / `LaunchGemmS8S8`**: TensorOps first; MSL ALU `gemm_s8s8` only on decline. `LtLastS8S8UsedTensorOps()` reports which path ran (`used_tensor_path` honesty).
3. **S32S8**: TensorOps always declines (no dedicated recipe); ALU `gemm_s32s8` / CPU ExactGemmS32S8 remain.
4. **Arch probe**: `ProbeLtMetalArch` / `ProbeLtMetalExactGemmCapabilities` → `m4_class` / `m5_class` (compile evidence preferred over device-name soft map).
5. **Env kill-switch**: `BTX_MATMUL_V4_LT_TENSOR_OPS=0` forces TensorOps decline (ALU may still run).

**Honest stubs (non-Apple CI):** `matmul_v4_lt_accel_stub.cpp` + tensor_gemm stub under `!BTX_ENABLE_METAL` decline all entry points; tests expect TensorOps unavailable.

## Production wiring

`SolveMatMulV4LT` now always resolves an `ExactGemmBackend`, including the LT-only TPU/Trainium choice while the full digest backend remains CPU. Full CUDA/HIP/Metal/Ascend backends keep their existing dispatch. Phase-B accelerated winners are re-sealed with the CPU reference; Phase-A winners already receive the unconditional CPU digest reseal.

## Validation status

The default macOS build and 84 focused LT/BMX4/backend/cloud-stub tests pass. A separate provider-enabled build passes all 9 fake TPU and Trainium qualification tests, covering correct, incorrect, host-only, proof-boundary, above-bound, resolver-wiring, and S32S8-decline behavior. This host has no CUDA, ROCm, CANN, PJRT/libtpu, Neuron, or target accelerator hardware, so H200/B200, MI300/MI355, Ascend, TPU, and Trainium compilation/performance still require the hardware qualification runbook. No on-silicon throughput claim is made here.
