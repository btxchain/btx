# Native ExactGemm tensor status (2026-07-19; updated 2026-07-20)

PR snapshot: `claude/matmul-v4-design-spec-af23sj` @ `1ca87fb`. This is a
status snapshot, not a claim that the named SHA remains the moving PR tip.

Consensus remains the **CPU integer transcript**. Public activation stays **`INT32_MAX`**. Winners are always **CPU-resealed**. Native tensor paths are miner-local only and must self-qualify vs `ExactGemmS8S8` before advertising IMMA / MFMA / Cube / TensorOps.

## Exact-MX vs native-MX (ENC-DR-LT)

| Term | Meaning | Report honesty |
|---|---|---|
| **exact-MX** | Bit-identical to `ComputeProjectedRightMxBlockScaleLT` (dense `Bhat·V` with `Bhat[i,j]=μ[i,j]<<e[i,j/32]`). INT8 scale-partitioned GEMM lowerings count. | `lt.exact_mx_scale_partitioned` may be true only when a **device** backend reports it after matching the CPU oracle. CPU-only report runs stay **false**. |
| **native-MX / native-FP8** | On-silicon MXFP4 or FP8 tensor kernel, wired + self-qualified vs the CPU oracle. | `lt.native_mxfp4_qualified` / `lt.native_fp8_qualified` default **false**. Never set from `PlanLTAccel` intent labels or CPU-only runs. |

Shared API: `ExactMxProjectionBackend` + `ComputeProjectedRightMxDispatched` in
`matmul_v4_lt.h` / `matmul_v4_lt_mx_exact.h`. C-15 remains **OPEN**.

### FP32-exact window for LT MX projection

Eligibility math only — **not** a claim that silicon passed self-qual.

| Pin | Value |
|---|---|
| M11 alphabet | `{0,±1,±2,±3,±4,±6}` — **11 symbols**, max `\|μ\|=\|V\|=6` (not ≤11) |
| E8M0 `e` | `{0,1,2,3}` → max `2^e = 8` |
| Per-MAC | `6·8·6 = 288` (`kLtMxProjPerMac`) |
| `\|Q\|_max` at `n=4096` | `288·4096 = 1,179,648` |
| IEEE FP32 exact integers | all `\|x\| ≤ 2^24`; gate uses strict `< 2^24 = 16,777,216` |

So `LtMxProjectionFitsFloat32ExactInteger(n,m)` is true throughout the production
`n≤4096` (and `n≤8192`) envelope: every integer `Q` entry and every partial sum
is exactly representable in FP32. Native MXFP4/FP8 FP32-accumulate attempts may
use this bound as a **precondition**, then must still pass
`MxProjectionMatchesCpuOracle` before setting `native_*_qualified`. Report JSON
keeps those flags **false** until a device backend reports them.

Helper: `LtMxProjectionFitsFloat32ExactInteger` /
`SimulateProjectedRightMxFloat32AccumulateLT` in `matmul_v4_lt_mx_exact.h`.

LT Extract consensus alphabet stays **[-48,48]**. BMX4C `ComputeCombineFp8FiveLimbBMX4C`
(E4M3 five-limb combine) is a **different** miner-local combine alphabet — do not
conflate it with LT MatExpand Extract.

“Native” below describes qualified GEMM kernels, not an end-to-end resident
miner. At `1ca87fb`, Q* was still issued as individual calls with host W
generation/digest and per-nonce synchronization; those wall rates do not rank
silicon and cannot calibrate ASERT.

Post-snapshot branch work adds complete-header CUDA/HIP Q* entries with device
W generation, device SHA256d(Chat), digest/status-only D2H, and one batch sync.
That changes the measurement path, not the native-instruction table below; it
still requires CUDA/ROCm compilation and fresh B200/5090/MI350 silicon data.

### Peak-performance qualification (Blackwell / CDNA4)

On **sm_10x/sm_12x** (CUDA) and **gfx950** (HIP), the resident LT miner
keeps the oracle-qualified exact INT8 MX scale-partitioned lane available by
default. Native MXFP4/MXFP8 capability is reported separately and is not a
consensus prerequisite. In the current implementation, the native launchers
serve the host-vector projection surface; the persistent Q* graph still uses
exact INT8, so `resident_native_mx_wired=false` and `peak_ready=false` even if a
standalone native projection self-qualifies.

An explicit native-only qualification run can block the resident fallback:

```text
BTX_MATMUL_V4_LT_REQUIRE_NATIVE_MX=1
```

Report JSON fields: `lt.peak_capable`, `lt.peak_required`, `lt.peak_ready`,
`lt.resident_native_mx_wired`, `lt.blocks_device_resident`,
`lt.allow_exact_mx_fallback`, `lt.deficit_reason`. A `PEAK DEFICIT` log does not
disable the exact resident miner unless native-only mode was explicitly set.

For the expensive CUDA differential, run the complete suite selector (some
Boost versions/builds have not resolved the narrower wildcard consistently):

```sh
BTX_MATMUL_V4_LT_CUDA_EXTENDED_SELFTEST=1 \
  build-cuda-review/bin/test_btx --run_test=matmul_v4_lt_tests
```

Metal: native MXFP4 remains unavailable by design; exact INT8 scale partitions
are the peak Metal path.

## Shipped production paths (SDK + silicon + self-qual)

| Vendor | Path | Activates when | Still fail-closed |
|---|---|---|---|
| **NVIDIA** | cuBLASLt `CUBLAS_COMPUTE_32I` IMMA s8×s8→s32 (host + device-ptr); resident MatExpand uses IMMA for G×W / U×Ahat / Bhat×V and hashes Chat on device | CUDA + IMMA self-qual (multi-shape incl. MatExpand panels) | S32×s8 IMMA; resident MXFP4 tensor |
| **AMD** | hipBLASLt `HIPBLAS_COMPUTE_32I` / rocBLAS `gemm_ex` i8→i32; device-ptr MFMA; LaunchGemm MFMA→ALU→CPU | HIP + library ExactGemm match | Scalar never labeled MFMA; HIP off → stubs |
| **Ascend 950** | aclnn Mm/Matmul (+ TransMatmulWeight INT8); KEEP_DTYPE; Cube only after odd-K / ±127 self-qual | `BTX_ENABLE_ASCEND` + CANN headers/libs + self-qual | Default CI stub; S32S8 Cube |
| **Apple Metal** | MPP `tensor_ops::matmul2d` ExactGemm; M4/M5 arch probe; LaunchGemm TensorOps→ALU | Apple + Metal 4 MPP + self-qual | Non-Apple stubs; S32S8 TensorOps |

## Honesty contract

- Never label scalar ALU as IMMA / MFMA / Cube / TensorOps.
- `IsLt*Available` / `used_*_path` false until ExactGemm match.
- exact-MX ≠ native-MX: matching `ComputeProjectedRightMxBlockScaleLT` does not qualify MXFP4 silicon.
- `PlanLTAccel` / `ProjectionLane::ScalePartitionedMxfp4` is intent only — not `native_path_eligible`.
- CPU-only CI stays green with all native flags declining.

## Commits (this push wave)

- CUDA harden: `8207560` / `61a19a2`
- Ascend Cube: `1e07707` / `dbd548a` (+ docs)
- Metal TensorOps: `cefb94f`+`b8e3415` / `0a95642`+`d02da9b`
- HIP MFMA: `315d6ec` / `1896fc0`

HeaderPoW bit-26 wire remains **withdrawn** (`f21a282`); activation of commitment-format HeaderPoW is still a hard NO-GO.
