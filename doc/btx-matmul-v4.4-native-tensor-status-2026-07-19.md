# Native ExactGemm tensor status (2026-07-19; updated 2026-07-20)

PR snapshot: `claude/matmul-v4-design-spec-af23sj` @ `1ca87fb`. This is a
status snapshot, not a claim that the named SHA remains the moving PR tip.

Consensus remains the **CPU integer transcript**. Public activation stays **`INT32_MAX`**. Winners are always **CPU-resealed**. Native tensor paths are miner-local only and must self-qualify vs `ExactGemmS8S8` before advertising IMMA / MFMA / Cube / TensorOps.

“Native” below describes qualified GEMM kernels, not an end-to-end resident
miner. At `1ca87fb`, Q* was still issued as individual calls with host W
generation/digest and per-nonce synchronization; those wall rates do not rank
silicon and cannot calibrate ASERT.

Post-snapshot branch work adds complete-header CUDA/HIP Q* entries with device
W generation, device SHA256d(Chat), digest/status-only D2H, and one batch sync.
That changes the measurement path, not the native-instruction table below; it
still requires CUDA/ROCm compilation and fresh B200/5090/MI350 silicon data.

## Shipped production paths (SDK + silicon + self-qual)

| Vendor | Path | Activates when | Still fail-closed |
|---|---|---|---|
| **NVIDIA** | cuBLASLt `CUBLAS_COMPUTE_32I` IMMA s8×s8→s32 (host + device-ptr); resident MatExpand uses IMMA for G×W / U×Ahat / Bhat×V | CUDA + IMMA self-qual (multi-shape incl. MatExpand panels) | S32×s8 IMMA; MXFP4 tensor; `device_hashing` (Chat still D2H) |
| **AMD** | hipBLASLt `HIPBLAS_COMPUTE_32I` / rocBLAS `gemm_ex` i8→i32; device-ptr MFMA; LaunchGemm MFMA→ALU→CPU | HIP + library ExactGemm match | Scalar never labeled MFMA; HIP off → stubs |
| **Ascend 950** | aclnn Mm/Matmul (+ TransMatmulWeight INT8); KEEP_DTYPE; Cube only after odd-K / ±127 self-qual | `BTX_ENABLE_ASCEND` + CANN headers/libs + self-qual | Default CI stub; S32S8 Cube |
| **Apple Metal** | MPP `tensor_ops::matmul2d` ExactGemm; M4/M5 arch probe; LaunchGemm TensorOps→ALU | Apple + Metal 4 MPP + self-qual | Non-Apple stubs; S32S8 TensorOps |

## Honesty contract

- Never label scalar ALU as IMMA / MFMA / Cube / TensorOps.
- `IsLt*Available` / `used_*_path` false until ExactGemm match.
- CPU-only CI stays green with all native flags declining.

## Commits (this push wave)

- CUDA harden: `8207560` / `61a19a2`
- Ascend Cube: `1e07707` / `dbd548a` (+ docs)
- Metal TensorOps: `cefb94f`+`b8e3415` / `0a95642`+`d02da9b`
- HIP MFMA: `315d6ec` / `1896fc0`

HeaderPoW bit-26 wire remains **withdrawn** (`f21a282`); activation of commitment-format HeaderPoW is still a hard NO-GO.
