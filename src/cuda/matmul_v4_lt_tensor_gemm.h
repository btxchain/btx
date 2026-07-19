// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_TENSOR_GEMM_H
#define BITCOIN_CUDA_MATMUL_V4_LT_TENSOR_GEMM_H

#include <cstdint>
#include <string>
#include <vector>

// LT ExactGemm tensor-core preference layer (IMMA on CUDA, MFMA on HIP,
// Metal TensorOps on Apple). Scalar ExactGemm* / device ALU tiles remain the
// always-available fallback; these entry points return false when the tensor
// path is unavailable or fails self-test so callers fall back without claiming
// a tensor datapath they did not run.

namespace matmul_v4::cuda {

/** Named SM classes for logging / capabilities JSON (PR #89 silicon map). */
enum class LtCudaArchNameClass : uint8_t {
    Unknown = 0,
    Hopper = 1,             // sm_90 (H100/H200)
    BlackwellDc = 2,        // sm_100 (B200)
    BlackwellConsumer = 3,  // sm_120 (RTX 5090)
    Other = 4,
};

struct LtCudaArchProbe {
    bool available{false};
    int device_index{-1};
    std::string device_name;
    uint32_t compute_capability_major{0};
    uint32_t compute_capability_minor{0};
    std::string sm_string;          // e.g. "sm_90"
    LtCudaArchNameClass name_class{LtCudaArchNameClass::Unknown};
    std::string name_class_string;  // hopper / blackwell_dc / blackwell_consumer / …
};

/** Miner-local ExactGemm capability snapshot (never conflates scalar with IMMA). */
struct LtCudaExactGemmCapabilities {
    bool exact_s8_s8_s32{false};          // cuBLASLt IMMA self-qualified
    bool exact_partitioned_s32_s8{false}; // no dedicated IMMA recipe today
    bool device_scalar_gemm{false};       // tiled ALU kernels available
    bool device_hashing{false};           // false: digest-only still Chat D2H
    LtCudaArchProbe arch{};
};

/** Probe primary CUDA device compute capability / name class for logs/JSON. */
[[nodiscard]] LtCudaArchProbe ProbeLtCudaArch();

/** Snapshot of ExactGemm lanes + arch for capabilities reporting. */
[[nodiscard]] LtCudaExactGemmCapabilities ProbeLtCudaExactGemmCapabilities();

/** True iff cuBLASLt IMMA s8xs8->s32 passed multi-shape bit-exact self-test vs
 *  ExactGemmS8S8 (square + MatExpand G*W / U*Ahat / Bhat*V panels). Does NOT
 *  imply s32xs8 IMMA — that lane always declines. */
[[nodiscard]] bool IsLtImmaGemmAvailable();

/** Attempt IMMA ExactGemmS8S8 (host vectors; persistent A/B/C scratch).
 *  Returns false → caller MUST use scalar/ALU and MUST NOT claim IMMA. */
[[nodiscard]] bool TryLaunchLtImmaGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);

/** Device-resident IMMA s8xs8->s32 on existing device pointers (row-major).
 *  `stream` may be nullptr (legacy default stream). Returns false → caller MUST
 *  use scalar DeviceGemm* and MUST NOT claim IMMA. */
[[nodiscard]] bool TryLaunchLtImmaGemmS8S8Device(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                                 uint32_t rows, uint32_t cols, uint32_t inner,
                                                 void* stream /* cudaStream_t */);

/** Attempt IMMA ExactGemmS32S8. Always declines: cuBLASLt CUBLAS_COMPUTE_32I is
 *  s8×s8→s32 only; no self-qualified s32×s8→s32 recipe on sm_90/100/120.
 *  Callers keep ExactGemmS32S8 / DeviceGemmS32S8Tiled (never label as IMMA). */
[[nodiscard]] bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

} // namespace matmul_v4::cuda

namespace matmul_v4::hip {

/** True iff hipBLASLt/rocBLAS s8×s8→s32 (INT32 accumulate) executed and matched
 *  ExactGemmS8S8 (square + MatExpand panel). Never true for scalar device-ALU
 *  tiles alone. Target arches: gfx942 (MI300), gfx950 (MI350) via
 *  BTX_HIP_ARCHITECTURES. */
[[nodiscard]] bool IsLtMfmaGemmAvailable();
[[nodiscard]] bool TryLaunchLtMfmaGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);

/** Device-resident MFMA s8xs8→s32 on existing device pointers (row-major).
 *  `stream` may be nullptr (default stream). Returns false → caller MUST use
 *  scalar DeviceGemm* and MUST NOT claim MFMA. */
[[nodiscard]] bool TryLaunchLtMfmaGemmS8S8Device(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                                 uint32_t rows, uint32_t cols, uint32_t inner,
                                                 void* stream /* hipStream_t */);

[[nodiscard]] bool TryLaunchLtMfmaGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

/** Portable device scalar ALU ExactGemm — honest label, not MFMA. */
[[nodiscard]] bool IsLtDeviceAluGemmAvailable();
[[nodiscard]] bool TryLaunchLtDeviceAluGemmS8S8(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right,
                                                uint32_t rows, uint32_t inner, uint32_t cols,
                                                std::vector<int32_t>& out);
[[nodiscard]] bool TryLaunchLtDeviceAluGemmS32S8(const std::vector<int32_t>& left,
                                                 const std::vector<int8_t>& right,
                                                 uint32_t rows, uint32_t inner, uint32_t cols,
                                                 std::vector<int32_t>& out);

} // namespace matmul_v4::hip

namespace matmul_v4::metal {

/** Named Apple Silicon classes for logging / capabilities JSON (PR #89).
 *  M4-class = pre-M5 GPU / ANE (ALU ExactGemm only; no INT8 TensorOps).
 *  M5-class = Metal 4 mpp::tensor_ops INT8→INT32 neural accelerators. */
enum class LtMetalArchNameClass : uint8_t {
    Unknown = 0,
    M4Class = 1,
    M5Class = 2,
    Other = 3,
};

struct LtMetalArchProbe {
    bool available{false};
    std::string device_name;
    LtMetalArchNameClass name_class{LtMetalArchNameClass::Unknown};
    std::string name_class_string; // m4_class / m5_class / unknown / other
    bool metal4_tensor_ops_compile_ok{false};
};

/** Miner-local ExactGemm capability snapshot (never conflates ALU with TensorOps). */
struct LtMetalExactGemmCapabilities {
    bool exact_s8_s8_s32{false};          // MPP TensorOps self-qualified
    bool exact_partitioned_s32_s8{false}; // TensorOps s32xs8 via base-256 limbs
    bool device_alu_gemm{false};          // MSL integer ALU tiles available
    bool device_hashing{false};           // false: digest still host-side
    LtMetalArchProbe arch{};
};

[[nodiscard]] LtMetalArchProbe ProbeLtMetalArch();
[[nodiscard]] LtMetalExactGemmCapabilities ProbeLtMetalExactGemmCapabilities();

/** True iff Metal 4 mpp::tensor_ops::matmul2d INT8→INT32 passed ExactGemm
 *  self-qual. Never true for plain ALU shaders alone. */
[[nodiscard]] bool IsLtTensorOpsGemmAvailable();
[[nodiscard]] bool TryLaunchLtTensorOpsGemmS8S8(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right,
                                                uint32_t rows, uint32_t inner, uint32_t cols,
                                                std::vector<int32_t>& out);
[[nodiscard]] bool TryLaunchLtTensorOpsGemmS32S8(const std::vector<int32_t>& left,
                                                 const std::vector<int8_t>& right,
                                                 uint32_t rows, uint32_t inner, uint32_t cols,
                                                 std::vector<int32_t>& out);

} // namespace matmul_v4::metal

#endif // BITCOIN_CUDA_MATMUL_V4_LT_TENSOR_GEMM_H
