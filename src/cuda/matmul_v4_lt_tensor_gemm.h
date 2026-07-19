// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_TENSOR_GEMM_H
#define BITCOIN_CUDA_MATMUL_V4_LT_TENSOR_GEMM_H

#include <cstdint>
#include <vector>

// LT ExactGemm tensor-core preference layer (IMMA on CUDA, MFMA on HIP,
// Metal TensorOps on Apple). Scalar ExactGemm* / device ALU tiles remain the
// always-available fallback; these entry points return false when the tensor
// path is unavailable or fails self-test so callers fall back without claiming
// a tensor datapath they did not run.

namespace matmul_v4::cuda {

/** True iff cuBLASLt IMMA s8xs8->s32 (and s32xs8 via int decomposition or
 *  dedicated path) passed the bit-exact self-test against ExactGemm*. */
[[nodiscard]] bool IsLtImmaGemmAvailable();

/** Attempt IMMA ExactGemmS8S8. Returns false → caller MUST use scalar/ALU. */
[[nodiscard]] bool TryLaunchLtImmaGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);

/** Attempt IMMA-backed ExactGemmS32S8 (may lower to IMMA after packing or
 *  decline to scalar). Returns false → caller MUST use scalar/ALU. */
[[nodiscard]] bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

} // namespace matmul_v4::cuda

namespace matmul_v4::hip {

[[nodiscard]] bool IsLtMfmaGemmAvailable();
[[nodiscard]] bool TryLaunchLtMfmaGemmS8S8(const std::vector<int8_t>& left,
                                           const std::vector<int8_t>& right,
                                           uint32_t rows, uint32_t inner, uint32_t cols,
                                           std::vector<int32_t>& out);
[[nodiscard]] bool TryLaunchLtMfmaGemmS32S8(const std::vector<int32_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t rows, uint32_t inner, uint32_t cols,
                                            std::vector<int32_t>& out);

} // namespace matmul_v4::hip

namespace matmul_v4::metal {

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
