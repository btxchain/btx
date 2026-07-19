// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

// Vendor stubs for LT ExactGemm tensor preference. Compiled for every backend
// that is NOT enabled in this build so the Try*/Is* symbols always resolve.
// When a backend is enabled, its strong TU (cuda .cu / hip .hip / metal .mm)
// replaces that namespace's definitions.

#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
namespace matmul_v4::cuda {

bool IsLtImmaGemmAvailable() { return false; }

bool TryLaunchLtImmaGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                             uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                              uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace matmul_v4::cuda
#endif

#if !defined(BTX_ENABLE_HIP)
namespace matmul_v4::hip {

bool IsLtMfmaGemmAvailable() { return false; }

bool TryLaunchLtMfmaGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                             uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool TryLaunchLtMfmaGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                              uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace matmul_v4::hip
#endif

#if !defined(BTX_ENABLE_METAL)
namespace matmul_v4::metal {

bool IsLtTensorOpsGemmAvailable() { return false; }

bool TryLaunchLtTensorOpsGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                  uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool TryLaunchLtTensorOpsGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                                   uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace matmul_v4::metal
#endif
