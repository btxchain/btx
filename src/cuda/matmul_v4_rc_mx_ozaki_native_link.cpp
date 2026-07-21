// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

// Default / no-CUDA-experimental build: RC Ozaki CUDA TU is not linked.

namespace matmul_v4::cuda {

bool IsRcOzakiCudaCompiled()
{
    return false;
}

bool IsRcOzakiCudaExactPanelsQualified()
{
    return false;
}

bool SelfQualifyRcOzakiCudaExactPanelsOnce()
{
    return false;
}

bool TryLaunchRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                             const std::vector<int8_t>& /*right*/,
                                             uint32_t /*rows*/, uint32_t /*inner*/,
                                             uint32_t /*cols*/, std::vector<int64_t>& out,
                                             std::string* error)
{
    out.clear();
    if (error) {
        *error = "RC Ozaki CUDA ExactPanels TU not linked (BTX_ENABLE_CUDA_EXPERIMENTAL off)";
    }
    return false;
}

bool IsRcOzakiCudaMxfp4Qualified()
{
    return false;
}

std::string RcOzakiCudaMxfp4ArchKey()
{
    return {};
}

std::string RcOzakiCudaMxfp4Backend()
{
    return {};
}

std::string RcOzakiCudaMxfp4Deficit()
{
    return "rc_ozaki_mxfp4_cuda_tu_not_linked";
}

bool SelfQualifyRcOzakiCudaMxfp4Once()
{
    return false;
}

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                       const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                       uint32_t /*inner*/, uint32_t /*cols*/,
                                       std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (error) {
        *error = "RC Ozaki CUDA MXFP4 TU not linked (BTX_ENABLE_CUDA_EXPERIMENTAL off)";
    }
    return false;
}

void ResetRcOzakiCudaQualForTest() {}

} // namespace matmul_v4::cuda
