// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

// Default / no-CUDA-experimental build: RC Ozaki CUDA TU is not linked.

namespace matmul_v4::cuda {

bool RcOzakiMxfp4Sm120aKernelLinked()
{
    return false;
}

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

RcOzakiMxfp4SelectedBackend RcOzakiCudaMxfp4SelectedBackend()
{
    return RcOzakiMxfp4SelectedBackend::Unqualified;
}

std::string RcOzakiCudaMxfp4ArchKey()
{
    return {};
}

std::string RcOzakiCudaMxfp4Backend()
{
    return "Unqualified";
}

std::string RcOzakiCudaMxfp4Deficit()
{
    return "rc_ozaki_mxfp4_cuda_tu_not_linked";
}

uint64_t RcOzakiCudaMxfp4NativeTensorLaunchCount()
{
    return 0;
}

uint64_t RcOzakiCudaMxfp4ScalarTailLaunchCount()
{
    return 0;
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

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64Device(const int8_t* /*d_left*/, const int8_t* /*d_right*/,
                                             int64_t* /*d_out*/, uint32_t /*rows*/,
                                             uint32_t /*inner*/, uint32_t /*cols*/,
                                             void* /*cuda_stream*/, std::string* error)
{
    if (error) {
        *error = "RC Ozaki CUDA MXFP4 device TU not linked (BTX_ENABLE_CUDA_EXPERIMENTAL off)";
    }
    return false;
}

bool EnsureRcOzakiMxfp4DeviceArena(size_t /*a_bytes*/, size_t /*b_bytes*/, size_t /*sfa_bytes*/,
                                   size_t /*sfb_bytes*/, size_t /*d_elems*/,
                                   size_t /*workspace_bytes*/)
{
    return false;
}

void ResetRcOzakiCudaQualForTest() {}

} // namespace matmul_v4::cuda
