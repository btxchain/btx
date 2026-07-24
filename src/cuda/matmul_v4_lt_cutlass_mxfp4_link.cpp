// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_cutlass_mxfp4.h>

// Default / no-CUTLASS build: LT SM120 OCP MXFP4 tensor path is not linked.
// Packing helpers in the header remain usable; TryLaunch always declines.
// Link path works with CUTLASS absent (this stub satisfies the symbols).

namespace matmul_v4::cuda::lt_cutlass_mxfp4 {

bool IsLtCutlassMxfp4Compiled()
{
    return false;
}

bool IsLtCutlassMxfp4Linked()
{
    return false;
}

bool TryLaunchCutlassMxfp4ProjectedRight(const std::vector<int8_t>& /*mu*/,
                                         const std::vector<uint8_t>& /*scales*/,
                                         const std::vector<int8_t>& /*V*/, uint32_t /*n*/,
                                         uint32_t /*m*/, std::vector<int32_t>& out,
                                         std::string* error)
{
    out.clear();
    if (error) {
        *error = "LT CUTLASS MXFP4 tensor TU not linked (BTX_BMX4C_CUTLASS_MXFP4 off "
                 "or no CUDA experimental)";
    }
    return false;
}

} // namespace matmul_v4::cuda::lt_cutlass_mxfp4
