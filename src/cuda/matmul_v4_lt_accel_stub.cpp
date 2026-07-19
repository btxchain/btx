// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// No-CUDA build: the MatMul v4.4 ENC-DR-LT ("MatExpand") backend is
// unavailable, so every entry point declines. Callers fall back to the
// host ExactGemm / WindowSketchMinerLT fail-closed path
// (matmul::v4::lt::ComputeDigestBMX4CLT) — that host path is the safety net,
// not a complete device accelerator. Keeps the tree building without a CUDA
// toolkit when BTX_ENABLE_CUDA_EXPERIMENTAL is OFF.

namespace matmul_v4::cuda {

bool IsMatMulLTCudaAvailable()
{
    return false;
}

bool LaunchGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                    uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool LaunchGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                     uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool ComputeDigestsOnlyLTCuda(const CBlockHeader& /*tmpl*/, uint32_t /*n*/,
                              const uint64_t* /*nonces*/, size_t /*count*/,
                              std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    return false;
}

bool LtLastS8S8UsedImma()
{
    return false;
}

} // namespace matmul_v4::cuda
