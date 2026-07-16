// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_accel.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// No-CUDA build: the MatMul v4.2 / ENC-BMX4C backend is unavailable, so the
// accelerated entry always declines and the caller uses the CPU reference
// (matmul::v4::bmx4::ComputeDigestBMX4C). Keeps the tree building without a
// CUDA toolkit when BTX_ENABLE_CUDA_EXPERIMENTAL is OFF.

namespace matmul_v4::cuda {

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
                              uint32_t /*rounds*/, std::vector<uint256>& /*digests_out*/,
                              std::vector<std::vector<unsigned char>>& /*payloads_out*/)
{
    return false;
}

} // namespace matmul_v4::cuda
