// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_accel.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// No-CUDA build: the MatMul v4 INT8 tensor-core backend is unavailable, so the
// accelerated entry always declines and the caller uses the CPU reference
// (matmul_v4::ComputeDigest). Keeps the tree building without a CUDA toolkit.

namespace matmul_v4::cuda {

bool ComputeDigestAccel(const CBlockHeader& /*header*/, uint32_t /*n*/, uint32_t /*rounds*/,
                        uint256& /*digest_out*/, std::vector<unsigned char>& /*payload_out*/)
{
    return false;
}

} // namespace matmul_v4::cuda
