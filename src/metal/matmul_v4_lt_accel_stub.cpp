// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

namespace matmul_v4::metal {

bool IsMatMulLTMetalAvailable() { return false; }

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

bool ComputeDigestsOnlyLTMetal(const CBlockHeader&, uint32_t,
                               const uint64_t*, size_t,
                               std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    return false;
}

bool LtLastS8S8UsedTensorOps() { return false; }

} // namespace matmul_v4::metal
