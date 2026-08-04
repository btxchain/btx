// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_accel.h>

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// Stub compiled when BTX_ENABLE_HIP is OFF (no ROCm toolchain). Keeps the
// matmul_v4::hip symbols present so a dispatch layer can link unconditionally;
// the backend simply reports itself unavailable and the caller uses the CPU
// reference path.

namespace matmul_v4 {
namespace hip {

bool HipBackendCompiled() { return false; }

bool ComputeDigestAccel(const CBlockHeader& /*header*/, uint32_t /*n*/, uint32_t /*rounds*/,
                        uint256& /*digest_out*/, std::vector<unsigned char>& /*payload_out*/)
{
    return false;
}

bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
                                uint32_t /*rounds*/, std::vector<uint256>& digests_out,
                                std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    return false;
}

} // namespace hip
} // namespace matmul_v4
