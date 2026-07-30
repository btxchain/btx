// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_v4_accel.h>

namespace matmul_v4::metal {

AccelProbe ProbeAcceleration()
{
    AccelProbe probe;
    probe.available = false;
    probe.reason = "Metal MatMul v4 acceleration is unavailable on this build";
    return probe;
}

bool ComputeDigestAccel(const CBlockHeader&, uint32_t, uint32_t,
                        uint256&, std::vector<unsigned char>&)
{
    // Non-Metal build: report no acceleration so the dispatch layer stays on
    // the CPU reference path.
    return false;
}

bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
                                uint32_t /*rounds*/, std::vector<uint256>& /*digests_out*/,
                                std::vector<std::vector<unsigned char>>& /*payloads_out*/)
{
    // Non-Metal build: no batched acceleration either; the dispatch layer
    // computes the window on the CPU reference path.
    return false;
}

} // namespace matmul_v4::metal
