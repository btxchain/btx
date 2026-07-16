// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_v4_bmx4_accel.h>

namespace matmul_v4::metal {

AccelProbe ProbeAcceleration()
{
    AccelProbe probe;
    probe.available = false;
    probe.reason = "Metal MatMul BMX4-C acceleration is unavailable on this build";
    return probe;
}

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
    uint32_t /*rounds*/, std::vector<uint256>& /*digests_out*/,
    std::vector<std::vector<unsigned char>>& /*payloads_out*/)
{
    // Non-Metal build: report no acceleration so the dispatch layer computes
    // the window on the CPU reference path (matmul::v4::bmx4::
    // ComputeDigestBMX4C).
    return false;
}

} // namespace matmul_v4::metal
