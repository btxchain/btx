// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// Non-Apple / non-Metal build: the MatMul v4.4 ENC-DR-LT ("MatExpand") Metal
// backend is unavailable, so every entry point declines and the caller uses
// the CPU/host-exact reference (matmul::v4::lt::ComputeDigestBMX4CLT /
// matmul::v4::lt::WindowSketchMinerLT).

namespace matmul_v4::metal {

bool IsMatMulLTMetalAvailable()
{
    return false;
}

bool ComputeDigestsOnlyLTMetal(const CBlockHeader& /*tmpl*/, uint32_t /*n*/,
                               const uint64_t* /*nonces*/, size_t /*count*/,
                               std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    return false;
}

} // namespace matmul_v4::metal
