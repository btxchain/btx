// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// Stub compiled when BTX_ENABLE_HIP is OFF (no ROCm toolchain). Keeps the
// matmul_v4::hip LT symbols present so a caller can link unconditionally;
// the backend declines and callers use the host ExactGemm /
// WindowSketchMinerLT fail-closed path (not a complete device accelerator).

namespace matmul_v4::hip {

bool IsMatMulLTHipAvailable()
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

bool ComputeDigestsOnlyLTHip(const CBlockHeader& /*tmpl*/, uint32_t /*n*/,
                             const uint64_t* /*nonces*/, size_t /*count*/,
                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    return false;
}

bool ComputeDigestsOnlyLTHip(
    const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtHipBatchProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    return false;
}

bool LtLastS8S8UsedMfma()
{
    return false;
}

} // namespace matmul_v4::hip
