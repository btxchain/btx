// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// Stub when BTX_ENABLE_ASCEND is OFF, or ON without a detected CANN toolkit.
// Always fail-closed — never claims Cube / ExactGemm / MX twin without CANN +
// self-qual. Provenance fields stay false.

namespace matmul_v4::ascend {

bool GetAscendRuntimeSocName(std::string& out)
{
    out.clear();
    return false;
}

bool IsAscendExactGemmAvailable()
{
    return false;
}

bool IsAscendExactMxProjectionAvailable()
{
    return false;
}

bool ExactGemmS8S8Ascend(const std::vector<int8_t>& /*left*/,
                         const std::vector<int8_t>& /*right*/,
                         uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                         std::vector<int32_t>& out, bool* used_cube_path)
{
    out.clear();
    if (used_cube_path) *used_cube_path = false;
    return false;
}

bool ExactGemmS32S8Ascend(const std::vector<int32_t>& /*left*/,
                          const std::vector<int8_t>& /*right*/,
                          uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                          std::vector<int32_t>& out, bool* used_cube_path)
{
    out.clear();
    if (used_cube_path) *used_cube_path = false;
    return false;
}

bool TryLaunchLtCubeGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                             uint32_t, uint32_t, uint32_t, std::vector<int32_t>& out)
{
    out.clear();
    return false;
}

bool TryLaunchLtCubeGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                              uint32_t, uint32_t, uint32_t, std::vector<int32_t>& out)
{
    out.clear();
    return false;
}

bool ComputeProjectedRightMxBlockScaleLTAscend(
    const std::vector<int8_t>& /*mu*/, const std::vector<uint8_t>& /*scales*/,
    const std::vector<int8_t>& /*V*/, uint32_t /*n*/, uint32_t /*m*/,
    std::vector<int32_t>& out, LtAscendDigestProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    return false;
}

bool TryLaunchLtCubeMxProjectRight(const std::vector<int8_t>& /*mu*/,
                                   const std::vector<uint8_t>& /*scales*/,
                                   const std::vector<int8_t>& /*V*/, uint32_t /*n*/,
                                   uint32_t /*m*/, std::vector<int32_t>& out,
                                   matmul::v4::lt::MxLaneProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    return false;
}

LtAscendDigestProvenance LastAscendDigestProvenance()
{
    return {};
}

bool ComputeDigestsOnlyLTAscend(const CBlockHeader& /*tmpl*/, uint32_t /*n*/,
                                const uint64_t* /*nonces*/, size_t /*count*/,
                                std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
                                LtAscendDigestProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    return false;
}

} // namespace matmul_v4::ascend
