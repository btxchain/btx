// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_bmx4_accel.h>

#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// Stub compiled when BTX_ENABLE_HIP is OFF (no ROCm toolchain). Keeps the
// matmul_v4::bmx4::hip symbols present so a dispatch layer can link
// unconditionally; the backend simply reports itself unavailable and the
// caller uses the CPU reference path (matmul::v4::bmx4::ComputeDigestBMX4C).

namespace matmul_v4::bmx4::hip {

bool Bmx4CHipBackendCompiled() { return false; }

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
                              uint32_t /*rounds*/, std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    return false;
}

} // namespace matmul_v4::bmx4::hip

// Dispatcher-integration adapter (see matmul_v4_bmx4_accel.h / .hip): provide
// the SAME strong `matmul_v4::hip::ComputeDigestsBMX4CAccel` symbol here too,
// so that whichever of this stub or the real .hip translation unit CMake
// selects, the dispatcher's declared entry point always resolves to a
// definition consistent with Bmx4CHipBackendCompiled() == false above.
namespace matmul_v4::hip {

bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
                              uint32_t /*rounds*/, std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    return false;
}

} // namespace matmul_v4::hip
