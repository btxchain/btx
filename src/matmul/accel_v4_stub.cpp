// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Ascend currently provides only LT/RC device entry points. Keep its generic
// v4/BMX4C fallbacks in every configuration. CUDA, Metal and HIP select their
// device implementations or per-backend stubs in src/CMakeLists.txt; defining
// those fallbacks here too produces duplicate strong symbols on Windows.

#include <matmul/accel_v4.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

// Windows builds need ordinary archive symbols. These Ascend entry points
// have no device implementation, including when the LT/RC backend is enabled.
#if defined(_MSC_VER) || defined(__MINGW32__)
#define BTX_ACCEL_V4_WEAK
#else
#define BTX_ACCEL_V4_WEAK [[gnu::weak]]
#endif

namespace matmul_v4::ascend {
BTX_ACCEL_V4_WEAK bool ComputeDigestAccel(const CBlockHeader&, uint32_t, uint32_t,
                                          uint256&, std::vector<unsigned char>&)
{
    return false;
}
BTX_ACCEL_V4_WEAK bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>&, uint32_t, uint32_t,
                                                  std::vector<uint256>&,
                                                  std::vector<std::vector<unsigned char>>&)
{
    return false;
}
BTX_ACCEL_V4_WEAK bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>&, uint32_t, uint32_t,
                                                std::vector<uint256>&,
                                                std::vector<std::vector<unsigned char>>&)
{
    return false;
}
} // namespace matmul_v4::ascend
