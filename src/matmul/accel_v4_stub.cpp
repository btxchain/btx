// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Weak CPU-only stubs for the MatMul v4 device backend entry points declared in
// matmul/accel_v4.h. Compiled into btx_matmul_backend UNCONDITIONALLY so the
// dispatch layer (matmul/accel_v4.cpp) always links, even with no GPU backend
// present. Each stub is:
//
//   * #if-guarded by the backend's CMake define -- when a backend is compiled in
//     (BTX_ENABLE_CUDA_EXPERIMENTAL / BTX_ENABLE_METAL /
//     BTX_ENABLE_HIP_EXPERIMENTAL, all PRIVATE to btx_matmul_backend, mirroring
//     v3's *_stub.cpp gating), the corresponding real strong definition in the
//     device translation unit is the sole definition and this stub drops out;
//
//   * marked WEAK regardless, so that even if a real backend definition is
//     linked without its guard macro matching (e.g. a differently-named define),
//     the strong device definition still overrides this stub instead of causing
//     a duplicate-symbol error.
//
// A stub simply returns false; the dispatcher then falls back to the byte-exact
// CPU reference (matmul_v4::ComputeDigest). NO floating point, NO market/price
// content -- pure consensus-mining plumbing.

#include <matmul/accel_v4.h>

#include <cstdint>
#include <vector>

class CBlockHeader;

#if defined(_MSC_VER)
#define BTX_ACCEL_V4_WEAK
#else
#define BTX_ACCEL_V4_WEAK [[gnu::weak]]
#endif

#if !defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
namespace matmul_v4::cuda {
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
} // namespace matmul_v4::cuda
#endif

#if !defined(BTX_ENABLE_METAL)
namespace matmul_v4::metal {
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
} // namespace matmul_v4::metal
#endif

#if !defined(BTX_ENABLE_HIP_EXPERIMENTAL)
namespace matmul_v4::hip {
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
} // namespace matmul_v4::hip
#endif
