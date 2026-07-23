// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds_sampled.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#if defined(__aarch64__)
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#include <arm_neon.h>
#endif

namespace matmul::v4::rc {
namespace {

bool DenseRowBlockFitsS32Local(uint32_t k)
{
    return static_cast<uint64_t>(k) * 128u * 128u <=
           static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
}

void DenseRowBlockScalarLocal(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                              uint32_t rhs_cols, uint32_t rhs_col0,
                              int64_t out[kRCMxBlockLen])
{
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = 0;
    for (uint32_t t = 0; t < k; ++t) {
        const int64_t a = static_cast<int64_t>(lhs[t]);
        const int8_t* row = rhs + static_cast<size_t>(t) * rhs_cols + rhs_col0;
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
            out[c] += a * static_cast<int64_t>(row[c]);
        }
    }
}

#if defined(__aarch64__) && defined(__ARM_NEON)
#if defined(__clang__) || defined(__GNUC__)
#define BTX_RC_TARGET_I8MM __attribute__((target("i8mm")))
#else
#define BTX_RC_TARGET_I8MM
#endif

bool HaveArmI8MMLocal()
{
#if defined(__ARM_FEATURE_MATMUL_INT8) || defined(__ARM_FEATURE_I8MM)
    return true;
#elif defined(__APPLE__)
    int val = 0;
    size_t len = sizeof(val);
    return sysctlbyname("hw.optional.arm.FEAT_I8MM", &val, &len, nullptr, 0) == 0 && val != 0;
#elif defined(__linux__) && defined(HWCAP2_I8MM)
    return (getauxval(AT_HWCAP2) & HWCAP2_I8MM) != 0;
#else
    return false;
#endif
}

BTX_RC_TARGET_I8MM void DenseRowBlockPackedI8mmS32(const int8_t* lhs,
                                                   const int8_t* rhs_packed,
                                                   uint32_t k,
                                                   uint32_t rhs_cols,
                                                   uint32_t rhs_col0,
                                                   int64_t out[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32Local(k));
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base = rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;
    const int8x8_t zero = vdup_n_s8(0);
    int32x4_t acc[kRCMxBlockLen / 2];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) acc[p] = vdupq_n_s32(0);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const int8x16_t a = vcombine_s8(vld1_s8(lhs + chunk * 8), zero);
        const int8_t* packed = block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
            acc[p] = vmmlaq_s32(acc[p], a, vld1q_s8(packed + p * 16));
        }
    }

    alignas(16) int32_t lanes[4];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
        vst1q_s32(lanes, acc[p]);
        out[2 * p] = static_cast<int64_t>(lanes[0]);
        out[2 * p + 1] = static_cast<int64_t>(lanes[1]);
    }
}

BTX_RC_TARGET_I8MM void DenseTwoRowsBlockPackedI8mmS32(const int8_t* lhs0,
                                                       const int8_t* lhs1,
                                                       const int8_t* rhs_packed,
                                                       uint32_t k,
                                                       uint32_t rhs_cols,
                                                       uint32_t rhs_col0,
                                                       int64_t out0[kRCMxBlockLen],
                                                       int64_t out1[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32Local(k));
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base = rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;
    int32x4_t acc[kRCMxBlockLen / 2];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) acc[p] = vdupq_n_s32(0);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const int8x16_t a = vcombine_s8(vld1_s8(lhs0 + chunk * 8), vld1_s8(lhs1 + chunk * 8));
        const int8_t* packed = block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
            acc[p] = vmmlaq_s32(acc[p], a, vld1q_s8(packed + p * 16));
        }
    }

    alignas(16) int32_t lanes[4];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
        vst1q_s32(lanes, acc[p]);
        out0[2 * p] = static_cast<int64_t>(lanes[0]);
        out0[2 * p + 1] = static_cast<int64_t>(lanes[1]);
        out1[2 * p] = static_cast<int64_t>(lanes[2]);
        out1[2 * p + 1] = static_cast<int64_t>(lanes[3]);
    }
}
#endif

bool PackedI8mmSelfTest()
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (!HaveArmI8MMLocal()) return false;
    constexpr uint32_t kRows = 264;
    constexpr uint32_t kCols = 96;
    constexpr uint32_t kCol0 = 32;
    std::vector<int8_t> lhs0(kRows);
    std::vector<int8_t> lhs1(kRows);
    std::vector<int8_t> rhs(static_cast<size_t>(kRows) * kCols);
    for (uint32_t i = 0; i < kRows; ++i) {
        lhs0[i] = static_cast<int8_t>((static_cast<int32_t>((i * 41u + 5u) & 0xffu)) - 128);
        lhs1[i] = static_cast<int8_t>((static_cast<int32_t>((i * 67u + 13u) & 0xffu)) - 128);
        for (uint32_t j = 0; j < kCols; ++j) {
            rhs[static_cast<size_t>(i) * kCols + j] =
                static_cast<int8_t>((static_cast<int32_t>(((i + 7u) * 109u + j * 23u) & 0xffu)) - 128);
        }
    }
    const std::vector<int8_t> packed = RCPackDenseI8mmOutputBlocks(rhs, kRows, kCols);
    int64_t scalar0[kRCMxBlockLen];
    int64_t scalar1[kRCMxBlockLen];
    int64_t one[kRCMxBlockLen];
    int64_t pair0[kRCMxBlockLen];
    int64_t pair1[kRCMxBlockLen];
    DenseRowBlockScalarLocal(lhs0.data(), rhs.data(), kRows, kCols, kCol0, scalar0);
    DenseRowBlockScalarLocal(lhs1.data(), rhs.data(), kRows, kCols, kCol0, scalar1);
    DenseRowBlockPackedI8mmS32(lhs0.data(), packed.data(), kRows, kCols, kCol0, one);
    DenseTwoRowsBlockPackedI8mmS32(lhs0.data(), lhs1.data(), packed.data(), kRows, kCols,
                                   kCol0, pair0, pair1);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        if (scalar0[c] != one[c] || scalar0[c] != pair0[c] || scalar1[c] != pair1[c]) {
            return false;
        }
    }
    return true;
#else
    return false;
#endif
}

} // namespace

bool RCDensePackedI8mmAvailable()
{
    static const bool ok = PackedI8mmSelfTest();
    return ok;
}

std::vector<int8_t> RCPackDenseI8mmOutputBlocks(const std::vector<int8_t>& rhs,
                                                uint32_t rows, uint32_t cols)
{
    assert(rows % 8 == 0);
    assert(cols % kRCMxBlockLen == 0);
    assert(rhs.size() == static_cast<size_t>(rows) * cols);
    const uint32_t chunks = rows / 8;
    const uint32_t blocks = cols / kRCMxBlockLen;
    std::vector<int8_t> packed(rhs.size());
    for (uint32_t block = 0; block < blocks; ++block) {
        for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
            int8_t* dst = packed.data() +
                ((static_cast<size_t>(block) * chunks + chunk) * (kRCMxBlockLen / 2) * 16);
            const uint32_t row0 = chunk * 8;
            const uint32_t col0 = block * kRCMxBlockLen;
            for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
                const uint32_t c0 = col0 + 2 * p;
                for (uint32_t lane = 0; lane < 8; ++lane) {
                    dst[p * 16 + lane] = rhs[static_cast<size_t>(row0 + lane) * cols + c0];
                    dst[p * 16 + 8 + lane] = rhs[static_cast<size_t>(row0 + lane) * cols + c0 + 1];
                }
            }
        }
    }
    return packed;
}

void RCDenseRowBlockPackedI8mmExactI8(const int8_t* lhs, const int8_t* rhs_packed,
                                      uint32_t k, uint32_t rhs_cols, uint32_t rhs_col0,
                                      int64_t out[kRCMxBlockLen])
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (RCDensePackedI8mmAvailable() && DenseRowBlockFitsS32Local(k) && (k % 8) == 0 &&
        (rhs_col0 % kRCMxBlockLen) == 0) {
        DenseRowBlockPackedI8mmS32(lhs, rhs_packed, k, rhs_cols, rhs_col0, out);
        return;
    }
#endif
    // This API requires packed RHS. If the packed kernel is unavailable, callers
    // must route to the transposed/scalar helper instead.
    assert(false);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = 0;
}

void RCDenseTwoRowsBlockPackedI8mmExactI8(const int8_t* lhs0, const int8_t* lhs1,
                                          const int8_t* rhs_packed, uint32_t k,
                                          uint32_t rhs_cols, uint32_t rhs_col0,
                                          int64_t out0[kRCMxBlockLen],
                                          int64_t out1[kRCMxBlockLen])
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (RCDensePackedI8mmAvailable() && DenseRowBlockFitsS32Local(k) && (k % 8) == 0 &&
        (rhs_col0 % kRCMxBlockLen) == 0) {
        DenseTwoRowsBlockPackedI8mmS32(lhs0, lhs1, rhs_packed, k, rhs_cols, rhs_col0, out0, out1);
        return;
    }
#endif
    assert(false);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out0[c] = 0;
        out1[c] = 0;
    }
}

} // namespace matmul::v4::rc
