// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds_sampled.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
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

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#include <compat/cpuid.h>
#include <immintrin.h>
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

void DenseRowBlockPackedScalarLocal(const int8_t* lhs, const int8_t* rhs_packed, uint32_t k,
                                    uint32_t rhs_cols, uint32_t rhs_col0,
                                    int64_t out[kRCMxBlockLen])
{
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = 0;
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    assert((rhs_cols % kRCMxBlockLen) == 0);
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base =
        rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;
    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const int8_t* packed =
            block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t lane = 0; lane < 8; ++lane) {
            const uint32_t t = chunk * 8 + lane;
            const int64_t a = static_cast<int64_t>(lhs[t]);
            for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
                out[2 * p] += a * static_cast<int64_t>(packed[p * 16 + lane]);
                out[2 * p + 1] += a * static_cast<int64_t>(packed[p * 16 + 8 + lane]);
            }
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

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#if defined(__clang__) || defined(__GNUC__)
#define BTX_RC_TARGET_AVX512VNNI \
    __attribute__((target("avx512f,avx512bw,avx512vl,avx512vnni")))
#else
#define BTX_RC_TARGET_AVX512VNNI
#endif

bool Avx512StateEnabledLocal()
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    if (((ecx >> 27) & 1u) == 0) return false; // OSXSAVE
    uint32_t a = 0, d = 0;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    // XMM (bit1) | YMM (bit2) | Opmask/ZMM_hi (bits 5..7)
    return (a & 0xe6u) == 0xe6u;
}

bool HaveAvx512VnniLocal()
{
    if (!Avx512StateEnabledLocal()) return false;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(7, 0, eax, ebx, ecx, edx);
    const bool avx512f = ((ebx >> 16) & 1u) != 0;
    const bool avx512vnni = ((ecx >> 11) & 1u) != 0;
    return avx512f && avx512vnni;
}

// VPDPBUSD is unsigned×signed. Map lhs via xor-0x80 so
//   sum((a+128)*b) = sum(a*b) + 128*sum(b)
// and correct with a second dpbusd against byte-ones for sum(b).
// Int32 accumulation is exact for RC dims (k*127*127 < 2^31).
BTX_RC_TARGET_AVX512VNNI void DenseRowBlockPackedVnniS32(const int8_t* lhs,
                                                         const int8_t* rhs_packed,
                                                         uint32_t k,
                                                         uint32_t rhs_cols,
                                                         uint32_t rhs_col0,
                                                         int64_t out[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32Local(k));
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    (void)rhs_cols;
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base =
        rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;

    alignas(64) int32_t acc[kRCMxBlockLen];
    std::memset(acc, 0, sizeof(acc));

    const __m128i xor80 = _mm_set1_epi8(static_cast<char>(0x80));
    const __m512i ones = _mm512_set1_epi8(1);
    const __m512i v128 = _mm512_set1_epi32(128);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const __m128i a_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs + chunk * 8));
        const __m128i a_u = _mm_xor_si128(a_s, xor80);
        const __m128i a_pair = _mm_unpacklo_epi64(a_u, a_u); // [a0..a7 | a0..a7]
        const __m512i a_pat = _mm512_broadcast_i32x4(a_pair);

        const int8_t* packed =
            block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        // 16 column-pairs × 16B = 256B = four ZMM loads.
        for (uint32_t g = 0; g < 4; ++g) {
            const __m512i b = _mm512_loadu_si512(packed + static_cast<size_t>(g) * 64);
            const __m512i dot_u = _mm512_dpbusd_epi32(_mm512_setzero_si512(), a_pat, b);
            const __m512i sum_b = _mm512_dpbusd_epi32(_mm512_setzero_si512(), ones, b);
            const __m512i signed_dot =
                _mm512_sub_epi32(dot_u, _mm512_mullo_epi32(sum_b, v128));
            alignas(64) int32_t du[16];
            _mm512_store_si512(du, signed_dot);
            for (uint32_t p = 0; p < 4; ++p) {
                const uint32_t pair = g * 4 + p;
                const int32_t* d = du + p * 4;
                acc[2 * pair] += d[0] + d[1];
                acc[2 * pair + 1] += d[2] + d[3];
            }
        }
    }
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = static_cast<int64_t>(acc[c]);
}

BTX_RC_TARGET_AVX512VNNI void DenseTwoRowsBlockPackedVnniS32(const int8_t* lhs0,
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
    (void)rhs_cols;
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base =
        rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;

    alignas(64) int32_t acc0[kRCMxBlockLen];
    alignas(64) int32_t acc1[kRCMxBlockLen];
    std::memset(acc0, 0, sizeof(acc0));
    std::memset(acc1, 0, sizeof(acc1));

    const __m128i xor80 = _mm_set1_epi8(static_cast<char>(0x80));
    const __m512i ones = _mm512_set1_epi8(1);
    const __m512i v128 = _mm512_set1_epi32(128);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const __m128i a0_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs0 + chunk * 8));
        const __m128i a1_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs1 + chunk * 8));
        const __m128i a0_pair = _mm_unpacklo_epi64(_mm_xor_si128(a0_s, xor80),
                                                   _mm_xor_si128(a0_s, xor80));
        const __m128i a1_pair = _mm_unpacklo_epi64(_mm_xor_si128(a1_s, xor80),
                                                   _mm_xor_si128(a1_s, xor80));
        const __m512i a0_pat = _mm512_broadcast_i32x4(a0_pair);
        const __m512i a1_pat = _mm512_broadcast_i32x4(a1_pair);

        const int8_t* packed =
            block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t g = 0; g < 4; ++g) {
            const __m512i b = _mm512_loadu_si512(packed + static_cast<size_t>(g) * 64);
            const __m512i sum_b = _mm512_dpbusd_epi32(_mm512_setzero_si512(), ones, b);
            const __m512i corr = _mm512_mullo_epi32(sum_b, v128);
            const __m512i d0 =
                _mm512_sub_epi32(_mm512_dpbusd_epi32(_mm512_setzero_si512(), a0_pat, b), corr);
            const __m512i d1 =
                _mm512_sub_epi32(_mm512_dpbusd_epi32(_mm512_setzero_si512(), a1_pat, b), corr);
            alignas(64) int32_t du0[16], du1[16];
            _mm512_store_si512(du0, d0);
            _mm512_store_si512(du1, d1);
            for (uint32_t p = 0; p < 4; ++p) {
                const uint32_t pair = g * 4 + p;
                const int32_t* e0 = du0 + p * 4;
                const int32_t* e1 = du1 + p * 4;
                acc0[2 * pair] += e0[0] + e0[1];
                acc0[2 * pair + 1] += e0[2] + e0[3];
                acc1[2 * pair] += e1[0] + e1[1];
                acc1[2 * pair + 1] += e1[2] + e1[3];
            }
        }
    }
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out0[c] = static_cast<int64_t>(acc0[c]);
        out1[c] = static_cast<int64_t>(acc1[c]);
    }
}

#if defined(__clang__) || defined(__GNUC__)
#define BTX_RC_TARGET_AVX2 __attribute__((target("avx2")))
#else
#define BTX_RC_TARGET_AVX2
#endif

bool AvxStateEnabledLocal()
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    if (((ecx >> 27) & 1u) == 0) return false; // OSXSAVE
    uint32_t a = 0, d = 0;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    // XMM (bit1) | YMM (bit2) enabled by the OS.
    return (a & 0x6u) == 0x6u;
}

bool HaveAvx2Local()
{
    if (!AvxStateEnabledLocal()) return false;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(7, 0, eax, ebx, ecx, edx);
    const bool avx2 = ((ebx >> 5) & 1u) != 0;
    return avx2;
}

// Pre-VNNI AVX2 path for CPUs without VPDPBUSD (AMD Zen 2/3, Intel
// Haswell–Skylake). VPMADDUBSW is unsigned×signed like VPDPBUSD, so we reuse
// the SAME xor-0x80 lhs mapping and the SAME +128*sum(rhs) correction as the
// VNNI kernel:
//   sum((a+128)*b) = sum(a*b) + 128*sum(b)  ->  sum(a*b) = sum((a+128)*b) - 128*sum(b).
// VPMADDUBSW forms i16 = u8*s8 + u8*s8 with SIGNED saturation of the pair sum.
// A single u8*s8 fits i16 (255*128 = 32640 < 32768) but the pair sum can reach
// 2*255*128 = 65280 and saturate. To stay bit-exact we split the unsigned lhs
// byte a_u = 16*a_hi + a_lo (a_hi,a_lo in [0,15]) so every VPMADDUBSW pair sum
// is at most 2*15*128 = 3840 << 32768 and cannot saturate, then recombine
// u = 16*hi + lo at int32. sum(b) is formed the same way via VPMADDUBSW against
// unsigned ones (pair sum <= 256). Int32 accumulation is exact for RC dims
// (k*128*128 <= 2^31, guaranteed by DenseRowBlockFitsS32Local).
BTX_RC_TARGET_AVX2 void DenseRowBlockPackedAvx2S32(const int8_t* lhs,
                                                   const int8_t* rhs_packed,
                                                   uint32_t k,
                                                   uint32_t rhs_cols,
                                                   uint32_t rhs_col0,
                                                   int64_t out[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32Local(k));
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    (void)rhs_cols;
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base =
        rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;

    alignas(32) int32_t acc[kRCMxBlockLen];
    std::memset(acc, 0, sizeof(acc));

    const __m128i xor80 = _mm_set1_epi8(static_cast<char>(0x80));
    const __m128i lo_mask = _mm_set1_epi8(0x0F);
    const __m256i ones8 = _mm256_set1_epi8(1);
    const __m256i ones16 = _mm256_set1_epi16(1);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const __m128i a_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs + chunk * 8));
        const __m128i a_u = _mm_xor_si128(a_s, xor80); // a + 128 in [0,255]
        const __m128i a_lo8 = _mm_and_si128(a_u, lo_mask);
        const __m128i a_hi8 = _mm_and_si128(_mm_srli_epi16(a_u, 4), lo_mask);
        const __m128i lo_pair = _mm_unpacklo_epi64(a_lo8, a_lo8); // [lo0..lo7 | lo0..lo7]
        const __m128i hi_pair = _mm_unpacklo_epi64(a_hi8, a_hi8);
        const __m256i lo_pat = _mm256_broadcastsi128_si256(lo_pair);
        const __m256i hi_pat = _mm256_broadcastsi128_si256(hi_pair);

        const int8_t* packed =
            block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        // 16 column-pairs × 16B = 256B = eight YMM loads (two column-pairs each).
        for (uint32_t g = 0; g < 8; ++g) {
            const __m256i b =
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(packed + static_cast<size_t>(g) * 32));
            // Group-of-4-rows partial dots for the low/high nibble and for sum(b).
            const __m256i lo_r = _mm256_madd_epi16(_mm256_maddubs_epi16(lo_pat, b), ones16);
            const __m256i hi_r = _mm256_madd_epi16(_mm256_maddubs_epi16(hi_pat, b), ones16);
            const __m256i sb_r = _mm256_madd_epi16(_mm256_maddubs_epi16(ones8, b), ones16);
            // u = 16*hi + lo ; signed = u - 128*sum(b), all exact at int32.
            const __m256i u_r = _mm256_add_epi32(_mm256_slli_epi32(hi_r, 4), lo_r);
            const __m256i signed_r = _mm256_sub_epi32(u_r, _mm256_slli_epi32(sb_r, 7));
            alignas(32) int32_t du[8];
            _mm256_store_si256(reinterpret_cast<__m256i*>(du), signed_r);
            for (uint32_t p = 0; p < 2; ++p) {
                const uint32_t pair = g * 2 + p;
                const int32_t* d = du + p * 4;
                acc[2 * pair] += d[0] + d[1];
                acc[2 * pair + 1] += d[2] + d[3];
            }
        }
    }
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = static_cast<int64_t>(acc[c]);
}

BTX_RC_TARGET_AVX2 void DenseTwoRowsBlockPackedAvx2S32(const int8_t* lhs0,
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
    (void)rhs_cols;
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base =
        rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;

    alignas(32) int32_t acc0[kRCMxBlockLen];
    alignas(32) int32_t acc1[kRCMxBlockLen];
    std::memset(acc0, 0, sizeof(acc0));
    std::memset(acc1, 0, sizeof(acc1));

    const __m128i xor80 = _mm_set1_epi8(static_cast<char>(0x80));
    const __m128i lo_mask = _mm_set1_epi8(0x0F);
    const __m256i ones8 = _mm256_set1_epi8(1);
    const __m256i ones16 = _mm256_set1_epi16(1);

    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const __m128i a0_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs0 + chunk * 8));
        const __m128i a1_s = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(lhs1 + chunk * 8));
        const __m128i a0_u = _mm_xor_si128(a0_s, xor80);
        const __m128i a1_u = _mm_xor_si128(a1_s, xor80);
        const __m128i a0_lo8 = _mm_and_si128(a0_u, lo_mask);
        const __m128i a0_hi8 = _mm_and_si128(_mm_srli_epi16(a0_u, 4), lo_mask);
        const __m128i a1_lo8 = _mm_and_si128(a1_u, lo_mask);
        const __m128i a1_hi8 = _mm_and_si128(_mm_srli_epi16(a1_u, 4), lo_mask);
        const __m256i lo0_pat = _mm256_broadcastsi128_si256(_mm_unpacklo_epi64(a0_lo8, a0_lo8));
        const __m256i hi0_pat = _mm256_broadcastsi128_si256(_mm_unpacklo_epi64(a0_hi8, a0_hi8));
        const __m256i lo1_pat = _mm256_broadcastsi128_si256(_mm_unpacklo_epi64(a1_lo8, a1_lo8));
        const __m256i hi1_pat = _mm256_broadcastsi128_si256(_mm_unpacklo_epi64(a1_hi8, a1_hi8));

        const int8_t* packed =
            block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t g = 0; g < 8; ++g) {
            const __m256i b =
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(packed + static_cast<size_t>(g) * 32));
            const __m256i corr = _mm256_slli_epi32(
                _mm256_madd_epi16(_mm256_maddubs_epi16(ones8, b), ones16), 7); // 128*sum(b)
            const __m256i lo0_r = _mm256_madd_epi16(_mm256_maddubs_epi16(lo0_pat, b), ones16);
            const __m256i hi0_r = _mm256_madd_epi16(_mm256_maddubs_epi16(hi0_pat, b), ones16);
            const __m256i lo1_r = _mm256_madd_epi16(_mm256_maddubs_epi16(lo1_pat, b), ones16);
            const __m256i hi1_r = _mm256_madd_epi16(_mm256_maddubs_epi16(hi1_pat, b), ones16);
            const __m256i d0 = _mm256_sub_epi32(
                _mm256_add_epi32(_mm256_slli_epi32(hi0_r, 4), lo0_r), corr);
            const __m256i d1 = _mm256_sub_epi32(
                _mm256_add_epi32(_mm256_slli_epi32(hi1_r, 4), lo1_r), corr);
            alignas(32) int32_t du0[8], du1[8];
            _mm256_store_si256(reinterpret_cast<__m256i*>(du0), d0);
            _mm256_store_si256(reinterpret_cast<__m256i*>(du1), d1);
            for (uint32_t p = 0; p < 2; ++p) {
                const uint32_t pair = g * 2 + p;
                const int32_t* e0 = du0 + p * 4;
                const int32_t* e1 = du1 + p * 4;
                acc0[2 * pair] += e0[0] + e0[1];
                acc0[2 * pair + 1] += e0[2] + e0[3];
                acc1[2 * pair] += e1[0] + e1[1];
                acc1[2 * pair + 1] += e1[2] + e1[3];
            }
        }
    }
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out0[c] = static_cast<int64_t>(acc0[c]);
        out1[c] = static_cast<int64_t>(acc1[c]);
    }
}

// Cached tier choice: prefer VNNI when present, else fall to AVX2. Read once so
// there is no per-block CPUID in the dispatchers.
bool PackedX86PreferVnni()
{
    static const bool v = HaveAvx512VnniLocal();
    return v;
}
#endif

bool PackedFastPathSelfTest()
{
    // Multi-vector randomized self-test (several shapes/seeds). A single-vector
    // check is insufficient as a fork-risk gate for consensus-critical kernels.
    struct Case {
        uint32_t rows;
        uint32_t cols;
        uint32_t col0;
        uint32_t mix;
    };
    const Case cases[] = {
        {64, 64, 0, 1u},
        {128, 96, 32, 2u},
        {264, 96, 32, 3u},
        {256, 160, 64, 4u},
        {512, 128, 96, 5u},
        {1024, 64, 0, 6u},
        {4096, 64, 32, 7u},
    };

#if defined(__aarch64__) && defined(__ARM_NEON)
    if (!HaveArmI8MMLocal()) return false;
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    const bool have_vnni = HaveAvx512VnniLocal();
    const bool have_avx2 = HaveAvx2Local();
    // No usable x86 fast kernel -> stay on the scalar-over-packed path.
    if (!have_vnni && !have_avx2) return false;
#else
    return false;
#endif

    for (const Case& cs : cases) {
        std::vector<int8_t> lhs0(cs.rows);
        std::vector<int8_t> lhs1(cs.rows);
        std::vector<int8_t> rhs(static_cast<size_t>(cs.rows) * cs.cols);
        for (uint32_t i = 0; i < cs.rows; ++i) {
            lhs0[i] = static_cast<int8_t>(
                (static_cast<int32_t>((i * 41u + 5u + cs.mix * 17u) & 0xffu)) - 128);
            lhs1[i] = static_cast<int8_t>(
                (static_cast<int32_t>((i * 67u + 13u + cs.mix * 29u) & 0xffu)) - 128);
            for (uint32_t j = 0; j < cs.cols; ++j) {
                rhs[static_cast<size_t>(i) * cs.cols + j] = static_cast<int8_t>(
                    (static_cast<int32_t>(((i + 7u + cs.mix) * 109u + j * 23u) & 0xffu)) - 128);
            }
        }
        const std::vector<int8_t> packed = RCPackDenseI8mmOutputBlocks(rhs, cs.rows, cs.cols);
        int64_t scalar0[kRCMxBlockLen];
        int64_t scalar1[kRCMxBlockLen];
#if (defined(__aarch64__) && defined(__ARM_NEON)) || defined(__x86_64__) || \
    defined(__amd64__) || defined(_M_X64)
        int64_t one[kRCMxBlockLen];
        int64_t pair0[kRCMxBlockLen];
        int64_t pair1[kRCMxBlockLen];
#endif
        DenseRowBlockScalarLocal(lhs0.data(), rhs.data(), cs.rows, cs.cols, cs.col0, scalar0);
        DenseRowBlockScalarLocal(lhs1.data(), rhs.data(), cs.rows, cs.cols, cs.col0, scalar1);
#if defined(__aarch64__) && defined(__ARM_NEON)
        DenseRowBlockPackedI8mmS32(lhs0.data(), packed.data(), cs.rows, cs.cols, cs.col0, one);
        DenseTwoRowsBlockPackedI8mmS32(lhs0.data(), lhs1.data(), packed.data(), cs.rows, cs.cols,
                                       cs.col0, pair0, pair1);
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
            if (scalar0[c] != one[c] || scalar0[c] != pair0[c] || scalar1[c] != pair1[c]) {
                return false;
            }
        }
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
        // Every tier the dispatcher may pick must be byte-identical to scalar.
        if (have_vnni) {
            DenseRowBlockPackedVnniS32(lhs0.data(), packed.data(), cs.rows, cs.cols, cs.col0, one);
            DenseTwoRowsBlockPackedVnniS32(lhs0.data(), lhs1.data(), packed.data(), cs.rows,
                                           cs.cols, cs.col0, pair0, pair1);
            for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
                if (scalar0[c] != one[c] || scalar0[c] != pair0[c] || scalar1[c] != pair1[c]) {
                    return false;
                }
            }
        }
        if (have_avx2) {
            DenseRowBlockPackedAvx2S32(lhs0.data(), packed.data(), cs.rows, cs.cols, cs.col0, one);
            DenseTwoRowsBlockPackedAvx2S32(lhs0.data(), lhs1.data(), packed.data(), cs.rows,
                                           cs.cols, cs.col0, pair0, pair1);
            for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
                if (scalar0[c] != one[c] || scalar0[c] != pair0[c] || scalar1[c] != pair1[c]) {
                    return false;
                }
            }
        }
#endif
        // Packed scalar oracle must also match (layout / fallback contract).
        int64_t packed_scalar[kRCMxBlockLen];
        DenseRowBlockPackedScalarLocal(lhs0.data(), packed.data(), cs.rows, cs.cols, cs.col0,
                                       packed_scalar);
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
            if (packed_scalar[c] != scalar0[c]) return false;
        }
    }
    return true;
}

} // namespace

bool RCDensePackedI8mmAvailable()
{
    // Single selection point for the packed int8 recompute fast path (ARM SMMLA /
    // x86 AVX-512-VNNI). Every caller — the production carrier verifier
    // (matmul_v4_rc_freivalds_sampled.cpp) and the compute bench — routes through
    // here, so BTX_RC_PACKED_I8MM=0 is a process-wide operator kill switch that
    // forces the non-packed scalar/transposed recompute everywhere. This is
    // consensus-safe: the packed and scalar paths are byte-identical (enforced by
    // PackedFastPathSelfTest below and by the cross-hardware digest match), so the
    // verdict is unchanged whether the switch is on or off — only throughput
    // differs. Use it as an escape hatch if a VNNI/SMMLA defect is ever found, or
    // to A/B the two recompute paths (run the suite once with the var unset and
    // once with BTX_RC_PACKED_I8MM=0; digests must match). Read once and cached so
    // there is no per-block getenv and no mid-process flip.
    static const bool ok = [] {
        if (const char* env = std::getenv("BTX_RC_PACKED_I8MM")) {
            if (env[0] == '0' && env[1] == '\0') return false;
        }
        return PackedFastPathSelfTest();
    }();
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
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    if (RCDensePackedI8mmAvailable() && DenseRowBlockFitsS32Local(k) && (k % 8) == 0 &&
        (rhs_col0 % kRCMxBlockLen) == 0) {
        // Tier: VNNI if present, else pre-VNNI AVX2. RCDensePackedI8mmAvailable()
        // being true means the selected tier passed PackedFastPathSelfTest.
        if (PackedX86PreferVnni()) {
            DenseRowBlockPackedVnniS32(lhs, rhs_packed, k, rhs_cols, rhs_col0, out);
        } else {
            DenseRowBlockPackedAvx2S32(lhs, rhs_packed, k, rhs_cols, rhs_col0, out);
        }
        return;
    }
#endif
    DenseRowBlockPackedScalarLocal(lhs, rhs_packed, k, rhs_cols, rhs_col0, out);
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
#elif defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    if (RCDensePackedI8mmAvailable() && DenseRowBlockFitsS32Local(k) && (k % 8) == 0 &&
        (rhs_col0 % kRCMxBlockLen) == 0) {
        // Tier: VNNI if present, else pre-VNNI AVX2. RCDensePackedI8mmAvailable()
        // being true means the selected tier passed PackedFastPathSelfTest.
        if (PackedX86PreferVnni()) {
            DenseTwoRowsBlockPackedVnniS32(lhs0, lhs1, rhs_packed, k, rhs_cols, rhs_col0, out0,
                                           out1);
        } else {
            DenseTwoRowsBlockPackedAvx2S32(lhs0, lhs1, rhs_packed, k, rhs_cols, rhs_col0, out0,
                                           out1);
        }
        return;
    }
#endif
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out0[c] = 0;
        out1[c] = 0;
    }
    assert((k % 8) == 0);
    assert((rhs_col0 % kRCMxBlockLen) == 0);
    assert((rhs_cols % kRCMxBlockLen) == 0);
    const uint32_t chunks = k / 8;
    const uint32_t block = rhs_col0 / kRCMxBlockLen;
    const int8_t* block_base = rhs_packed + static_cast<size_t>(block) * chunks * (kRCMxBlockLen / 2) * 16;
    for (uint32_t chunk = 0; chunk < chunks; ++chunk) {
        const int8_t* packed = block_base + static_cast<size_t>(chunk) * (kRCMxBlockLen / 2) * 16;
        for (uint32_t lane = 0; lane < 8; ++lane) {
            const uint32_t t = chunk * 8 + lane;
            const int64_t a0 = static_cast<int64_t>(lhs0[t]);
            const int64_t a1 = static_cast<int64_t>(lhs1[t]);
            for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
                const int64_t b0 = static_cast<int64_t>(packed[p * 16 + lane]);
                const int64_t b1 = static_cast<int64_t>(packed[p * 16 + 8 + lane]);
                out0[2 * p] += a0 * b0;
                out0[2 * p + 1] += a0 * b1;
                out1[2 * p] += a1 * b0;
                out1[2 * p + 1] += a1 * b1;
            }
        }
    }
}

} // namespace matmul::v4::rc
