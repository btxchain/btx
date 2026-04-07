// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/field.h>

#include <crypto/common.h>
#include <hash.h>
#include <logging.h>
#include <uint256.h>

#include <cassert>
#include <bit>
#include <cstdint>

#if defined(__ARM_NEON)
#include <arm_neon.h>
#endif

namespace matmul::field {
namespace {

static_assert(std::endian::native == std::endian::little,
              "MatMul consensus code requires little-endian host architecture");

// Double Mersenne fold reduction for q = 2^31 - 1, safe for all uint64_t inputs.
static Element reduce64(uint64_t x)
{
    const uint64_t fold1 = (x & static_cast<uint64_t>(MODULUS)) + (x >> 31);
    const uint32_t lo = static_cast<uint32_t>(fold1 & MODULUS);
    const uint32_t hi = static_cast<uint32_t>(fold1 >> 31);
    uint32_t result = lo + hi;
    const uint32_t ge_mask = static_cast<uint32_t>(-static_cast<int32_t>(result >= MODULUS));
    result -= (MODULUS & ge_mask);
    return result;
}

Element ScalarDot(const Element* a, const Element* b, uint32_t len)
{
    // At q = 2^31 - 1, worst-case 32x32->64 products can be added four times
    // without overflowing uint64_t.
    static constexpr uint32_t REDUCE_INTERVAL = 4;

    uint64_t acc = 0;
    uint32_t pending = 0;
    for (uint32_t i = 0; i < len; ++i) {
        acc += static_cast<uint64_t>(a[i]) * b[i];
        if (++pending == REDUCE_INTERVAL) {
            acc = reduce64(acc);
            pending = 0;
        }
    }
    return reduce64(acc);
}

#if defined(__ARM_NEON)
Element NeonDot(const Element* a, const Element* b, uint32_t len)
{
    uint64_t acc = 0;
    uint32_t i = 0;

    for (; i + 4 <= len; i += 4) {
        const uint32x4_t va = vld1q_u32(a + i);
        const uint32x4_t vb = vld1q_u32(b + i);

        const uint64x2_t prod_lo = vmull_u32(vget_low_u32(va), vget_low_u32(vb));
        const uint64x2_t prod_hi = vmull_u32(vget_high_u32(va), vget_high_u32(vb));

        acc += vgetq_lane_u64(prod_lo, 0);
        acc += vgetq_lane_u64(prod_lo, 1);
        acc += vgetq_lane_u64(prod_hi, 0);
        acc += vgetq_lane_u64(prod_hi, 1);
        acc = reduce64(acc);
    }

    return add(reduce64(acc), ScalarDot(a + i, b + i, len - i));
}
#endif

} // namespace

Element add(Element a, Element b)
{
    assert(a < MODULUS && b < MODULUS);
    uint32_t s = a + b;
    if (s >= MODULUS) {
        s -= MODULUS;
    }
    return s;
}

Element sub(Element a, Element b)
{
    assert(a < MODULUS && b < MODULUS);
    if (a >= b) {
        return a - b;
    }
    return a + MODULUS - b;
}

Element mul(Element a, Element b)
{
    assert(a < MODULUS && b < MODULUS);
    return reduce64(static_cast<uint64_t>(a) * b);
}

Element neg(Element a)
{
    if (a == 0) {
        return 0;
    }
    return MODULUS - a;
}

Element from_uint32(uint32_t x)
{
    return reduce64(x);
}

Element inv(Element a)
{
    assert(a != 0);
    uint32_t exp = MODULUS - 2;
    Element result = 1;
    Element base = a;

    while (exp > 0) {
        if ((exp & 1U) != 0) {
            result = mul(result, base);
        }
        exp >>= 1;
        if (exp > 0) {
            base = mul(base, base);
        }
    }

    return result;
}

Element from_oracle(const uint256& seed, uint32_t index)
{
    uint8_t seed_bytes[32];
    for (size_t i = 0; i < sizeof(seed_bytes); ++i) {
        seed_bytes[i] = seed.data()[sizeof(seed_bytes) - 1 - i];
    }

    for (uint32_t retry = 0; retry < 256; ++retry) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));

        uint8_t index_le[4];
        WriteLE32(index_le, index);
        hasher.Write(index_le, sizeof(index_le));

        if (retry > 0) {
            uint8_t retry_le[4];
            WriteLE32(retry_le, retry);
            hasher.Write(retry_le, sizeof(retry_le));
        }

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        const uint32_t candidate = ReadLE32(hash) & MODULUS;
        if (candidate < MODULUS) {
            return candidate;
        }
    }

    // This path is effectively unreachable in practice (~2^-7936), but
    // consensus requires deterministic behavior across all implementations if
    // it is ever hit.
    CSHA256 fallback_hasher;
    fallback_hasher.Write(seed_bytes, sizeof(seed_bytes));
    uint8_t index_le[4];
    WriteLE32(index_le, index);
    fallback_hasher.Write(index_le, sizeof(index_le));
    static constexpr uint8_t fallback_tag[] = "oracle-fallback";
    fallback_hasher.Write(fallback_tag, sizeof(fallback_tag) - 1);

    uint8_t fallback_hash[CSHA256::OUTPUT_SIZE];
    fallback_hasher.Finalize(fallback_hash);
    LogPrintf("MATMUL WARNING: from_oracle exhausted retries at index=%u; using deterministic fallback\n", index);
    return ReadLE32(fallback_hash) % MODULUS;
}

Element dot(const Element* a, const Element* b, uint32_t len)
{
#if defined(__ARM_NEON)
    return NeonDot(a, b, len);
#else
    return ScalarDot(a, b, len);
#endif
}

DotKernelInfo ProbeDotKernel()
{
#if defined(__ARM_NEON)
    return DotKernelInfo{
        .neon_compiled = true,
        .reason = "neon_enabled",
    };
#else
    return DotKernelInfo{
        .neon_compiled = false,
        .reason = "scalar_fallback",
    };
#endif
}

// Test-only hook declared manually by matmul_field_tests.cpp.
Element Reduce64ForTest(uint64_t x)
{
    return reduce64(x);
}

} // namespace matmul::field
