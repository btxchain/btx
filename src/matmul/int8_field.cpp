// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/int8_field.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <uint256.h>

#include <bit>
#include <cstdint>

namespace matmul::int8_field {
namespace {

static_assert(std::endian::native == std::endian::little,
              "MatMul v4 consensus code requires little-endian host architecture");

// Rejection-sampling threshold for the p = 251 residue field: a uniform byte
// is accepted iff it is < 251, giving an exactly uniform residue in [0, 250]
// (§B.2/§B.3, ~2.0% rejection).
constexpr uint8_t kRejectThreshold = 251;

// Little-endian byte image of a uint256, matching matmul::field::from_oracle so
// v4 operand/challenge derivation is byte-compatible with the v3 convention.
void SeedBytesLE(const uint256& seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; ++i) {
        out[i] = seed.data()[31 - i];
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Exact-integer INT8 compute domain.
// ---------------------------------------------------------------------------

bool CheckAccumulationBound(uint32_t n)
{
    // |C_ij| <= n * 125^2 must stay strictly below 2^30 (§B.4/§0.7-(2)). This is
    // the conservative spec bound; the raw s32 accumulator would not wrap until
    // ~2^31-1, but v4 fixes 2^30 as the normative headroom guarantee.
    return static_cast<uint64_t>(n) * static_cast<uint64_t>(kElementSqBound) < (static_cast<uint64_t>(1) << 30);
}

int8_t SampleBalancedS8(uint8_t byte, bool& accepted)
{
    if (byte >= kRejectThreshold) {
        accepted = false;
        return 0;
    }
    accepted = true;
    // Residue in [0, 250] -> balanced representative in [-125, 125] (§B.4).
    return static_cast<int8_t>(static_cast<int32_t>(byte) - kBalancedBound);
}

int8_t SampleBalancedS8FromOracle(const uint256& seed, uint32_t index)
{
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

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

        bool accepted = false;
        const int8_t candidate = SampleBalancedS8(hash[0], accepted);
        if (accepted) {
            return candidate;
        }
    }

    // Effectively unreachable (rejection probability per draw ~2%, so 256
    // consecutive rejections is ~2^-1470), but consensus requires a
    // deterministic result if it is ever reached.
    CSHA256 fallback;
    fallback.Write(seed_bytes, sizeof(seed_bytes));
    uint8_t index_le[4];
    WriteLE32(index_le, index);
    fallback.Write(index_le, sizeof(index_le));
    static constexpr uint8_t fallback_tag[] = "s8-oracle-fallback";
    fallback.Write(fallback_tag, sizeof(fallback_tag) - 1);
    uint8_t hash[CSHA256::OUTPUT_SIZE];
    fallback.Finalize(hash);
    LogPrintf("MATMUL v4 WARNING: SampleBalancedS8FromOracle exhausted retries at index=%u; using deterministic fallback\n", index);
    // Map uniformly into [0,250] then to the balanced range; deterministic.
    return static_cast<int8_t>(static_cast<int32_t>(hash[0] % kRejectThreshold) - kBalancedBound);
}

int32_t ExactDot(const int8_t* a, const int8_t* b, uint32_t len)
{
    // Exact s8xs8->s32 accumulation. Integer addition is associative and
    // commutative, so the result is order-independent and bit-identical across
    // every conforming backend (§B.6). Provided the caller honored
    // CheckAccumulationBound, this int32 accumulator never overflows.
    int32_t acc = 0;
    for (uint32_t i = 0; i < len; ++i) {
        acc += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
    }
    return acc;
}

// ---------------------------------------------------------------------------
// Independent Freivalds soundness field F_q, q = 2^61 - 1.
// ---------------------------------------------------------------------------

Fq FqReduce(unsigned __int128 x)
{
    // Mersenne fold for q = 2^61 - 1. For any product of two canonical
    // elements x < q^2 < 2^122, one fold brings the value below 2^62 and a
    // second fold plus a single conditional subtract yields the canonical
    // representative in [0, q).
    const uint64_t lo = static_cast<uint64_t>(x & kFieldPrime);
    const uint64_t hi = static_cast<uint64_t>(x >> 61); // x < 2^122 => hi < 2^61
    uint64_t s = lo + hi;                                // < 2^62
    s = (s & kFieldPrime) + (s >> 61);                  // <= q + 1
    if (s >= kFieldPrime) {
        s -= kFieldPrime;
    }
    return s;
}

Fq FqAdd(Fq a, Fq b)
{
    uint64_t s = a + b; // a, b < q < 2^61 => s < 2^62, no wrap
    if (s >= kFieldPrime) {
        s -= kFieldPrime;
    }
    return s;
}

Fq FqSub(Fq a, Fq b)
{
    if (a >= b) {
        return a - b;
    }
    return a + kFieldPrime - b;
}

Fq FqMul(Fq a, Fq b)
{
    return FqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

Fq FqNeg(Fq a)
{
    if (a == 0) {
        return 0;
    }
    return kFieldPrime - a;
}

Fq FqFromSigned(int64_t x)
{
    if (x >= 0) {
        return FqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1; // safe for INT64_MIN
    return FqNeg(FqReduce(static_cast<unsigned __int128>(magnitude)));
}

Fq FqFromInt32(int32_t x)
{
    return FqFromSigned(static_cast<int64_t>(x));
}

Fq FqFromOracle(const uint256& seed, uint32_t index)
{
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

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

        // Take the low 61 bits; the only rejected value is exactly q (the mask
        // maximum), which is the non-canonical representative of 0. Rejection
        // keeps the sample exactly uniform over [0, q).
        const uint64_t candidate = ReadLE64(hash) & kFieldPrime;
        if (candidate < kFieldPrime) {
            return candidate;
        }
    }

    CSHA256 fallback;
    fallback.Write(seed_bytes, sizeof(seed_bytes));
    uint8_t index_le[4];
    WriteLE32(index_le, index);
    fallback.Write(index_le, sizeof(index_le));
    static constexpr uint8_t fallback_tag[] = "fq-oracle-fallback";
    fallback.Write(fallback_tag, sizeof(fallback_tag) - 1);
    uint8_t hash[CSHA256::OUTPUT_SIZE];
    fallback.Finalize(hash);
    LogPrintf("MATMUL v4 WARNING: FqFromOracle exhausted retries at index=%u; using deterministic fallback\n", index);
    return FqReduce(static_cast<unsigned __int128>(ReadLE64(hash)));
}

} // namespace matmul::int8_field
