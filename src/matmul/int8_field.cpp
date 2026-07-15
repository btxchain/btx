// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/int8_field.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
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

// Domain-separation bytes for the two counter-mode XOF keystreams, so a seed
// accidentally shared between the s8 and F_q samplers could never yield
// correlated streams. Hash input is seed(32) || domain(1) || LE64(block) =
// 41 bytes -- still a single SHA-256 compression per keystream block.
constexpr uint8_t kS8StreamDomain = 0x73; // 's'
constexpr uint8_t kFqStreamDomain = 0x71; // 'q'

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

void ExpandBalancedS8Stream(const uint256& seed, size_t count, int8_t* out)
{
    // WIDE counter-mode XOF (Appendix C-12; PR #89 review fix). One SHA-256
    // per 32-byte keystream block -- SHA256(seed_le || 's' || LE64(block)) --
    // and per-byte rejection sampling over the whole block, consuming accepted
    // bytes in stream order. Expected yield is 32 * 251/256 ~ 31.4 elements
    // per compression, i.e. ~32x fewer hashes than the retired per-element
    // oracle (which burned one full SHA-256 per element and kept one byte).
    //
    // Determinism: the accepted-byte stream is a pure function of the seed --
    // exact-integer, byte-reproducible, endianness pinned by SeedBytesLE /
    // WriteLE64 -- so every conforming backend (CPU reference, CUDA, Metal,
    // MFMA, AVX-512) reproduces identical operands bit-for-bit. Backends may
    // hash keystream blocks in parallel and compact accepted bytes with a
    // prefix sum, but the element order committed here is normative.
    //
    // No retry cap / fallback is needed: rejection simply advances the stream,
    // and the probability that any fixed prefix rejects forever is 0; the
    // stream always terminates after ~count*256/251 bytes in expectation.
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

    size_t filled = 0;
    uint64_t block = 0;
    while (filled < count) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));
        hasher.Write(&kS8StreamDomain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        for (size_t i = 0; i < CSHA256::OUTPUT_SIZE && filled < count; ++i) {
            bool accepted = false;
            const int8_t candidate = SampleBalancedS8(hash[i], accepted);
            if (accepted) {
                out[filled++] = candidate;
            }
        }
        ++block;
    }
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

void ExpandFqStream(const uint256& seed, size_t count, Fq* out)
{
    // WIDE counter-mode XOF for F_q challenge vectors, mirroring
    // ExpandBalancedS8Stream: SHA256(seed_le || 'q' || LE64(block)) yields
    // four little-endian 64-bit words per compression; each word is masked to
    // its low 61 bits and rejection-sampled (the only rejected value is
    // exactly q, the non-canonical representative of 0, probability 2^-61),
    // keeping every accepted element exactly uniform over [0, q).
    // Deterministic, exact-integer, endianness pinned -- same cross-backend
    // bit-exactness argument as the s8 stream.
    uint8_t seed_bytes[32];
    SeedBytesLE(seed, seed_bytes);

    size_t filled = 0;
    uint64_t block = 0;
    while (filled < count) {
        CSHA256 hasher;
        hasher.Write(seed_bytes, sizeof(seed_bytes));
        hasher.Write(&kFqStreamDomain, 1);
        uint8_t block_le[8];
        WriteLE64(block_le, block);
        hasher.Write(block_le, sizeof(block_le));

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        for (size_t word = 0; word < CSHA256::OUTPUT_SIZE / sizeof(uint64_t) && filled < count; ++word) {
            const uint64_t candidate = ReadLE64(hash + word * sizeof(uint64_t)) & kFieldPrime;
            if (candidate < kFieldPrime) {
                out[filled++] = candidate;
            }
        }
        ++block;
    }
}

} // namespace matmul::int8_field
