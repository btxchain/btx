// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SIPHASH_H
#define BITCOIN_CRYPTO_SIPHASH_H

#include <stdint.h>

#include <span.h>
#include <uint256.h>

#include <array>
#include <bit>

/** SipHash-2-4 */
class CSipHasher
{
private:
    uint64_t v[4];
    uint64_t tmp;
    uint8_t count; // Only the low 8 bits of the input size matter.

public:
    /** Construct a SipHash calculator initialized with 128-bit key (k0, k1) */
    CSipHasher(uint64_t k0, uint64_t k1);
    /** Hash a 64-bit integer worth of data
     *  It is treated as if this was the little-endian interpretation of 8 bytes.
     *  This function can only be used when a multiple of 8 bytes have been written so far.
     */
    CSipHasher& Write(uint64_t data);
    /** Hash arbitrary bytes. */
    CSipHasher& Write(Span<const unsigned char> data);
    /** Compute the 64-bit SipHash-2-4 of the data written so far. The object remains untouched. */
    uint64_t Finalize() const;
};

namespace siphash_13uj_detail {

inline void SipRound(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3) noexcept
{
    v0 += v1; v1 = std::rotl(v1, 13); v1 ^= v0;
    v0 = std::rotl(v0, 32);
    v2 += v3; v3 = std::rotl(v3, 16); v3 ^= v2;
    v0 += v3; v3 = std::rotl(v3, 21); v3 ^= v0;
    v2 += v1; v1 = std::rotl(v1, 17); v1 ^= v2;
    v2 = std::rotl(v2, 32);
}

inline void Process(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3,
                    const uint256& data) noexcept
{
    const uint64_t d0{data.GetUint64(0)};
    const uint64_t d1{data.GetUint64(1)};
    const uint64_t d2{data.GetUint64(2)};
    const uint64_t d3{data.GetUint64(3)};
    v3 ^= d0; v0 ^= d1; v1 ^= d2; v2 ^= d3;
    SipRound(v0, v1, v2, v3);
    v0 ^= d0; v1 ^= d1; v2 ^= d2; v3 ^= d3;
}

inline void Process(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3,
                    uint64_t data) noexcept
{
    v3 ^= data;
    SipRound(v0, v1, v2, v3);
    v0 ^= data;
}

inline uint64_t Finalize(uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3) noexcept
{
    // Domain-separate the unpadded construction from standard SipHash-1-3.
    v2 ^= 0x6465646461706E75ULL; // "unpadded" in little endian.
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    SipRound(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

} // namespace siphash_13uj_detail

/**
 * Fixed-width SipHash-1-3-UJ implementation for hash-table keys.
 *
 * A 256-bit cryptographic hash is mixed as one "jumbo" block, followed by an
 * optional 64-bit integer block. This deliberately weaker, process-salted
 * construction is only suitable where almost all retained jumbo inputs are
 * already cryptographic hashes and the result is never persisted or exposed.
 */
class SipHasher13UJ
{
private:
    const std::array<uint64_t, 4> m_state;

public:
    SipHasher13UJ(uint64_t k0, uint64_t k1) noexcept
        : m_state{0x736f6d6570736575ULL ^ k0,
                  0x646f72616e646f6dULL ^ k1,
                  0x6c7967656e657261ULL ^ k0,
                  0x7465646279746573ULL ^ k1}
    {
    }

    uint64_t Hash(const uint256& hash) const noexcept
    {
        uint64_t v0{m_state[0]}, v1{m_state[1]}, v2{m_state[2]}, v3{m_state[3]};
        siphash_13uj_detail::Process(v0, v1, v2, v3, hash);
        return siphash_13uj_detail::Finalize(v0, v1, v2, v3);
    }

    uint64_t Hash(const uint256& hash, uint64_t extra) const noexcept
    {
        uint64_t v0{m_state[0]}, v1{m_state[1]}, v2{m_state[2]}, v3{m_state[3]};
        siphash_13uj_detail::Process(v0, v1, v2, v3, hash);
        siphash_13uj_detail::Process(v0, v1, v2, v3, extra);
        return siphash_13uj_detail::Finalize(v0, v1, v2, v3);
    }
};

/** Optimized SipHash-2-4 implementation for uint256.
 *
 *  It is identical to:
 *    SipHasher(k0, k1)
 *      .Write(val.GetUint64(0))
 *      .Write(val.GetUint64(1))
 *      .Write(val.GetUint64(2))
 *      .Write(val.GetUint64(3))
 *      .Finalize()
 */
uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val);
uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra);

#endif // BITCOIN_CRYPTO_SIPHASH_H
