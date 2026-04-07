// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CT_UTILS_H
#define BITCOIN_CRYPTO_CT_UTILS_H

#include <cstddef>
#include <cstdint>

inline int ct_memcmp(const unsigned char* a, const unsigned char* b, size_t len)
{
    // Use volatile reads to prevent the compiler from turning this into a
    // data-dependent early-exit compare in optimized builds.
    const volatile unsigned char* va = a;
    const volatile unsigned char* vb = b;
    unsigned char diff{0};
    for (size_t i = 0; i < len; ++i) {
        diff |= va[i] ^ vb[i];
    }
    return diff;
}

template <typename T>
inline T ct_select(uint8_t condition, T a, T b)
{
    const auto mask = static_cast<T>(-static_cast<T>(condition != 0));
    return (a & mask) | (b & ~mask);
}

inline uint8_t ct_is_zero(uint8_t value)
{
    uint8_t x = value;
    x |= static_cast<uint8_t>(x >> 4);
    x |= static_cast<uint8_t>(x >> 2);
    x |= static_cast<uint8_t>(x >> 1);
    return static_cast<uint8_t>((x ^ 0x01) & 0x01);
}

inline void secure_memzero(void* ptr, size_t len)
{
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

#endif // BITCOIN_CRYPTO_CT_UTILS_H
