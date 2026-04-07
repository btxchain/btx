// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// This file contains helper functions to handle big-endian architectures.
/// The Ethash algorithm is naturally defined for little-endian architectures
/// so for those the helpers are just no-op empty functions.
/// For big-endian architectures we need 32-bit and 64-bit byte swapping in
/// some places.

#pragma once

#include <crypto/ethash/include/ethash/ethash.hpp>

#if defined(_WIN32)

#include <stdlib.h>

#define bswap32 _byteswap_ulong
#define bswap64 _byteswap_uint64

// On Windows assume little endian.
#define ETHASH_LITTLE_ENDIAN 1234
#define ETHASH_BIG_ENDIAN 4321
#define ETHASH_BYTE_ORDER ETHASH_LITTLE_ENDIAN

#elif defined(__APPLE__)

#include <machine/endian.h>

#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

#if defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN)
#define ETHASH_BYTE_ORDER BYTE_ORDER
#define ETHASH_LITTLE_ENDIAN LITTLE_ENDIAN
#define ETHASH_BIG_ENDIAN BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
#define ETHASH_BYTE_ORDER __BYTE_ORDER__
#define ETHASH_LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define ETHASH_BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#else

#include <endian.h>

#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
#define ETHASH_BYTE_ORDER __BYTE_ORDER
#define ETHASH_LITTLE_ENDIAN __LITTLE_ENDIAN
#define ETHASH_BIG_ENDIAN __BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
#define ETHASH_BYTE_ORDER __BYTE_ORDER__
#define ETHASH_LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define ETHASH_BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#endif

namespace ethash
{
#if !defined(ETHASH_BYTE_ORDER) || !defined(ETHASH_LITTLE_ENDIAN) || !defined(ETHASH_BIG_ENDIAN)
#error "Unable to determine platform byte order."
#endif

#if ETHASH_BYTE_ORDER == ETHASH_LITTLE_ENDIAN

struct le
{
    static uint32_t uint32(uint32_t x) noexcept { return x; }
    static uint64_t uint64(uint64_t x) noexcept { return x; }

    static const hash1024& uint32s(const hash1024& h) noexcept { return h; }
    static const hash512& uint32s(const hash512& h) noexcept { return h; }
    static const hash256& uint32s(const hash256& h) noexcept { return h; }
};

struct be
{
    static uint64_t uint64(uint64_t x) noexcept { return bswap64(x); }
};


#elif ETHASH_BYTE_ORDER == ETHASH_BIG_ENDIAN

struct le
{
    static uint32_t uint32(uint32_t x) noexcept { return bswap32(x); }
    static uint64_t uint64(uint64_t x) noexcept { return bswap64(x); }

    static hash1024 uint32s(hash1024 h) noexcept
    {
        for (auto& w : h.word32s)
            w = uint32(w);
        return h;
    }

    static hash512 uint32s(hash512 h) noexcept
    {
        for (auto& w : h.word32s)
            w = uint32(w);
        return h;
    }

    static hash256 uint32s(hash256 h) noexcept
    {
        for (auto& w : h.word32s)
            w = uint32(w);
        return h;
    }
};

struct be
{
    static uint64_t uint64(uint64_t x) noexcept { return x; }
};

#endif
}  // namespace ethash
