// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_CPUID_H
#define BITCOIN_COMPAT_CPUID_H

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#define HAVE_GETCPUID

#include <immintrin.h>
#include <intrin.h>

#include <cstdint>

// MSVC has no GCC extended asm. The leaves and the XCR0 bits are the same
// ones the GCC path reads below.
void static inline GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    a = static_cast<uint32_t>(regs[0]);
    b = static_cast<uint32_t>(regs[1]);
    c = static_cast<uint32_t>(regs[2]);
    d = static_cast<uint32_t>(regs[3]);
}

void static inline GetXGETBV(uint32_t& a, uint32_t& d)
{
    const unsigned __int64 value = _xgetbv(0);
    a = static_cast<uint32_t>(value);
    d = static_cast<uint32_t>(value >> 32);
}

#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#define HAVE_GETCPUID

#include <cpuid.h>

#include <cstdint>

// We can't use cpuid.h's __get_cpuid as it does not support subleafs.
void static inline GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
#ifdef __GNUC__
    __cpuid_count(leaf, subleaf, a, b, c, d);
#else
  __asm__ ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(leaf), "2"(subleaf));
#endif
}

void static inline GetXGETBV(uint32_t& a, uint32_t& d)
{
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
}

#endif // x86 / MSVC x86
#endif // BITCOIN_COMPAT_CPUID_H
