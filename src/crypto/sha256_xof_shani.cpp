// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// x86 SHA-NI (Intel SHA Extensions) hardware SHA-256 for the BMX4 41-byte
// counter-mode XOF. Each lane hashes an independent padded block
// (seed‖domain‖counter‖pad‖bitlen) on the CPU's dedicated SHA unit. Output is
// byte-identical to four sequential CSHA256 Finalize results. Motivating target:
// AMD Zen 1+ (e.g. EPYC 7573X) and Intel Ice Lake / Goldmont+, which expose a
// hardware SHA-256 unit that the AVX2 software multibuffer leaves idle.
//
// Built ON TOP OF the existing single-block sha256_x86_shani::Transform
// compression primitive (the same one CSHA256 dispatches to) rather than
// hand-rolled SHA rounds, so correctness reduces to the identical padding and
// state handling used by the scalar reference. Requires SSE4.1 + SHA-NI; gated
// at runtime by the caller (CPUID + self-test).

#if defined(ENABLE_SSE41) && defined(ENABLE_X86_SHANI)

#include <cstdint>
#include <cstring>

namespace sha256_x86_shani {
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

namespace {

void WriteLE64Local(unsigned char* p, uint64_t x)
{
    for (int i = 0; i < 8; ++i) p[i] = static_cast<unsigned char>((x >> (8 * i)) & 0xffu);
}

void WriteBE32Local(unsigned char* p, uint32_t x)
{
    p[0] = static_cast<unsigned char>(x >> 24);
    p[1] = static_cast<unsigned char>(x >> 16);
    p[2] = static_cast<unsigned char>(x >> 8);
    p[3] = static_cast<unsigned char>(x);
}

void MakeBlock41(const unsigned char seed[32], unsigned char domain, uint64_t block,
                 unsigned char chunk[64])
{
    std::memset(chunk, 0, 64);
    std::memcpy(chunk, seed, 32);
    chunk[32] = domain;
    WriteLE64Local(chunk + 33, block);
    chunk[41] = 0x80;
    WriteBE32Local(chunk + 60, 41u * 8u);
}

} // namespace

namespace sha256_xof_shani {

void Transform4x41(unsigned char output[4][32], const unsigned char seed[32],
                   unsigned char domain, uint64_t block0)
{
    // Single-lane SHA-NI over four consecutive counters. Each lane starts from
    // the SHA-256 IV and consumes exactly one padded 64-byte block, mirroring
    // the scalar CSHA256 Finalize the XofBlock41 reference performs; the SHA-NI
    // compression itself is the shared sha256_x86_shani::Transform.
    for (int lane = 0; lane < 4; ++lane) {
        unsigned char chunk[64];
        MakeBlock41(seed, domain, block0 + static_cast<uint64_t>(lane), chunk);
        uint32_t s[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };
        sha256_x86_shani::Transform(s, chunk, 1);
        for (int word = 0; word < 8; ++word) {
            WriteBE32Local(output[lane] + 4 * word, s[word]);
        }
    }
}

} // namespace sha256_xof_shani

#endif // defined(ENABLE_SSE41) && defined(ENABLE_X86_SHANI)
