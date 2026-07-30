// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Multi-buffer SHA-256 for the BMX4 41-byte counter-mode XOF. Each SIMD lane
// hashes an independent padded block (seed‖domain‖counter‖pad‖bitlen). Output
// is byte-identical to four/eight sequential CSHA256 Finalize results.
// Requires AVX2 (+ OS XSAVE); gated at runtime by the caller.

#ifdef ENABLE_AVX2

#include <array>
#include <cstdint>
#include <cstring>

#include <immintrin.h>

namespace {

alignas(32) constexpr uint32_t K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

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

uint32_t LoadBE32(const unsigned char* p)
{
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}

using v8u32 = __m256i;

inline v8u32 VAdd(v8u32 a, v8u32 b) { return _mm256_add_epi32(a, b); }
inline v8u32 VXor(v8u32 a, v8u32 b) { return _mm256_xor_si256(a, b); }
inline v8u32 VAnd(v8u32 a, v8u32 b) { return _mm256_and_si256(a, b); }
inline v8u32 VOr(v8u32 a, v8u32 b) { return _mm256_or_si256(a, b); }
inline v8u32 VRotr(v8u32 x, int n)
{
    return VOr(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n));
}
inline v8u32 VBroadcast(uint32_t x) { return _mm256_set1_epi32(static_cast<int>(x)); }

inline v8u32 Ch(v8u32 x, v8u32 y, v8u32 z)
{
    return VXor(VAnd(x, y), VAnd(VXor(x, _mm256_set1_epi32(-1)), z));
}
inline v8u32 Maj(v8u32 x, v8u32 y, v8u32 z)
{
    return VOr(VAnd(x, y), VOr(VAnd(x, z), VAnd(y, z)));
}
inline v8u32 Epsi0(v8u32 x) { return VXor(VRotr(x, 2), VXor(VRotr(x, 13), VRotr(x, 22))); }
inline v8u32 Epsi1(v8u32 x) { return VXor(VRotr(x, 6), VXor(VRotr(x, 11), VRotr(x, 25))); }
inline v8u32 Sig0(v8u32 x) { return VXor(VRotr(x, 7), VXor(VRotr(x, 18), _mm256_srli_epi32(x, 3))); }
inline v8u32 Sig1(v8u32 x) { return VXor(VRotr(x, 17), VXor(VRotr(x, 19), _mm256_srli_epi32(x, 10))); }

} // namespace

namespace sha256_xof_avx2 {

void Transform8x41(unsigned char output[8][32], const unsigned char seed[32],
                   unsigned char domain, uint64_t block0)
{
    unsigned char chunk[8][64];
    for (int lane = 0; lane < 8; ++lane) {
        MakeBlock41(seed, domain, block0 + static_cast<uint64_t>(lane), chunk[lane]);
    }

    // W[t][lane]: message schedule word t for stream `lane`, transposed into v8u32.
    v8u32 W[64];
    for (int t = 0; t < 16; ++t) {
        alignas(32) uint32_t words[8];
        for (int lane = 0; lane < 8; ++lane) {
            words[lane] = LoadBE32(chunk[lane] + 4 * t);
        }
        W[t] = _mm256_load_si256(reinterpret_cast<const v8u32*>(words));
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = VAdd(VAdd(Sig1(W[t - 2]), W[t - 7]), VAdd(Sig0(W[t - 15]), W[t - 16]));
    }

    v8u32 a = VBroadcast(0x6a09e667u);
    v8u32 b = VBroadcast(0xbb67ae85u);
    v8u32 c = VBroadcast(0x3c6ef372u);
    v8u32 d = VBroadcast(0xa54ff53au);
    v8u32 e = VBroadcast(0x510e527fu);
    v8u32 f = VBroadcast(0x9b05688cu);
    v8u32 g = VBroadcast(0x1f83d9abu);
    v8u32 h = VBroadcast(0x5be0cd19u);
    const v8u32 a0 = a, b0 = b, c0 = c, d0 = d, e0 = e, f0 = f, g0 = g, h0 = h;

    for (int t = 0; t < 64; ++t) {
        const v8u32 T1 = VAdd(VAdd(VAdd(VAdd(h, Epsi1(e)), Ch(e, f, g)), VBroadcast(K[t])), W[t]);
        const v8u32 T2 = VAdd(Epsi0(a), Maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = VAdd(d, T1);
        d = c;
        c = b;
        b = a;
        a = VAdd(T1, T2);
    }

    a = VAdd(a, a0);
    b = VAdd(b, b0);
    c = VAdd(c, c0);
    d = VAdd(d, d0);
    e = VAdd(e, e0);
    f = VAdd(f, f0);
    g = VAdd(g, g0);
    h = VAdd(h, h0);

    alignas(32) uint32_t sa[8], sb[8], sc[8], sd[8], se[8], sf[8], sg[8], sh[8];
    _mm256_store_si256(reinterpret_cast<v8u32*>(sa), a);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sb), b);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sc), c);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sd), d);
    _mm256_store_si256(reinterpret_cast<v8u32*>(se), e);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sf), f);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sg), g);
    _mm256_store_si256(reinterpret_cast<v8u32*>(sh), h);

    for (int lane = 0; lane < 8; ++lane) {
        WriteBE32Local(output[lane] + 0, sa[lane]);
        WriteBE32Local(output[lane] + 4, sb[lane]);
        WriteBE32Local(output[lane] + 8, sc[lane]);
        WriteBE32Local(output[lane] + 12, sd[lane]);
        WriteBE32Local(output[lane] + 16, se[lane]);
        WriteBE32Local(output[lane] + 20, sf[lane]);
        WriteBE32Local(output[lane] + 24, sg[lane]);
        WriteBE32Local(output[lane] + 28, sh[lane]);
    }
}

} // namespace sha256_xof_avx2

#endif // ENABLE_AVX2
