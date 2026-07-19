// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_DEVICE_MX_H
#define BITCOIN_CUDA_MATMUL_V4_LT_DEVICE_MX_H

#include <cstdint>

// Small CUDA/HIP common helpers used by the LT resident miners.  Keep these
// device-only: the host oracle remains DeriveMatExpandMxScale() in
// matmul_v4_lt.cpp and the accelerator self-qualification compares the complete
// resulting digest against that oracle before enabling the resident path.
namespace matmul_v4::lt_device {

__device__ __forceinline__ uint32_t ShaRor32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

__device__ __forceinline__ uint32_t ShaCh(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

__device__ __forceinline__ uint32_t ShaMaj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t ShaBig0(uint32_t x)
{
    return ShaRor32(x, 2U) ^ ShaRor32(x, 13U) ^ ShaRor32(x, 22U);
}

__device__ __forceinline__ uint32_t ShaBig1(uint32_t x)
{
    return ShaRor32(x, 6U) ^ ShaRor32(x, 11U) ^ ShaRor32(x, 25U);
}

__device__ __forceinline__ uint32_t ShaSmall0(uint32_t x)
{
    return ShaRor32(x, 7U) ^ ShaRor32(x, 18U) ^ (x >> 3U);
}

__device__ __forceinline__ uint32_t ShaSmall1(uint32_t x)
{
    return ShaRor32(x, 17U) ^ ShaRor32(x, 19U) ^ (x >> 10U);
}

// Internal linkage is intentional: this header is compiled once by the CUDA TU
// and once by the HIP TU, without exporting or colliding with their other SHA
// device constants.
static __device__ __constant__ uint32_t kSha256Round[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

__device__ __forceinline__ void ShaSetByte(uint32_t words[16], uint32_t offset,
                                           uint32_t byte)
{
    const uint32_t word = offset >> 2U;
    const uint32_t shift = (3U - (offset & 3U)) * 8U;
    words[word] |= (byte & 0xffU) << shift;
}

__device__ __forceinline__ void ShaInit(uint32_t state[8])
{
    state[0] = 0x6a09e667U;
    state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U;
    state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU;
    state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU;
    state[7] = 0x5be0cd19U;
}

// A 16-word sliding schedule avoids the 64-word per-thread local-memory spill.
__device__ __forceinline__ void ShaCompress(uint32_t state[8], uint32_t words[16])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

#pragma unroll
    for (uint32_t round = 0; round < 64; ++round) {
        uint32_t word;
        if (round < 16) {
            word = words[round];
        } else {
            word = ShaSmall1(words[(round - 2) & 15U]) +
                   words[(round - 7) & 15U] +
                   ShaSmall0(words[(round - 15) & 15U]) +
                   words[(round - 16) & 15U];
            words[round & 15U] = word;
        }
        const uint32_t t1 = h + ShaBig1(e) + ShaCh(e, f, g) +
                            kSha256Round[round] + word;
        const uint32_t t2 = ShaBig0(a) + ShaMaj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// Bit-identical specialization of:
// SHA256("BTX_MATEXPAND_MXSCALE_V44LT" || prf_key || i_LE32 || bj_LE32)[0] & 3.
// The message is exactly 67 bytes, hence two SHA-256 blocks.  `key_words`
// contains the byte sequence of uint256 grouped as little-endian uint32 words,
// matching the ChaCha key already passed to the extraction kernel.
__device__ __forceinline__ uint8_t DeriveMatExpandMxScale(const uint32_t key_words[8],
                                                          uint32_t i, uint32_t bj)
{
    constexpr char kTag[] = "BTX_MATEXPAND_MXSCALE_V44LT";
    constexpr uint32_t kTagLen = sizeof(kTag) - 1;
    static_assert(kTagLen == 27, "MX scale tag layout changed");
    constexpr uint32_t kMessageLen = kTagLen + 32 + 4 + 4;
    static_assert(kMessageLen == 67, "MX scale SHA specialization pins 67 bytes");

    uint32_t state[8];
    uint32_t block[16] = {};
    ShaInit(state);

#pragma unroll
    for (uint32_t p = 0; p < kTagLen; ++p) {
        ShaSetByte(block, p, static_cast<uint8_t>(kTag[p]));
    }
#pragma unroll
    for (uint32_t p = 0; p < 32; ++p) {
        ShaSetByte(block, kTagLen + p,
                   (key_words[p >> 2U] >> (8U * (p & 3U))) & 0xffU);
    }
#pragma unroll
    for (uint32_t p = 0; p < 4; ++p) {
        ShaSetByte(block, kTagLen + 32 + p, (i >> (8U * p)) & 0xffU);
    }
    // The first bj byte is the final byte of block zero.
    ShaSetByte(block, 63, bj & 0xffU);
    ShaCompress(state, block);

#pragma unroll
    for (uint32_t p = 0; p < 16; ++p) block[p] = 0;
    ShaSetByte(block, 0, (bj >> 8U) & 0xffU);
    ShaSetByte(block, 1, (bj >> 16U) & 0xffU);
    ShaSetByte(block, 2, (bj >> 24U) & 0xffU);
    ShaSetByte(block, 3, 0x80U);
    block[15] = kMessageLen * 8U;
    ShaCompress(state, block);

    // SHA-256 serializes state[0] big-endian; only digest byte zero is needed.
    return static_cast<uint8_t>((state[0] >> 24U) & 0x3U);
}

} // namespace matmul_v4::lt_device

#endif // BITCOIN_CUDA_MATMUL_V4_LT_DEVICE_MX_H
