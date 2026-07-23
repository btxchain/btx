// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_ARM_SHANI

#include <array>
#include <cstdint>
#include <cstring>

#include <arm_acle.h>
#include <arm_neon.h>

namespace {

alignas(uint32x4_t) static constexpr std::array<uint32_t, 64> K = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
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

#define BTX_SHA256_ROUND4(MSG, NEXT1, NEXT2, NEXT3, KIDX)               \
    do {                                                                \
        TMP = vld1q_u32(&K[(KIDX)]);                                    \
        TMP0A = vaddq_u32(MSG##A, TMP);                                 \
        TMP0B = vaddq_u32(MSG##B, TMP);                                 \
        TMP0C = vaddq_u32(MSG##C, TMP);                                 \
        TMP0D = vaddq_u32(MSG##D, TMP);                                 \
        TMP2A = STATE0A;                                                \
        TMP2B = STATE0B;                                                \
        TMP2C = STATE0C;                                                \
        TMP2D = STATE0D;                                                \
        MSG##A = vsha256su0q_u32(MSG##A, NEXT1##A);                     \
        MSG##B = vsha256su0q_u32(MSG##B, NEXT1##B);                     \
        MSG##C = vsha256su0q_u32(MSG##C, NEXT1##C);                     \
        MSG##D = vsha256su0q_u32(MSG##D, NEXT1##D);                     \
        STATE0A = vsha256hq_u32(STATE0A, STATE1A, TMP0A);               \
        STATE0B = vsha256hq_u32(STATE0B, STATE1B, TMP0B);               \
        STATE0C = vsha256hq_u32(STATE0C, STATE1C, TMP0C);               \
        STATE0D = vsha256hq_u32(STATE0D, STATE1D, TMP0D);               \
        STATE1A = vsha256h2q_u32(STATE1A, TMP2A, TMP0A);                \
        STATE1B = vsha256h2q_u32(STATE1B, TMP2B, TMP0B);                \
        STATE1C = vsha256h2q_u32(STATE1C, TMP2C, TMP0C);                \
        STATE1D = vsha256h2q_u32(STATE1D, TMP2D, TMP0D);                \
        MSG##A = vsha256su1q_u32(MSG##A, NEXT2##A, NEXT3##A);           \
        MSG##B = vsha256su1q_u32(MSG##B, NEXT2##B, NEXT3##B);           \
        MSG##C = vsha256su1q_u32(MSG##C, NEXT2##C, NEXT3##C);           \
        MSG##D = vsha256su1q_u32(MSG##D, NEXT2##D, NEXT3##D);           \
    } while (false)

#define BTX_SHA256_FINAL4(MSG, KIDX)                                    \
    do {                                                                \
        TMP = vld1q_u32(&K[(KIDX)]);                                    \
        TMP0A = vaddq_u32(MSG##A, TMP);                                 \
        TMP0B = vaddq_u32(MSG##B, TMP);                                 \
        TMP0C = vaddq_u32(MSG##C, TMP);                                 \
        TMP0D = vaddq_u32(MSG##D, TMP);                                 \
        TMP2A = STATE0A;                                                \
        TMP2B = STATE0B;                                                \
        TMP2C = STATE0C;                                                \
        TMP2D = STATE0D;                                                \
        STATE0A = vsha256hq_u32(STATE0A, STATE1A, TMP0A);               \
        STATE0B = vsha256hq_u32(STATE0B, STATE1B, TMP0B);               \
        STATE0C = vsha256hq_u32(STATE0C, STATE1C, TMP0C);               \
        STATE0D = vsha256hq_u32(STATE0D, STATE1D, TMP0D);               \
        STATE1A = vsha256h2q_u32(STATE1A, TMP2A, TMP0A);                \
        STATE1B = vsha256h2q_u32(STATE1B, TMP2B, TMP0B);                \
        STATE1C = vsha256h2q_u32(STATE1C, TMP2C, TMP0C);                \
        STATE1D = vsha256h2q_u32(STATE1D, TMP2D, TMP0D);                \
    } while (false)

} // namespace

namespace sha256_xof_arm_shani {

void Transform4x41(unsigned char output[4][32], const unsigned char seed[32],
                   unsigned char domain, uint64_t block0)
{
    alignas(uint32x4_t) static constexpr std::array<uint32_t, 8> INIT = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    unsigned char chunk[4][64];
    MakeBlock41(seed, domain, block0 + 0, chunk[0]);
    MakeBlock41(seed, domain, block0 + 1, chunk[1]);
    MakeBlock41(seed, domain, block0 + 2, chunk[2]);
    MakeBlock41(seed, domain, block0 + 3, chunk[3]);

    uint32x4_t STATE0A = vld1q_u32(&INIT[0]);
    uint32x4_t STATE0B = STATE0A;
    uint32x4_t STATE0C = STATE0A;
    uint32x4_t STATE0D = STATE0A;
    uint32x4_t STATE1A = vld1q_u32(&INIT[4]);
    uint32x4_t STATE1B = STATE1A;
    uint32x4_t STATE1C = STATE1A;
    uint32x4_t STATE1D = STATE1A;
    const uint32x4_t SAVE0 = STATE0A;
    const uint32x4_t SAVE1 = STATE1A;

    uint32x4_t MSG0A = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[0] + 0)));
    uint32x4_t MSG1A = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[0] + 16)));
    uint32x4_t MSG2A = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[0] + 32)));
    uint32x4_t MSG3A = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[0] + 48)));
    uint32x4_t MSG0B = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[1] + 0)));
    uint32x4_t MSG1B = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[1] + 16)));
    uint32x4_t MSG2B = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[1] + 32)));
    uint32x4_t MSG3B = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[1] + 48)));
    uint32x4_t MSG0C = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[2] + 0)));
    uint32x4_t MSG1C = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[2] + 16)));
    uint32x4_t MSG2C = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[2] + 32)));
    uint32x4_t MSG3C = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[2] + 48)));
    uint32x4_t MSG0D = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[3] + 0)));
    uint32x4_t MSG1D = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[3] + 16)));
    uint32x4_t MSG2D = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[3] + 32)));
    uint32x4_t MSG3D = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk[3] + 48)));

    uint32x4_t TMP, TMP0A, TMP0B, TMP0C, TMP0D, TMP2A, TMP2B, TMP2C, TMP2D;

    BTX_SHA256_ROUND4(MSG0, MSG1, MSG2, MSG3, 0);
    BTX_SHA256_ROUND4(MSG1, MSG2, MSG3, MSG0, 4);
    BTX_SHA256_ROUND4(MSG2, MSG3, MSG0, MSG1, 8);
    BTX_SHA256_ROUND4(MSG3, MSG0, MSG1, MSG2, 12);
    BTX_SHA256_ROUND4(MSG0, MSG1, MSG2, MSG3, 16);
    BTX_SHA256_ROUND4(MSG1, MSG2, MSG3, MSG0, 20);
    BTX_SHA256_ROUND4(MSG2, MSG3, MSG0, MSG1, 24);
    BTX_SHA256_ROUND4(MSG3, MSG0, MSG1, MSG2, 28);
    BTX_SHA256_ROUND4(MSG0, MSG1, MSG2, MSG3, 32);
    BTX_SHA256_ROUND4(MSG1, MSG2, MSG3, MSG0, 36);
    BTX_SHA256_ROUND4(MSG2, MSG3, MSG0, MSG1, 40);
    BTX_SHA256_ROUND4(MSG3, MSG0, MSG1, MSG2, 44);
    BTX_SHA256_FINAL4(MSG0, 48);
    BTX_SHA256_FINAL4(MSG1, 52);
    BTX_SHA256_FINAL4(MSG2, 56);
    BTX_SHA256_FINAL4(MSG3, 60);

    STATE0A = vaddq_u32(STATE0A, SAVE0);
    STATE0B = vaddq_u32(STATE0B, SAVE0);
    STATE0C = vaddq_u32(STATE0C, SAVE0);
    STATE0D = vaddq_u32(STATE0D, SAVE0);
    STATE1A = vaddq_u32(STATE1A, SAVE1);
    STATE1B = vaddq_u32(STATE1B, SAVE1);
    STATE1C = vaddq_u32(STATE1C, SAVE1);
    STATE1D = vaddq_u32(STATE1D, SAVE1);

    alignas(uint32x4_t) uint32_t state[4][8];
    vst1q_u32(&state[0][0], STATE0A);
    vst1q_u32(&state[0][4], STATE1A);
    vst1q_u32(&state[1][0], STATE0B);
    vst1q_u32(&state[1][4], STATE1B);
    vst1q_u32(&state[2][0], STATE0C);
    vst1q_u32(&state[2][4], STATE1C);
    vst1q_u32(&state[3][0], STATE0D);
    vst1q_u32(&state[3][4], STATE1D);

    for (int lane = 0; lane < 4; ++lane) {
        for (int word = 0; word < 8; ++word) {
            WriteBE32Local(output[lane] + 4 * word, state[lane][word]);
        }
    }
}

} // namespace sha256_xof_arm_shani

#undef BTX_SHA256_ROUND4
#undef BTX_SHA256_FINAL4

#endif // ENABLE_ARM_SHANI
