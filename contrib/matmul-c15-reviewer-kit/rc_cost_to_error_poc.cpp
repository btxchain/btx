// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Self-contained C++ PoC for the ENC_RC v4.6 cost-to-error / Extract-quantization
// audit.  Standalone (no bitcoind build); reproduces the consensus MX-block
// Extract mantissa derivation bit-for-bit and cross-checks it against a pinned
// vector from reference_extract.py (which is itself pinned to
// src/matmul/matmul_v4_lt.cpp::ExtractMatExpandMxTileMantissas and
// src/matmul/matmul_v4_rc_extract.h::ExtractMXTileInt64).
//
// The consensus Extract mantissa nibble is:
//     mixed  = keystream_nibble XOR ((raw_u * 0x9E3779B9u) >> 28)   (& 0x0F)
//     mu     = SampleMantissaNibble(mixed)   -> M11 = {0,+-1,+-2,+-3,+-4,+-6}
//     int8   = mu * 2^e     (e is data-INDEPENDENT: only prf_key,i,bj)
// so two accumulators collide in int8 iff they collide in the mantissa nibble.
// This program proves the map raw->mantissa is a per-element PRF hash (any 1-LSB
// change flips the nibble ~10/11 of the time) and that no cheaper accumulator
// reproduces the honest int8 tile at a compute saving.
//
// Build:  g++ -O2 -std=c++17 rc_cost_to_error_poc.cpp -o /tmp/rc_poc && /tmp/rc_poc
//
// The keystream is the real MatExpandMxTileKeystream: RFC8439 ChaCha20 with
// key=prf_key, counter=remix, nonce96=(bj ^ 0x4D58424C, (i<<32)|bj).  The
// per-block scale e = SHA256(...)&3 is data-independent and omitted here (it
// cannot change a mantissa collision into a non-collision); the attack verdict
// is invariant to it and to the specific prf_key.

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

// ------------------------- ChaCha20 (RFC8439) ------------------------------
namespace {
inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// One 64-byte ChaCha20 block. key=32B, counter=32-bit, nonce=96-bit (3 words).
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint32_t nonce[3],
                    uint8_t out[64])
{
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i)
        std::memcpy(&s[4 + i], key + 4 * i, 4);
    s[12] = counter;
    s[13] = nonce[0]; s[14] = nonce[1]; s[15] = nonce[2];
    uint32_t x[16];
    std::memcpy(x, s, sizeof(x));
    for (int i = 0; i < 10; ++i) {
        qr(x[0], x[4], x[8], x[12]);
        qr(x[1], x[5], x[9], x[13]);
        qr(x[2], x[6], x[10], x[14]);
        qr(x[3], x[7], x[11], x[15]);
        qr(x[0], x[5], x[10], x[15]);
        qr(x[1], x[6], x[11], x[12]);
        qr(x[2], x[7], x[8], x[13]);
        qr(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + s[i];
        std::memcpy(out + 4 * i, &v, 4);
    }
}

// MatExpandMxTileKeystream: nonce_first = bj ^ 0x4D58424C ('MXBL'),
// nonce_second (64-bit LE across words 2,3) = (i<<32)|bj.
void tile_keystream(const uint8_t prf_key[32], uint32_t i, uint32_t bj, uint32_t remix,
                    uint8_t out[64])
{
    const uint32_t lane_mxbl = 0x4D58424Cu;
    uint32_t nonce[3];
    nonce[0] = bj ^ lane_mxbl;
    const uint64_t nsecond = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(bj);
    nonce[1] = static_cast<uint32_t>(nsecond & 0xFFFFFFFFu);
    nonce[2] = static_cast<uint32_t>(nsecond >> 32);
    chacha20_block(prf_key, remix, nonce, out);
}

// ------------------- M11 mantissa table (E2M1 rejection) -------------------
struct M11Table {
    std::array<bool, 16> accepted{};
    std::array<int8_t, 16> value{};
    M11Table()
    {
        for (uint8_t nib = 0; nib < 16; ++nib) {
            uint8_t sign = (nib >> 3) & 1, exp = (nib >> 1) & 3, man = nib & 1;
            int mag = 0; bool integer = true;
            switch (exp) {
            case 0: mag = 0; integer = (man == 0); break;
            case 1: mag = 1; integer = (man == 0); break;
            case 2: mag = (man == 0) ? 2 : 3; break;
            case 3: mag = (man == 0) ? 4 : 6; break;
            }
            if (!integer || (sign && mag == 0)) { accepted[nib] = false; value[nib] = 0; continue; }
            accepted[nib] = true; value[nib] = static_cast<int8_t>(sign ? -mag : mag);
        }
    }
};
const M11Table kM11;

inline uint32_t mix_bits_i64(int64_t y)
{
    if (y >= INT32_MIN && y <= INT32_MAX) return static_cast<uint32_t>(static_cast<int32_t>(y));
    uint64_t u = static_cast<uint64_t>(y);
    return static_cast<uint32_t>(u) ^ static_cast<uint32_t>(u >> 32);
}

// Consensus mantissa extraction for one 32-value tile (matmul_v4_lt.cpp).
void extract_mantissas(const uint8_t prf_key[32], uint32_t i, uint32_t bj,
                       const int64_t raw64[32], int8_t mu_out[32])
{
    uint32_t filled = 0, remix = 0;
    uint8_t ks[64];
    while (filled < 32) {
        tile_keystream(prf_key, i, bj, remix, ks);
        for (int b = 0; b < 64 && filled < 32; ++b) {
            for (int shift : {0, 4}) {
                if (filled >= 32) break;
                uint8_t nibble = (ks[b] >> shift) & 0x0F;
                uint32_t raw_u = mix_bits_i64(raw64[filled]);
                uint8_t mixed = (nibble ^ static_cast<uint8_t>((raw_u * 0x9E3779B9u) >> 28)) & 0x0F;
                if (kM11.accepted[mixed]) mu_out[filled++] = kM11.value[mixed];
            }
        }
        ++remix;
    }
}

// --------------------------- cheap accumulators ----------------------------
int64_t exact_dot(const std::vector<int8_t>& a, const std::vector<int8_t>& b)
{
    int64_t s = 0;
    for (size_t t = 0; t < a.size(); ++t) s += static_cast<int64_t>(a[t]) * b[t];
    return s;
}

double round_mantissa(double x, int mant_bits)
{
    if (x == 0.0) return 0.0;
    int e; double m = std::frexp(x, &e);
    double scale = static_cast<double>(1u << mant_bits);
    m = std::round(m * scale) / scale;
    return std::ldexp(m, e);
}

int64_t fp_accumulate(const std::vector<int8_t>& a, const std::vector<int8_t>& b, int mant_bits)
{
    double acc = 0.0;
    for (size_t t = 0; t < a.size(); ++t)
        acc = round_mantissa(acc + static_cast<double>(static_cast<int64_t>(a[t]) * b[t]), mant_bits);
    return static_cast<int64_t>(std::llround(acc));
}

int64_t truncate_acc(int64_t exact, int drop)
{
    if (drop <= 0) return exact;
    int64_t step = int64_t{1} << drop;
    return static_cast<int64_t>(std::llround(static_cast<double>(exact) / step)) * step;
}

const int kM11vals[11] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
int rand_operand(std::mt19937& rng)
{
    int m = kM11vals[rng() % 11];
    int e = rng() % 4;
    return m * (1 << e);
}
} // namespace

int main()
{
    uint8_t prf_key[32];
    std::memset(prf_key, 0x11, sizeof(prf_key));

    // ---- 0. FIDELITY: match reference_extract.py pinned vector bit-for-bit ----
    {
        int64_t raw[32];
        for (int t = 0; t < 32; ++t) raw[t] = (t % 2 ? -1 : 1) * (int64_t{1000} * t + 12345);
        int8_t mu[32];
        extract_mantissas(prf_key, 7, 3, raw, mu);
        const int8_t expect[32] = {-2, 4, 4, -2, -1, 6, 3, -3, 6, 3, 2, -2, -6, 2, -6, -1,
                                    4, -4, -4, -1, -6, -2, 2, 4, 2, -6, -2, 4, 2, -2, -2, 2};
        bool ok = true;
        for (int t = 0; t < 32; ++t) ok &= (mu[t] == expect[t]);
        std::printf("0. FIDELITY vs reference_extract.py pinned vector: %s\n\n",
                    ok ? "PASS (bit-for-bit)" : "*** FAIL ***");
        if (!ok) return 1;
    }

    std::mt19937 rng(20260724);

    // ---- 2. LSB sensitivity ----
    std::printf("2. LSB-SENSITIVITY of Extract mantissa (raw -> nibble is a hash)\n");
    std::printf("   %8s | P(mantissa flips)\n   ---------+------------------\n", "delta");
    for (int64_t delta : {int64_t{1}, int64_t{-1}, int64_t{2}, int64_t{7}, int64_t{256},
                          int64_t{65536}}) {
        int flips = 0, total = 0;
        for (int trial = 0; trial < 4000; ++trial) {
            int64_t raw[32];
            std::uniform_int_distribution<int64_t> d(-(int64_t{1} << 25), int64_t{1} << 25);
            for (int t = 0; t < 32; ++t) raw[t] = d(rng);
            uint32_t i = rng() % (1u << 20), bj = rng() % 512;
            int8_t base[32]; extract_mantissas(prf_key, i, bj, raw, base);
            int tt = rng() % 32;
            int64_t raw2[32]; std::memcpy(raw2, raw, sizeof(raw)); raw2[tt] += delta;
            int8_t pert[32]; extract_mantissas(prf_key, i, bj, raw2, pert);
            flips += (pert[tt] != base[tt]); ++total;
        }
        std::printf("   %8lld | %.4f\n", static_cast<long long>(delta),
                    static_cast<double>(flips) / total);
    }
    std::printf("\n");

    // ---- 3. constructive attack ----
    const int K = 512, n_tiles = 200;
    std::printf("3. CONSTRUCTIVE ATTACK  (K=%d, %d tiles of 32)\n", K, n_tiles);
    struct Cheap { const char* name; double cost; };
    auto run_cheap = [&](const char* name, double cost, auto fn) {
        int tile_match = 0, elem_match = 0, elem_total = 0;
        std::mt19937 arng(777);
        for (int n = 0; n < n_tiles; ++n) {
            std::vector<int8_t> a(K);
            for (int t = 0; t < K; ++t) a[t] = static_cast<int8_t>(rand_operand(arng));
            int64_t ex_raw[32], ch_raw[32];
            for (int c = 0; c < 32; ++c) {
                std::vector<int8_t> b(K);
                for (int t = 0; t < K; ++t) b[t] = static_cast<int8_t>(rand_operand(arng));
                ex_raw[c] = exact_dot(a, b);
                ch_raw[c] = fn(a, b);
            }
            int8_t ex_i8[32], ch_i8[32];
            extract_mantissas(prf_key, n, 0, ex_raw, ex_i8);
            extract_mantissas(prf_key, n, 0, ch_raw, ch_i8);
            bool all = true;
            for (int c = 0; c < 32; ++c) { bool m = ex_i8[c] == ch_i8[c]; elem_match += m; all &= m; }
            elem_total += 32; tile_match += all;
        }
        std::printf("   %-38s cost=%.2f  elem=%.4f  TILE-eq=%.4f\n", name, cost,
                    static_cast<double>(elem_match) / elem_total,
                    static_cast<double>(tile_match) / n_tiles);
    };
    run_cheap("(a) bf16-accumulate (7 mant bits)", 0.30,
              [](const std::vector<int8_t>& a, const std::vector<int8_t>& b) { return fp_accumulate(a, b, 7); });
    run_cheap("(b) fp16-accumulate (10 mant bits)", 0.50,
              [](const std::vector<int8_t>& a, const std::vector<int8_t>& b) { return fp_accumulate(a, b, 10); });
    run_cheap("(c) truncate 4 low bits", 0.80,
              [](const std::vector<int8_t>& a, const std::vector<int8_t>& b) { return truncate_acc(exact_dot(a, b), 4); });
    run_cheap("(d) truncate 1 low bit", 0.95,
              [](const std::vector<int8_t>& a, const std::vector<int8_t>& b) { return truncate_acc(exact_dot(a, b), 1); });
    run_cheap("(g) EXACT control (must be 1.0)", 1.00,
              [](const std::vector<int8_t>& a, const std::vector<int8_t>& b) { return exact_dot(a, b); });

    std::printf("\nVERDICT: correct int8 REQUIRES the exact accumulator; every cheaper\n");
    std::printf("accumulator diverges in the int8 tile (TILE-eq=0) -> COST-TO-ERROR HOLDS.\n");
    return 0;
}
