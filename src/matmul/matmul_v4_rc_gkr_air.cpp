// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr_air.h>

#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <span.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>

// ENC_RC Extract AIR — implementation. See header for the high-level map and
// the blueprint references (§5, Thm 5.2). The int64 reference in
// src/matmul/matmul_v4_lt.cpp + matmul_v4_rc_extract.h is the sole oracle: this
// file recomputes the same values in-circuit, records every intermediate as a
// committed cell, and constrains their algebraic relations. Byte-exactness is
// asserted against the reference; the AIR never redefines Extract.

namespace matmul::v4::rc::gkr_air {

using gkr_field::Add;
using gkr_field::Sub;
using gkr_field::Mul;
using gkr_field::Fp;

namespace {

// The MX-scale SHA domain tag — consensus constant, mirrors the (anonymous)
// kMatExpandMxScaleTag in src/matmul/matmul_v4_lt.cpp:216. Kept in sync by the
// byte-exactness assertion against DeriveMatExpandMxScale in TraceTile.
constexpr char kMxScaleTag[] = "BTX_MATEXPAND_MXSCALE_V44LT";
// ChaCha nonce_first lane tag 'MXBL' (mirrors kMatExpandPrfLaneMxBlock).
constexpr uint32_t kLaneMxBlock = 0x4D58424Cu;

// -------- golden-ratio mixing constant (matmul_v4_lt.cpp:330) --------
constexpr uint32_t kGolden = 0x9E3779B9u;

// ===========================================================================
// In-circuit ChaCha20 block (records intermediates). Byte-exact to the library
// ChaCha20 used by MatExpandMxTileKeystream. Constraints (checked below):
//  - init state = (constants | key words | counter | nonce) — public;
//  - each quarter-round: ARX identity from committed in-cells to out-cells,
//    with committed add-carry witnesses (0/1) and 16-bit result limbs (T_R16),
//    and 4-bit xor nibbles (T_X);
//  - feed-forward add: keystream word = working + init (mod 2^32);
//  - output byte -> low/high nibble decomposition (the C-E1 nibble stream).
// ===========================================================================

inline uint32_t Rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

// (ChaChaAdd / ChaChaBlockTrace are public committed-cell structs; header §2b.)

// Records an add and returns result.
uint32_t DoAdd(uint32_t a, uint32_t b, std::vector<ChaChaAdd>& adds)
{
    const uint64_t s = static_cast<uint64_t>(a) + b;
    const uint32_t r = static_cast<uint32_t>(s);
    adds.push_back(ChaChaAdd{a, b, r, static_cast<uint8_t>(s >> 32)});
    return r;
}

uint32_t DoXor(uint32_t a, uint32_t b, std::vector<std::array<uint32_t, 3>>& xors)
{
    const uint32_t r = a ^ b;
    xors.push_back({a, b, r});
    return r;
}

ChaChaBlockTrace ChaChaBlockInCircuit(const std::array<uint32_t, 16>& init)
{
    ChaChaBlockTrace t;
    t.init = init;
    std::array<uint32_t, 16> x = init;
    auto QR = [&](int a, int b, int c, int d) {
        x[a] = DoAdd(x[a], x[b], t.adds); x[d] = Rotl32(DoXor(x[d], x[a], t.xors), 16);
        x[c] = DoAdd(x[c], x[d], t.adds); x[b] = Rotl32(DoXor(x[b], x[c], t.xors), 12);
        x[a] = DoAdd(x[a], x[b], t.adds); x[d] = Rotl32(DoXor(x[d], x[a], t.xors), 8);
        x[c] = DoAdd(x[c], x[d], t.adds); x[b] = Rotl32(DoXor(x[b], x[c], t.xors), 7);
    };
    for (int r = 0; r < 10; ++r) {
        QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
    }
    t.final_working = x;
    for (int k = 0; k < 16; ++k) {
        t.keystream_words[k] = DoAdd(x[k], init[k], t.adds);
    }
    for (int k = 0; k < 16; ++k) {
        WriteLE32(t.out_bytes.data() + 4 * k, t.keystream_words[k]);
    }
    return t;
}

// Structural constraint check for one ChaCha block trace (pure over cells).
bool CheckChaChaBlock(const ChaChaBlockTrace& t, std::string& fail)
{
    // (i) every recorded add is a true modular add with a boolean carry and an
    //     in-range 32-bit result (the T_R16 limb ranges are enforced by the
    //     LogUp; here we check the algebraic add identity + carry booleanity).
    for (const auto& ad : t.adds) {
        if (ad.carry > 1) { fail = "chacha:add_carry_not_boolean"; return false; }
        const uint64_t lhs = static_cast<uint64_t>(ad.a) + ad.b;
        const uint64_t rhs = static_cast<uint64_t>(ad.r) +
                             (static_cast<uint64_t>(ad.carry) << 32);
        if (lhs != rhs) { fail = "chacha:add_identity"; return false; }
    }
    // (ii) every recorded xor is the true 4-bit-decomposed xor (T_X membership
    //      is enforced by LogUp; here the recomposed value identity).
    for (const auto& xr : t.xors) {
        if ((xr[0] ^ xr[1]) != xr[2]) { fail = "chacha:xor_identity"; return false; }
    }
    // (iii) feed-forward: keystream word = final_working + init (mod 2^32).
    for (int k = 0; k < 16; ++k) {
        if (t.keystream_words[k] !=
            static_cast<uint32_t>(t.final_working[k] + t.init[k])) {
            fail = "chacha:feedforward"; return false;
        }
    }
    // (iv) output bytes decompose the keystream words (little-endian).
    for (int k = 0; k < 16; ++k) {
        uint32_t w = 0;
        for (int b = 0; b < 4; ++b) {
            w |= static_cast<uint32_t>(t.out_bytes[4 * k + b]) << (8 * b);
        }
        if (w != t.keystream_words[k]) { fail = "chacha:out_byte_decomp"; return false; }
    }
    return true;
}

// ---------------------------------------------------------------------------
// ChaCha dataflow walk. The ARX schedule is a fixed DAG over the committed
// cells; a rotation is a fixed relabeling of the producing xor's bit columns
// (blueprint §5.4: "rotations by fixed amounts = limb re-wiring, free"). A
// state word is therefore either (a) a committed cell (init word or an add
// result) or (b) the rotation-relabel of a committed xor result. WordRef
// carries both the value and the provenance so the polynomial emitter can
// express case (b) as   operand - sum_i 2^{(i+rot) mod 32} bit_i(xor_r) = 0.
// ---------------------------------------------------------------------------

struct WordRef {
    uint32_t value{0};
    int xor_src{-1};  // index into t.xors if this word is a rotated xor result
    int rot{0};       // rotation amount applied to that xor result
};

// Walks the fixed ChaCha20 op schedule over the committed cells. Invokes
// on_add(add_idx, a_ref, b_ref) / on_xor(xor_idx, x_ref, y_ref) BEFORE each op
// consumes its operands. Returns false on a cell-count (shape) mismatch.
// Feed-forward adds are the final 16 (indices 320..335).
template <typename FAdd, typename FXor>
bool WalkChaChaSchedule(const ChaChaBlockTrace& t, FAdd&& on_add, FXor&& on_xor,
                        std::array<WordRef, 16>* final_state)
{
    if (t.adds.size() != 336 || t.xors.size() != 320) return false;
    std::array<WordRef, 16> st;
    for (int k = 0; k < 16; ++k) st[k] = WordRef{t.init[k], -1, 0};
    size_t ai = 0, xi = 0;
    auto STEP = [&](int a, int b, int c, int d) {
        on_add(ai, st[a], st[b]);
        st[a] = WordRef{t.adds[ai].r, -1, 0}; ++ai;
        on_xor(xi, st[d], st[a]);
        st[d] = WordRef{Rotl32(t.xors[xi][2], 16), static_cast<int>(xi), 16}; ++xi;
        on_add(ai, st[c], st[d]);
        st[c] = WordRef{t.adds[ai].r, -1, 0}; ++ai;
        on_xor(xi, st[b], st[c]);
        st[b] = WordRef{Rotl32(t.xors[xi][2], 12), static_cast<int>(xi), 12}; ++xi;
        on_add(ai, st[a], st[b]);
        st[a] = WordRef{t.adds[ai].r, -1, 0}; ++ai;
        on_xor(xi, st[d], st[a]);
        st[d] = WordRef{Rotl32(t.xors[xi][2], 8), static_cast<int>(xi), 8}; ++xi;
        on_add(ai, st[c], st[d]);
        st[c] = WordRef{t.adds[ai].r, -1, 0}; ++ai;
        on_xor(xi, st[b], st[c]);
        st[b] = WordRef{Rotl32(t.xors[xi][2], 7), static_cast<int>(xi), 7}; ++xi;
    };
    for (int r = 0; r < 10; ++r) {
        STEP(0, 4, 8, 12); STEP(1, 5, 9, 13); STEP(2, 6, 10, 14); STEP(3, 7, 11, 15);
        STEP(0, 5, 10, 15); STEP(1, 6, 11, 12); STEP(2, 7, 8, 13); STEP(3, 4, 9, 14);
    }
    if (final_state) *final_state = st;
    for (int k = 0; k < 16; ++k) {
        on_add(ai, st[k], WordRef{t.init[k], -1, 0});
        ++ai;
    }
    return ai == t.adds.size() && xi == t.xors.size();
}

// Dataflow (copy-constraint) check: every recorded operand cell equals the
// scheduled state word, final_working matches the walked state, and the
// keystream words are the feed-forward add results. Together with
// CheckChaChaBlock's per-op identities this pins the whole permutation to the
// committed cells (no re-derivation of any intermediate).
bool CheckChaChaWiring(const ChaChaBlockTrace& t, std::string& fail)
{
    bool ok = true;
    std::array<WordRef, 16> fin{};
    const bool shape = WalkChaChaSchedule(
        t,
        [&](size_t ai, const WordRef& a, const WordRef& b) {
            if (t.adds[ai].a != a.value || t.adds[ai].b != b.value) ok = false;
        },
        [&](size_t xi, const WordRef& x, const WordRef& y) {
            if (t.xors[xi][0] != x.value || t.xors[xi][1] != y.value) ok = false;
        },
        &fin);
    if (!shape) { fail = "chacha:wiring_shape"; return false; }
    if (!ok) { fail = "chacha:wiring_operand"; return false; }
    for (int k = 0; k < 16; ++k) {
        if (t.final_working[k] != fin[k].value) { fail = "chacha:final_state_binding"; return false; }
        if (t.adds[320 + k].r != t.keystream_words[k]) { fail = "chacha:keystream_ff_binding"; return false; }
    }
    return true;
}

// ===========================================================================
// In-circuit SHA-256 compression for the MX scale (§6.2). Bit-decomposition
// arithmetization: every 32-bit quantity carries a 32-bit booleanity witness,
// so Ch/Maj/Sigma/sigma are bit-algebra (xor = a+b-2ab, and = ab, not = 1-a)
// and all 32-bit ranges are self-enforced; modular adds carry an explicit
// integer carry witness. Documented deviation from the T_X/T_R16 routing used
// for ChaCha (§5.4): strictly sound, self-contained, avoids a second table
// path for the hash. Byte-exact to CSHA256 (asserted in TraceTile).
// ===========================================================================

constexpr std::array<uint32_t, 64> kSHA_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr std::array<uint32_t, 8> kSHA_H0 = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline uint32_t Rotr32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

// (ShaAdd / ShaCompressTrace are public committed-cell structs; header §2b.)

// Records an n-ary modular add (mod 2^32) with an integer carry witness.
uint32_t ShaSum(std::vector<uint32_t> terms, std::vector<ShaAdd>& adds)
{
    uint64_t s = 0;
    for (uint32_t t : terms) s += t;
    const uint32_t r = static_cast<uint32_t>(s);
    adds.push_back(ShaAdd{r, static_cast<uint8_t>(s >> 32), std::move(terms)});
    return r;
}

ShaCompressTrace ShaCompressInCircuit(const std::array<uint32_t, 8>& h_in,
                                      const std::array<uint32_t, 16>& block)
{
    ShaCompressTrace t;
    t.h_in = h_in;
    for (int i = 0; i < 16; ++i) t.w[i] = block[i];
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Rotr32(t.w[i - 15], 7) ^ Rotr32(t.w[i - 15], 18) ^ (t.w[i - 15] >> 3);
        const uint32_t s1 = Rotr32(t.w[i - 2], 17) ^ Rotr32(t.w[i - 2], 19) ^ (t.w[i - 2] >> 10);
        t.w[i] = ShaSum({t.w[i - 16], s0, t.w[i - 7], s1}, t.adds);
    }
    std::array<uint32_t, 8> v = h_in;  // a,b,c,d,e,f,g,h
    t.vars[0] = v;
    for (int i = 0; i < 64; ++i) {
        const uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
        const uint32_t e = v[4], f = v[5], g = v[6], h = v[7];
        const uint32_t S1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = ShaSum({h, S1, ch, kSHA_K[i], t.w[i]}, t.adds);
        const uint32_t S0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = ShaSum({S0, maj}, t.adds);
        v[7] = g; v[6] = f; v[5] = e;
        v[4] = ShaSum({d, t1}, t.adds);
        v[3] = c; v[2] = b; v[1] = a;
        v[0] = ShaSum({t1, t2}, t.adds);
        t.vars[i + 1] = v;
    }
    for (int k = 0; k < 8; ++k) t.h_out[k] = ShaSum({h_in[k], v[k]}, t.adds);
    return t;
}

bool CheckShaCompress(const ShaCompressTrace& t, std::string& fail)
{
    // Modular-add identities with boolean-bounded carry witnesses.
    for (const auto& ad : t.adds) {
        uint64_t s = 0;
        for (uint32_t x : ad.terms) s += x;
        if (static_cast<uint32_t>(s) != ad.r ||
            static_cast<uint8_t>(s >> 32) != ad.carry) {
            fail = "sha:add_identity"; return false;
        }
    }
    // Message-schedule recurrence (bit ops recomputed from committed words).
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Rotr32(t.w[i - 15], 7) ^ Rotr32(t.w[i - 15], 18) ^ (t.w[i - 15] >> 3);
        const uint32_t s1 = Rotr32(t.w[i - 2], 17) ^ Rotr32(t.w[i - 2], 19) ^ (t.w[i - 2] >> 10);
        if (t.w[i] != static_cast<uint32_t>(static_cast<uint64_t>(t.w[i - 16]) + s0 + t.w[i - 7] + s1)) {
            fail = "sha:msg_schedule"; return false;
        }
    }
    // Per-round working-variable update relations.
    for (int i = 0; i < 64; ++i) {
        const auto& p = t.vars[i];
        const auto& n = t.vars[i + 1];
        const uint32_t a = p[0], b = p[1], c = p[2], d = p[3];
        const uint32_t e = p[4], f = p[5], g = p[6], h = p[7];
        const uint32_t S1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = static_cast<uint32_t>(static_cast<uint64_t>(h) + S1 + ch + kSHA_K[i] + t.w[i]);
        const uint32_t S0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = static_cast<uint32_t>(static_cast<uint64_t>(S0) + maj);
        if (n[1] != a || n[2] != b || n[3] != c || n[5] != e || n[6] != f || n[7] != g) {
            fail = "sha:round_shift"; return false;
        }
        if (n[4] != static_cast<uint32_t>(static_cast<uint64_t>(d) + t1)) { fail = "sha:round_e"; return false; }
        if (n[0] != static_cast<uint32_t>(static_cast<uint64_t>(t1) + t2)) { fail = "sha:round_a"; return false; }
    }
    // Feed-forward digest.
    for (int k = 0; k < 8; ++k) {
        if (t.h_out[k] != static_cast<uint32_t>(static_cast<uint64_t>(t.h_in[k]) + t.vars[64][k])) {
            fail = "sha:feedforward"; return false;
        }
    }
    return true;
}

// SHA-256 of the scale message (tag | prf_key | le32(i) | le32(bj)), returning
// h_out of the FINAL compression and the full per-block traces.
struct ScaleShaTrace {
    std::vector<ShaCompressTrace> blocks;
    std::array<uint32_t, 8> digest{};
    uint8_t byte0{0};
    uint8_t e{0};
};

// Public (assignment-independent) scale message: SHA-256-padded block words
// of (tag ‖ prf_key ‖ le32(i) ‖ le32(bj)) — a pure function of the tile's
// public inputs; the message-binding constraints reference these constants.
std::vector<std::array<uint32_t, 16>> ScaleMessageBlockWords(const uint256& prf_key,
                                                             uint32_t i, uint32_t bj)
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), kMxScaleTag, kMxScaleTag + sizeof(kMxScaleTag) - 1);
    for (int k = 0; k < 32; ++k) msg.push_back(prf_key.data()[k]);
    uint8_t le[4];
    WriteLE32(le, i); msg.insert(msg.end(), le, le + 4);
    WriteLE32(le, bj); msg.insert(msg.end(), le, le + 4);
    // SHA-256 padding.
    const uint64_t bitlen = static_cast<uint64_t>(msg.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int s = 7; s >= 0; --s) msg.push_back(static_cast<uint8_t>(bitlen >> (8 * s)));

    std::vector<std::array<uint32_t, 16>> out;
    for (size_t off = 0; off < msg.size(); off += 64) {
        std::array<uint32_t, 16> blk{};
        for (int w = 0; w < 16; ++w) {
            blk[w] = (static_cast<uint32_t>(msg[off + 4 * w]) << 24) |
                     (static_cast<uint32_t>(msg[off + 4 * w + 1]) << 16) |
                     (static_cast<uint32_t>(msg[off + 4 * w + 2]) << 8) |
                     (static_cast<uint32_t>(msg[off + 4 * w + 3]));
        }
        out.push_back(blk);
    }
    return out;
}

ScaleShaTrace ScaleShaInCircuit(const uint256& prf_key, uint32_t i, uint32_t bj)
{
    ScaleShaTrace st;
    std::array<uint32_t, 8> h = kSHA_H0;
    for (const auto& blk : ScaleMessageBlockWords(prf_key, i, bj)) {
        ShaCompressTrace ct = ShaCompressInCircuit(h, blk);
        h = ct.h_out;
        st.blocks.push_back(std::move(ct));
    }
    st.digest = h;
    st.byte0 = static_cast<uint8_t>(h[0] >> 24);  // big-endian first digest byte
    st.e = static_cast<uint8_t>(st.byte0 & 0x3);
    return st;
}

// ===========================================================================
// MixBits (§5.4 C-E7..E9) — int64-domain, the crux branch.
// ===========================================================================

// Reproduces ExtractMixBitsFromInt64 (matmul_v4_lt.cpp:302) with witnesses.
struct MixBitsWitness {
    uint32_t y_lo{0};   // low 32 bits of two's-complement pattern
    uint32_t y_hi{0};   // high 32 bits
    uint8_t sign{0};    // top bit of y_hi
    uint8_t branch{0};  // 1 = in-range [-2^31, 2^31), 0 = fold branch
    uint32_t u_mix{0};  // raw_u
    uint32_t gold_q{0}; // u*G = q*2^32 + v
    uint32_t gold_v{0};
    uint8_t h{0};       // v >> 28
};

MixBitsWitness MixBitsInCircuit(int64_t y)
{
    MixBitsWitness m;
    const uint64_t u64 = static_cast<uint64_t>(y);
    m.y_lo = static_cast<uint32_t>(u64);
    m.y_hi = static_cast<uint32_t>(u64 >> 32);
    m.sign = static_cast<uint8_t>(m.y_hi >> 31);
    const bool in_range = (m.y_hi == 0 && (m.y_lo >> 31) == 0) ||
                          (m.y_hi == 0xFFFFFFFFu && (m.y_lo >> 31) == 1);
    m.branch = in_range ? 1 : 0;
    m.u_mix = m.branch ? m.y_lo : (m.y_lo ^ m.y_hi);
    const uint64_t prod = static_cast<uint64_t>(m.u_mix) * kGolden;
    m.gold_v = static_cast<uint32_t>(prod);
    m.gold_q = static_cast<uint32_t>(prod >> 32);
    m.h = static_cast<uint8_t>(m.gold_v >> 28);
    return m;
}

// ---------- LogUp tuple fingerprints ----------
// Compress a tuple of small integer coordinates into Fp2 via gamma-powers.
Fp2 Fingerprint(std::initializer_list<uint64_t> coords, Fp2 gamma)
{
    Fp2 acc = Fp2::Zero();
    Fp2 gpow = Fp2::One();
    for (uint64_t c : coords) {
        acc = gkr_field::Add(acc, gkr_field::Mul(gpow, Fp2::FromFp(gkr_field::FromU64(c))));
        gpow = gkr_field::Mul(gpow, gamma);
    }
    return acc;
}

} // namespace

// ===========================================================================
// Preprocessed tables + self-check.
// ===========================================================================

TableTM::TableTM()
{
    for (uint16_t n = 0; n < 16; ++n) {
        bool accepted = false;
        const int8_t v = bmx4::SampleMantissaNibble(static_cast<uint8_t>(n), accepted);
        acc[n] = accepted ? 1 : 0;
        mu[n] = v;
    }
}

TableTX::TableTX()
{
    for (int a = 0; a < 16; ++a)
        for (int b = 0; b < 16; ++b)
            axorb[a * 16 + b] = static_cast<uint8_t>(a ^ b);
}

bool SelfCheckTables()
{
    TableTM tm;
    int accepted = 0;
    for (uint16_t n = 0; n < 16; ++n) {
        bool a = false;
        const int8_t v = bmx4::SampleMantissaNibble(static_cast<uint8_t>(n), a);
        if (tm.acc[n] != (a ? 1 : 0) || tm.mu[n] != v) return false;
        accepted += a ? 1 : 0;
    }
    if (accepted != 11) return false;  // exactly 11 of 16 (matmul_v4_bmx4.cpp)
    TableTX tx;
    for (int a = 0; a < 16; ++a)
        for (int b = 0; b < 16; ++b)
            if (tx.axorb[a * 16 + b] != static_cast<uint8_t>(a ^ b)) return false;
    // Construction II <-> III consistency: the degree-4 acceptance selector
    // polynomial agrees with the T_M reference vector on all 16 nibble codes.
    for (uint16_t n = 0; n < 16; ++n) {
        const Fp b0 = (n >> 0) & 1, b1 = (n >> 1) & 1, b2 = (n >> 2) & 1, b3 = (n >> 3) & 1;
        if (AirAcceptNibblePoly(b0, b1, b2, b3) != gkr_field::FromU64(tm.acc[n])) return false;
    }
    return true;
}

// ===========================================================================
// Dual-alpha LogUp aggregate verification.
// ===========================================================================

namespace {

// Sum over a multiset of 1/(alpha - w_i). FAIL-CLOSED: the log-derivative
// identity has a pole wherever alpha == w_i (denominator zero). At a pole the
// summand is undefined and the multiset-equality guarantee is voided, so we
// MUST reject rather than compute through gkr_field::Inv(0)==0 (which silently
// drops the term and could mask a false membership). Returns false iff any
// denominator is zero; `out` holds the sum on success.
[[nodiscard]] bool FracSum(const std::vector<Fp2>& fps, Fp2 alpha, Fp2& out)
{
    Fp2 acc = Fp2::Zero();
    for (const Fp2& w : fps) {
        const Fp2 denom = gkr_field::Sub(alpha, w);
        if (gkr_field::IsZero(denom)) return false; // alpha collides with a key
        acc = gkr_field::Add(acc, gkr_field::Inv(denom));
    }
    out = acc;
    return true;
}

// Sum over table of m_j/(alpha - t_j). FAIL-CLOSED on a zero denominator for
// the same reason as FracSum.
[[nodiscard]] bool FracSumMult(const std::vector<Fp2>& fps, const std::vector<uint64_t>& mult,
                               Fp2 alpha, Fp2& out)
{
    Fp2 acc = Fp2::Zero();
    for (size_t j = 0; j < fps.size(); ++j) {
        const Fp2 denom = gkr_field::Sub(alpha, fps[j]);
        if (gkr_field::IsZero(denom)) return false; // alpha collides with a table key
        const Fp2 num = Fp2::FromFp(gkr_field::FromU64(mult[j]));
        acc = gkr_field::Add(acc, gkr_field::Div(num, denom));
    }
    out = acc;
    return true;
}

bool InstanceHoldsAt(const LogUpInstance& in, Fp2 alpha, std::string& why)
{
    Fp2 lhs, rhs;
    if (!FracSum(in.witness, alpha, lhs)) {
        why = in.name + ":alpha_collides_witness_key";
        return false;
    }
    if (!FracSumMult(in.table, in.table_mult, alpha, rhs)) {
        why = in.name + ":alpha_collides_table_key";
        return false;
    }
    if (!gkr_field::Eq(lhs, rhs)) { why = in.name + ":sum_mismatch"; return false; }
    return true;
}

} // namespace

LogUpVerifyResult LogUpDualAlphaVerify(const std::vector<LogUpInstance>& instances,
                                       Fp2 alpha1, Fp2 alpha2)
{
    LogUpVerifyResult r;
    uint64_t nw = 0, nt = 0;
    for (const auto& in : instances) {
        nw += in.witness.size();
        nt += in.table.size();
        if (in.table.size() != in.table_mult.size()) {
            r.failure = in.name + ":mult_shape";
            return r;
        }
    }
    r.n_witness = nw;
    r.n_table = nt;

    std::string why1, why2;
    r.sum_ok_a1 = true;
    r.sum_ok_a2 = true;
    for (const auto& in : instances) {
        if (r.sum_ok_a1 && !InstanceHoldsAt(in, alpha1, why1)) r.sum_ok_a1 = false;
        if (r.sum_ok_a2 && !InstanceHoldsAt(in, alpha2, why2)) r.sum_ok_a2 = false;
    }
    r.ok = r.sum_ok_a1 && r.sum_ok_a2;
    if (!r.ok) r.failure = r.sum_ok_a1 ? why2 : why1;

    // Thm 5.2 alpha-collision soundness over Fp2^2: acceptance of a FALSE
    // membership <= ((N_w+N_t)/|Fp2|)^2. Bits = 2*(128 - log2(N_w+N_t)),
    // post-grind subtracts g=40.
    const double n = static_cast<double>(nw + nt);
    const double pre = (n > 0) ? 2.0 * (128.0 - std::log2(n)) : 256.0;
    r.achieved_bits = pre - 40.0;
    return r;
}

// ===========================================================================
// Trace one tile.
// ===========================================================================

TileWitness TraceTile(const TilePublic& pub, const std::array<int64_t, kRCMxBlockLen>& input)
{
    TileWitness w;
    w.pub = pub;
    w.input = input;

    // ---- Scale SHA (in-circuit), byte-exact vs the reference oracle. ----
    ScaleShaTrace st = ScaleShaInCircuit(pub.prf_key, pub.i, pub.bj);
    const uint8_t e_ref = lt::DeriveMatExpandMxScale(pub.prf_key, pub.i, pub.bj);
    assert(st.e == e_ref && "scale SHA AIR must be byte-exact vs reference");
    (void)e_ref;
    w.scale_e = st.e;
    w.scale_byte0 = st.byte0;
    w.scale_sha = std::move(st.blocks);  // committed compression cells

    // ---- ChaCha keystream + rejection sampler (in-circuit). ----
    uint32_t remix = 0;
    uint32_t filled = 0;
    // Build the ChaCha init state exactly as the library does.
    std::array<uint32_t, 8> key_words{};
    for (int k = 0; k < 8; ++k) key_words[k] = ReadLE32(pub.prf_key.data() + 4 * k);
    const uint32_t nonce_first = pub.bj ^ kLaneMxBlock;
    const uint64_t nonce_second = (static_cast<uint64_t>(pub.i) << 32) | pub.bj;

    while (filled < kRCMxBlockLen) {
        std::array<uint32_t, 16> init{};
        init[0] = 0x61707865; init[1] = 0x3320646e; init[2] = 0x79622d32; init[3] = 0x6b206574;
        for (int k = 0; k < 8; ++k) init[4 + k] = key_words[k];
        init[12] = remix;
        init[13] = nonce_first;
        init[14] = static_cast<uint32_t>(nonce_second);
        init[15] = static_cast<uint32_t>(nonce_second >> 32);

        ChaChaBlockTrace ct = ChaChaBlockInCircuit(init);

        // Byte-exactness assertion against the library ChaCha20.
        std::array<std::byte, 32> kb{};
        std::memcpy(kb.data(), pub.prf_key.data(), 32);
        ChaCha20 ref{Span<const std::byte>{kb}};
        ref.Seek(ChaCha20::Nonce96{nonce_first, nonce_second}, remix);
        std::array<std::byte, 64> ref_ks{};
        ref.Keystream(Span<std::byte>{ref_ks});
        for (int b = 0; b < 64; ++b) {
            assert(ct.out_bytes[b] == static_cast<uint8_t>(ref_ks[b]) &&
                   "ChaCha AIR must be byte-exact vs reference");
        }

        w.keystream.insert(w.keystream.end(), ct.out_bytes.begin(), ct.out_bytes.end());

        for (size_t b = 0; b < 64 && filled < kRCMxBlockLen; ++b) {
            const uint8_t byte = ct.out_bytes[b];
            for (uint8_t shift : {0, 4}) {
                if (filled >= kRCMxBlockLen) break;
                const uint8_t nibble = static_cast<uint8_t>((byte >> shift) & 0x0F);
                const int64_t y = input[filled];
                MixBitsWitness mb = MixBitsInCircuit(y);
                const uint8_t mixed = static_cast<uint8_t>((nibble ^ mb.h) & 0x0F);
                bool accepted = false;
                const int8_t mu = bmx4::SampleMantissaNibble(mixed, accepted);

                TileWitness::Cand cand;
                cand.global_c = remix * 128u +
                                static_cast<uint32_t>(2 * b + (shift == 0 ? 0 : 1));
                cand.kappa = nibble;
                cand.pos = filled;
                cand.acc = accepted ? 1 : 0;
                cand.mu = accepted ? mu : 0;
                cand.mixed = mixed;
                cand.h = mb.h;
                cand.y_lo = mb.y_lo;
                cand.y_hi = mb.y_hi;
                cand.y_sign = mb.sign;
                cand.branch = mb.branch;
                cand.u_mix = mb.u_mix;
                cand.gold_q = mb.gold_q;
                cand.gold_v = mb.gold_v;
                // C-E5 liveness inverse: (32 - pos)^{-1} in Fp; pos < 32 on
                // every candidate row, so the inverse exists.
                cand.inv_live = gkr_field::Inv(
                    Sub(gkr_field::FromU64(32), gkr_field::FromU64(filled)));
                w.cands.push_back(cand);

                if (accepted) {
                    w.mantissa[filled] = mu;
                    ++filled;
                }
            }
        }
        w.chacha.push_back(std::move(ct));  // committed ARX cells for the block
        ++remix;
    }
    w.chacha_blocks = remix;

    // ---- Output (C-E10): out[t] = mantissa[t] * 2^e. ----
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        w.out[t] = static_cast<int8_t>(static_cast<int32_t>(w.mantissa[t]) *
                                       (int32_t{1} << w.scale_e));
    }
    return w;
}

// ===========================================================================
// Per-tile constraint check (C-E1..E10 + ChaCha + SHA), pure over cells.
// ===========================================================================

TileCheckResult CheckTileConstraints(const TileWitness& w, const TableTM& tm, const TableTX& tx)
{
    TileCheckResult r;
    std::string fail;

    // ---- ChaCha over COMMITTED cells: init binding (public), per-op ARX
    //      identities, dataflow copies, keystream binding (C-E1 source). ----
    {
        if (w.chacha.size() != w.chacha_blocks ||
            w.keystream.size() != static_cast<size_t>(w.chacha_blocks) * 64) {
            r.failure = "C-E1:chacha_trace_shape"; return r;
        }
        std::array<uint32_t, 8> key_words{};
        for (int k = 0; k < 8; ++k) key_words[k] = ReadLE32(w.pub.prf_key.data() + 4 * k);
        const uint32_t nonce_first = w.pub.bj ^ kLaneMxBlock;
        const uint64_t nonce_second = (static_cast<uint64_t>(w.pub.i) << 32) | w.pub.bj;
        for (uint32_t rmx = 0; rmx < w.chacha_blocks; ++rmx) {
            const ChaChaBlockTrace& ct = w.chacha[rmx];
            // Init binding: the committed init cells equal the PUBLIC init
            // state (constants | key | counter=rmx | nonce) of this tile.
            std::array<uint32_t, 16> init{};
            init[0] = 0x61707865; init[1] = 0x3320646e; init[2] = 0x79622d32; init[3] = 0x6b206574;
            for (int k = 0; k < 8; ++k) init[4 + k] = key_words[k];
            init[12] = rmx; init[13] = nonce_first;
            init[14] = static_cast<uint32_t>(nonce_second);
            init[15] = static_cast<uint32_t>(nonce_second >> 32);
            for (int k = 0; k < 16; ++k) {
                if (ct.init[k] != init[k]) { r.failure = "C-E1:chacha_init_binding"; return r; }
            }
            // Per-op algebraic identities over the committed cells.
            if (!CheckChaChaBlock(ct, fail)) { r.failure = fail; return r; }
            // Dataflow copy constraints (operand wiring + rotation relabels).
            if (!CheckChaChaWiring(ct, fail)) { r.failure = fail; return r; }
            // The committed keystream byte column equals the block's bytes.
            for (int b = 0; b < 64; ++b) {
                const size_t idx = static_cast<size_t>(rmx) * 64 + b;
                if (w.keystream[idx] != ct.out_bytes[b]) {
                    r.failure = "C-E1:chacha_keystream_binding"; return r;
                }
            }
        }
    }

    // ---- Scale SHA over COMMITTED cells: message binding (public), round
    //      identities, block chaining, digest/e binding (C-E10 scale). ----
    {
        const std::vector<std::array<uint32_t, 16>> msg_words =
            ScaleMessageBlockWords(w.pub.prf_key, w.pub.i, w.pub.bj);
        if (w.scale_sha.size() != msg_words.size()) {
            r.failure = "C-E10:scale_sha_shape"; return r;
        }
        for (size_t sb = 0; sb < w.scale_sha.size(); ++sb) {
            const ShaCompressTrace& ct = w.scale_sha[sb];
            // Message binding: committed schedule head equals the PUBLIC words.
            for (int k = 0; k < 16; ++k) {
                if (ct.w[k] != msg_words[sb][k]) { r.failure = "C-E10:scale_msg_binding"; return r; }
            }
            // Chaining: h_in = H0 for block 0, else previous block's h_out.
            for (int k = 0; k < 8; ++k) {
                const uint32_t expect = (sb == 0) ? kSHA_H0[k] : w.scale_sha[sb - 1].h_out[k];
                if (ct.h_in[k] != expect) { r.failure = "C-E10:scale_chain_binding"; return r; }
            }
            if (!CheckShaCompress(ct, fail)) { r.failure = fail; return r; }
        }
        const uint8_t byte0 = static_cast<uint8_t>(w.scale_sha.back().h_out[0] >> 24);
        if (byte0 != w.scale_byte0) { r.failure = "C-E10:scale_byte0"; return r; }
        if (static_cast<uint8_t>(byte0 & 0x3) != w.scale_e) { r.failure = "C-E10:scale_e_bits"; return r; }
    }

    // ---- Sampler rows (C-E1..E9). ----
    uint32_t pos = 0;
    for (size_t idx = 0; idx < w.cands.size(); ++idx) {
        const auto& c = w.cands[idx];

        // C-E1: kappa(c) equals nibble (c mod 128) of the committed keystream.
        const uint32_t cc = c.global_c;
        const uint32_t within = cc % 128;
        const uint32_t blk = cc / 128;
        const size_t byte_idx = static_cast<size_t>(blk) * 64 + within / 2;
        if (byte_idx >= w.keystream.size()) { r.failure = "C-E1:keystream_index"; return r; }
        const uint8_t kbyte = w.keystream[byte_idx];
        const uint8_t knib = static_cast<uint8_t>((within & 1) ? ((kbyte >> 4) & 0xF) : (kbyte & 0xF));
        if (knib != c.kappa) { r.failure = "C-E1:kappa_binding"; return r; }

        // C-E2: position pointer bound to the running pos accumulator.
        if (c.pos != pos) { r.failure = "C-E2:pos_binding"; return r; }

        // C-E5 liveness: (32 - pos) * inv_live = 1 in Fp — a candidate row
        // cannot exist once all 32 positions are filled (no idling).
        if (Mul(Sub(gkr_field::FromU64(32), gkr_field::FromU64(c.pos)), c.inv_live) !=
            gkr_field::FromU64(1)) {
            r.failure = "C-E5:liveness_inverse"; return r;
        }

        // C-E7/E8: MixBits int64 decomposition + branch, bound to committed y.
        const int64_t y = w.input[c.pos];
        const uint64_t u64 = static_cast<uint64_t>(y);
        // two's-complement decomposition identity (committed lo/hi).
        if (c.y_lo != static_cast<uint32_t>(u64) || c.y_hi != static_cast<uint32_t>(u64 >> 32)) {
            r.failure = "C-E7:twos_complement_decomp"; return r;
        }
        if (c.y_sign != static_cast<uint8_t>(c.y_hi >> 31)) { r.failure = "C-E7:sign_bit"; return r; }
        // Field-embedding binding: Fp(lo)+2^32*Fp(hi) == FromSigned(y) + s*(2^32-1).
        {
            const Fp lhs = Add(gkr_field::FromU64(c.y_lo),
                               Mul(gkr_field::FromU64(1ull << 32), gkr_field::FromU64(c.y_hi)));
            const Fp rhs = Add(gkr_field::FromSigned(y),
                               Mul(gkr_field::FromU64(c.y_sign), gkr_field::FromU64((1ull << 32) - 1)));
            if (lhs != rhs) { r.failure = "C-E7:field_embedding_binding"; return r; }
        }
        const bool in_range = (c.y_hi == 0 && (c.y_lo >> 31) == 0) ||
                              (c.y_hi == 0xFFFFFFFFu && (c.y_lo >> 31) == 1);
        if (c.branch != (in_range ? 1 : 0)) { r.failure = "C-E8:branch"; return r; }
        if (c.branch > 1) { r.failure = "C-E8:branch_boolean"; return r; }
        const uint32_t u_expect = c.branch ? c.y_lo : (c.y_lo ^ c.y_hi);
        if (c.u_mix != u_expect) { r.failure = "C-E8:u_mix"; return r; }

        // C-E9: golden mix u*G = q*2^32 + v, h = v>>28.
        const uint64_t prod = static_cast<uint64_t>(c.u_mix) * kGolden;
        if (static_cast<uint64_t>(c.gold_v) + (static_cast<uint64_t>(c.gold_q) << 32) != prod) {
            r.failure = "C-E9:golden_mix_identity"; return r;
        }
        // Canonicity guard q <= G. Over F_p the integer identity above has a
        // SECOND representative for u in {0,1}: (q', v') with q'*2^32 + v' =
        // u*G + p, q' = 2^32 - 1, both limbs still in [0, 2^32). Every such
        // alias has q' > G (since u*G + p >= p forces q' = 2^32-1 > G), so
        // constraining q <= G (range row (G - q) in T_R16) excludes all mod-p
        // aliases and pins (q, v) to the unique integer decomposition.
        if (c.gold_q > kGolden) { r.failure = "C-E9:golden_q_canonical"; return r; }
        if (c.h != static_cast<uint8_t>(c.gold_v >> 28)) { r.failure = "C-E9:h_top_nibble"; return r; }

        // C-E3: mixed = kappa ^ h (T_X membership).
        if (tx.axorb[c.kappa * 16 + c.h] != c.mixed) { r.failure = "C-E3:xor_TX"; return r; }

        // C-E4: (acc, mu) = T_M[mixed] (T_M membership).
        if (tm.acc[c.mixed] != c.acc) { r.failure = "C-E4:acc_TM"; return r; }
        if (c.acc && tm.mu[c.mixed] != c.mu) { r.failure = "C-E4:mu_TM"; return r; }
        if (c.acc > 1) { r.failure = "C-E4:acc_boolean"; return r; }

        // C-E5: pos update.
        if (c.acc) {
            if (c.mu != w.mantissa[c.pos]) { r.failure = "C-E6:mantissa_bind"; return r; }
            ++pos;
        }
    }
    // C-E5 boundary: exactly 32 accepted.
    if (pos != kRCMxBlockLen) { r.failure = "C-E5:boundary_not_32"; return r; }

    // C-E6: acceptance registration is a permutation of {(t, M[t]) : t<32}.
    // Every position filled exactly once (checked by monotone pos above) and
    // the mantissa column matches the accepted rows (checked inline).

    // C-E10: out[t] = M[t] * 2^e with scale = (1+e0)(1+3e1).
    const uint8_t e0 = w.scale_e & 1;
    const uint8_t e1 = (w.scale_e >> 1) & 1;
    const int32_t scale = static_cast<int32_t>((1 + e0) * (1 + 3 * e1));
    if (scale != (int32_t{1} << w.scale_e)) { r.failure = "C-E10:scale_form"; return r; }
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        const int32_t prod = static_cast<int32_t>(w.mantissa[t]) * scale;
        if (w.out[t] != static_cast<int8_t>(prod)) { r.failure = "C-E10:output"; return r; }
    }

    r.ok = true;
    return r;
}

// ===========================================================================
// LogUp tuple emission (T_M / T_X / T_R16) — dual-alpha aggregate feed.
// ===========================================================================

namespace {

// Canonical reference-vector population (Construction III). These are pure
// functions of the consensus tables and gamma — no assignment data enters —
// and are the SINGLE source of the fingerprints for both the emitting side
// (AppendTileLookups) and the regenerating verifier
// (BuildPreprocessedLogUpTables), so the two agree bit-for-bit.
void PopulateCanonicalTM(LogUpInstance& inst, const TableTM& tm, Fp2 gamma)
{
    inst.name = "T_M";
    if (!inst.table.empty()) return;
    for (uint16_t n = 0; n < 16; ++n)
        inst.table.push_back(Fingerprint({n, tm.acc[n],
            static_cast<uint64_t>(static_cast<uint8_t>(tm.mu[n]))}, gamma));
}

void PopulateCanonicalTX(LogUpInstance& inst, const TableTX& tx, Fp2 gamma)
{
    inst.name = "T_X";
    if (!inst.table.empty()) return;
    for (int a = 0; a < 16; ++a)
        for (int b = 0; b < 16; ++b)
            inst.table.push_back(Fingerprint(
                {static_cast<uint64_t>(a), static_cast<uint64_t>(b),
                 tx.axorb[a * 16 + b]}, gamma));
}

void PopulateCanonicalR16(LogUpInstance& inst, Fp2 gamma)
{
    inst.name = "T_R16";
    if (!inst.table.empty()) return;
    for (uint32_t v = 0; v < (1u << 16); ++v)
        inst.table.push_back(Fingerprint({v}, gamma));
}

} // namespace

void AppendTileLookups(const TileWitness& w, const TableTM& tm, const TableTX& tx,
                       Fp2 gamma,
                       LogUpInstance& inst_tm, LogUpInstance& inst_tx,
                       LogUpInstance& inst_r16)
{
    // Reference-vector sides: canonical, idempotent (see Construction III).
    PopulateCanonicalTM(inst_tm, tm, gamma);
    PopulateCanonicalTX(inst_tx, tx, gamma);
    PopulateCanonicalR16(inst_r16, gamma);

    auto emit_r16 = [&](uint32_t v32) {
        inst_r16.witness.push_back(Fingerprint({v32 & 0xFFFF}, gamma));
        inst_r16.witness.push_back(Fingerprint({(v32 >> 16) & 0xFFFF}, gamma));
    };

    for (const auto& c : w.cands) {
        // T_M lookup: (mixed, acc, mu).
        inst_tm.witness.push_back(Fingerprint(
            {c.mixed, c.acc, static_cast<uint64_t>(static_cast<uint8_t>(c.mu))}, gamma));
        // T_X lookup for mixed = kappa ^ h.
        inst_tx.witness.push_back(Fingerprint({c.kappa, c.h, c.mixed}, gamma));
        // T_R16 range lookups for the MixBits 32-bit limbs.
        emit_r16(c.y_lo);
        emit_r16(c.y_hi);
        emit_r16(c.gold_v);
        emit_r16(c.gold_q);
        // C-E9 canonicity: (G - q) in [0, 2^32) excludes the mod-p alias of
        // the golden-mix decomposition (see CheckTileConstraints C-E9 note).
        emit_r16(kGolden - c.gold_q);
    }
}

void FinalizeTableMultiplicities(LogUpInstance& inst_tm, LogUpInstance& inst_tx,
                                 LogUpInstance& inst_r16)
{
    // Multiplicity m_j = number of witness rows equal to table row j.
    auto build_mult = [](LogUpInstance& in) {
        in.table_mult.assign(in.table.size(), 0);
        for (const Fp2& wt : in.witness) {
            for (size_t j = 0; j < in.table.size(); ++j) {
                if (gkr_field::Eq(wt, in.table[j])) { in.table_mult[j] += 1; break; }
            }
        }
    };
    build_mult(inst_tm);
    build_mult(inst_tx);
    build_mult(inst_r16);
}

// ===========================================================================
// CONSTRUCTION II — the Extract map as explicit degree-<=4 polynomial
// identities over F_p, combined into ONE composition polynomial.
//
// COMPLETENESS: TraceTile() populates the committed cells by evaluating the
// reference primitives, so every emitted identity below evaluates to the zero
// field element on an honest assignment (the tests assert Compose ok == true
// and, independently, byte-exactness against ExtractMXTileInt64).
// SEPARATION: an invalid assignment makes at least one C_slot(x*) != 0; the
// row composition sum_slot eta^slot C_slot(x*) then vanishes for at most
// (n_slots-1)/|Fp2| of the eta (Schwartz-Zippel on the slot polynomial):
// n_slots <= kAirSlotBudget = 256  =>  <= 2^8/2^128 = 2^-120 pre-grinding,
// 2^-80 after the g=40 grinding convention.
// ===========================================================================

Fp AirXorBit(Fp x, Fp y)
{
    return Sub(Add(x, y), Mul(gkr_field::FromU64(2), Mul(x, y)));
}

Fp AirXor3Bit(Fp x, Fp y, Fp z) { return AirXorBit(AirXorBit(x, y), z); }

Fp AirMajBit(Fp a, Fp b, Fp c)
{
    const Fp ab = Mul(a, b);
    return Sub(Add(Add(ab, Mul(a, c)), Mul(b, c)), Mul(gkr_field::FromU64(2), Mul(ab, c)));
}

Fp AirChBit(Fp a, Fp b, Fp c) { return Add(c, Mul(a, Sub(b, c))); }

Fp AirBool(Fp b) { return Mul(b, Sub(b, gkr_field::FromU64(1))); }

Fp AirAcceptNibblePoly(Fp b0, Fp b1, Fp b2, Fp b3)
{
    const Fp one = gkr_field::FromU64(1);
    // rejected(n) = (1-b2) * ((1-b3)*b0 + b3*(1 - b1 + b1*b0)); exactly 1 on
    // the rejected E2M1 codes {1,3,8,9,11} and 0 on the 11 accepted codes.
    const Fp inner = Add(Mul(Sub(one, b3), b0),
                         Mul(b3, Add(Sub(one, b1), Mul(b1, b0))));
    const Fp rejected = Mul(Sub(one, b2), inner);
    return Sub(one, rejected);
}

void RCAirConstraintSet::Push(uint64_t row, uint32_t slot, const char* family, Fp value)
{
    entries.push_back(Entry{row, slot, family, gkr_field::Canonical(value)});
    if (row + 1 > n_rows) n_rows = row + 1;
    if (slot + 1 > n_slots) n_slots = slot + 1;
}

RCAirConstraintSet EmitTileConstraints(const TileWitness& w)
{
    RCAirConstraintSet cs;
    uint64_t row = 0;
    const Fp one = gkr_field::FromU64(1);
    auto U = [](uint64_t v) { return gkr_field::FromU64(v); };
    auto bitf = [&](uint32_t word, int i) -> Fp { return U((word >> i) & 1u); };
    auto pow2 = [&](int i) -> Fp { return U(1ull << i); };  // i < 63

    // Word bit package: booleanity b_i(b_i - 1) on slots [base, base+32) and
    // recomposition sum_i 2^i b_i - v on slot rslot. (In the committed layout
    // the b_i are their own columns; here they are the canonical decomposition
    // of the committed word cell, so booleanity doubles as documentation and
    // the binding force lives in the cross-cell identities.)
    auto emit_word_bits = [&](uint64_t r, uint32_t base, uint32_t rslot,
                              const char* fam_bool, const char* fam_recomp, uint32_t word) {
        Fp recomp = U(0);
        for (int i = 0; i < 32; ++i) {
            const Fp bi = bitf(word, i);
            cs.Push(r, base + i, fam_bool, AirBool(bi));
            recomp = Add(recomp, Mul(pow2(i), bi));
        }
        cs.Push(r, rslot, fam_recomp, Sub(recomp, U(word)));
    };

    // ---------------- ChaCha20 ARX blocks ----------------
    std::array<uint32_t, 8> key_words{};
    for (int k = 0; k < 8; ++k) key_words[k] = ReadLE32(w.pub.prf_key.data() + 4 * k);
    const uint32_t nonce_first = w.pub.bj ^ kLaneMxBlock;
    const uint64_t nonce_second = (static_cast<uint64_t>(w.pub.i) << 32) | w.pub.bj;

    if (w.chacha.size() != w.chacha_blocks ||
        w.keystream.size() != static_cast<size_t>(w.chacha_blocks) * 64) {
        cs.Push(row++, 0, "cc.trace_shape", one);
    }
    for (uint32_t bl = 0; bl < w.chacha.size(); ++bl) {
        const ChaChaBlockTrace& t = w.chacha[bl];
        // Init binding: committed init cells equal the PUBLIC init state.
        {
            std::array<uint32_t, 16> init{};
            init[0] = 0x61707865; init[1] = 0x3320646e; init[2] = 0x79622d32; init[3] = 0x6b206574;
            for (int k = 0; k < 8; ++k) init[4 + k] = key_words[k];
            init[12] = bl; init[13] = nonce_first;
            init[14] = static_cast<uint32_t>(nonce_second);
            init[15] = static_cast<uint32_t>(nonce_second >> 32);
            const uint64_t r = row++;
            for (int k = 0; k < 16; ++k)
                cs.Push(r, k, "cc.init_binding", Sub(U(t.init[k]), U(init[k])));
        }
        if (t.adds.size() != 336 || t.xors.size() != 320) {
            cs.Push(row++, 0, "cc.block_shape", one);
            continue;
        }
        // Operand copy constraint: committed operand cell minus its scheduled
        // provenance. A rotation is the fixed index relabeling of the
        // producing xor's bit columns: op - sum_i 2^{(i+rot) mod 32} b_i = 0.
        auto operand_copy = [&](uint64_t r, uint32_t slot, const char* fam,
                                uint32_t opcell, const WordRef& ref) {
            if (ref.xor_src < 0) {
                cs.Push(r, slot, fam, Sub(U(opcell), U(ref.value)));
            } else {
                const uint32_t src = t.xors[static_cast<size_t>(ref.xor_src)][2];
                Fp relab = U(0);
                for (int i = 0; i < 32; ++i)
                    relab = Add(relab, Mul(pow2((i + ref.rot) % 32), bitf(src, i)));
                cs.Push(r, slot, fam, Sub(U(opcell), relab));
            }
        };
        std::array<WordRef, 16> fin{};
        (void)WalkChaChaSchedule(
            t,
            [&](size_t ai, const WordRef& aref, const WordRef& bref) {
                const ChaChaAdd& ad = t.adds[ai];
                const uint64_t r = row++;
                emit_word_bits(r, 0, 96, "cc.add.a.bool", "cc.add.a.recomp", ad.a);
                emit_word_bits(r, 32, 97, "cc.add.b.bool", "cc.add.b.recomp", ad.b);
                emit_word_bits(r, 64, 98, "cc.add.r.bool", "cc.add.r.recomp", ad.r);
                // add mod 2^32: a + b - r - 2^32*carry = 0; carry boolean.
                cs.Push(r, 99, "cc.add.identity",
                        Sub(Sub(Add(U(ad.a), U(ad.b)), U(ad.r)),
                            Mul(U(1ull << 32), U(ad.carry))));
                cs.Push(r, 100, "cc.add.carry.bool", AirBool(U(ad.carry)));
                operand_copy(r, 101, "cc.add.copy_a", ad.a, aref);
                operand_copy(r, 102, "cc.add.copy_b", ad.b, bref);
            },
            [&](size_t xi, const WordRef& xref, const WordRef& yref) {
                const auto& xr = t.xors[xi];
                const uint64_t r = row++;
                emit_word_bits(r, 0, 96, "cc.xor.x.bool", "cc.xor.x.recomp", xr[0]);
                emit_word_bits(r, 32, 97, "cc.xor.y.bool", "cc.xor.y.recomp", xr[1]);
                emit_word_bits(r, 64, 98, "cc.xor.r.bool", "cc.xor.r.recomp", xr[2]);
                // xor per bit: x_i + y_i - 2 x_i y_i - r_i = 0 (degree 2).
                for (int i = 0; i < 32; ++i)
                    cs.Push(r, 99 + i, "cc.xor.bit",
                            Sub(AirXorBit(bitf(xr[0], i), bitf(xr[1], i)), bitf(xr[2], i)));
                operand_copy(r, 131, "cc.xor.copy_x", xr[0], xref);
                operand_copy(r, 132, "cc.xor.copy_y", xr[1], yref);
            },
            &fin);
        // Final-state binding (rotation relabels resolved via provenance).
        {
            const uint64_t r = row++;
            for (int k = 0; k < 16; ++k)
                operand_copy(r, k, "cc.final_binding", t.final_working[k], fin[k]);
        }
        // Keystream words: feed-forward copy, LE byte decomposition, and the
        // global keystream byte-column copy (the C-E1 source cells).
        const bool ks_ok = w.keystream.size() >= (static_cast<size_t>(bl) + 1) * 64;
        for (int k = 0; k < 16; ++k) {
            const uint64_t r = row++;
            cs.Push(r, 0, "cc.ks.ff_copy",
                    Sub(U(t.keystream_words[k]), U(t.adds[320 + k].r)));
            Fp bytes = U(0);
            for (int b = 0; b < 4; ++b) {
                bytes = Add(bytes, Mul(U(1ull << (8 * b)), U(t.out_bytes[4 * k + b])));
                const Fp global = ks_ok ? U(w.keystream[static_cast<size_t>(bl) * 64 + 4 * k + b]) : U(0);
                cs.Push(r, 2 + b, "cc.ks.byte_copy", Sub(U(t.out_bytes[4 * k + b]), global));
            }
            cs.Push(r, 1, "cc.ks.byte_decomp", Sub(U(t.keystream_words[k]), bytes));
        }
    }

    // ---------------- SHA-256 scale compression blocks ----------------
    const std::vector<std::array<uint32_t, 16>> msg_words =
        ScaleMessageBlockWords(w.pub.prf_key, w.pub.i, w.pub.bj);
    if (w.scale_sha.size() != msg_words.size()) cs.Push(row++, 0, "sha.shape", one);
    const size_t n_sha = std::min(w.scale_sha.size(), msg_words.size());
    for (size_t sb = 0; sb < n_sha; ++sb) {
        const ShaCompressTrace& t = w.scale_sha[sb];
        // Message binding: committed schedule head equals the PUBLIC words.
        {
            const uint64_t r = row++;
            for (int k = 0; k < 16; ++k)
                cs.Push(r, k, "sha.msg_binding", Sub(U(t.w[k]), U(msg_words[sb][k])));
        }
        // Chain binding: h_in = H0 (block 0) or previous h_out; vars[0] = h_in.
        {
            const uint64_t r = row++;
            for (int k = 0; k < 8; ++k) {
                const uint32_t expect = (sb == 0) ? kSHA_H0[k] : w.scale_sha[sb - 1].h_out[k];
                cs.Push(r, k, "sha.chain_binding", Sub(U(t.h_in[k]), U(expect)));
                cs.Push(r, 8 + k, "sha.var0_binding", Sub(U(t.vars[0][k]), U(t.h_in[k])));
            }
        }
        // Message schedule: w[i] = w[i-16] + sigma0(w[i-15]) + w[i-7] +
        // sigma1(w[i-2]) mod 2^32, with sigma as xor-of-relabelings and the
        // shift as a truncated relabel (top bits xor a zero column).
        for (int i = 16; i < 64; ++i) {
            const uint64_t r = row++;
            const uint32_t w15 = t.w[i - 15], w2 = t.w[i - 2];
            emit_word_bits(r, 16, 208, "sha.sched.w15.bool", "sha.sched.w15.recomp", w15);
            emit_word_bits(r, 48, 209, "sha.sched.w2.bool", "sha.sched.w2.recomp", w2);
            Fp s0 = U(0), s1 = U(0);
            for (int i2 = 0; i2 < 32; ++i2) {
                const Fp a7 = bitf(w15, (i2 + 7) % 32);
                const Fp a18 = bitf(w15, (i2 + 18) % 32);
                const Fp a3 = (i2 <= 28) ? bitf(w15, i2 + 3) : U(0);
                s0 = Add(s0, Mul(pow2(i2), AirXor3Bit(a7, a18, a3)));
                const Fp b17 = bitf(w2, (i2 + 17) % 32);
                const Fp b19 = bitf(w2, (i2 + 19) % 32);
                const Fp b10 = (i2 <= 21) ? bitf(w2, i2 + 10) : U(0);
                s1 = Add(s1, Mul(pow2(i2), AirXor3Bit(b17, b19, b10)));
            }
            const uint32_t s0u = Rotr32(w15, 7) ^ Rotr32(w15, 18) ^ (w15 >> 3);
            const uint32_t s1u = Rotr32(w2, 17) ^ Rotr32(w2, 19) ^ (w2 >> 10);
            const uint64_t sum = static_cast<uint64_t>(t.w[i - 16]) + s0u +
                                 static_cast<uint64_t>(t.w[i - 7]) + s1u;
            const uint64_t carry = sum >> 32;  // <= 3: two carry bits
            cs.Push(r, 0, "sha.sched.identity",
                    Sub(Sub(Add(Add(Add(U(t.w[i - 16]), s0), U(t.w[i - 7])), s1), U(t.w[i])),
                        Mul(U(1ull << 32), U(carry))));
            cs.Push(r, 8, "sha.sched.carry.b0", AirBool(U(carry & 1)));
            cs.Push(r, 9, "sha.sched.carry.b1", AirBool(U((carry >> 1) & 1)));
        }
        // Round function: Ch/Maj/Sigma as bit polynomials; adds carry-witnessed.
        for (int i = 0; i < 64; ++i) {
            const uint64_t r = row++;
            const auto& p = t.vars[i];
            const auto& n = t.vars[i + 1];
            const uint32_t a = p[0], b = p[1], c = p[2], e = p[4], f = p[5], g = p[6];
            emit_word_bits(r, 16, 208, "sha.rnd.e.bool", "sha.rnd.e.recomp", e);
            emit_word_bits(r, 48, 209, "sha.rnd.f.bool", "sha.rnd.f.recomp", f);
            emit_word_bits(r, 80, 210, "sha.rnd.g.bool", "sha.rnd.g.recomp", g);
            emit_word_bits(r, 112, 211, "sha.rnd.a.bool", "sha.rnd.a.recomp", a);
            emit_word_bits(r, 144, 212, "sha.rnd.b.bool", "sha.rnd.b.recomp", b);
            emit_word_bits(r, 176, 213, "sha.rnd.c.bool", "sha.rnd.c.recomp", c);
            Fp S1 = U(0), S0 = U(0), ch = U(0), maj = U(0);
            for (int i2 = 0; i2 < 32; ++i2) {
                S1 = Add(S1, Mul(pow2(i2), AirXor3Bit(bitf(e, (i2 + 6) % 32),
                                                      bitf(e, (i2 + 11) % 32),
                                                      bitf(e, (i2 + 25) % 32))));
                S0 = Add(S0, Mul(pow2(i2), AirXor3Bit(bitf(a, (i2 + 2) % 32),
                                                      bitf(a, (i2 + 13) % 32),
                                                      bitf(a, (i2 + 22) % 32))));
                ch = Add(ch, Mul(pow2(i2), AirChBit(bitf(e, i2), bitf(f, i2), bitf(g, i2))));
                maj = Add(maj, Mul(pow2(i2), AirMajBit(bitf(a, i2), bitf(b, i2), bitf(c, i2))));
            }
            const uint32_t S1u = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
            const uint32_t chu = (e & f) ^ ((~e) & g);
            const uint32_t S0u = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
            const uint32_t maju = (a & b) ^ (a & c) ^ (b & c);
            const uint64_t sumE = static_cast<uint64_t>(p[3]) + p[7] + S1u + chu +
                                  kSHA_K[i] + t.w[i];
            const uint64_t carryE = sumE >> 32;  // <= 5: three carry bits
            const uint64_t sumA = static_cast<uint64_t>(p[7]) + S1u + chu + kSHA_K[i] +
                                  t.w[i] + S0u + maju;
            const uint64_t carryA = sumA >> 32;  // <= 6: three carry bits
            const Fp lhsE = Add(Add(Add(Add(Add(U(p[3]), U(p[7])), S1), ch),
                                    U(kSHA_K[i])), U(t.w[i]));
            cs.Push(r, 0, "sha.rnd.e_update",
                    Sub(Sub(lhsE, U(n[4])), Mul(U(1ull << 32), U(carryE))));
            const Fp lhsA = Add(Add(Add(Add(Add(Add(U(p[7]), S1), ch), U(kSHA_K[i])),
                                        U(t.w[i])), S0), maj);
            cs.Push(r, 1, "sha.rnd.a_update",
                    Sub(Sub(lhsA, U(n[0])), Mul(U(1ull << 32), U(carryA))));
            cs.Push(r, 2, "sha.rnd.shift_b", Sub(U(n[1]), U(p[0])));
            cs.Push(r, 3, "sha.rnd.shift_c", Sub(U(n[2]), U(p[1])));
            cs.Push(r, 4, "sha.rnd.shift_d", Sub(U(n[3]), U(p[2])));
            cs.Push(r, 5, "sha.rnd.shift_f", Sub(U(n[5]), U(p[4])));
            cs.Push(r, 6, "sha.rnd.shift_g", Sub(U(n[6]), U(p[5])));
            cs.Push(r, 7, "sha.rnd.shift_h", Sub(U(n[7]), U(p[6])));
            for (int cb = 0; cb < 3; ++cb) {
                cs.Push(r, 8 + cb, "sha.rnd.carryE.bool", AirBool(U((carryE >> cb) & 1)));
                cs.Push(r, 11 + cb, "sha.rnd.carryA.bool", AirBool(U((carryA >> cb) & 1)));
            }
        }
        // Feed-forward digest adds.
        {
            const uint64_t r = row++;
            for (int k = 0; k < 8; ++k) {
                const uint64_t sum = static_cast<uint64_t>(t.h_in[k]) + t.vars[64][k];
                const uint64_t carry = sum >> 32;
                cs.Push(r, k, "sha.ff.identity",
                        Sub(Sub(Add(U(t.h_in[k]), U(t.vars[64][k])), U(t.h_out[k])),
                            Mul(U(1ull << 32), U(carry))));
                cs.Push(r, 8 + k, "sha.ff.carry.bool", AirBool(U(carry)));
            }
        }
    }
    // Digest -> scale binding: byte0 is the top byte of h_out[0]; e = byte0
    // mod 4 via the two selector bits e0, e1 (used degree-3 in out.dequant).
    if (!w.scale_sha.empty()) {
        const uint64_t r = row++;
        const uint32_t h0 = w.scale_sha.back().h_out[0];
        const uint32_t low24 = h0 & 0xFFFFFFu;  // limb; ranged via T_R16/T_B rows
        cs.Push(r, 0, "scale.byte0_decomp",
                Sub(U(h0), Add(Mul(U(1ull << 24), U(w.scale_byte0)), U(low24))));
        const Fp e0 = U(w.scale_byte0 & 1);
        const Fp e1 = U((w.scale_byte0 >> 1) & 1);
        cs.Push(r, 1, "scale.e0_bind", Sub(e0, U(w.scale_e & 1)));
        cs.Push(r, 2, "scale.e1_bind", Sub(e1, U((w.scale_e >> 1) & 1)));
        cs.Push(r, 3, "scale.e_recomp",
                Sub(U(w.scale_e), Add(U(w.scale_e & 1),
                                      Mul(U(2), U((w.scale_e >> 1) & 1)))));
        cs.Push(r, 4, "scale.e0.bool", AirBool(e0));
        cs.Push(r, 5, "scale.e1.bool", AirBool(e1));
    }

    // ---------------- Sampler candidate rows (C-E1..E9) ----------------
    const uint64_t two32m1 = (1ull << 32) - 1;
    for (size_t ci = 0; ci < w.cands.size(); ++ci) {
        const auto& c = w.cands[ci];
        const uint64_t r = row++;
        // C-E1: kappa binds to the committed keystream byte column.
        const uint32_t within = c.global_c % 128;
        const size_t byte_idx = static_cast<size_t>(c.global_c / 128) * 64 + within / 2;
        const uint8_t kbyte = (byte_idx < w.keystream.size()) ? w.keystream[byte_idx] : 0;
        if (byte_idx >= w.keystream.size()) cs.Push(r, 40, "samp.kappa.index", one);
        const Fp nlo = U(kbyte & 0xF), nhi = U((kbyte >> 4) & 0xF);
        cs.Push(r, 0, "samp.byte_decomp", Sub(U(kbyte), Add(nlo, Mul(U(16), nhi))));
        cs.Push(r, 1, "samp.kappa_copy", Sub(U(c.kappa), (within & 1) ? nhi : nlo));
        // Nibble bit columns for kappa, h, mixed.
        Fp kb[4], hb[4], mb[4];
        for (int i = 0; i < 4; ++i) {
            kb[i] = U((c.kappa >> i) & 1);
            hb[i] = U((c.h >> i) & 1);
            mb[i] = U((c.mixed >> i) & 1);
            cs.Push(r, 2 + i, "samp.kappa.bool", AirBool(kb[i]));
            cs.Push(r, 6 + i, "samp.h.bool", AirBool(hb[i]));
            cs.Push(r, 10 + i, "samp.mixed.bool", AirBool(mb[i]));
        }
        Fp krec = U(0), hrec = U(0), mrec = U(0), mxor = U(0);
        for (int i = 0; i < 4; ++i) {
            krec = Add(krec, Mul(pow2(i), kb[i]));
            hrec = Add(hrec, Mul(pow2(i), hb[i]));
            mrec = Add(mrec, Mul(pow2(i), mb[i]));
            mxor = Add(mxor, Mul(pow2(i), AirXorBit(kb[i], hb[i])));
        }
        cs.Push(r, 14, "samp.kappa.recomp", Sub(krec, U(c.kappa)));
        cs.Push(r, 15, "samp.h.recomp", Sub(hrec, U(c.h)));
        cs.Push(r, 16, "samp.mixed.recomp", Sub(mrec, U(c.mixed)));
        // C-E3: mixed = kappa XOR h, per bit.
        cs.Push(r, 17, "samp.mixed_xor", Sub(U(c.mixed), mxor));
        // C-E4 acceptance selector as a degree-4 polynomial in mixed's bits.
        cs.Push(r, 18, "samp.acc.bool", AirBool(U(c.acc)));
        cs.Push(r, 19, "samp.accept_poly",
                Sub(U(c.acc), AirAcceptNibblePoly(mb[0], mb[1], mb[2], mb[3])));
        // C-E5: liveness inverse + position transition.
        cs.Push(r, 20, "samp.liveness",
                Sub(Mul(Sub(U(32), U(c.pos)), c.inv_live), one));
        const uint64_t next_pos = (ci + 1 < w.cands.size()) ? w.cands[ci + 1].pos : 32;
        cs.Push(r, 21, "samp.pos_transition", Sub(U(next_pos), Add(U(c.pos), U(c.acc))));
        // C-E6 registration: acc * (mu - M[pos]) = 0.
        const Fp Mpos = (c.pos < kRCMxBlockLen) ? gkr_field::FromSigned(w.mantissa[c.pos]) : U(0);
        cs.Push(r, 22, "samp.mantissa_reg",
                Mul(U(c.acc), Sub(gkr_field::FromSigned(c.mu), Mpos)));
        // C-E7: two's-complement embedding lo + 2^32 hi = y + s(2^32-1) mod p.
        // Unique over the ranged limbs: the mod-p alias flips s inconsistently
        // with hi's top bit (see CheckTileConstraints).
        const int64_t y = (c.pos < kRCMxBlockLen) ? w.input[c.pos] : 0;
        cs.Push(r, 23, "samp.embed",
                Sub(Sub(Add(U(c.y_lo), Mul(U(1ull << 32), U(c.y_hi))),
                        gkr_field::FromSigned(y)),
                    Mul(U(c.y_sign), U(two32m1))));
        cs.Push(r, 24, "samp.sign_bind", Sub(U(c.y_sign), U((c.y_hi >> 31) & 1)));
        cs.Push(r, 25, "samp.sign.bool", AirBool(U(c.y_sign)));
        // C-E8 branch: zero-test selectors t0 = [hi = 0], t1 = [hi = 2^32-1]
        // with inverse witnesses; b = t0(1-lt) + t1 lt, lt = top bit of lo.
        const Fp hiF = U(c.y_hi);
        const Fp hiM = Sub(hiF, U(two32m1));
        const Fp t0 = (c.y_hi == 0) ? one : U(0);
        const Fp w0 = (c.y_hi == 0) ? U(0) : gkr_field::Inv(hiF);
        const Fp t1 = (c.y_hi == 0xFFFFFFFFu) ? one : U(0);
        const Fp w1 = (c.y_hi == 0xFFFFFFFFu) ? U(0) : gkr_field::Inv(hiM);
        cs.Push(r, 26, "samp.t0.zero", Mul(hiF, t0));
        cs.Push(r, 27, "samp.t0.inv", Sub(Add(t0, Mul(hiF, w0)), one));
        cs.Push(r, 28, "samp.t1.zero", Mul(hiM, t1));
        cs.Push(r, 29, "samp.t1.inv", Sub(Add(t1, Mul(hiM, w1)), one));
        cs.Push(r, 30, "samp.t0.bool", AirBool(t0));
        cs.Push(r, 31, "samp.t1.bool", AirBool(t1));
        const Fp lt = U((c.y_lo >> 31) & 1);
        cs.Push(r, 32, "samp.branch_def",
                Sub(U(c.branch), Add(Mul(t0, Sub(one, lt)), Mul(t1, lt))));
        cs.Push(r, 33, "samp.branch.bool", AirBool(U(c.branch)));
        // u = b*lo + (1-b)*(lo XOR hi), the 32-bit xor as a bit polynomial.
        Fp xw = U(0);
        for (int i = 0; i < 32; ++i)
            xw = Add(xw, Mul(pow2(i), AirXorBit(U((c.y_lo >> i) & 1), U((c.y_hi >> i) & 1))));
        cs.Push(r, 34, "samp.u_mix",
                Sub(U(c.u_mix),
                    Add(Mul(U(c.branch), U(c.y_lo)), Mul(Sub(one, U(c.branch)), xw))));
        // C-E9: u*G = q*2^32 + v (exact over F_p: u*G < p) and h = v >> 28.
        // The q <= G canonicity that excludes the mod-p alias is a T_R16
        // range obligation on (G - q) — membership, not an identity.
        cs.Push(r, 35, "samp.golden",
                Sub(Mul(U(c.u_mix), U(kGolden)),
                    Add(Mul(U(1ull << 32), U(c.gold_q)), U(c.gold_v))));
        Fp hn = U(0);
        for (int i = 28; i < 32; ++i)
            hn = Add(hn, Mul(pow2(i - 28), U((c.gold_v >> i) & 1)));
        cs.Push(r, 36, "samp.h_nibble", Sub(U(c.h), hn));
    }
    // Boundary row: pos(0) = 0 and pos_final = 32 (C-E5 boundary).
    {
        const uint64_t r = row++;
        const Fp pos0 = w.cands.empty() ? one : U(w.cands.front().pos);
        const Fp posL = w.cands.empty() ? one
                        : Add(U(w.cands.back().pos), U(w.cands.back().acc));
        cs.Push(r, 0, "samp.boundary_first", pos0);
        cs.Push(r, 1, "samp.boundary_last", Sub(posL, U(32)));
    }
    // C-E10 output rows: out[t] - M[t]*(1+e0)(1+3e1) = 0 (degree 3).
    {
        const Fp e0 = U(w.scale_e & 1);
        const Fp e1 = U((w.scale_e >> 1) & 1);
        const Fp scale = Mul(Add(one, e0), Add(one, Mul(U(3), e1)));
        for (uint32_t t2 = 0; t2 < kRCMxBlockLen; ++t2) {
            const uint64_t r = row++;
            cs.Push(r, 0, "out.dequant",
                    Sub(gkr_field::FromSigned(w.out[t2]),
                        Mul(gkr_field::FromSigned(w.mantissa[t2]), scale)));
        }
    }
    return cs;
}

CompositionResult ComposeConstraints(const RCAirConstraintSet& cs, Fp2 eta)
{
    CompositionResult res;
    res.n_rows = cs.n_rows;
    res.n_slots = cs.n_slots;
    res.n_constraints = cs.entries.size();

    std::vector<Fp2> pow(cs.n_slots == 0 ? 1 : cs.n_slots);
    pow[0] = Fp2::One();
    for (size_t i = 1; i < pow.size(); ++i) pow[i] = gkr_field::Mul(pow[i - 1], eta);

    // Comp(x) = sum_slot eta^slot * C_slot(x), accumulated per row; the check
    // is that Comp vanishes on the ENTIRE domain (all rows).
    std::vector<Fp2> comp(res.n_rows, Fp2::Zero());
    for (const auto& en : cs.entries) {
        if (gkr_field::Canonical(en.value) == 0) continue;
        comp[en.row] = gkr_field::Add(comp[en.row],
                                      gkr_field::Mul(pow[en.slot], Fp2::FromFp(en.value)));
    }
    res.ok = true;
    for (uint64_t x = 0; x < res.n_rows; ++x) {
        if (!gkr_field::IsZero(comp[x])) {
            res.ok = false;
            res.first_bad_row = x;
            for (const auto& en : cs.entries) {
                if (en.row == x && gkr_field::Canonical(en.value) != 0) {
                    if (!res.first_bad_families.empty()) res.first_bad_families += ",";
                    res.first_bad_families += en.family;
                }
            }
            break;
        }
    }
    const double log2p2 = 2.0 * std::log2(static_cast<double>(gkr_field::kP));
    const double k = std::max<double>(1.0, static_cast<double>(res.n_slots) - 1.0);
    res.soundness_bits = log2p2 - std::log2(k) - 40.0;
    return res;
}

SeparationBound ComputeSeparationBound(uint32_t n_slots, uint64_t n_logup_rows)
{
    SeparationBound b;
    const double log2p2 = 2.0 * std::log2(static_cast<double>(gkr_field::kP));  // ~128
    const double k = std::max<double>(1.0, static_cast<double>(n_slots) - 1.0);
    b.composition_bits = log2p2 - std::log2(k) - 40.0;
    const double n = std::max<double>(1.0, static_cast<double>(n_logup_rows));
    b.lookup_bits = 2.0 * (log2p2 - std::log2(n)) - 40.0;
    const double lo = std::min(b.composition_bits, b.lookup_bits);
    const double hi = std::max(b.composition_bits, b.lookup_bits);
    b.composed_bits = lo - std::log2(1.0 + std::pow(2.0, lo - hi));
    return b;
}

// ===========================================================================
// CONSTRUCTION III — membership against the FIXED reference vectors.
// ===========================================================================

RCAirPreprocessedTables BuildPreprocessedLogUpTables(Fp2 gamma)
{
    // Pure function of the consensus tables and gamma; regenerable by any
    // verifier build with NO assignment data (blueprint §5.3: "the table side
    // of every LogUp instance is not prover data").
    RCAirPreprocessedTables p;
    const TableTM tm;
    const TableTX tx;
    PopulateCanonicalTM(p.tm, tm, gamma);
    PopulateCanonicalTX(p.tx, tx, gamma);
    PopulateCanonicalR16(p.r16, gamma);
    return p;
}

LookupBindResult VerifyLookupAgainstPreprocessed(const std::vector<LogUpInstance>& instances,
                                                 Fp2 gamma, Fp2 alpha1, Fp2 alpha2)
{
    LookupBindResult out;
    const RCAirPreprocessedTables canon = BuildPreprocessedLogUpTables(gamma);
    for (const auto& in : instances) {
        const LogUpInstance* c = nullptr;
        if (in.name == "T_M") c = &canon.tm;
        else if (in.name == "T_X") c = &canon.tx;
        else if (in.name == "T_R16") c = &canon.r16;
        if (c == nullptr) {
            out.failure = in.name + ":unknown_table";
            return out;
        }
        // (i) Reference-vector equality: the supplied table side must match
        // the independently regenerated canonical vector fingerprint-for-
        // fingerprint. A vector chosen by the constructing routine (e.g. the
        // Theorem-5.1 clone table := witness) is rejected HERE, regardless of
        // whether its fractional sums happen to balance.
        if (in.table.size() != c->table.size()) {
            out.failure = in.name + ":table_not_canonical";
            return out;
        }
        for (size_t j = 0; j < in.table.size(); ++j) {
            if (!gkr_field::Eq(in.table[j], c->table[j])) {
                out.failure = in.name + ":table_not_canonical";
                return out;
            }
        }
        // (ii) Multiplicity accounting: sum_j m_j = |W| exactly. Together
        // with the dual-alpha identity this pins each m_j to the exact
        // occurrence count (S3: char F_p >> N, no wraparound).
        if (in.table_mult.size() != in.table.size()) {
            out.failure = in.name + ":mult_shape";
            return out;
        }
        uint64_t msum = 0;
        for (uint64_t m : in.table_mult) {
            const uint64_t next = msum + m;
            if (next < msum) {
                out.failure = in.name + ":mult_overflow";
                return out;
            }
            msum = next;
        }
        if (msum != in.witness.size()) {
            out.failure = in.name + ":multiplicity_sum";
            return out;
        }
    }
    // (iii) Dual-alpha log-derivative identity; FAIL-CLOSED on any pole
    // (alpha colliding with a key) via FracSum/FracSumMult.
    out.logup = LogUpDualAlphaVerify(instances, alpha1, alpha2);
    if (!out.logup.ok) {
        out.failure = out.logup.failure;
        return out;
    }
    out.ok = true;
    return out;
}

// ===========================================================================
// End-to-end byte-exactness vs the immutable reference.
// ===========================================================================

bool ByteExactVsReference(const TilePublic& pub,
                          const std::array<int64_t, kRCMxBlockLen>& input)
{
    TileWitness w = TraceTile(pub, input);
    std::array<int8_t, kRCMxBlockLen> ref{};
    ExtractMXTileInt64(pub.prf_key, pub.i, pub.bj, input.data(), ref.data());
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        if (w.out[t] != ref[t]) return false;
    }
    return true;
}

// ===========================================================================
// AIR-level intermediate tamper hooks.
// ===========================================================================

bool ChaChaIntermediateTamperRejected()
{
    std::array<uint32_t, 16> init{};
    init[0] = 0x61707865; init[1] = 0x3320646e; init[2] = 0x79622d32; init[3] = 0x6b206574;
    for (int k = 0; k < 8; ++k) init[4 + k] = 0x11111111u * (k + 1);
    init[12] = 7; init[13] = 0xDEADBEEFu; init[14] = 0x01234567u; init[15] = 0x89ABCDEFu;

    ChaChaBlockTrace t = ChaChaBlockInCircuit(init);
    std::string fail;
    if (!CheckChaChaBlock(t, fail)) return false;  // honest trace must pass
    // Tamper a mid-round quarter-round add result (a committed ARX cell).
    if (t.adds.size() < 40) return false;
    t.adds[37].r ^= 0x00010000u;  // flip a bit of an intermediate add output
    return !CheckChaChaBlock(t, fail);  // must now be rejected
}

bool ShaIntermediateTamperRejected()
{
    std::array<uint32_t, 8> h = kSHA_H0;
    std::array<uint32_t, 16> blk{};
    for (int w = 0; w < 16; ++w) blk[w] = 0x2468ACE0u + w * 0x01010101u;
    ShaCompressTrace t = ShaCompressInCircuit(h, blk);
    std::string fail;
    if (!CheckShaCompress(t, fail)) return false;  // honest trace must pass
    // Tamper a mid-schedule working variable 'a' (a committed round cell).
    t.vars[30][0] ^= 0x00000010u;
    return !CheckShaCompress(t, fail);  // must now be rejected
}

// ===========================================================================
// Generic in-circuit SHA-256 / SHA-256d over arbitrary-length messages.
// Every 64-byte compression is a ShaCompressTrace whose ARX/round/feed-forward
// identities are checked by CheckShaCompress (so an internal-cell tamper is
// rejected by the arithmetic constraints, not merely at the digest boundary).
// Shared by MxExpandAir (§5.7) and TileTreeAir (§6.3). Byte-exact to CSHA256.
// ===========================================================================
namespace {

std::array<uint8_t, 32> SeedBytesLE(const uint256& seed)
{
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < 32; ++i) out[i] = seed.data()[31 - i];
    return out;
}

// Big-endian byte image of the 8-word digest (matches CSHA256::Finalize).
std::array<uint8_t, 32> DigestBytes(const std::array<uint32_t, 8>& h)
{
    std::array<uint8_t, 32> b{};
    for (int k = 0; k < 8; ++k) {
        b[4 * k + 0] = static_cast<uint8_t>(h[k] >> 24);
        b[4 * k + 1] = static_cast<uint8_t>(h[k] >> 16);
        b[4 * k + 2] = static_cast<uint8_t>(h[k] >> 8);
        b[4 * k + 3] = static_cast<uint8_t>(h[k]);
    }
    return b;
}

// SHA-256 of an arbitrary message; pushes every compression trace and returns
// the 8-word digest.
std::array<uint32_t, 8> Sha256InCircuit(const uint8_t* msg, size_t len,
                                        std::vector<ShaCompressTrace>& traces)
{
    std::vector<uint8_t> padded(msg, msg + len);
    const uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) padded.push_back(0x00);
    for (int s = 7; s >= 0; --s) padded.push_back(static_cast<uint8_t>(bitlen >> (8 * s)));

    std::array<uint32_t, 8> h = kSHA_H0;
    for (size_t off = 0; off < padded.size(); off += 64) {
        std::array<uint32_t, 16> blk{};
        for (int w = 0; w < 16; ++w) {
            blk[w] = (static_cast<uint32_t>(padded[off + 4 * w]) << 24) |
                     (static_cast<uint32_t>(padded[off + 4 * w + 1]) << 16) |
                     (static_cast<uint32_t>(padded[off + 4 * w + 2]) << 8) |
                     (static_cast<uint32_t>(padded[off + 4 * w + 3]));
        }
        ShaCompressTrace ct = ShaCompressInCircuit(h, blk);
        h = ct.h_out;
        traces.push_back(std::move(ct));
    }
    return h;
}

// SHA-256d = SHA-256(SHA-256(msg)); pushes every compression trace.
std::array<uint8_t, 32> Sha256dInCircuit(const uint8_t* msg, size_t len,
                                         std::vector<ShaCompressTrace>& traces)
{
    const std::array<uint32_t, 8> h1 = Sha256InCircuit(msg, len, traces);
    const std::array<uint8_t, 32> d1 = DigestBytes(h1);
    const std::array<uint32_t, 8> h2 = Sha256InCircuit(d1.data(), d1.size(), traces);
    return DigestBytes(h2);
}

uint256 ToUint256(const std::array<uint8_t, 32>& b)
{
    return uint256{Span<const unsigned char>{b.data(), b.size()}};
}

// Consensus XOF domain bytes (mirror matmul_v4_bmx4.cpp — kept in sync by the
// byte-exactness assertion vs ExpandMxDequantInt8).
constexpr uint8_t kMantissaStreamDomain = 0x6D; // 'm'
constexpr uint8_t kScaleStreamDomain = 0x65;    // 'e'

// One XOF block message: seed_bytes(32) ‖ domain(1) ‖ le64(block_counter).
std::array<uint8_t, 41> XofMessage(const std::array<uint8_t, 32>& seed_bytes, uint8_t domain,
                                   uint64_t block)
{
    std::array<uint8_t, 41> m{};
    std::memcpy(m.data(), seed_bytes.data(), 32);
    m[32] = domain;
    WriteLE64(m.data() + 33, block);
    return m;
}

} // namespace

// ===========================================================================
// MxExpand operand-expansion AIR (§5.7).
// ===========================================================================

MxExpandVerifyResult VerifyMxExpandColumn(const uint256& seed, uint32_t rows, uint32_t cols,
                                          const std::vector<int8_t>& committed_out,
                                          const TableTM& tm, Fp2 gamma, LogUpInstance& inst_tm)
{
    MxExpandVerifyResult r;
    if ((rows % kRCMxBlockLen) != 0 || (cols % kRCMxBlockLen) != 0 || rows == 0 || cols == 0) {
        r.failure = "mxexpand:dims";
        return r;
    }
    const size_t count = static_cast<size_t>(rows) * cols;
    if (committed_out.size() != count) {
        r.failure = "mxexpand:committed_size";
        return r;
    }

    // Ensure the T_M table side is populated once (idempotent by size check).
    inst_tm.name = "T_M";
    if (inst_tm.table.empty()) {
        for (uint16_t n = 0; n < 16; ++n)
            inst_tm.table.push_back(Fingerprint({n, tm.acc[n],
                static_cast<uint64_t>(static_cast<uint8_t>(tm.mu[n]))}, gamma));
    }

    const std::array<uint8_t, 32> seed_bytes = SeedBytesLE(seed);

    // ---- Mantissa XOF: SHA-256 counter blocks, E2M1 rejection into M11. ----
    std::vector<int8_t> mu_stream;
    mu_stream.reserve(count);
    uint64_t block = 0;
    while (mu_stream.size() < count) {
        const std::array<uint8_t, 41> msg = XofMessage(seed_bytes, kMantissaStreamDomain, block);
        std::vector<ShaCompressTrace> traces;
        const std::array<uint32_t, 8> h = Sha256InCircuit(msg.data(), msg.size(), traces);
        std::string fail;
        for (const auto& ct : traces) {
            ++r.n_mantissa_blocks;
            if (!CheckShaCompress(ct, fail)) { r.failure = "mxexpand:" + fail; return r; }
        }
        const std::array<uint8_t, 32> digest = DigestBytes(h);
        for (size_t i = 0; i < 32 && mu_stream.size() < count; ++i) {
            const uint8_t nibs[2] = {static_cast<uint8_t>(digest[i] & 0x0F),
                                     static_cast<uint8_t>((digest[i] >> 4) & 0x0F)};
            for (uint8_t nib : nibs) {
                const uint8_t acc = tm.acc[nib];
                const int8_t mu = tm.mu[nib];
                // (nib,acc,mu) T_M lookup — same aggregate as Extract's inst_tm.
                inst_tm.witness.push_back(Fingerprint(
                    {nib, acc, static_cast<uint64_t>(static_cast<uint8_t>(mu))}, gamma));
                if (acc) {
                    mu_stream.push_back(mu);
                    if (mu_stream.size() == count) break;
                }
            }
        }
        ++block;
    }

    // ---- Scale XOF: SHA-256 counter blocks, 2 bits/code, rejection-free. ----
    const size_t scale_count = static_cast<size_t>(rows) * (cols / kRCMxBlockLen);
    std::vector<uint8_t> scale;
    scale.reserve(scale_count);
    block = 0;
    while (scale.size() < scale_count) {
        const std::array<uint8_t, 41> msg = XofMessage(seed_bytes, kScaleStreamDomain, block);
        std::vector<ShaCompressTrace> traces;
        const std::array<uint32_t, 8> h = Sha256InCircuit(msg.data(), msg.size(), traces);
        std::string fail;
        for (const auto& ct : traces) {
            ++r.n_scale_blocks;
            if (!CheckShaCompress(ct, fail)) { r.failure = "mxexpand:" + fail; return r; }
        }
        const std::array<uint8_t, 32> digest = DigestBytes(h);
        for (size_t i = 0; i < 32 && scale.size() < scale_count; ++i) {
            for (int shift = 0; shift < 8 && scale.size() < scale_count; shift += 2) {
                const uint8_t code = static_cast<uint8_t>((digest[i] >> shift) & 0x03);
                if (code > 3) { r.failure = "mxexpand:scale_code_range"; return r; }
                scale.push_back(code);
            }
        }
        ++block;
    }

    // ---- Dequant identity: out[i,j] = mu[i,j] · 2^{e[i, j/32]} == committed. ----
    const uint32_t nblk = cols / kRCMxBlockLen;
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t j = 0; j < cols; ++j) {
            const size_t idx = static_cast<size_t>(i) * cols + j;
            const uint8_t e = scale[static_cast<size_t>(i) * nblk + (j / kRCMxBlockLen)];
            const int32_t dq = static_cast<int32_t>(mu_stream[idx]) * (int32_t{1} << e);
            if (committed_out[idx] != static_cast<int8_t>(dq)) {
                r.failure = "mxexpand:dequant_binding";
                return r;
            }
        }
    }

    r.ok = true;
    return r;
}

bool MxExpandByteExactVsReference(const uint256& seed, uint32_t rows, uint32_t cols)
{
    const std::vector<int8_t> ref = ExpandMxDequantInt8(seed, rows, cols);
    TableTM tm;
    LogUpInstance inst_tm;
    const Fp2 gamma = Fp2{0x00000000DEADBEEFull, 0x00000000FEEDFACEull};
    const MxExpandVerifyResult r = VerifyMxExpandColumn(seed, rows, cols, ref, tm, gamma, inst_tm);
    return r.ok;
}

bool MxExpandIntermediateTamperRejected()
{
    // Trace a real mantissa XOF block, confirm it passes, then tamper a SHA
    // round working variable and confirm CheckShaCompress rejects it.
    std::array<uint8_t, 32> sb{};
    for (int i = 0; i < 32; ++i) sb[i] = static_cast<uint8_t>(0x11 * (i + 1));
    const std::array<uint8_t, 41> msg = XofMessage(sb, kMantissaStreamDomain, 0);
    std::vector<ShaCompressTrace> traces;
    (void)Sha256InCircuit(msg.data(), msg.size(), traces);
    if (traces.empty()) return false;
    std::string fail;
    if (!CheckShaCompress(traces[0], fail)) return false; // honest must pass
    traces[0].vars[20][0] ^= 0x00000040u;                 // tamper working var 'a'
    return !CheckShaCompress(traces[0], fail);            // must now reject
}

// ===========================================================================
// Tile-tree AIR (§6.3): in-circuit SHA256d Merkle tile-tree over the committed
// extract byte-stream. Byte-exact to RoundMerkleStream / BuildTileTreeRoot.
// ===========================================================================

namespace {

// SHA256d(tag_byte ‖ payload) in-circuit; pushes compression traces.
uint256 TaggedSha256dInCircuit(uint8_t tag, const uint8_t* payload, size_t len,
                               std::vector<ShaCompressTrace>& traces)
{
    std::vector<uint8_t> pre;
    pre.reserve(1 + len);
    pre.push_back(tag);
    pre.insert(pre.end(), payload, payload + len);
    return ToUint256(Sha256dInCircuit(pre.data(), pre.size(), traces));
}

} // namespace

TileTreeCheckResult CheckTileTreeInCircuit(const std::vector<int8_t>& stream, uint32_t t_leaf,
                                           const uint256& claimed_root)
{
    TileTreeCheckResult r;
    if (t_leaf == 0) { r.failure = "tiletree:t_leaf"; return r; }
    std::vector<ShaCompressTrace> traces;
    std::string fail;

    // Leaves: SHA256d(kRCLeafTag ‖ t_leaf bytes), last partial zero-padded;
    // an empty stream still emits one zero leaf (matches RoundMerkleStream).
    std::vector<uint256> leaves;
    const size_t n = stream.size();
    if (n == 0) {
        std::vector<uint8_t> zero(t_leaf, 0);
        leaves.push_back(TaggedSha256dInCircuit(kRCLeafTag, zero.data(), zero.size(), traces));
    } else {
        for (size_t off = 0; off < n; off += t_leaf) {
            std::vector<uint8_t> leaf(t_leaf, 0);
            const size_t take = std::min<size_t>(t_leaf, n - off);
            for (size_t b = 0; b < take; ++b)
                leaf[b] = static_cast<uint8_t>(stream[off + b]);
            leaves.push_back(TaggedSha256dInCircuit(kRCLeafTag, leaf.data(), leaf.size(), traces));
        }
    }

    // Pad to next power of two with the canonical pad-leaf hash.
    auto next_pow2 = [](size_t v) { size_t p = 1; while (p < v) p <<= 1; return p; };
    const size_t target = next_pow2(leaves.empty() ? 1 : leaves.size());
    if (leaves.size() < target) {
        std::vector<uint8_t> pad(kRCPadTag, kRCPadTag + sizeof(kRCPadTag) - 1);
        const uint256 pad_leaf =
            TaggedSha256dInCircuit(kRCPadLeafTag, pad.data(), pad.size(), traces);
        while (leaves.size() < target) leaves.push_back(pad_leaf);
    }

    // Fold: parent = SHA256d(kRCNodeTag ‖ L ‖ R).
    while (leaves.size() > 1) {
        std::vector<uint256> parent;
        parent.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            std::array<uint8_t, 64> lr{};
            std::memcpy(lr.data(), leaves[i].data(), 32);
            std::memcpy(lr.data() + 32, leaves[i + 1].data(), 32);
            parent.push_back(TaggedSha256dInCircuit(kRCNodeTag, lr.data(), lr.size(), traces));
        }
        leaves.swap(parent);
    }

    // Constraint-check every SHA-256 compression in the whole tree.
    for (const auto& ct : traces) {
        ++r.n_compressions;
        if (!CheckShaCompress(ct, fail)) { r.failure = "tiletree:" + fail; return r; }
    }

    r.root = leaves.front();
    if (r.root != claimed_root) { r.failure = "tiletree:root_mismatch"; return r; }
    r.ok = true;
    return r;
}

bool TileTreeIntermediateTamperRejected()
{
    // Build a small stream, hash a leaf in-circuit, tamper a SHA intermediate.
    std::vector<uint8_t> leaf(64, 0);
    for (int i = 0; i < 64; ++i) leaf[i] = static_cast<uint8_t>(3 * i + 1);
    std::vector<ShaCompressTrace> traces;
    (void)TaggedSha256dInCircuit(kRCLeafTag, leaf.data(), leaf.size(), traces);
    if (traces.empty()) return false;
    std::string fail;
    if (!CheckShaCompress(traces[0], fail)) return false; // honest must pass
    traces[0].w[20] ^= 0x00000004u;                       // tamper a schedule word
    return !CheckShaCompress(traces[0], fail);            // must now reject
}

} // namespace matmul::v4::rc::gkr_air
