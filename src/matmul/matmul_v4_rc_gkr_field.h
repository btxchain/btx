// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_H

#include <cstdint>

// ENC_RC Stage E — Goldilocks prime field for winner-only GKR/sumcheck.
//
// p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001 (Goldilocks).
// Used for int64→Fp wire embedding. Fiat–Shamir challenges for the Section-2
// succinct scaffold live in the degree-2 extension Fp2
// (matmul_v4_rc_gkr_field_ext.h) — single Goldilocks is insufficient for
// ≤2^{-64} after PoW grinding.
//
// SOUNDNESS HONESTY: computational under SHA256d FS + Fp2 (ROM/SZ-style
// bounds deg/|F| per round). NOT ε=0. Full STREAMED replay remains available
// as dispute/oracle only; ExactReplay remains the active Profile-1 authority.

namespace matmul::v4::rc::gkr_field {

using Fp = uint64_t;

/** Goldilocks prime. */
inline constexpr Fp kP = 0xFFFFFFFF00000001ULL;

[[nodiscard]] inline Fp Canonical(Fp x) { return x >= kP ? x - kP : x; }

/** 2^64 ≡ 2^32 − 1 (mod p). This constant is what makes Goldilocks reduction
 *  division-free; it is the same `GL_NEGP` the CUDA row-leaf kernel uses. */
inline constexpr uint64_t kEpsilon = 0xFFFFFFFFULL;

/**
 * Reduce a 128-bit value mod p, returning the CANONICAL representative in
 * [0, p). Bit-identical to the previous `x % kP` for every 128-bit input, but
 * without the libgcc `__umodti3` software division that expression compiled
 * to (a call, not an instruction — it dominated every field multiply and
 * therefore every Poseidon2 permutation on the verify path).
 *
 * Derivation. Write x = lo + hi·2^64 with hi = hh·2^32 + hl. Then
 *   2^64 ≡ 2^32 − 1 = ε           (mod p)
 *   2^96 ≡ ε·2^32 = 2^64 − 2^32 ≡ (2^32 − 1) − 2^32 = −1   (mod p)
 * so x ≡ lo − hh + hl·ε (mod p), which is two 64-bit adds, one 32×32 multiply
 * and two carry fixups.
 *
 * Range safety (why each fixup is exact and why one final subtract suffices):
 *  • hh < 2^32, so if lo < hh the wrapped lo−hh exceeds 2^64 − 2^32 ≥ ε and
 *    subtracting ε cannot underflow (borrowing 2^64 costs exactly ε mod p).
 *  • hl, ε < 2^32 so hl·ε < 2^64 exactly — no overflow in the product.
 *  • t0 + t1 < 2^65, and after the carry fixup the result is still < 2^64.
 *  • r < 2^64 = p + ε, hence r − p < ε < p: a single conditional subtract
 *    canonicalizes.
 * Pinned against the `% kP` reference over edge cases and randoms by
 * gkr_field_reduce128_matches_modulo_reference (alg_hash tests).
 */
[[nodiscard]] inline Fp Reduce128(unsigned __int128 x)
{
    const uint64_t lo = static_cast<uint64_t>(x);
    const uint64_t hi = static_cast<uint64_t>(x >> 64);
    const uint64_t hh = hi >> 32;        // coefficient of 2^96 ≡ −1
    const uint64_t hl = hi & kEpsilon;   // coefficient of 2^64 ≡ ε
    uint64_t t0;
    const uint64_t borrow = static_cast<uint64_t>(__builtin_sub_overflow(lo, hh, &t0));
    t0 -= kEpsilon * borrow;
    const uint64_t t1 = hl * kEpsilon;
    uint64_t r;
    const uint64_t carry = static_cast<uint64_t>(__builtin_add_overflow(t0, t1, &r));
    r += kEpsilon * carry;
    r -= kP * static_cast<uint64_t>(r >= kP);
    return r;
}

/**
 * Bit-identical to the previous 128-bit-widening form for EVERY pair of
 * uint64 inputs, including non-canonical ones.
 *
 * The input Canonical() calls are LOAD-BEARING and must not be dropped as an
 * "optimization": callers outside the hash core do pass values in [p, 2^64),
 * and a variant without them diverges from this one on 13 of the edge-grid
 * cases (measured). With both inputs reduced below p the sum needs at most
 * one wrap fixup (2^64 ≡ ε) and one conditional subtract, so no 128-bit
 * intermediate is required.
 */
[[nodiscard]] inline Fp Add(Fp a, Fp b)
{
    a = Canonical(a);
    b = Canonical(b);
    uint64_t s;
    const uint64_t carry = static_cast<uint64_t>(__builtin_add_overflow(a, b, &s));
    s += kEpsilon * carry;
    s -= kP * static_cast<uint64_t>(s >= kP);
    return s;
}

[[nodiscard]] inline Fp Sub(Fp a, Fp b)
{
    a = Canonical(a);
    b = Canonical(b);
    return a >= b ? a - b : static_cast<Fp>(kP - (b - a));
}

[[nodiscard]] inline Fp Neg(Fp a)
{
    a = Canonical(a);
    return a == 0 ? 0 : static_cast<Fp>(kP - a);
}

[[nodiscard]] inline Fp Mul(Fp a, Fp b)
{
    return Reduce128(static_cast<unsigned __int128>(Canonical(a)) * Canonical(b));
}

/** Fermat inverse a^{p-2} mod p. Requires a != 0. */
[[nodiscard]] inline Fp Inv(Fp a)
{
    Fp base = Canonical(a);
    Fp exp = kP - 2;
    Fp result = 1;
    while (exp > 0) {
        if (exp & 1u) result = Mul(result, base);
        base = Mul(base, base);
        exp >>= 1;
    }
    return result;
}

[[nodiscard]] inline Fp Div(Fp a, Fp b) { return Mul(a, Inv(b)); }

/** Map signed int64 into Fp (injective for |x| < p/2). */
[[nodiscard]] inline Fp FromSigned(int64_t x)
{
    if (x >= 0) {
        return static_cast<Fp>(static_cast<uint64_t>(x) % kP);
    }
    // Two's-complement magnitude in unsigned arithmetic: well-defined for INT64_MIN
    // (whose signed negation -x would overflow / is UB). Identical to -x for every
    // other x < 0.
    const uint64_t ax = -static_cast<uint64_t>(x);
    return Sub(0, static_cast<Fp>(ax % kP));
}

[[nodiscard]] inline Fp FromU64(uint64_t x) { return static_cast<Fp>(x % kP); }

/** Low 8 LE bytes of a 32-byte FS challenge, reduced mod p. */
[[nodiscard]] inline Fp FromChallengeBytes(const unsigned char* b32)
{
    uint64_t w = 0;
    for (int i = 0; i < 8; ++i) {
        w |= static_cast<uint64_t>(b32[i]) << (8 * i);
    }
    return static_cast<Fp>(w % kP);
}

} // namespace matmul::v4::rc::gkr_field

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_H
