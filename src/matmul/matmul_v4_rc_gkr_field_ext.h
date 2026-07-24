// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT_H

#include <matmul/matmul_v4_rc_gkr_field.h>

#include <array>
#include <cstdint>

// Degree-2 Goldilocks extension Fp2 = Fp[x] / (x^2 - 7).
//
// WHY: single Goldilocks (|F| ≈ 2^64) cannot deliver ≤2^{-64} soundness AFTER
// PoW grinding. Each sumcheck/FRI challenge contributes ~deg/|F| soundness;
// union-bound over O(log n) rounds already consumes the base field, and PoW
// grinding subtracts further bits. Fp2 gives |F| ≈ 2^128 base soundness so
// that after union bound + grinding the net target ≤2^{-64} is reachable.
//
// Irreducible: x^2 - 7 over Goldilocks (same choice as Plonky2 Goldilocks2).
// All Fiat–Shamir challenges for the Section-2 succinct scaffold live in Fp2.
// Base-field Fp arithmetic remains for int64→Fp embedding of wire values.

namespace matmul::v4::rc::gkr_field {

/** Non-residue for the quadratic extension (x^2 = W). */
inline constexpr Fp kFp2W = 7;

struct Fp2 {
    Fp c0{0};
    Fp c1{0};

    [[nodiscard]] static Fp2 Zero() { return Fp2{0, 0}; }
    [[nodiscard]] static Fp2 One() { return Fp2{1, 0}; }
    [[nodiscard]] static Fp2 FromFp(Fp a) { return Fp2{Canonical(a), 0}; }
};

[[nodiscard]] inline bool Eq(const Fp2& a, const Fp2& b)
{
    return Canonical(a.c0) == Canonical(b.c0) && Canonical(a.c1) == Canonical(b.c1);
}

[[nodiscard]] inline bool IsZero(const Fp2& a)
{
    return Canonical(a.c0) == 0 && Canonical(a.c1) == 0;
}

[[nodiscard]] inline Fp2 Add(const Fp2& a, const Fp2& b)
{
    return Fp2{Add(a.c0, b.c0), Add(a.c1, b.c1)};
}

[[nodiscard]] inline Fp2 Sub(const Fp2& a, const Fp2& b)
{
    return Fp2{Sub(a.c0, b.c0), Sub(a.c1, b.c1)};
}

[[nodiscard]] inline Fp2 Neg(const Fp2& a) { return Fp2{Neg(a.c0), Neg(a.c1)}; }

/** (a0 + a1 x)(b0 + b1 x) = (a0 b0 + W a1 b1) + (a0 b1 + a1 b0) x. */
[[nodiscard]] inline Fp2 Mul(const Fp2& a, const Fp2& b)
{
    const Fp a0b0 = Mul(a.c0, b.c0);
    const Fp a1b1 = Mul(a.c1, b.c1);
    const Fp a0b1 = Mul(a.c0, b.c1);
    const Fp a1b0 = Mul(a.c1, b.c0);
    return Fp2{Add(a0b0, Mul(a1b1, kFp2W)), Add(a0b1, a1b0)};
}

[[nodiscard]] inline Fp2 Inv(const Fp2& a)
{
    // (a0 + a1 x)^{-1} = (a0 - a1 x) / (a0^2 - W a1^2)
    const Fp n = Sub(Mul(a.c0, a.c0), Mul(Mul(a.c1, a.c1), kFp2W));
    const Fp inv_n = Inv(n);
    return Fp2{Mul(a.c0, inv_n), Neg(Mul(a.c1, inv_n))};
}

[[nodiscard]] inline Fp2 Div(const Fp2& a, const Fp2& b) { return Mul(a, Inv(b)); }

/** Map signed int64 into Fp2 via the base field (c1 = 0). */
[[nodiscard]] inline Fp2 FromSigned2(int64_t x) { return Fp2::FromFp(FromSigned(x)); }

[[nodiscard]] inline Fp2 FromU64_2(uint64_t x) { return Fp2::FromFp(FromU64(x)); }

/**
 * Derive an Fp2 challenge from 32 FS bytes: c0 = bytes[0..8), c1 = bytes[8..16),
 * both reduced mod p. Using 16 bytes of entropy (not 8) is required for the
 * extension-field soundness argument.
 */
[[nodiscard]] inline Fp2 FromChallengeBytes2(const unsigned char* b32)
{
    uint64_t w0 = 0, w1 = 0;
    for (int i = 0; i < 8; ++i) {
        w0 |= static_cast<uint64_t>(b32[i]) << (8 * i);
        w1 |= static_cast<uint64_t>(b32[8 + i]) << (8 * i);
    }
    return Fp2{static_cast<Fp>(w0 % kP), static_cast<Fp>(w1 % kP)};
}

[[nodiscard]] inline std::array<uint64_t, 2> ToU64Pair(const Fp2& a)
{
    return {Canonical(a.c0), Canonical(a.c1)};
}

} // namespace matmul::v4::rc::gkr_field

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT_H
