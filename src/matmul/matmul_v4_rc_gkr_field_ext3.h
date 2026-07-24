// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT3_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT3_H

#include <matmul/matmul_v4_rc_gkr_field.h>

#include <array>
#include <cstdint>

// Degree-3 Goldilocks extension Fp3 = Fp[x] / (x^3 - 2).
//
// WHY: Fp2 (|F| ≈ 2^128) already clears the per-challenge soundness target,
// but the composed-bound analysis (doc/btx-matmul-v4.5-rc-gkr-
// arithmetization-construction.md, "Parameter levers") shows the FS subtotal
// caps the composed bound once the FRI query count rises to Q = 128. Moving
// the FS/algebraic challenges to Fp3 (|F| = p^3 ≈ 2^192) lifts the FS union
// bound (≈72 → ≈136 bits) so the FRI query term becomes the binding floor.
//
// IRREDUCIBILITY OF x^3 - 2 OVER GOLDILOCKS:
//   p = 2^64 - 2^32 + 1, so p - 1 = 2^32 (2^32 - 1) and 3 | (2^32 - 1),
//   hence 3 | p - 1 and the cubes form an index-3 subgroup of Fp*.
//   A binomial x^3 - W3 with 3 prime is irreducible over Fp iff W3 is not a
//   cube in Fp (standard binomial criterion: for prime n | p - 1, x^n - a is
//   irreducible iff a is not an n-th power). W3 is a non-cube iff
//   W3^((p-1)/3) != 1. Testing W3 = 2 (the smallest candidate > 1):
//     2^((p-1)/3) mod p = 2^0x5555555500000000 mod p = 0xFFFFFFFF != 1,
//   so 2 is a non-cube and x^3 - 2 is irreducible; Fp[x]/(x^3 - 2) is the
//   field F_{p^3}. (0xFFFFFFFF = 2^32 - 1 is in fact a primitive cube root
//   of unity omega, since (2^32 - 1)^3 = 1 mod p; see kFp3Omega below.)
//   The non-cube property is re-verified at test time in
//   src/test/matmul_v4_rc_gkr_field_ext3_tests.cpp.
//
// FROBENIUS: x^p = (x^3)^((p-1)/3) * x = W3^((p-1)/3) * x = omega * x, so
//   Frob(a0 + a1 x + a2 x^2)   = a0 + omega   a1 x + omega^2 a2 x^2,
//   Frob^2(a0 + a1 x + a2 x^2) = a0 + omega^2 a1 x + omega   a2 x^2,
// with omega = 0xFFFFFFFF and omega^2 = 0xFFFFFFFE00000001 (= p - 2^32).

namespace matmul::v4::rc::gkr_field {

/** Non-cube for the cubic extension (x^3 = W3). Smallest positive non-cube. */
inline constexpr Fp kFp3W = 2;

/** omega = kFp3W^((p-1)/3) = 2^32 - 1, a primitive cube root of unity mod p. */
inline constexpr Fp kFp3Omega = 0xFFFFFFFFULL;

/** omega^2 = p - 2^32 (the other primitive cube root of unity). */
inline constexpr Fp kFp3Omega2 = 0xFFFFFFFE00000001ULL;

struct Fp3 {
    Fp c0{0};
    Fp c1{0};
    Fp c2{0};

    [[nodiscard]] static Fp3 Zero() { return Fp3{0, 0, 0}; }
    [[nodiscard]] static Fp3 One() { return Fp3{1, 0, 0}; }
    [[nodiscard]] static Fp3 FromFp(Fp a) { return Fp3{Canonical(a), 0, 0}; }
};

[[nodiscard]] inline bool Eq(const Fp3& a, const Fp3& b)
{
    return Canonical(a.c0) == Canonical(b.c0) &&
           Canonical(a.c1) == Canonical(b.c1) &&
           Canonical(a.c2) == Canonical(b.c2);
}

[[nodiscard]] inline bool IsZero(const Fp3& a)
{
    return Canonical(a.c0) == 0 && Canonical(a.c1) == 0 && Canonical(a.c2) == 0;
}

[[nodiscard]] inline Fp3 Add(const Fp3& a, const Fp3& b)
{
    return Fp3{Add(a.c0, b.c0), Add(a.c1, b.c1), Add(a.c2, b.c2)};
}

[[nodiscard]] inline Fp3 Sub(const Fp3& a, const Fp3& b)
{
    return Fp3{Sub(a.c0, b.c0), Sub(a.c1, b.c1), Sub(a.c2, b.c2)};
}

[[nodiscard]] inline Fp3 Neg(const Fp3& a)
{
    return Fp3{Neg(a.c0), Neg(a.c1), Neg(a.c2)};
}

/**
 * (a0 + a1 x + a2 x^2)(b0 + b1 x + b2 x^2) reduced by x^3 = W3.
 * Schoolbook degrees 0..4, then fold x^3 -> W3 and x^4 -> W3 x:
 *   c0 = a0 b0 + W3 (a1 b2 + a2 b1)
 *   c1 = a0 b1 + a1 b0 + W3 (a2 b2)
 *   c2 = a0 b2 + a1 b1 + a2 b0
 */
[[nodiscard]] inline Fp3 Mul(const Fp3& a, const Fp3& b)
{
    const Fp a0b0 = Mul(a.c0, b.c0);
    const Fp a0b1 = Mul(a.c0, b.c1);
    const Fp a0b2 = Mul(a.c0, b.c2);
    const Fp a1b0 = Mul(a.c1, b.c0);
    const Fp a1b1 = Mul(a.c1, b.c1);
    const Fp a1b2 = Mul(a.c1, b.c2);
    const Fp a2b0 = Mul(a.c2, b.c0);
    const Fp a2b1 = Mul(a.c2, b.c1);
    const Fp a2b2 = Mul(a.c2, b.c2);
    const Fp c0 = Add(a0b0, Mul(kFp3W, Add(a1b2, a2b1)));
    const Fp c1 = Add(Add(a0b1, a1b0), Mul(kFp3W, a2b2));
    const Fp c2 = Add(Add(a0b2, a1b1), a2b0);
    return Fp3{c0, c1, c2};
}

/** Frobenius a -> a^p: (a0, a1, a2) -> (a0, omega a1, omega^2 a2). */
[[nodiscard]] inline Fp3 Frobenius(const Fp3& a)
{
    return Fp3{Canonical(a.c0), Mul(a.c1, kFp3Omega), Mul(a.c2, kFp3Omega2)};
}

/** Frobenius squared a -> a^{p^2}: (a0, a1, a2) -> (a0, omega^2 a1, omega a2). */
[[nodiscard]] inline Fp3 Frobenius2(const Fp3& a)
{
    return Fp3{Canonical(a.c0), Mul(a.c1, kFp3Omega2), Mul(a.c2, kFp3Omega)};
}

/**
 * Extension inverse a^{-1} = a^{p^2 + p} / N(a) with N(a) = a a^p a^{p^2} in Fp.
 *
 * DERIVATION (closed-form adjugate = the norm-quotient made explicit).
 * With omega^3 = 1 and 1 + omega + omega^2 = 0, expand the conjugate product
 *   a^p a^{p^2} = (a0 + w a1 x + w^2 a2 x^2)(a0 + w^2 a1 x + w a2 x^2)
 * reduced by x^3 = W3 (w = omega); the omega powers collapse via
 * w + w^2 = -1 and w^4 = w to base-field coefficients
 *   t0 = a0^2 - W3 a1 a2
 *   t1 = W3 a2^2 - a0 a1
 *   t2 = a1^2 - a0 a2,
 * which are exactly the adjugate columns of the multiplication-by-a matrix.
 * The norm is the constant term of a * (t0 + t1 x + t2 x^2):
 *   N(a) = a0 t0 + W3 (a1 t2 + a2 t1)  in Fp
 * (the x and x^2 coordinates of a * a^p * a^{p^2} vanish identically because
 * the product is Frobenius-invariant, hence lies in Fp; the unit test checks
 * this). Then a^{-1} = (t0 + t1 x + t2 x^2) / N(a), with N(a) inverted by the
 * base-field Fermat inverse.
 *
 * Inv(Zero()) = Zero(): N(0) = 0 and the base Inv(0) = 0^{p-2} = 0, matching
 * the Fp2 module's precondition-style (non-fatal) handling of zero input.
 */
[[nodiscard]] inline Fp3 Inv(const Fp3& a)
{
    const Fp t0 = Sub(Mul(a.c0, a.c0), Mul(kFp3W, Mul(a.c1, a.c2)));
    const Fp t1 = Sub(Mul(kFp3W, Mul(a.c2, a.c2)), Mul(a.c0, a.c1));
    const Fp t2 = Sub(Mul(a.c1, a.c1), Mul(a.c0, a.c2));
    const Fp n = Add(Mul(a.c0, t0), Mul(kFp3W, Add(Mul(a.c1, t2), Mul(a.c2, t1))));
    const Fp inv_n = Inv(n);
    return Fp3{Mul(t0, inv_n), Mul(t1, inv_n), Mul(t2, inv_n)};
}

[[nodiscard]] inline Fp3 Div(const Fp3& a, const Fp3& b) { return Mul(a, Inv(b)); }

/** Map signed int64 into Fp3 via the base field (c1 = c2 = 0). */
[[nodiscard]] inline Fp3 FromSigned3(int64_t x) { return Fp3::FromFp(FromSigned(x)); }

[[nodiscard]] inline Fp3 FromU64_3(uint64_t x) { return Fp3::FromFp(FromU64(x)); }

/**
 * Derive an Fp3 challenge from 24 FS bytes: c0 = bytes[0..8),
 * c1 = bytes[8..16), c2 = bytes[16..24), each 8 LE bytes reduced mod p.
 * Consuming 24 bytes (~192 bits of entropy, |F_{p^3}| = p^3 ≈ 2^192) is
 * required for the extension-field soundness argument — this is the lever
 * that lifts the FS union bound above the FRI query floor.
 */
[[nodiscard]] inline Fp3 FromChallengeBytes3(const unsigned char* b24)
{
    uint64_t w0 = 0, w1 = 0, w2 = 0;
    for (int i = 0; i < 8; ++i) {
        w0 |= static_cast<uint64_t>(b24[i]) << (8 * i);
        w1 |= static_cast<uint64_t>(b24[8 + i]) << (8 * i);
        w2 |= static_cast<uint64_t>(b24[16 + i]) << (8 * i);
    }
    return Fp3{static_cast<Fp>(w0 % kP), static_cast<Fp>(w1 % kP), static_cast<Fp>(w2 % kP)};
}

[[nodiscard]] inline std::array<uint64_t, 3> ToU64Triple(const Fp3& a)
{
    return {Canonical(a.c0), Canonical(a.c1), Canonical(a.c2)};
}

} // namespace matmul::v4::rc::gkr_field

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_FIELD_EXT3_H
