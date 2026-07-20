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
// as dispute/oracle until Stage I cutover. nMatMulRCHeight stays INT32_MAX.

namespace matmul::v4::rc::gkr_field {

using Fp = uint64_t;

/** Goldilocks prime. */
inline constexpr Fp kP = 0xFFFFFFFF00000001ULL;

[[nodiscard]] inline Fp Canonical(Fp x) { return x >= kP ? x - kP : x; }

[[nodiscard]] inline Fp Reduce128(unsigned __int128 x)
{
    return static_cast<Fp>(x % kP);
}

[[nodiscard]] inline Fp Add(Fp a, Fp b)
{
    const unsigned __int128 s = static_cast<unsigned __int128>(Canonical(a)) + Canonical(b);
    return s >= kP ? static_cast<Fp>(s - kP) : static_cast<Fp>(s);
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
    const uint64_t ax = static_cast<uint64_t>(-x);
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
