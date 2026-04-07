// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_POLY_H
#define BTX_SHIELDED_LATTICE_POLY_H

#include <shielded/lattice/params.h>

#include <serialize.h>
#include <span.h>

#include <array>
#include <cstdint>
#include <vector>

namespace shielded::lattice {

/** Polynomial in R_q = Z_q[X] / (X^256 + 1). */
struct Poly256 {
    std::array<int32_t, POLY_N> coeffs{};

    /** Forward NTT (in-place). */
    void NTT();

    /** Inverse NTT with Montgomery correction (in-place). */
    void InverseNTT();

    /** Reduce coefficients to Dilithium's centered representative. */
    void Reduce();

    /** Conditionally add q to map coefficients to [0, q). */
    void CAddQ();

    /** Pointwise multiplication in NTT domain (Montgomery reduction). */
    [[nodiscard]] static Poly256 PointwiseMul(const Poly256& a, const Poly256& b);

    [[nodiscard]] Poly256 operator+(const Poly256& other) const;
    [[nodiscard]] Poly256 operator-(const Poly256& other) const;

    [[nodiscard]] bool operator==(const Poly256& other) const = default;

    /** Infinity norm (max absolute coefficient). */
    [[nodiscard]] int32_t InfNorm() const;

    /** Pack coefficients as LE int32 values (debug/test helper). */
    [[nodiscard]] std::vector<unsigned char> Pack() const;
    [[nodiscard]] static Poly256 Unpack(Span<const unsigned char> data);

    SERIALIZE_METHODS(Poly256, obj)
    {
        for (size_t i = 0; i < POLY_N; ++i) {
            READWRITE(obj.coeffs[i]);
        }
    }
};

/** Ring multiplication in coefficient domain using NTT/InvNTT. */
[[nodiscard]] Poly256 PolyMul(const Poly256& a, const Poly256& b);

/** Multiply polynomial coefficients by scalar (mod q). */
[[nodiscard]] Poly256 PolyScale(const Poly256& poly, int64_t scalar);

/** Construct a polynomial with only the constant term set. */
[[nodiscard]] Poly256 PolyFromConstant(int64_t value);

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_POLY_H
