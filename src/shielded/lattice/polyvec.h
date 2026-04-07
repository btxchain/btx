// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_POLYVEC_H
#define BTX_SHIELDED_LATTICE_POLYVEC_H

#include <shielded/lattice/params.h>
#include <shielded/lattice/poly.h>

#include <cstdint>
#include <vector>

namespace shielded::lattice {

using PolyVec = std::vector<Poly256>;

/** Returns true if vector has expected dimension and bounded coefficients. */
[[nodiscard]] bool IsValidPolyVec(const PolyVec& vec, size_t expected_size = MODULE_RANK);

/** Coefficient-wise vector addition. */
[[nodiscard]] PolyVec PolyVecAdd(const PolyVec& a, const PolyVec& b);

/** Coefficient-wise vector subtraction. */
[[nodiscard]] PolyVec PolyVecSub(const PolyVec& a, const PolyVec& b);

/** Scalar multiplication (mod q). */
[[nodiscard]] PolyVec PolyVecScale(const PolyVec& vec, int64_t scalar);

/** Forward NTT for every polynomial in the vector. */
void PolyVecNTT(PolyVec& vec);

/** Inverse NTT for every polynomial in the vector. */
void PolyVecInverseNTT(PolyVec& vec);

/** Infinity norm across all polynomials in the vector. */
[[nodiscard]] int32_t PolyVecInfNorm(const PolyVec& vec);

/** Constant-time equality comparison of two PolyVec values.
 *  Does not short-circuit on the first differing coefficient. */
[[nodiscard]] bool PolyVecEqualCT(const PolyVec& a, const PolyVec& b);

/** Inner product of two vectors using ring multiplication. */
[[nodiscard]] Poly256 InnerProduct(const PolyVec& a, const PolyVec& b);

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_POLYVEC_H
