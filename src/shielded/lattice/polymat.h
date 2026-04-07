// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_POLYMAT_H
#define BTX_SHIELDED_LATTICE_POLYMAT_H

#include <shielded/lattice/polyvec.h>

#include <vector>

namespace shielded::lattice {

using PolyMat = std::vector<PolyVec>; // row-major

/** Returns true if every row has exactly expected_cols elements. */
[[nodiscard]] bool IsRectangular(const PolyMat& mat, size_t expected_cols);

/** Matrix-vector product over R_q: result = mat * vec. */
[[nodiscard]] PolyVec MatVecMul(const PolyMat& mat, const PolyVec& vec);

/** Build an identity matrix with constant polynomial 1 on the diagonal. */
[[nodiscard]] PolyMat PolyMatIdentity(size_t dim);

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_POLYMAT_H
