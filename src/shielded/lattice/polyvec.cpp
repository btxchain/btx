// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/polyvec.h>

#include <shielded/lattice/polymat.h>

#include <algorithm>
#include <stdexcept>

namespace shielded::lattice {

bool IsValidPolyVec(const PolyVec& vec, size_t expected_size)
{
    if (vec.size() != expected_size) return false;
    for (const auto& poly : vec) {
        for (const int32_t coeff : poly.coeffs) {
            if (coeff <= -POLY_Q || coeff >= POLY_Q) return false;
        }
    }
    return true;
}

PolyVec PolyVecAdd(const PolyVec& a, const PolyVec& b)
{
    if (a.size() != b.size()) {
        throw std::runtime_error("PolyVecAdd size mismatch");
    }

    PolyVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i] + b[i];
        out[i].Reduce();
        out[i].CAddQ();
    }
    return out;
}

PolyVec PolyVecSub(const PolyVec& a, const PolyVec& b)
{
    if (a.size() != b.size()) {
        throw std::runtime_error("PolyVecSub size mismatch");
    }

    PolyVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i] - b[i];
        out[i].Reduce();
        out[i].CAddQ();
    }
    return out;
}

PolyVec PolyVecScale(const PolyVec& vec, int64_t scalar)
{
    PolyVec out(vec.size());
    for (size_t i = 0; i < vec.size(); ++i) {
        out[i] = PolyScale(vec[i], scalar);
        out[i].Reduce();
        out[i].CAddQ();
    }
    return out;
}

void PolyVecNTT(PolyVec& vec)
{
    for (auto& poly : vec) {
        poly.NTT();
    }
}

void PolyVecInverseNTT(PolyVec& vec)
{
    for (auto& poly : vec) {
        poly.InverseNTT();
        poly.Reduce();
        poly.CAddQ();
    }
}

int32_t PolyVecInfNorm(const PolyVec& vec)
{
    int32_t max_norm{0};
    for (const auto& poly : vec) {
        const int32_t norm = poly.InfNorm();
        // Constant-time max: avoid std::max which may compile to a branch.
        const int32_t diff = max_norm - norm;
        const int32_t select = diff >> 31; // -1 if max_norm < norm, 0 otherwise
        max_norm = max_norm + (select & (norm - max_norm));
    }
    return max_norm;
}

bool PolyVecEqualCT(const PolyVec& a, const PolyVec& b)
{
    if (a.size() != b.size()) return false;
    // Accumulate XOR of all coefficient differences to avoid short-circuiting.
    int32_t diff_acc{0};
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < POLY_N; ++j) {
            diff_acc |= (a[i].coeffs[j] ^ b[i].coeffs[j]);
        }
    }
    return diff_acc == 0;
}

Poly256 InnerProduct(const PolyVec& a, const PolyVec& b)
{
    if (a.size() != b.size()) {
        throw std::runtime_error("InnerProduct size mismatch");
    }

    Poly256 out{};
    for (size_t i = 0; i < a.size(); ++i) {
        const Poly256 term = PolyMul(a[i], b[i]);
        out = out + term;
    }
    out.Reduce();
    out.CAddQ();
    return out;
}

bool IsRectangular(const PolyMat& mat, size_t expected_cols)
{
    for (const auto& row : mat) {
        if (row.size() != expected_cols) return false;
    }
    return true;
}

PolyVec MatVecMul(const PolyMat& mat, const PolyVec& vec)
{
    if (!IsRectangular(mat, vec.size())) {
        throw std::runtime_error("MatVecMul dimension mismatch");
    }

    PolyVec out(mat.size());
    for (size_t row = 0; row < mat.size(); ++row) {
        out[row] = InnerProduct(mat[row], vec);
    }
    return out;
}

PolyMat PolyMatIdentity(size_t dim)
{
    PolyMat out(dim, PolyVec(dim));
    for (size_t i = 0; i < dim; ++i) {
        out[i][i] = PolyFromConstant(1);
    }
    return out;
}

} // namespace shielded::lattice
