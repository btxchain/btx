// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_POLY_H
#define BTX_SHIELDED_SMILE2_POLY_H

#include <shielded/smile2/params.h>

#include <array>
#include <cstdint>
#include <vector>

namespace smile2 {

// Polynomial in R_q = Z_q[X] / (X^128 + 1)
struct SmilePoly {
    std::array<int64_t, POLY_DEGREE> coeffs{};

    SmilePoly() { coeffs.fill(0); }

    // Coefficient access
    int64_t& operator[](size_t i) { return coeffs[i]; }
    const int64_t& operator[](size_t i) const { return coeffs[i]; }

    // Reduce all coefficients to [0, q)
    void Reduce();
    void SecureClear();

    // Arithmetic in R_q = Z_q[X]/(X^128+1)
    SmilePoly operator+(const SmilePoly& other) const;
    SmilePoly operator-(const SmilePoly& other) const;
    SmilePoly operator*(int64_t scalar) const;
    SmilePoly& operator+=(const SmilePoly& other);
    SmilePoly& operator-=(const SmilePoly& other);

    // Polynomial multiplication via schoolbook (for testing) — use NTT version for performance
    SmilePoly MulSchoolbook(const SmilePoly& other) const;

    bool operator==(const SmilePoly& other) const;
    bool operator!=(const SmilePoly& other) const { return !(*this == other); }

    // Check if zero
    bool IsZero() const;
};

// Vector of polynomials
using SmilePolyVec = std::vector<SmilePoly>;

// NTT slot: element of M_q = Z_q[X]/(X^4 - root)
struct NttSlot {
    std::array<int64_t, SLOT_DEGREE> coeffs{};

    NttSlot() { coeffs.fill(0); }

    int64_t& operator[](size_t i) { return coeffs[i]; }
    const int64_t& operator[](size_t i) const { return coeffs[i]; }

    // Arithmetic in Z_q[X]/(X^4 - root)
    NttSlot Add(const NttSlot& other) const;
    NttSlot Sub(const NttSlot& other) const;
    NttSlot Mul(const NttSlot& other, int64_t root) const;
    NttSlot ScalarMul(int64_t scalar) const;

    bool operator==(const NttSlot& other) const;
    bool operator!=(const NttSlot& other) const { return !(*this == other); }

    bool IsZero() const;
};

// NTT representation: 32 slots of degree 4
struct NttForm {
    std::array<NttSlot, NUM_NTT_SLOTS> slots;

    NttSlot& operator[](size_t i) { return slots[i]; }
    const NttSlot& operator[](size_t i) const { return slots[i]; }

    // Component-wise operations (using slot roots for multiplication)
    NttForm operator+(const NttForm& other) const;
    NttForm operator-(const NttForm& other) const;
    NttForm& operator+=(const NttForm& other);
    NttForm PointwiseMul(const NttForm& other) const;

    // Inner product: ⟨this, other⟩ = Σ slots[j] * other.slots[j] mod (X^4 - root_j)
    // Result is a single NttSlot summed over all slots — but actually returns a SmilePoly
    // via INTT of the pointwise product.
    // For scalar slots (constant polynomials), this is linear.

    bool operator==(const NttForm& other) const;
};

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_POLY_H
