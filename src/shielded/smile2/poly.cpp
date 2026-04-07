// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/poly.h>

#include <support/cleanse.h>

namespace smile2 {

// --- SmilePoly ---

void SmilePoly::Reduce() {
    for (auto& c : coeffs) {
        c = mod_q(c);
    }
}

void SmilePoly::SecureClear()
{
    memory_cleanse(coeffs.data(), sizeof(coeffs));
}

SmilePoly SmilePoly::operator+(const SmilePoly& other) const {
    SmilePoly result;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        result.coeffs[i] = add_mod_q(coeffs[i], other.coeffs[i]);
    }
    return result;
}

SmilePoly SmilePoly::operator-(const SmilePoly& other) const {
    SmilePoly result;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        result.coeffs[i] = sub_mod_q(coeffs[i], other.coeffs[i]);
    }
    return result;
}

SmilePoly SmilePoly::operator*(int64_t scalar) const {
    SmilePoly result;
    int64_t s = mod_q(scalar);
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        result.coeffs[i] = mul_mod_q(coeffs[i], s);
    }
    return result;
}

SmilePoly& SmilePoly::operator+=(const SmilePoly& other) {
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        coeffs[i] = add_mod_q(coeffs[i], other.coeffs[i]);
    }
    return *this;
}

SmilePoly& SmilePoly::operator-=(const SmilePoly& other) {
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        coeffs[i] = sub_mod_q(coeffs[i], other.coeffs[i]);
    }
    return *this;
}

SmilePoly SmilePoly::MulSchoolbook(const SmilePoly& other) const {
    // Multiply in Z_q[X]/(X^128+1) via schoolbook with negacyclic reduction
    SmilePoly result;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        for (size_t j = 0; j < POLY_DEGREE; ++j) {
            int64_t prod = mul_mod_q(coeffs[i], other.coeffs[j]);
            size_t idx = i + j;
            if (idx < POLY_DEGREE) {
                result.coeffs[idx] = add_mod_q(result.coeffs[idx], prod);
            } else {
                // X^128 = -1 in the quotient ring
                result.coeffs[idx - POLY_DEGREE] = sub_mod_q(result.coeffs[idx - POLY_DEGREE], prod);
            }
        }
    }
    return result;
}

bool SmilePoly::operator==(const SmilePoly& other) const {
    uint64_t diff{0};
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        diff |= static_cast<uint64_t>(mod_q(coeffs[i]) ^ mod_q(other.coeffs[i]));
    }
    return diff == 0;
}

bool SmilePoly::IsZero() const {
    uint64_t diff{0};
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        diff |= static_cast<uint64_t>(mod_q(coeffs[i]));
    }
    return diff == 0;
}

// --- NttSlot ---

NttSlot NttSlot::Add(const NttSlot& other) const {
    NttSlot result;
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        result.coeffs[i] = add_mod_q(coeffs[i], other.coeffs[i]);
    }
    return result;
}

NttSlot NttSlot::Sub(const NttSlot& other) const {
    NttSlot result;
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        result.coeffs[i] = sub_mod_q(coeffs[i], other.coeffs[i]);
    }
    return result;
}

NttSlot NttSlot::Mul(const NttSlot& other, int64_t root) const {
    // Multiply in Z_q[X]/(X^4 - root)
    // Let a = a0 + a1*X + a2*X^2 + a3*X^3
    //     b = b0 + b1*X + b2*X^2 + b3*X^3
    // Product mod (X^4 - root):
    //   X^4 = root, X^5 = root*X, X^6 = root*X^2, X^7... not needed for degree 3*3=6
    // Actually max degree of product is 6, so we reduce X^4 -> root, X^5 -> root*X, X^6 -> root*X^2
    std::array<int64_t, 7> tmp{};
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        for (size_t j = 0; j < SLOT_DEGREE; ++j) {
            int64_t prod = mul_mod_q(coeffs[i], other.coeffs[j]);
            tmp[i + j] = add_mod_q(tmp[i + j], prod);
        }
    }
    // Reduce: X^k for k >= 4 becomes root^(k/4) * X^(k%4)... no, just X^4 = root
    NttSlot result;
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        result.coeffs[i] = tmp[i];
    }
    // tmp[4] contributes root to coeff 0, tmp[5] contributes root to coeff 1, tmp[6] to coeff 2
    result.coeffs[0] = add_mod_q(result.coeffs[0], mul_mod_q(tmp[4], root));
    result.coeffs[1] = add_mod_q(result.coeffs[1], mul_mod_q(tmp[5], root));
    result.coeffs[2] = add_mod_q(result.coeffs[2], mul_mod_q(tmp[6], root));
    return result;
}

NttSlot NttSlot::ScalarMul(int64_t scalar) const {
    NttSlot result;
    int64_t s = mod_q(scalar);
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        result.coeffs[i] = mul_mod_q(coeffs[i], s);
    }
    return result;
}

bool NttSlot::operator==(const NttSlot& other) const {
    uint64_t diff{0};
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        diff |= static_cast<uint64_t>(mod_q(coeffs[i]) ^ mod_q(other.coeffs[i]));
    }
    return diff == 0;
}

bool NttSlot::IsZero() const {
    uint64_t diff{0};
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        diff |= static_cast<uint64_t>(mod_q(coeffs[i]));
    }
    return diff == 0;
}

// --- NttForm ---

NttForm NttForm::operator+(const NttForm& other) const {
    NttForm result;
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        result.slots[j] = slots[j].Add(other.slots[j]);
    }
    return result;
}

NttForm& NttForm::operator+=(const NttForm& other) {
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        for (size_t i = 0; i < SLOT_DEGREE; ++i) {
            slots[j].coeffs[i] = add_mod_q(slots[j].coeffs[i], other.slots[j].coeffs[i]);
        }
    }
    return *this;
}

NttForm NttForm::operator-(const NttForm& other) const {
    NttForm result;
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        result.slots[j] = slots[j].Sub(other.slots[j]);
    }
    return result;
}

NttForm NttForm::PointwiseMul(const NttForm& other) const {
    NttForm result;
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        result.slots[j] = slots[j].Mul(other.slots[j], SLOT_ROOTS[j]);
    }
    return result;
}

bool NttForm::operator==(const NttForm& other) const {
    uint64_t diff{0};
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        for (size_t i = 0; i < SLOT_DEGREE; ++i) {
            diff |= static_cast<uint64_t>(
                mod_q(slots[j].coeffs[i]) ^ mod_q(other.slots[j].coeffs[i]));
        }
    }
    return diff == 0;
}

} // namespace smile2
