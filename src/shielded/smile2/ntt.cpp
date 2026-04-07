// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/ntt.h>

#include <cassert>
#include <limits>
#include <mutex>

namespace smile2 {

namespace {

// Precomputed power table: NTT_POWERS[j][k] = SLOT_ROOTS[j]^k mod Q
// Computed once on first use, avoids recomputing per NttForward call.
static std::array<std::array<int64_t, POLY_DEGREE / SLOT_DEGREE>, NUM_NTT_SLOTS> NTT_POWERS{};
static std::once_flag NTT_POWERS_ONCE;
static std::array<std::array<int64_t, NUM_NTT_SLOTS>, NUM_NTT_SLOTS> NTT_VANDERMONDE_INV{};
static std::once_flag NTT_VANDERMONDE_INV_ONCE;

static void EnsureNttPowers()
{
    std::call_once(NTT_POWERS_ONCE, [] {
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            NTT_POWERS[j][0] = 1;
            for (size_t k = 1; k < POLY_DEGREE / SLOT_DEGREE; ++k) {
                NTT_POWERS[j][k] = mul_mod_q(NTT_POWERS[j][k - 1], SLOT_ROOTS[j]);
            }
        }
    });
}

static const std::array<std::array<int64_t, NUM_NTT_SLOTS>, NUM_NTT_SLOTS>& GetNttVandermondeInverse()
{
    std::call_once(NTT_VANDERMONDE_INV_ONCE, [] {
        std::array<std::array<int64_t, NUM_NTT_SLOTS>, NUM_NTT_SLOTS> V{};
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            V[j][0] = 1;
            for (size_t k = 1; k < NUM_NTT_SLOTS; ++k) {
                V[j][k] = mul_mod_q(V[j][k - 1], SLOT_ROOTS[j]);
            }
        }

        std::array<std::array<int64_t, 2 * NUM_NTT_SLOTS>, NUM_NTT_SLOTS> aug{};
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            for (size_t k = 0; k < NUM_NTT_SLOTS; ++k) {
                aug[j][k] = V[j][k];
                aug[j][k + NUM_NTT_SLOTS] = (j == k) ? 1 : 0;
            }
        }

        for (size_t col = 0; col < NUM_NTT_SLOTS; ++col) {
            size_t pivot = col;
            for (size_t row = col; row < NUM_NTT_SLOTS; ++row) {
                if (aug[row][col] != 0) { pivot = row; break; }
            }
            if (pivot != col) std::swap(aug[col], aug[pivot]);

            int64_t inv = inv_mod_q(aug[col][col]);
            for (size_t k = 0; k < 2 * NUM_NTT_SLOTS; ++k) {
                aug[col][k] = mul_mod_q(aug[col][k], inv);
            }

            for (size_t row = 0; row < NUM_NTT_SLOTS; ++row) {
                if (row == col) continue;
                int64_t factor = aug[row][col];
                if (factor == 0) continue;
                for (size_t k = 0; k < 2 * NUM_NTT_SLOTS; ++k) {
                    aug[row][k] = sub_mod_q(aug[row][k], mul_mod_q(factor, aug[col][k]));
                }
            }
        }

        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            for (size_t k = 0; k < NUM_NTT_SLOTS; ++k) {
                NTT_VANDERMONDE_INV[j][k] = aug[j][k + NUM_NTT_SLOTS];
            }
        }
    });
    return NTT_VANDERMONDE_INV;
}

} // namespace

NttForm NttForward(const SmilePoly& p) {
    EnsureNttPowers();
    NttForm result;
    for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            int64_t sum = 0;
            for (size_t k = 0; k < POLY_DEGREE / SLOT_DEGREE; ++k) {
                sum = add_mod_q(sum, mul_mod_q(p.coeffs[4 * k + c], NTT_POWERS[j][k]));
            }
            result.slots[j].coeffs[c] = sum;
        }
    }
    return result;
}

NttForm SlotPointwiseMul(const NttForm& a, const NttForm& b) {
    return a.PointwiseMul(b);
}


SmilePoly NttInverse(const NttForm& ntt) {
    const auto& vinv = GetNttVandermondeInverse();

    SmilePoly result;
    for (size_t c = 0; c < SLOT_DEGREE; ++c) {
        for (size_t k = 0; k < NUM_NTT_SLOTS; ++k) {
            int64_t sum = 0;
            for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
                sum = add_mod_q(sum, mul_mod_q(vinv[k][j], ntt.slots[j].coeffs[c]));
            }
            result.coeffs[4 * k + c] = sum;
        }
    }

    return result;
}

SmilePoly NttMul(const SmilePoly& a, const SmilePoly& b) {
    NttForm na = NttForward(a);
    NttForm nb = NttForward(b);
    NttForm nc = na.PointwiseMul(nb);
    return NttInverse(nc);
}

std::vector<int64_t> TensorProduct(const std::vector<std::array<int64_t, NUM_NTT_SLOTS>>& vectors) {
    size_t m = vectors.size();
    if (m == 0) return {};

    size_t max_product_size = NUM_NTT_SLOTS;
    for (size_t i = 1; i < m; ++i) {
        if (max_product_size > std::numeric_limits<size_t>::max() / NUM_NTT_SLOTS) {
            return {};
        }
        max_product_size *= NUM_NTT_SLOTS;
    }

    // Start with first vector
    std::vector<int64_t> result(vectors[0].begin(), vectors[0].end());

    // Tensor with each subsequent vector
    // Index convention: index = d_1 + d_2*l + d_3*l^2 + ...
    // So v_{i+1} becomes the OUTER (most significant) index.
    for (size_t i = 1; i < m; ++i) {
        std::vector<int64_t> prev = std::move(result);
        if (prev.size() > std::numeric_limits<size_t>::max() / NUM_NTT_SLOTS) {
            return {};
        }
        size_t new_size = prev.size() * NUM_NTT_SLOTS;
        result.resize(new_size, 0);
        for (size_t b = 0; b < NUM_NTT_SLOTS; ++b) {
            for (size_t a = 0; a < prev.size(); ++a) {
                result[b * prev.size() + a] = mul_mod_q(prev[a], vectors[i][b]);
            }
        }
    }

    return result;
}

std::vector<std::array<int64_t, NUM_NTT_SLOTS>> DecomposeIndex(size_t index, size_t m) {
    std::vector<std::array<int64_t, NUM_NTT_SLOTS>> result(m);
    size_t remaining = index;
    for (size_t i = 0; i < m; ++i) {
        size_t digit = remaining % NUM_NTT_SLOTS;
        for (size_t slot = 0; slot < NUM_NTT_SLOTS; ++slot) {
            result[i][slot] = static_cast<int64_t>(slot == digit);
        }
        remaining /= NUM_NTT_SLOTS;
    }
    return result;
}

} // namespace smile2
