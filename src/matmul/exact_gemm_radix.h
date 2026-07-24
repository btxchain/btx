// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_EXACT_GEMM_RADIX_H
#define BITCOIN_MATMUL_EXACT_GEMM_RADIX_H

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace matmul::v4::lt {

/**
 * Implement a bounded exact S32 x S8 -> S32 GEMM using four exact
 * S8 x S8 -> S32 tensor GEMMs.
 *
 * Every S32 left operand is represented by four signed radix-256 planes.  The
 * low three bytes are biased into S8 and a single right-column correction is
 * added after the four products.  Reconstruction is deliberately performed
 * modulo 2^32 and bit-cast back to S32, so it is independent of signed-shift
 * and signed-overflow behaviour.  The conservative input bound admits only
 * products whose mathematical result is guaranteed to fit S32.
 */
template <typename GemmS8S8>
[[nodiscard]] bool ExactGemmS32S8ViaRadix256(
    const std::vector<int32_t>& left, const std::vector<int8_t>& right,
    uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out,
    GemmS8S8&& gemm_s8s8)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) return false;

    const auto checked_product = [](size_t a, size_t b, size_t& product) {
        if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
        product = a * b;
        return true;
    };
    size_t left_elems{0};
    size_t right_elems{0};
    size_t out_elems{0};
    if (!checked_product(rows, inner, left_elems) ||
        !checked_product(inner, cols, right_elems) ||
        !checked_product(rows, cols, out_elems) ||
        left.size() != left_elems || right.size() != right_elems) {
        return false;
    }

    uint64_t max_left{0};
    uint64_t max_right{0};
    for (const int32_t value : left) {
        const int64_t wide = value;
        const uint64_t magnitude = static_cast<uint64_t>(wide < 0 ? -wide : wide);
        if (magnitude > max_left) max_left = magnitude;
    }
    for (const int8_t value : right) {
        const int32_t wide = value;
        const uint64_t magnitude = static_cast<uint64_t>(wide < 0 ? -wide : wide);
        if (magnitude > max_right) max_right = magnitude;
    }
    // This bound is intentionally conservative. It proves every output fits
    // S32 before the modular reconstruction below. The production Y*H values
    // are comfortably inside it.
    constexpr uint64_t kMaxS32 = std::numeric_limits<int32_t>::max();
    if (max_left != 0 && max_right != 0 &&
        (max_left > kMaxS32 / max_right ||
         static_cast<uint64_t>(inner) > kMaxS32 / (max_left * max_right))) {
        return false;
    }

    std::vector<int8_t> plane;
    std::vector<int32_t> plane_product;
    std::vector<uint32_t> result_bits;
    std::vector<int64_t> right_column_sums;
    try {
        plane.resize(left_elems);
        result_bits.assign(out_elems, 0);
        right_column_sums.assign(cols, 0);
    } catch (...) {
        return false;
    }

    for (uint32_t k = 0; k < inner; ++k) {
        const int8_t* right_row = right.data() + static_cast<size_t>(k) * cols;
        for (uint32_t c = 0; c < cols; ++c) {
            right_column_sums[c] += static_cast<int32_t>(right_row[c]);
        }
    }

    for (uint32_t limb = 0; limb < 4; ++limb) {
        const uint32_t shift = limb * 8;
        for (size_t i = 0; i < left_elems; ++i) {
            const uint32_t bits = std::bit_cast<uint32_t>(left[i]);
            const uint8_t byte = static_cast<uint8_t>(bits >> shift);
            plane[i] = limb == 3
                ? std::bit_cast<int8_t>(byte)
                : static_cast<int8_t>(static_cast<int32_t>(byte) - 128);
        }
        plane_product.clear();
        if (!gemm_s8s8(plane, right, rows, inner, cols, plane_product) ||
            plane_product.size() != out_elems) {
            out.clear();
            return false;
        }
        const uint32_t weight = uint32_t{1} << shift;
        for (size_t i = 0; i < out_elems; ++i) {
            result_bits[i] += std::bit_cast<uint32_t>(plane_product[i]) * weight;
        }
    }

    // Each biased low byte contributed -128. Restore the three omitted terms:
    // 128 * (1 + 256 + 65536) * sum(right_column).
    constexpr int64_t kBias = int64_t{128} * (1 + 256 + 65536);
    try {
        out.resize(out_elems);
    } catch (...) {
        out.clear();
        return false;
    }
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t col = 0; col < cols; ++col) {
            const size_t index = static_cast<size_t>(row) * cols + col;
            result_bits[index] += static_cast<uint32_t>(kBias * right_column_sums[col]);
            out[index] = std::bit_cast<int32_t>(result_bits[index]);
        }
    }
    return true;
}

} // namespace matmul::v4::lt

#endif // BITCOIN_MATMUL_EXACT_GEMM_RADIX_H
