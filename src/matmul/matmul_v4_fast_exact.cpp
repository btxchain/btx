// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_fast_exact.h>

#include <limits>

namespace matmul::v4::fast_exact {
namespace {

using S8 = std::vector<int8_t>;
using S32 = std::vector<int32_t>;

S8 Block(const S8& matrix, uint32_t matrix_cols, uint32_t row0, uint32_t col0,
         uint32_t rows, uint32_t cols)
{
    S8 out(static_cast<size_t>(rows) * cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            out[static_cast<size_t>(r) * cols + c] =
                matrix[static_cast<size_t>(row0 + r) * matrix_cols + col0 + c];
        }
    }
    return out;
}

bool AddS8(const S8& a, const S8& b, int sign_b, S8& out)
{
    if (a.size() != b.size()) return false;
    out.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        const int value = static_cast<int>(a[i]) + sign_b * static_cast<int>(b[i]);
        if (value < std::numeric_limits<int8_t>::min() ||
            value > std::numeric_limits<int8_t>::max()) {
            out.clear();
            return false;
        }
        out[i] = static_cast<int8_t>(value);
    }
    return true;
}

bool Classical(const S8& a, const S8& b, uint32_t rows, uint32_t inner, uint32_t cols,
               S32& out)
{
    std::vector<int64_t> accum(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t k = 0; k < inner; ++k) {
            const int64_t av = a[static_cast<size_t>(i) * inner + k];
            if (av == 0) continue;
            for (uint32_t j = 0; j < cols; ++j) {
                accum[static_cast<size_t>(i) * cols + j] +=
                    av * static_cast<int64_t>(b[static_cast<size_t>(k) * cols + j]);
            }
        }
    }
    out.resize(accum.size());
    for (size_t i = 0; i < accum.size(); ++i) {
        // A transform product that cannot be represented exactly in S32 is
        // unusable by an S8xS8->S32 accelerator lane.  The public dimensions
        // are far below this limit, but keep the standalone calibration API
        // defined for arbitrary callers.
        if (accum[i] < std::numeric_limits<int32_t>::min() ||
            accum[i] > std::numeric_limits<int32_t>::max()) {
            out.clear();
            return false;
        }
        out[i] = static_cast<int32_t>(accum[i]);
    }
    return true;
}

bool StoreChecked(S32& out, uint32_t out_cols, uint32_t row0, uint32_t col0,
                  uint32_t rows, uint32_t cols, const S32& x, const S32* y = nullptr,
                  int sign_y = 1, const S32* z = nullptr, int sign_z = 1,
                  const S32* w = nullptr, int sign_w = 1)
{
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            const size_t i = static_cast<size_t>(r) * cols + c;
            int64_t value = x[i];
            if (y) value += static_cast<int64_t>(sign_y) * (*y)[i];
            if (z) value += static_cast<int64_t>(sign_z) * (*z)[i];
            if (w) value += static_cast<int64_t>(sign_w) * (*w)[i];
            if (value < std::numeric_limits<int32_t>::min() ||
                value > std::numeric_limits<int32_t>::max()) {
                return false;
            }
            out[static_cast<size_t>(row0 + r) * out_cols + col0 + c] =
                static_cast<int32_t>(value);
        }
    }
    return true;
}

} // namespace

bool GemmS8S8Strassen1(const std::vector<int8_t>& left,
                       const std::vector<int8_t>& right,
                       uint32_t rows, uint32_t inner, uint32_t cols,
                       std::vector<int32_t>& out)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0 ||
        (rows & 1U) != 0 || (inner & 1U) != 0 || (cols & 1U) != 0) {
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        return false;
    }

    const uint32_t rh = rows / 2;
    const uint32_t kh = inner / 2;
    const uint32_t ch = cols / 2;
    const S8 a11 = Block(left, inner, 0, 0, rh, kh);
    const S8 a12 = Block(left, inner, 0, kh, rh, kh);
    const S8 a21 = Block(left, inner, rh, 0, rh, kh);
    const S8 a22 = Block(left, inner, rh, kh, rh, kh);
    const S8 b11 = Block(right, cols, 0, 0, kh, ch);
    const S8 b12 = Block(right, cols, 0, ch, kh, ch);
    const S8 b21 = Block(right, cols, kh, 0, kh, ch);
    const S8 b22 = Block(right, cols, kh, ch, kh, ch);

    S8 x1, x2;
    if (!AddS8(a11, a22, +1, x1) || !AddS8(b11, b22, +1, x2)) return false;
    S32 m1, m2, m3, m4, m5, m6, m7;
    if (!Classical(x1, x2, rh, kh, ch, m1)) return false;
    if (!AddS8(a21, a22, +1, x1)) return false;
    if (!Classical(x1, b11, rh, kh, ch, m2)) return false;
    if (!AddS8(b12, b22, -1, x2)) return false;
    if (!Classical(a11, x2, rh, kh, ch, m3)) return false;
    if (!AddS8(b21, b11, -1, x2)) return false;
    if (!Classical(a22, x2, rh, kh, ch, m4)) return false;
    if (!AddS8(a11, a12, +1, x1)) return false;
    if (!Classical(x1, b22, rh, kh, ch, m5)) return false;
    if (!AddS8(a21, a11, -1, x1) || !AddS8(b11, b12, +1, x2)) return false;
    if (!Classical(x1, x2, rh, kh, ch, m6)) return false;
    if (!AddS8(a12, a22, -1, x1) || !AddS8(b21, b22, +1, x2)) return false;
    if (!Classical(x1, x2, rh, kh, ch, m7)) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    // C11=M1+M4-M5+M7; C12=M3+M5; C21=M2+M4; C22=M1-M2+M3+M6.
    if (!StoreChecked(out, cols, 0, 0, rh, ch, m1, &m4, +1, &m5, -1, &m7, +1) ||
        !StoreChecked(out, cols, 0, ch, rh, ch, m3, &m5, +1) ||
        !StoreChecked(out, cols, rh, 0, rh, ch, m2, &m4, +1) ||
        !StoreChecked(out, cols, rh, ch, rh, ch, m1, &m2, -1, &m3, +1, &m6, +1)) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace matmul::v4::fast_exact
