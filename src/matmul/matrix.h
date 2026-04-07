// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATRIX_H
#define BTX_MATMUL_MATRIX_H

#include <matmul/field.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

class uint256;

namespace matmul {

struct MatrixMemoryStats {
    uint64_t matrices_constructed{0};
    uint64_t matrices_destroyed{0};
    uint64_t live_bytes{0};
    uint64_t peak_live_bytes{0};
};

class ConstMatrixView
{
public:
    ConstMatrixView(const field::Element* data, uint32_t rows, uint32_t cols, uint32_t stride);

    const field::Element& at(uint32_t row, uint32_t col) const;
    const field::Element* row_ptr(uint32_t row) const;

    uint32_t rows() const;
    uint32_t cols() const;

private:
    const field::Element* m_data;
    uint32_t m_rows;
    uint32_t m_cols;
    uint32_t m_stride;
};

class MatrixView
{
public:
    MatrixView(field::Element* data, uint32_t rows, uint32_t cols, uint32_t stride);

    field::Element& at(uint32_t row, uint32_t col);
    const field::Element& at(uint32_t row, uint32_t col) const;
    field::Element* row_ptr(uint32_t row);
    const field::Element* row_ptr(uint32_t row) const;

    uint32_t rows() const;
    uint32_t cols() const;

private:
    field::Element* m_data;
    uint32_t m_rows;
    uint32_t m_cols;
    uint32_t m_stride;
};

class Matrix {
public:
    Matrix(uint32_t rows, uint32_t cols);
    Matrix(const Matrix& other);
    Matrix(Matrix&& other) noexcept;
    Matrix& operator=(const Matrix& other);
    Matrix& operator=(Matrix&& other) noexcept;
    ~Matrix();

    field::Element& at(uint32_t row, uint32_t col);
    const field::Element& at(uint32_t row, uint32_t col) const;

    uint32_t rows() const;
    uint32_t cols() const;

    field::Element* data();
    const field::Element* data() const;

    Matrix block(uint32_t bi, uint32_t bj, uint32_t b) const;
    ConstMatrixView block_view(uint32_t bi, uint32_t bj, uint32_t b) const;
    MatrixView mutable_block_view(uint32_t bi, uint32_t bj, uint32_t b);
    void set_block(uint32_t bi, uint32_t bj, uint32_t b, const Matrix& blk);

    Matrix operator+(const Matrix& rhs) const;
    Matrix operator-(const Matrix& rhs) const;
    Matrix operator*(const Matrix& rhs) const;

    uint256 ContentHash() const;
    bool operator==(const Matrix& rhs) const;

private:
    void ReconcileTrackedBytes(size_t new_bytes);

    uint32_t m_rows;
    uint32_t m_cols;
    std::vector<field::Element> m_data;
    size_t m_tracked_bytes{0};
};

Matrix Identity(uint32_t n);
Matrix FromSeed(const uint256& seed, uint32_t n);
std::shared_ptr<const Matrix> SharedFromSeed(const uint256& seed, uint32_t n);
Matrix MultiplyBlocked(const Matrix& lhs, const Matrix& rhs, uint32_t tile_size);
MatrixMemoryStats ProbeMatrixMemoryStats();
void ResetMatrixMemoryStats();

} // namespace matmul

#endif // BTX_MATMUL_MATRIX_H
