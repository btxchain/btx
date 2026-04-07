// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MATMUL_FREIVALDS_H
#define BITCOIN_MATMUL_FREIVALDS_H

#include <matmul/field.h>
#include <matmul/matrix.h>

#include <cstdint>
#include <vector>

class uint256;

namespace matmul::freivalds {

struct VerifyResult {
    bool passed{false};
    uint32_t rounds_executed{0};
    uint64_t ops_performed{0};
};

/** Deterministically derive a Freivalds random vector from sigma and round. */
[[nodiscard]] std::vector<field::Element> DeriveRandomVector(const uint256& sigma,
                                                              uint32_t round,
                                                              uint32_t n);

/** Multiply a matrix by a vector over GF(2^31-1). */
[[nodiscard]] std::vector<field::Element> MatVecMul(const Matrix& matrix,
                                                     const std::vector<field::Element>& vector);

/** Verify A*B==C using Freivalds rounds derived from sigma.
 *  Each round costs O(n^2) and has false-positive probability at most
 *  1/|F| = 1/(2^31-1). With k rounds the combined error probability
 *  is at most (1/|F|)^k. */
[[nodiscard]] VerifyResult Verify(const Matrix& A,
                                  const Matrix& B,
                                  const Matrix& C,
                                  const uint256& sigma,
                                  uint32_t num_rounds);

} // namespace matmul::freivalds

#endif // BITCOIN_MATMUL_FREIVALDS_H
