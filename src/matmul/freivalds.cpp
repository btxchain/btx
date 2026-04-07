// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/freivalds.h>

#include <hash.h>

#include <algorithm>
#include <cstdint>
#include <limits>

namespace matmul::freivalds {
namespace {
constexpr uint8_t FREIVALDS_DOMAIN_TAG{0xF4};
constexpr uint8_t FREIVALDS_MATRIX_A_TAG{0xA1};
constexpr uint8_t FREIVALDS_MATRIX_B_TAG{0xB2};
constexpr uint8_t FREIVALDS_MATRIX_C_TAG{0xC3};

uint64_t SaturatingAdd(uint64_t lhs, uint64_t rhs)
{
    if (rhs > std::numeric_limits<uint64_t>::max() - lhs) {
        return std::numeric_limits<uint64_t>::max();
    }
    return lhs + rhs;
}

void HashMatrix(HashWriter& hasher, uint8_t matrix_tag, const Matrix& matrix)
{
    hasher << matrix_tag;
    hasher << matrix.rows();
    hasher << matrix.cols();
    const size_t elements = static_cast<size_t>(matrix.rows()) * matrix.cols();
    const field::Element* data = matrix.data();
    for (size_t i = 0; i < elements; ++i) {
        hasher << data[i];
    }
}

uint256 DeriveChallengeSeed(const Matrix& A, const Matrix& B, const Matrix& C, const uint256& sigma)
{
    // Bind challenge vectors to all matrix witnesses so vectors are not a fixed
    // function of sigma alone.
    HashWriter challenge_hasher{};
    challenge_hasher << FREIVALDS_DOMAIN_TAG;
    challenge_hasher << sigma;
    HashMatrix(challenge_hasher, FREIVALDS_MATRIX_A_TAG, A);
    HashMatrix(challenge_hasher, FREIVALDS_MATRIX_B_TAG, B);
    HashMatrix(challenge_hasher, FREIVALDS_MATRIX_C_TAG, C);
    return challenge_hasher.GetSHA256();
}
} // namespace

std::vector<field::Element> DeriveRandomVector(const uint256& sigma, uint32_t round, uint32_t n)
{
    HashWriter seed_hasher{};
    seed_hasher << FREIVALDS_DOMAIN_TAG;
    seed_hasher << sigma;
    seed_hasher << round;
    seed_hasher << n;
    const uint256 round_seed{seed_hasher.GetSHA256()};

    std::vector<field::Element> random_vector(n);
    for (uint32_t i = 0; i < n; ++i) {
        random_vector[i] = field::from_oracle(round_seed, i);
    }
    return random_vector;
}

std::vector<field::Element> MatVecMul(const Matrix& matrix, const std::vector<field::Element>& vector)
{
    if (matrix.cols() != vector.size()) {
        return {};
    }

    std::vector<field::Element> out(matrix.rows());
    for (uint32_t row = 0; row < matrix.rows(); ++row) {
        const field::Element* row_ptr = matrix.data() + static_cast<size_t>(row) * matrix.cols();
        out[row] = field::dot(row_ptr, vector.data(), matrix.cols());
    }
    return out;
}

VerifyResult Verify(const Matrix& A,
                    const Matrix& B,
                    const Matrix& C,
                    const uint256& sigma,
                    uint32_t num_rounds)
{
    VerifyResult result{
        .passed = false,
        .rounds_executed = 0,
        .ops_performed = 0,
    };

    if (A.cols() != B.rows()) return result;
    if (A.rows() != C.rows()) return result;
    if (B.cols() != C.cols()) return result;

    if (num_rounds == 0) {
        result.passed = true;
        return result;
    }

    const uint64_t per_round_ops =
        static_cast<uint64_t>(B.rows()) * B.cols() +
        static_cast<uint64_t>(A.rows()) * A.cols() +
        static_cast<uint64_t>(C.rows()) * C.cols();
    const uint256 challenge_seed = DeriveChallengeSeed(A, B, C, sigma);

    for (uint32_t round = 0; round < num_rounds; ++round) {
        const auto random_vector = DeriveRandomVector(challenge_seed, round, C.cols());
        const auto y = MatVecMul(B, random_vector);
        if (y.empty()) return result;
        const auto z = MatVecMul(A, y);
        if (z.empty()) return result;
        const auto w = MatVecMul(C, random_vector);
        if (w.empty()) return result;

        result.ops_performed = SaturatingAdd(result.ops_performed, per_round_ops);
        result.rounds_executed++;
        if (!std::equal(z.begin(), z.end(), w.begin(), w.end())) return result;
    }

    result.passed = true;
    return result;
}

} // namespace matmul::freivalds
