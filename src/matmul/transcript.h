// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_TRANSCRIPT_H
#define BTX_MATMUL_TRANSCRIPT_H

#include <matmul/noise.h>
#include <matmul/matrix.h>

#include <crypto/sha256.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <string_view>
#include <vector>

namespace matmul::transcript {

inline constexpr std::string_view COMPRESS_TAG{"matmul-compress-v1"};
inline constexpr std::string_view PRODUCT_DIGEST_TAG{"matmul-product-digest-v3"};

std::vector<field::Element> DeriveCompressionVector(const uint256& sigma, uint32_t b);
field::Element CompressBlock(const Matrix& block_bb, const std::vector<field::Element>& v);
field::Element CompressBlock(const ConstMatrixView& block_bb, const std::vector<field::Element>& v);

class TranscriptHasher {
public:
    TranscriptHasher(const uint256& sigma, uint32_t b);

    void AddIntermediate(uint32_t i, uint32_t j, uint32_t ell, const Matrix& block_bb);
    void AddIntermediate(uint32_t i, uint32_t j, uint32_t ell, const ConstMatrixView& block_bb);
    uint256 Finalize();

private:
    uint32_t m_b;
    CSHA256 m_hasher;
    std::vector<field::Element> m_compress_vec;
};

struct CanonicalResult {
    Matrix C_prime;
    uint256 transcript_hash;
};

CanonicalResult CanonicalMatMul(const Matrix& A_prime, const Matrix& B_prime, uint32_t b, const uint256& sigma);
std::vector<Matrix> PrecomputeCleanBlockProducts(const Matrix& A, const Matrix& B, uint32_t b);
uint256 ReplayCanonicalHashWithReusableCleanProducts(
    const Matrix& A,
    const Matrix& B,
    const std::vector<Matrix>& clean_block_products,
    const noise::NoisePair& noise,
    uint32_t b,
    const uint256& sigma);

/** Compute the post-61000 digest from the sigma-bound compressed final block
 *  image of C'. Validators can rebuild the compressed image from the carried
 *  C' payload in O(n^2) and then use Freivalds to confirm A'B' == C'. */
uint256 HashMatrixWords(Span<const field::Element> words);
uint256 FinalizeProductCommittedDigestFromHash(const uint256& c_prime_hash,
                                               const uint256& sigma,
                                               uint32_t dim,
                                               uint32_t b);
uint256 ComputeProductCommittedDigestFromWords(Span<const field::Element> c_prime_words,
                                               const uint256& sigma,
                                               uint32_t dim,
                                               uint32_t b);
uint256 ComputeProductCommittedDigest(const Matrix& C_prime, uint32_t b, const uint256& sigma);
uint256 ComputeProductCommittedDigestFromPerturbed(const Matrix& A_prime,
                                                   const Matrix& B_prime,
                                                   uint32_t b,
                                                   const uint256& sigma);

} // namespace matmul::transcript

#endif // BTX_MATMUL_TRANSCRIPT_H
