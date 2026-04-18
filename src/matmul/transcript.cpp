// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/transcript.h>

#include <crypto/common.h>
#include <hash.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <stdexcept>

namespace matmul::transcript {
namespace {

std::array<uint8_t, 32> ToCanonicalBytes(const uint256& value)
{
    std::array<uint8_t, 32> out;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = value.data()[out.size() - 1 - i];
    }
    return out;
}

uint256 CanonicalBytesToUint256(const uint8_t* bytes)
{
    std::array<unsigned char, 32> internal;
    for (size_t i = 0; i < internal.size(); ++i) {
        internal[i] = bytes[internal.size() - 1 - i];
    }
    return uint256{Span<const unsigned char>{internal.data(), internal.size()}};
}

uint256 DeriveCompressionSeed(const uint256& sigma)
{
    const auto sigma_bytes = ToCanonicalBytes(sigma);

    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(COMPRESS_TAG.data()), COMPRESS_TAG.size());
    hasher.Write(sigma_bytes.data(), sigma_bytes.size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return CanonicalBytesToUint256(digest);
}

ConstMatrixView RowBlockAllCols(const Matrix& matrix, uint32_t block_index, uint32_t block_rows)
{
    return ConstMatrixView(
        matrix.data() + static_cast<size_t>(block_index) * block_rows * matrix.cols(),
        block_rows,
        matrix.cols(),
        matrix.cols());
}

ConstMatrixView AllRowsColBlock(const Matrix& matrix, uint32_t block_index, uint32_t block_cols)
{
    return ConstMatrixView(
        matrix.data() + static_cast<size_t>(block_index) * block_cols,
        matrix.rows(),
        block_cols,
        matrix.cols());
}

size_t BlockProductIndex(uint32_t i, uint32_t j, uint32_t ell, uint32_t blocks_per_axis)
{
    return (static_cast<size_t>(i) * blocks_per_axis + j) * blocks_per_axis + ell;
}

field::Element CompressAfBlock(
    const ConstMatrixView& a_block,
    const ConstMatrixView& f_l_block,
    const ConstMatrixView& f_r_block,
    const std::vector<field::Element>& v)
{
    const uint32_t b = a_block.rows();
    const uint32_t r = f_l_block.cols();
    std::vector<field::Element> weighted_v(static_cast<size_t>(b) * r, 0);
    for (uint32_t x = 0; x < b; ++x) {
        for (uint32_t u = 0; u < r; ++u) {
            field::Element acc = 0;
            for (uint32_t y = 0; y < b; ++y) {
                acc = field::add(acc, field::mul(v[static_cast<size_t>(x) * b + y], f_r_block.at(u, y)));
            }
            weighted_v[static_cast<size_t>(x) * r + u] = acc;
        }
    }

    field::Element scalar = 0;
    for (uint32_t t = 0; t < b; ++t) {
        for (uint32_t u = 0; u < r; ++u) {
            field::Element acc = 0;
            for (uint32_t x = 0; x < b; ++x) {
                acc = field::add(acc, field::mul(a_block.at(x, t), weighted_v[static_cast<size_t>(x) * r + u]));
            }
            scalar = field::add(scalar, field::mul(f_l_block.at(t, u), acc));
        }
    }
    return scalar;
}

field::Element CompressEbBlock(
    const ConstMatrixView& e_l_block,
    const ConstMatrixView& e_r_block,
    const ConstMatrixView& b_block,
    const std::vector<field::Element>& v)
{
    const uint32_t b = e_l_block.rows();
    const uint32_t r = e_l_block.cols();
    std::vector<field::Element> weighted_v(static_cast<size_t>(r) * b, 0);
    for (uint32_t u = 0; u < r; ++u) {
        for (uint32_t y = 0; y < b; ++y) {
            field::Element acc = 0;
            for (uint32_t x = 0; x < b; ++x) {
                acc = field::add(acc, field::mul(e_l_block.at(x, u), v[static_cast<size_t>(x) * b + y]));
            }
            weighted_v[static_cast<size_t>(u) * b + y] = acc;
        }
    }

    field::Element scalar = 0;
    for (uint32_t u = 0; u < r; ++u) {
        for (uint32_t t = 0; t < b; ++t) {
            field::Element acc = 0;
            for (uint32_t y = 0; y < b; ++y) {
                acc = field::add(acc, field::mul(weighted_v[static_cast<size_t>(u) * b + y], b_block.at(t, y)));
            }
            scalar = field::add(scalar, field::mul(e_r_block.at(u, t), acc));
        }
    }
    return scalar;
}

field::Element CompressEfBlock(
    const ConstMatrixView& e_l_block,
    const ConstMatrixView& e_r_block,
    const ConstMatrixView& f_l_block,
    const ConstMatrixView& f_r_block,
    const std::vector<field::Element>& v)
{
    const uint32_t b = e_l_block.rows();
    const uint32_t r = e_l_block.cols();
    std::vector<field::Element> weighted_v(static_cast<size_t>(r) * b, 0);
    for (uint32_t u = 0; u < r; ++u) {
        for (uint32_t y = 0; y < b; ++y) {
            field::Element acc = 0;
            for (uint32_t x = 0; x < b; ++x) {
                acc = field::add(acc, field::mul(e_l_block.at(x, u), v[static_cast<size_t>(x) * b + y]));
            }
            weighted_v[static_cast<size_t>(u) * b + y] = acc;
        }
    }

    std::vector<field::Element> weighted_fr(static_cast<size_t>(r) * r, 0);
    for (uint32_t u = 0; u < r; ++u) {
        for (uint32_t v_idx = 0; v_idx < r; ++v_idx) {
            field::Element acc = 0;
            for (uint32_t y = 0; y < b; ++y) {
                acc = field::add(acc, field::mul(weighted_v[static_cast<size_t>(u) * b + y], f_r_block.at(v_idx, y)));
            }
            weighted_fr[static_cast<size_t>(u) * r + v_idx] = acc;
        }
    }

    field::Element scalar = 0;
    for (uint32_t t = 0; t < b; ++t) {
        for (uint32_t v_idx = 0; v_idx < r; ++v_idx) {
            field::Element acc = 0;
            for (uint32_t u = 0; u < r; ++u) {
                acc = field::add(acc, field::mul(e_r_block.at(u, t), weighted_fr[static_cast<size_t>(u) * r + v_idx]));
            }
            scalar = field::add(scalar, field::mul(acc, f_l_block.at(t, v_idx)));
        }
    }
    return scalar;
}

} // namespace

std::vector<field::Element> DeriveCompressionVector(const uint256& sigma, uint32_t b)
{
    if (b == 0) {
        throw std::runtime_error("block size b must be non-zero");
    }

    const uint256 seed = DeriveCompressionSeed(sigma);

    std::vector<field::Element> vec;
    const uint64_t len = static_cast<uint64_t>(b) * b;
    vec.reserve(static_cast<size_t>(len));

    for (uint64_t k = 0; k < len; ++k) {
        vec.push_back(field::from_oracle(seed, static_cast<uint32_t>(k)));
    }

    return vec;
}

field::Element CompressBlock(const Matrix& block_bb, const std::vector<field::Element>& v)
{
    const uint64_t len = static_cast<uint64_t>(block_bb.rows()) * block_bb.cols();
    if (len != v.size()) {
        throw std::runtime_error("CompressBlock: dimension mismatch between block and compression vector");
    }
    if (len > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("CompressBlock: block size exceeds uint32_t range");
    }
    return field::dot(block_bb.data(), v.data(), static_cast<uint32_t>(len));
}

field::Element CompressBlock(const ConstMatrixView& block_bb, const std::vector<field::Element>& v)
{
    const uint64_t len = static_cast<uint64_t>(block_bb.rows()) * block_bb.cols();
    if (len != v.size()) {
        throw std::runtime_error("CompressBlock: dimension mismatch between block view and compression vector");
    }

    field::Element acc = 0;
    for (uint32_t row = 0; row < block_bb.rows(); ++row) {
        const auto* row_ptr = block_bb.row_ptr(row);
        const auto* weights = &v[static_cast<size_t>(row) * block_bb.cols()];
        acc = field::add(acc, field::dot(row_ptr, weights, block_bb.cols()));
    }
    return acc;
}

TranscriptHasher::TranscriptHasher(const uint256& sigma, uint32_t b)
    : m_b(b), m_hasher(), m_compress_vec(DeriveCompressionVector(sigma, b))
{
}

void TranscriptHasher::AddIntermediate(uint32_t i, uint32_t j, uint32_t ell, const Matrix& block_bb)
{
    AddIntermediate(i,
                    j,
                    ell,
                    ConstMatrixView{
                        block_bb.data(),
                        block_bb.rows(),
                        block_bb.cols(),
                        block_bb.cols(),
                    });
}

void TranscriptHasher::AddIntermediate(uint32_t i, uint32_t j, uint32_t ell, const ConstMatrixView& block_bb)
{
    (void)i;
    (void)j;
    (void)ell;

    assert(block_bb.rows() == m_b);
    assert(block_bb.cols() == m_b);

    const field::Element compressed = CompressBlock(block_bb, m_compress_vec);

    uint8_t bytes[4];
    WriteLE32(bytes, compressed);
    m_hasher.Write(bytes, sizeof(bytes));
}

uint256 TranscriptHasher::Finalize()
{
    uint8_t inner[CSHA256::OUTPUT_SIZE];
    m_hasher.Finalize(inner);

    uint256 out;
    CSHA256().Write(inner, sizeof(inner)).Finalize(out.begin());
    return out;
}

CanonicalResult CanonicalMatMul(const Matrix& A_prime, const Matrix& B_prime, uint32_t b, const uint256& sigma)
{
    if (A_prime.rows() != A_prime.cols() || B_prime.rows() != B_prime.cols() || A_prime.rows() != B_prime.rows()) {
        throw std::runtime_error("canonical matmul requires square matrices of equal size");
    }
    if (b == 0 || (A_prime.rows() % b) != 0) {
        throw std::runtime_error("invalid transcript block size");
    }

    const uint32_t n = A_prime.rows();
    const uint32_t N = n / b;

    Matrix C_prime(n, n);
    TranscriptHasher hasher(sigma, b);

    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = 0; j < N; ++j) {
            for (uint32_t ell = 0; ell < N; ++ell) {
                const Matrix a_block = A_prime.block(i, ell, b);
                const Matrix b_block = B_prime.block(ell, j, b);
                const Matrix product = a_block * b_block;

                Matrix c_block = C_prime.block(i, j, b);
                c_block = c_block + product;
                C_prime.set_block(i, j, b, c_block);

                hasher.AddIntermediate(i, j, ell, c_block);
            }
        }
    }

    return {
        .C_prime = std::move(C_prime),
        .transcript_hash = hasher.Finalize(),
    };
}

std::vector<Matrix> PrecomputeCleanBlockProducts(const Matrix& A, const Matrix& B, uint32_t b)
{
    if (A.rows() != A.cols() || B.rows() != B.cols() || A.rows() != B.rows()) {
        throw std::runtime_error("clean block products require square matrices of equal size");
    }
    if (b == 0 || (A.rows() % b) != 0) {
        throw std::runtime_error("invalid transcript block size");
    }

    const uint32_t n = A.rows();
    const uint32_t N = n / b;
    std::vector<Matrix> out;
    out.reserve(static_cast<size_t>(N) * N * N);
    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = 0; j < N; ++j) {
            for (uint32_t ell = 0; ell < N; ++ell) {
                out.push_back(A.block(i, ell, b) * B.block(ell, j, b));
            }
        }
    }
    return out;
}

uint256 ReplayCanonicalHashWithReusableCleanProducts(
    const Matrix& A,
    const Matrix& B,
    const std::vector<Matrix>& clean_block_products,
    const noise::NoisePair& noise,
    uint32_t b,
    const uint256& sigma)
{
    if (A.rows() != A.cols() || B.rows() != B.cols() || A.rows() != B.rows()) {
        throw std::runtime_error("replay requires square matrices of equal size");
    }
    if (b == 0 || (A.rows() % b) != 0) {
        throw std::runtime_error("invalid transcript block size");
    }

    const uint32_t n = A.rows();
    const uint32_t N = n / b;
    if (clean_block_products.size() != static_cast<size_t>(N) * N * N) {
        throw std::runtime_error("clean block product count mismatch");
    }
    if (noise.E_L.rows() != n || noise.E_L.cols() != noise.E_R.rows() ||
        noise.E_R.cols() != n || noise.F_L.rows() != n ||
        noise.F_L.cols() != noise.F_R.rows() || noise.F_R.cols() != n) {
        throw std::runtime_error("noise dimensions do not match matrix dimensions");
    }

    const auto compress_vec = DeriveCompressionVector(sigma, b);
    CHash256 hasher;

    for (uint32_t i = 0; i < N; ++i) {
        const ConstMatrixView e_l_block = RowBlockAllCols(noise.E_L, i, b);
        for (uint32_t j = 0; j < N; ++j) {
            const ConstMatrixView f_r_block = AllRowsColBlock(noise.F_R, j, b);
            field::Element compressed_prefix = 0;
            for (uint32_t ell = 0; ell < N; ++ell) {
                const Matrix& clean_block = clean_block_products[BlockProductIndex(i, j, ell, N)];
                const field::Element clean_compressed = CompressBlock(clean_block, compress_vec);

                const ConstMatrixView a_block = A.block_view(i, ell, b);
                const ConstMatrixView b_block = B.block_view(ell, j, b);
                const ConstMatrixView e_r_block = AllRowsColBlock(noise.E_R, ell, b);
                const ConstMatrixView f_l_block = RowBlockAllCols(noise.F_L, ell, b);

                const field::Element af_compressed = CompressAfBlock(a_block, f_l_block, f_r_block, compress_vec);
                const field::Element eb_compressed = CompressEbBlock(e_l_block, e_r_block, b_block, compress_vec);
                const field::Element ef_compressed = CompressEfBlock(e_l_block, e_r_block, f_l_block, f_r_block, compress_vec);

                compressed_prefix = field::add(
                    compressed_prefix,
                    field::add(
                        clean_compressed,
                        field::add(af_compressed, field::add(eb_compressed, ef_compressed))));

                uint8_t bytes[4];
                WriteLE32(bytes, compressed_prefix);
                hasher.Write(Span<const unsigned char>{bytes, sizeof(bytes)});
            }
        }
    }

    uint256 digest;
    hasher.Finalize(digest);
    return digest;
}

uint256 HashMatrixWords(Span<const field::Element> words)
{
    CHash256 hasher;
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    if (!words.empty()) {
        const auto* raw = reinterpret_cast<const unsigned char*>(words.data());
        hasher.Write(Span<const unsigned char>{raw, words.size() * sizeof(field::Element)});
    }
#else
    for (const field::Element value : words) {
        unsigned char buf[4];
        buf[0] = static_cast<unsigned char>(value);
        buf[1] = static_cast<unsigned char>(value >> 8);
        buf[2] = static_cast<unsigned char>(value >> 16);
        buf[3] = static_cast<unsigned char>(value >> 24);
        hasher.Write(Span<const unsigned char>{buf, sizeof(buf)});
    }
#endif
    uint256 digest;
    hasher.Finalize(digest);
    return digest;
}

uint256 FinalizeTranscriptDigestFromWords(Span<const field::Element> words)
{
    return HashMatrixWords(words);
}

uint256 FinalizeProductCommittedDigestFromHash(const uint256& c_prime_hash,
                                               const uint256& sigma,
                                               uint32_t dim,
                                               uint32_t b)
{
    if (dim == 0 || b == 0) {
        throw std::runtime_error("product-committed digest requires non-zero dimensions");
    }
    if ((dim % b) != 0) {
        throw std::runtime_error("product-committed digest requires dim divisible by b");
    }

    // Outer hash: SHA256d(tag || sigma || H(compressed_final_blocks(C')) || dim_le32 || b_le32)
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(PRODUCT_DIGEST_TAG.data()),
                PRODUCT_DIGEST_TAG.size());
    outer.Write(sigma.begin(), 32);
    outer.Write(c_prime_hash.begin(), 32);

    unsigned char dim_buf[4];
    dim_buf[0] = static_cast<unsigned char>(dim);
    dim_buf[1] = static_cast<unsigned char>(dim >> 8);
    dim_buf[2] = static_cast<unsigned char>(dim >> 16);
    dim_buf[3] = static_cast<unsigned char>(dim >> 24);
    outer.Write(dim_buf, 4);

    unsigned char block_buf[4];
    block_buf[0] = static_cast<unsigned char>(b);
    block_buf[1] = static_cast<unsigned char>(b >> 8);
    block_buf[2] = static_cast<unsigned char>(b >> 16);
    block_buf[3] = static_cast<unsigned char>(b >> 24);
    outer.Write(block_buf, 4);

    unsigned char inner[32];
    outer.Finalize(inner);
    uint256 result;
    CSHA256().Write(inner, 32).Finalize(result.begin());
    return result;
}

uint256 ComputeProductCommittedDigestFromWords(Span<const field::Element> c_prime_words,
                                               const uint256& sigma,
                                               uint32_t dim,
                                               uint32_t b)
{
    if (dim == 0 || b == 0 || (dim % b) != 0) {
        throw std::runtime_error("product-committed digest word span requires valid dimensions");
    }
    const uint32_t blocks_per_axis = dim / b;
    const size_t expected_words = static_cast<size_t>(blocks_per_axis) * blocks_per_axis;
    if (c_prime_words.size() != expected_words) {
        throw std::runtime_error("product-committed digest word span size mismatch");
    }
    return FinalizeProductCommittedDigestFromHash(HashMatrixWords(c_prime_words), sigma, dim, b);
}

uint256 ComputeProductCommittedDigest(const Matrix& C_prime, uint32_t b, const uint256& sigma)
{
    if (C_prime.rows() != C_prime.cols()) {
        throw std::runtime_error("product-committed digest requires square C'");
    }
    if (b == 0 || (C_prime.rows() % b) != 0) {
        throw std::runtime_error("product-committed digest requires valid transcript block size");
    }

    const uint32_t blocks_per_axis = C_prime.rows() / b;
    const auto compress_vec = DeriveCompressionVector(sigma, b);
    std::vector<field::Element> compressed_blocks;
    compressed_blocks.reserve(static_cast<size_t>(blocks_per_axis) * blocks_per_axis);
    for (uint32_t i = 0; i < blocks_per_axis; ++i) {
        for (uint32_t j = 0; j < blocks_per_axis; ++j) {
            compressed_blocks.push_back(CompressBlock(C_prime.block_view(i, j, b), compress_vec));
        }
    }

    return ComputeProductCommittedDigestFromWords(
        Span<const field::Element>{compressed_blocks.data(), compressed_blocks.size()},
        sigma,
        C_prime.rows(),
        b);
}

uint256 ComputeProductCommittedDigestFromPerturbed(const Matrix& A_prime,
                                                   const Matrix& B_prime,
                                                   uint32_t b,
                                                   const uint256& sigma)
{
    if (A_prime.rows() != A_prime.cols() || B_prime.rows() != B_prime.cols() || A_prime.rows() != B_prime.rows()) {
        throw std::runtime_error("product-committed digest requires square matrices of equal size");
    }
    if (b == 0 || (A_prime.rows() % b) != 0) {
        throw std::runtime_error("product-committed digest requires valid transcript block size");
    }

    const uint32_t n = A_prime.rows();
    const uint32_t blocks_per_axis = n / b;
    const auto compress_vec = DeriveCompressionVector(sigma, b);
    std::vector<field::Element> compressed_blocks;
    compressed_blocks.reserve(static_cast<size_t>(blocks_per_axis) * blocks_per_axis);

    for (uint32_t i = 0; i < blocks_per_axis; ++i) {
        for (uint32_t j = 0; j < blocks_per_axis; ++j) {
            field::Element compressed_acc = 0;
            for (uint32_t ell = 0; ell < blocks_per_axis; ++ell) {
                const Matrix product = A_prime.block(i, ell, b) * B_prime.block(ell, j, b);
                compressed_acc = field::add(compressed_acc, CompressBlock(product, compress_vec));
            }
            compressed_blocks.push_back(compressed_acc);
        }
    }

    return ComputeProductCommittedDigestFromWords(
        Span<const field::Element>{compressed_blocks.data(), compressed_blocks.size()},
        sigma,
        n,
        b);
}

} // namespace matmul::transcript
