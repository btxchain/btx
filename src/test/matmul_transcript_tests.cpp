// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/transcript.h>

#include <crypto/common.h>
#include <hash.h>
#include <matmul/noise.h>
#include <random.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <array>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <set>
#include <string_view>
#include <vector>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

uint256 ParseUint256Raw(std::string_view hex)
{
    const auto bytes = ParseHex(hex);
    BOOST_REQUIRE(bytes.size() == uint256::size());
    return uint256{Span<const unsigned char>{bytes.data(), bytes.size()}};
}

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

matmul::Matrix RandomMatrix(FastRandomContext& rng, uint32_t n)
{
    matmul::Matrix out(n, n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            out.at(r, c) = matmul::field::from_uint32(rng.rand32());
        }
    }
    return out;
}

matmul::Matrix MatrixFromRows(const std::vector<std::vector<uint32_t>>& rows)
{
    matmul::Matrix out(rows.size(), rows[0].size());
    for (uint32_t r = 0; r < out.rows(); ++r) {
        for (uint32_t c = 0; c < out.cols(); ++c) {
            out.at(r, c) = rows[r][c];
        }
    }
    return out;
}

std::pair<matmul::Matrix, uint256> ManualCanonical(
    const matmul::Matrix& A,
    const matmul::Matrix& B,
    uint32_t b,
    const uint256& sigma,
    std::vector<uint8_t>* out_stream_bytes = nullptr)
{
    const uint32_t n = A.rows();
    const uint32_t N = n / b;

    matmul::Matrix C(n, n);
    const auto v = matmul::transcript::DeriveCompressionVector(sigma, b);

    CHash256 hasher;
    std::vector<uint8_t> stream;

    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = 0; j < N; ++j) {
            for (uint32_t ell = 0; ell < N; ++ell) {
                const matmul::Matrix a_block = A.block(i, ell, b);
                const matmul::Matrix b_block = B.block(ell, j, b);
                matmul::Matrix c_block = C.block(i, j, b);
                c_block = c_block + (a_block * b_block);
                C.set_block(i, j, b, c_block);

                const auto compressed = matmul::transcript::CompressBlock(c_block, v);
                uint8_t le[4];
                WriteLE32(le, compressed);
                hasher.Write(le);
                stream.insert(stream.end(), le, le + 4);
            }
        }
    }

    uint256 digest;
    hasher.Finalize(digest);

    if (out_stream_bytes != nullptr) {
        *out_stream_bytes = std::move(stream);
    }

    return {std::move(C), digest};
}

std::vector<matmul::field::Element> ManualCompressedTranscriptWords(
    const matmul::Matrix& A,
    const matmul::Matrix& B,
    uint32_t b,
    const uint256& sigma)
{
    const uint32_t n = A.rows();
    const uint32_t N = n / b;
    const auto v = matmul::transcript::DeriveCompressionVector(sigma, b);

    matmul::Matrix C(n, n);
    std::vector<matmul::field::Element> compressed;
    compressed.reserve(static_cast<size_t>(N) * N * N);

    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = 0; j < N; ++j) {
            for (uint32_t ell = 0; ell < N; ++ell) {
                const matmul::Matrix a_block = A.block(i, ell, b);
                const matmul::Matrix b_block = B.block(ell, j, b);
                matmul::Matrix c_block = C.block(i, j, b);
                c_block = c_block + (a_block * b_block);
                C.set_block(i, j, b, c_block);
                compressed.push_back(matmul::transcript::CompressBlock(c_block, v));
            }
        }
    }

    return compressed;
}

uint256 ManualVariantOrderHash(
    const matmul::Matrix& A,
    const matmul::Matrix& B,
    uint32_t b,
    const uint256& sigma)
{
    const uint32_t n = A.rows();
    const uint32_t N = n / b;

    matmul::Matrix C(n, n);
    matmul::transcript::TranscriptHasher hasher(sigma, b);

    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t ell = 0; ell < N; ++ell) {
            for (uint32_t j = 0; j < N; ++j) {
                const matmul::Matrix a_block = A.block(i, ell, b);
                const matmul::Matrix b_block = B.block(ell, j, b);
                matmul::Matrix c_block = C.block(i, j, b);
                c_block = c_block + (a_block * b_block);
                C.set_block(i, j, b, c_block);
                hasher.AddIntermediate(i, j, ell, c_block);
            }
        }
    }

    return hasher.Finalize();
}

std::vector<matmul::field::Element> DeriveCompressionVectorWithTag(std::string_view tag, const uint256& sigma, uint32_t b)
{
    const auto sigma_bytes = ToCanonicalBytes(sigma);

    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    hasher.Write(sigma_bytes.data(), sigma_bytes.size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    const uint256 seed = CanonicalBytesToUint256(digest);

    std::vector<matmul::field::Element> out;
    out.reserve(static_cast<size_t>(b) * b);
    for (uint32_t k = 0; k < b * b; ++k) {
        out.push_back(matmul::field::from_oracle(seed, k));
    }
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_transcript_tests, BasicTestingSetup)

// TEST: kernel_c_prime_output_correct
BOOST_AUTO_TEST_CASE(transcript_correct_product)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    const auto result = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    BOOST_CHECK(result.C_prime == (a * b));
}

// TEST: transcript_compressed_hash_deterministic
// TEST: kernel_deterministic_across_launches
BOOST_AUTO_TEST_CASE(transcript_hash_deterministic)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    const auto first = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    const auto second = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);

    BOOST_CHECK_EQUAL(first.transcript_hash, second.transcript_hash);
}

BOOST_AUTO_TEST_CASE(transcript_hash_changes_with_input)
{
    FastRandomContext rng{true};
    matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    const auto first = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    a.at(0, 0) = matmul::field::add(a.at(0, 0), 1);
    const auto second = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);

    BOOST_CHECK_NE(first.transcript_hash, second.transcript_hash);
}

BOOST_AUTO_TEST_CASE(transcript_uses_b_not_r)
{
    constexpr uint32_t n = 64;
    constexpr uint32_t b = 16;
    constexpr uint32_t r = 8;

    const uint32_t intermediates_b = (n / b) * (n / b) * (n / b);
    const uint32_t intermediates_r = (n / r) * (n / r) * (n / r);

    BOOST_CHECK_EQUAL(intermediates_b, 64U);
    BOOST_CHECK_EQUAL(intermediates_r, 512U);

    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, b);
    BOOST_CHECK_EQUAL(compress_vec.size(), 256U);
    BOOST_CHECK_NE(compress_vec.size(), static_cast<size_t>(r) * r);
}

BOOST_AUTO_TEST_CASE(transcript_streaming_matches_batch)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    const auto canonical = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    const auto manual = ManualCanonical(a, b, 4, sigma);

    BOOST_CHECK(canonical.C_prime == manual.first);
    BOOST_CHECK_EQUAL(canonical.transcript_hash, manual.second);
}

BOOST_AUTO_TEST_CASE(product_digest_matches_hash_of_final_ell_transcript_slice)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();
    constexpr uint32_t kBlockSize = 4;
    constexpr uint32_t kNBlocks = 2;

    const auto canonical = matmul::transcript::CanonicalMatMul(a, b, kBlockSize, sigma);
    const auto compressed_words = ManualCompressedTranscriptWords(a, b, kBlockSize, sigma);
    BOOST_REQUIRE_EQUAL(compressed_words.size(), static_cast<size_t>(kNBlocks) * kNBlocks * kNBlocks);

    std::vector<matmul::field::Element> final_ell_words;
    final_ell_words.reserve(static_cast<size_t>(kNBlocks) * kNBlocks);
    for (uint32_t i = 0; i < kNBlocks; ++i) {
        for (uint32_t j = 0; j < kNBlocks; ++j) {
            const size_t offset = (static_cast<size_t>(i) * kNBlocks + j) * kNBlocks + (kNBlocks - 1);
            final_ell_words.push_back(compressed_words[offset]);
        }
    }

    const uint256 final_ell_hash = matmul::transcript::HashMatrixWords(final_ell_words);
    const uint256 final_ell_digest = matmul::transcript::FinalizeProductCommittedDigestFromHash(
        final_ell_hash,
        sigma,
        a.rows(),
        kBlockSize);

    BOOST_CHECK_EQUAL(
        final_ell_digest,
        matmul::transcript::ComputeProductCommittedDigest(
            canonical.C_prime,
            kBlockSize,
            sigma));
}

BOOST_AUTO_TEST_CASE(replay_from_clean_block_products_matches_canonical_hash)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();
    const auto clean_block_products = matmul::transcript::PrecomputeCleanBlockProducts(a, b, 4);
    const auto noise = matmul::noise::Generate(sigma, 8, 2);

    const matmul::Matrix a_prime = a + (noise.E_L * noise.E_R);
    const matmul::Matrix b_prime = b + (noise.F_L * noise.F_R);
    const auto canonical = matmul::transcript::CanonicalMatMul(a_prime, b_prime, 4, sigma);
    const auto replayed = matmul::transcript::ReplayCanonicalHashWithReusableCleanProducts(
        a,
        b,
        clean_block_products,
        noise,
        4,
        sigma);

    BOOST_CHECK_EQUAL(canonical.transcript_hash, replayed);
}

BOOST_AUTO_TEST_CASE(replay_from_clean_block_products_matches_zero_noise_case)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();
    const auto clean_block_products = matmul::transcript::PrecomputeCleanBlockProducts(a, b, 4);
    matmul::noise::NoisePair zero_noise{
        .E_L = matmul::Matrix(8, 2),
        .E_R = matmul::Matrix(2, 8),
        .F_L = matmul::Matrix(8, 2),
        .F_R = matmul::Matrix(2, 8),
    };

    const auto canonical = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    const auto replayed = matmul::transcript::ReplayCanonicalHashWithReusableCleanProducts(
        a,
        b,
        clean_block_products,
        zero_noise,
        4,
        sigma);

    BOOST_CHECK_EQUAL(canonical.transcript_hash, replayed);
}

// TEST: transcript_compressed_hash_differs_naive
BOOST_AUTO_TEST_CASE(transcript_canonical_order_enforced)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    const auto canonical = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    const uint256 reordered = ManualVariantOrderHash(a, b, 4, sigma);

    BOOST_CHECK_NE(canonical.transcript_hash, reordered);
}

BOOST_AUTO_TEST_CASE(compress_vector_deterministic)
{
    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto a = matmul::transcript::DeriveCompressionVector(sigma, 8);
    const auto b = matmul::transcript::DeriveCompressionVector(sigma, 8);

    BOOST_CHECK(a == b);
}

// TEST: transcript_hasher_takes_sigma
BOOST_AUTO_TEST_CASE(compress_vector_changes_with_sigma)
{
    const uint256 sigma_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 sigma_b = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    const auto a = matmul::transcript::DeriveCompressionVector(sigma_a, 8);
    const auto b = matmul::transcript::DeriveCompressionVector(sigma_b, 8);

    BOOST_CHECK(a != b);
}

// TEST: compress_block_matches_manual_dot_product
BOOST_AUTO_TEST_CASE(compress_block_single_element_output)
{
    FastRandomContext rng{true};
    matmul::Matrix block(4, 4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            block.at(r, c) = matmul::field::from_uint32(rng.rand32());
        }
    }

    const auto v = matmul::transcript::DeriveCompressionVector(rng.rand256(), 4);
    const auto compressed = matmul::transcript::CompressBlock(block, v);
    uint32_t manual = 0;
    size_t idx = 0;
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            manual = matmul::field::add(manual, matmul::field::mul(block.at(r, c), v[idx++]));
        }
    }
    BOOST_CHECK_EQUAL(compressed, manual);
    BOOST_CHECK(compressed < matmul::field::MODULUS);
}

BOOST_AUTO_TEST_CASE(compress_block_deterministic)
{
    FastRandomContext rng{true};
    matmul::Matrix block(4, 4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            block.at(r, c) = matmul::field::from_uint32(rng.rand32());
        }
    }

    const auto v = matmul::transcript::DeriveCompressionVector(rng.rand256(), 4);
    BOOST_CHECK_EQUAL(matmul::transcript::CompressBlock(block, v), matmul::transcript::CompressBlock(block, v));
}

BOOST_AUTO_TEST_CASE(compress_block_view_matches_dense_block)
{
    FastRandomContext rng{true};
    matmul::Matrix container(8, 8);
    matmul::Matrix dense_block(4, 4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            const auto value = matmul::field::from_uint32(rng.rand32());
            dense_block.at(r, c) = value;
            container.at(4 + r, 4 + c) = value;
        }
    }

    const auto v = matmul::transcript::DeriveCompressionVector(rng.rand256(), 4);
    const auto dense = matmul::transcript::CompressBlock(dense_block, v);
    const auto view = matmul::transcript::CompressBlock(container.block_view(1, 1, 4), v);
    BOOST_CHECK_EQUAL(dense, view);
}

// TEST: compress_block_different_blocks_differ
BOOST_AUTO_TEST_CASE(compress_block_distinguishes_inputs)
{
    FastRandomContext rng{true};
    matmul::Matrix block_a(4, 4);
    matmul::Matrix block_b(4, 4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            block_a.at(r, c) = matmul::field::from_uint32(rng.rand32());
            block_b.at(r, c) = block_a.at(r, c);
        }
    }
    block_b.at(0, 0) = matmul::field::add(block_b.at(0, 0), 1);

    const auto v = matmul::transcript::DeriveCompressionVector(rng.rand256(), 4);
    BOOST_CHECK_NE(matmul::transcript::CompressBlock(block_a, v), matmul::transcript::CompressBlock(block_b, v));
}

// TEST: transcript_compressed_bytes_bounded
BOOST_AUTO_TEST_CASE(transcript_hasher_le32_stream_size)
{
    FastRandomContext rng{true};
    const matmul::Matrix a = RandomMatrix(rng, 8);
    const matmul::Matrix b = RandomMatrix(rng, 8);
    const uint256 sigma = rng.rand256();

    std::vector<uint8_t> stream;
    const auto manual = ManualCanonical(a, b, 4, sigma, &stream);
    const auto canonical = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);

    BOOST_CHECK_EQUAL(stream.size(), 32U); // (8/4)^3 * 4 bytes
    BOOST_CHECK_EQUAL(canonical.transcript_hash, manual.second);
}

BOOST_AUTO_TEST_CASE(compression_vector_b8_pinned)
{
    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto vec = matmul::transcript::DeriveCompressionVector(sigma, 8);

    const std::vector<uint32_t> expected{
        854323467U, 1922810799U, 138893669U, 774245080U, 1910322065U, 479659975U, 1001665414U, 846347437U,
        1594558452U, 1190555733U, 1946094175U, 949130026U, 1989820537U, 1338239980U, 112664120U, 495418066U,
        763100808U, 963296335U, 2104825498U, 911035817U, 840832198U, 1648834108U, 249535501U, 987286922U,
        1284151614U, 1283357078U, 2095142933U, 1026823933U, 277904251U, 448493396U, 683839780U, 146995467U,
        1820928528U, 1115770288U, 926380059U, 1478244584U, 235132119U, 415929716U, 1528251740U, 441728812U,
        717970846U, 1597403828U, 852380403U, 1541164172U, 1576656695U, 2088271682U, 1066081759U, 1868395032U,
        1496940987U, 878288754U, 366484956U, 1828311227U, 588781468U, 931740877U, 1126598725U, 1663853027U,
        797953804U, 984550866U, 1476302989U, 1991155073U, 707298527U, 1170652932U, 414389278U, 869587357U,
    };

    BOOST_CHECK_EQUAL(vec.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK_EQUAL(vec[i], expected[i]);
    }
}

BOOST_AUTO_TEST_CASE(compression_vector_b16_pinned_prefix)
{
    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto vec8 = matmul::transcript::DeriveCompressionVector(sigma, 8);
    const auto vec16 = matmul::transcript::DeriveCompressionVector(sigma, 16);

    BOOST_CHECK_EQUAL(vec16.size(), 256U);
    for (size_t i = 0; i < vec8.size(); ++i) {
        BOOST_CHECK_EQUAL(vec16[i], vec8[i]);
    }
}

BOOST_AUTO_TEST_CASE(canonical_matmul_n8_b4_pinned_digest)
{
    const uint256 seed_a = ParseUint256("376d8f3e225ed14f5614a884f822920360a7b021684bd74600aa5f88dbd32a27");
    const uint256 seed_b = ParseUint256("3609c5eaeae940efb3035712cd65b09f0330d77fdf852128a89069b3ac02f586");
    const uint256 sigma = ParseUint256("ffc381ccd5e78ab52348ec8ba82f51d5feb0e857d7969ab0df9a5891c68cdf15");

    const matmul::Matrix a = matmul::FromSeed(seed_a, 8);
    const matmul::Matrix b = matmul::FromSeed(seed_b, 8);

    const auto result = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);
    BOOST_CHECK_EQUAL(result.transcript_hash, ParseUint256Raw("b134b59bfdd28f3bf566e35a4d44b0af8e9530dce8047125a59d308ed22c17b8"));
}

BOOST_AUTO_TEST_CASE(canonical_matmul_n8_b4_pinned_product)
{
    const uint256 seed_a = ParseUint256("376d8f3e225ed14f5614a884f822920360a7b021684bd74600aa5f88dbd32a27");
    const uint256 seed_b = ParseUint256("3609c5eaeae940efb3035712cd65b09f0330d77fdf852128a89069b3ac02f586");
    const uint256 sigma = ParseUint256("ffc381ccd5e78ab52348ec8ba82f51d5feb0e857d7969ab0df9a5891c68cdf15");

    const matmul::Matrix a = matmul::FromSeed(seed_a, 8);
    const matmul::Matrix b = matmul::FromSeed(seed_b, 8);

    const auto result = matmul::transcript::CanonicalMatMul(a, b, 4, sigma);

    const std::vector<std::vector<uint32_t>> expected_rows{
        {131245387U, 996985597U, 1415691111U, 75647953U, 1453769508U, 226370569U, 1602132038U, 1924870967U},
        {1994294548U, 464104048U, 179583508U, 1527279991U, 1126483094U, 36768432U, 2013561722U, 1312578439U},
        {1436220467U, 466816144U, 126453702U, 753329165U, 471499874U, 1418934695U, 1761650946U, 1573241549U},
        {645246462U, 175153553U, 361276609U, 966664511U, 1705575876U, 1016078365U, 605091080U, 797357023U},
        {1699709533U, 616249584U, 837573788U, 722153758U, 528778884U, 538341887U, 960803804U, 432492092U},
        {1221896789U, 1497511969U, 1409959869U, 2018077429U, 1838839539U, 842677057U, 1591736450U, 1282074994U},
        {1199405744U, 1776639913U, 43247130U, 1950021239U, 161220525U, 936954211U, 92632281U, 1714468946U},
        {1349493752U, 1294873866U, 580920316U, 1375526319U, 301361523U, 290972387U, 1491529954U, 626629023U},
    };

    BOOST_CHECK(result.C_prime == MatrixFromRows(expected_rows));
}

// TEST: transcript_domain_separation
BOOST_AUTO_TEST_CASE(compression_vector_domain_separator)
{
    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto canonical = matmul::transcript::DeriveCompressionVector(sigma, 8);
    const auto wrong_tag = DeriveCompressionVectorWithTag("matmul-compress-v0", sigma, 8);

    BOOST_CHECK(canonical != wrong_tag);
}

// TEST: transcript_compression_binding
BOOST_AUTO_TEST_CASE(compression_binding_no_collisions)
{
    const uint256 sigma = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const auto v = matmul::transcript::DeriveCompressionVector(sigma, 4);
    BOOST_REQUIRE(v[0] != 0);

    std::set<matmul::field::Element> seen;
    for (uint32_t i = 0; i < 10000; ++i) {
        matmul::Matrix block(4, 4);
        block.at(0, 0) = i;
        seen.insert(matmul::transcript::CompressBlock(block, v));
    }

    BOOST_CHECK_EQUAL(seen.size(), 10000U);
}

BOOST_AUTO_TEST_SUITE_END()
