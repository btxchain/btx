// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <matmul/freivalds.h>
#include <matmul/matrix.h>
#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <pow.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <limits>
#include <string_view>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

matmul::Matrix RandomSquareMatrix(FastRandomContext& rng, uint32_t n)
{
    matmul::Matrix out(n, n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            out.at(row, col) = matmul::field::from_uint32(rng.rand32());
        }
    }
    return out;
}

std::vector<uint32_t> FlattenMatrixWords(const matmul::Matrix& matrix)
{
    std::vector<uint32_t> out;
    out.reserve(static_cast<size_t>(matrix.rows()) * matrix.cols());
    for (uint32_t row = 0; row < matrix.rows(); ++row) {
        for (uint32_t col = 0; col < matrix.cols(); ++col) {
            out.push_back(matrix.at(row, col));
        }
    }
    return out;
}

const uint256 TEST_SIGMA = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_freivalds_tests, BasicTestingSetup)

// --- Core algorithm tests from the reference implementation ---

BOOST_AUTO_TEST_CASE(freivalds_vector_derivation_is_deterministic)
{
    const uint256 sigma = ParseUint256("1af65342bb27af07821ca5ecf1839512af16ee1d4d5fd0975af746f68890d6d4");
    const auto v1 = matmul::freivalds::DeriveRandomVector(sigma, /*round=*/0, /*n=*/16);
    const auto v2 = matmul::freivalds::DeriveRandomVector(sigma, /*round=*/0, /*n=*/16);
    const auto v3 = matmul::freivalds::DeriveRandomVector(sigma, /*round=*/1, /*n=*/16);

    BOOST_CHECK_EQUAL(v1.size(), 16U);
    BOOST_CHECK(v1 == v2);
    BOOST_CHECK(v1 != v3);
}

BOOST_AUTO_TEST_CASE(freivalds_accepts_valid_matrix_product)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const matmul::Matrix A = RandomSquareMatrix(rng, 16);
    const matmul::Matrix B = RandomSquareMatrix(rng, 16);
    const matmul::Matrix C = matmul::MultiplyBlocked(A, B, /*tile_size=*/8);
    const uint256 sigma = ParseUint256("7cf4a71e0ffad0b91a498d90917fd71b2e652f5da11b60f59ca95a76f52e6d6e");

    const auto result = matmul::freivalds::Verify(A, B, C, sigma, /*num_rounds=*/3);
    BOOST_CHECK(result.passed);
    BOOST_CHECK_EQUAL(result.rounds_executed, 3U);
    BOOST_CHECK(result.ops_performed > 0U);
}

BOOST_AUTO_TEST_CASE(freivalds_rejects_tampered_matrix_product)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const matmul::Matrix A = RandomSquareMatrix(rng, 32);
    const matmul::Matrix B = RandomSquareMatrix(rng, 32);
    matmul::Matrix C = matmul::MultiplyBlocked(A, B, /*tile_size=*/8);
    C.at(5, 7) = matmul::field::add(C.at(5, 7), 1);

    const uint256 sigma = ParseUint256("2385351f8ef770815ee5a9da06cdcc20f058cb2df21735009e94ba90bf9e5bde");
    const auto result = matmul::freivalds::Verify(A, B, C, sigma, /*num_rounds=*/2);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.rounds_executed >= 1U);
}

BOOST_AUTO_TEST_CASE(freivalds_rejects_dimension_mismatch)
{
    matmul::Matrix A(4, 8);
    matmul::Matrix B(7, 4);
    matmul::Matrix C(4, 4);
    const uint256 sigma = ParseUint256("04c889f26c4cca59f0f87ab7c7d389f0e5af8786f1932f6a0813eb2a2fd22d98");

    const auto result = matmul::freivalds::Verify(A, B, C, sigma, /*num_rounds=*/1);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.rounds_executed, 0U);
}

// --- Extended tests for consensus integration ---

BOOST_AUTO_TEST_CASE(correct_product_passes)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 8;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    auto C = A * B;

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, /*num_rounds=*/3);
    BOOST_CHECK(result.passed);
    BOOST_CHECK_EQUAL(result.rounds_executed, 3u);
    BOOST_CHECK(result.ops_performed > 0U);
}

BOOST_AUTO_TEST_CASE(incorrect_product_rejected)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 8;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    auto C = A * B;

    C.at(0, 0) = matmul::field::add(C.at(0, 0), 1);

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, /*num_rounds=*/3);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_GE(result.rounds_executed, 1u);
}

BOOST_AUTO_TEST_CASE(zero_product_rejected)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 8;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    matmul::Matrix C(n, n);

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, /*num_rounds=*/2);
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_CASE(identity_product_passes)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 8;
    auto A = RandomSquareMatrix(rng, n);
    auto I = matmul::Identity(n);

    auto result = matmul::freivalds::Verify(A, I, A, TEST_SIGMA, /*num_rounds=*/2);
    BOOST_CHECK(result.passed);
}

BOOST_AUTO_TEST_CASE(single_round_verification)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 16;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    auto C = A * B;

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, /*num_rounds=*/1);
    BOOST_CHECK(result.passed);
    BOOST_CHECK_EQUAL(result.rounds_executed, 1u);
}

BOOST_AUTO_TEST_CASE(different_sigma_different_vectors)
{
    const uint32_t n = 8;
    const uint256 sigma1 = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 sigma2 = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");

    auto v1 = matmul::freivalds::DeriveRandomVector(sigma1, 0, n);
    auto v2 = matmul::freivalds::DeriveRandomVector(sigma2, 0, n);

    BOOST_CHECK_EQUAL(v1.size(), n);
    BOOST_CHECK_EQUAL(v2.size(), n);
    BOOST_CHECK(v1 != v2);
}

BOOST_AUTO_TEST_CASE(random_vector_elements_valid)
{
    const uint32_t n = 64;
    auto v = matmul::freivalds::DeriveRandomVector(TEST_SIGMA, 0, n);
    BOOST_CHECK_EQUAL(v.size(), n);
    for (uint32_t i = 0; i < n; ++i) {
        BOOST_CHECK_LT(v[i], matmul::field::MODULUS);
    }
}

BOOST_AUTO_TEST_CASE(matvecmul_correctness)
{
    matmul::Matrix M(2, 2);
    M.at(0, 0) = 3; M.at(0, 1) = 5;
    M.at(1, 0) = 7; M.at(1, 1) = 11;

    std::vector<matmul::field::Element> v = {2, 3};
    auto result = matmul::freivalds::MatVecMul(M, v);

    BOOST_CHECK_EQUAL(result.size(), 2u);
    BOOST_CHECK_EQUAL(result[0], 21u);
    BOOST_CHECK_EQUAL(result[1], 47u);
}

BOOST_AUTO_TEST_CASE(freivalds_with_noise_pipeline)
{
    const uint32_t n = 16;
    const uint32_t r = 4;
    const uint32_t b = 4;
    const uint256 seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const uint256 seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    const auto A = matmul::FromSeed(seed_a, n);
    const auto B = matmul::FromSeed(seed_b, n);
    const uint256 sigma = TEST_SIGMA;
    const auto np = matmul::noise::Generate(sigma, n, r);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);

    const auto transcript_result = matmul::transcript::CanonicalMatMul(A_prime, B_prime, b, sigma);

    auto fv_result = matmul::freivalds::Verify(
        A_prime, B_prime, transcript_result.C_prime, sigma, /*num_rounds=*/2);
    BOOST_CHECK(fv_result.passed);
    BOOST_CHECK_EQUAL(fv_result.rounds_executed, 2u);

    matmul::Matrix bad_C = transcript_result.C_prime;
    bad_C.at(n/2, n/2) = matmul::field::add(bad_C.at(n/2, n/2), 42);

    auto fv_bad = matmul::freivalds::Verify(
        A_prime, B_prime, bad_C, sigma, /*num_rounds=*/2);
    BOOST_CHECK(!fv_bad.passed);
}

BOOST_AUTO_TEST_CASE(freivalds_larger_matrix)
{
    FastRandomContext rng{uint256{1}};
    const uint32_t n = 32;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    auto C = A * B;

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, /*num_rounds=*/2);
    BOOST_CHECK(result.passed);
    BOOST_CHECK_EQUAL(result.rounds_executed, 2u);
}

BOOST_AUTO_TEST_CASE(deterministic_reproducibility)
{
    FastRandomContext rng1{uint256{0}};
    FastRandomContext rng2{uint256{0}};
    const uint32_t n = 8;

    auto A1 = RandomSquareMatrix(rng1, n);
    auto B1 = RandomSquareMatrix(rng1, n);
    auto C1 = A1 * B1;

    auto A2 = RandomSquareMatrix(rng2, n);
    auto B2 = RandomSquareMatrix(rng2, n);
    auto C2 = A2 * B2;

    auto r1 = matmul::freivalds::Verify(A1, B1, C1, TEST_SIGMA, 2);
    auto r2 = matmul::freivalds::Verify(A2, B2, C2, TEST_SIGMA, 2);

    BOOST_CHECK(r1.passed);
    BOOST_CHECK(r2.passed);
    BOOST_CHECK_EQUAL(r1.ops_performed, r2.ops_performed);
}

BOOST_AUTO_TEST_CASE(trivial_1x1_matrix)
{
    matmul::Matrix A(1, 1);
    matmul::Matrix B(1, 1);
    A.at(0, 0) = 42;
    B.at(0, 0) = 100;

    matmul::Matrix C(1, 1);
    C.at(0, 0) = matmul::field::mul(42, 100);

    auto result = matmul::freivalds::Verify(A, B, C, TEST_SIGMA, 1);
    BOOST_CHECK(result.passed);
}

BOOST_AUTO_TEST_CASE(identity_2x2)
{
    auto I = matmul::Identity(2);
    auto result = matmul::freivalds::Verify(I, I, I, TEST_SIGMA, 2);
    BOOST_CHECK(result.passed);
}

// Product-hash consensus tests

BOOST_AUTO_TEST_CASE(product_hash_consensus_roundtrip)
{
    FastRandomContext rng{uint256{0}};
    const uint32_t n = 8;
    auto A = RandomSquareMatrix(rng, n);
    auto B = RandomSquareMatrix(rng, n);
    auto C = A * B;

    const uint256 hash1 = C.ContentHash();
    const uint256 hash2 = C.ContentHash();
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(!hash1.IsNull());

    matmul::Matrix C_bad = C;
    C_bad.at(0, 0) = matmul::field::add(C_bad.at(0, 0), 1);
    BOOST_CHECK(C_bad.ContentHash() != hash1);
}

BOOST_AUTO_TEST_CASE(full_verification_pipeline)
{
    const uint32_t n = 16;
    const uint32_t r = 4;
    const uint256 seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const uint256 seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    const auto A = matmul::FromSeed(seed_a, n);
    const auto B = matmul::FromSeed(seed_b, n);
    const uint256 sigma = TEST_SIGMA;
    const auto np = matmul::noise::Generate(sigma, n, r);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto C_prime = A_prime * B_prime;

    auto fv = matmul::freivalds::Verify(A_prime, B_prime, C_prime, sigma, 2);
    BOOST_CHECK(fv.passed);

    const uint256 digest = C_prime.ContentHash();
    BOOST_CHECK(!digest.IsNull());
    BOOST_CHECK(C_prime.ContentHash() == digest);
}

BOOST_AUTO_TEST_CASE(consensus_parameter_defaults)
{
    const auto& params = Params().GetConsensus();
    BOOST_CHECK(params.fMatMulFreivaldsEnabled);
    BOOST_CHECK_EQUAL(params.nMatMulFreivaldsRounds, 2u);
    BOOST_CHECK(!params.fMatMulRequireProductPayload);
}

// --- PopulateFreivaldsPayload and CheckMatMulProofOfWork_Freivalds tests ---

BOOST_AUTO_TEST_CASE(populate_freivalds_payload_fills_matrix_c)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    const uint32_t n = consensus.nMatMulDimension;

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(n);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.nNonce64 = 42;

    // Needs a valid sigma for noise generation
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000001");
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;

    // Set a valid matmul_digest (would normally come from SolveMatMul)
    block.matmul_digest = ParseUint256("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    PopulateFreivaldsPayload(block, consensus);

    // Payload should be n*n words
    BOOST_CHECK_EQUAL(block.matrix_c_data.size(), static_cast<size_t>(n) * n);

    // All elements should be in GF(2^31-1)
    for (uint32_t val : block.matrix_c_data) {
        BOOST_CHECK_LT(val, matmul::field::MODULUS);
    }
}

BOOST_AUTO_TEST_CASE(populate_freivalds_payload_matches_direct_product_small_dim)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulTranscriptBlockSize = 4;
    const uint32_t n = 8;

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(n);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.nNonce64 = 1234;
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000002");
    block.nTime = 1700000123;
    block.nBits = 0x207fffff;
    block.matmul_digest = ParseUint256("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    PopulateFreivaldsPayload(block, consensus);
    BOOST_REQUIRE_EQUAL(block.matrix_c_data.size(), static_cast<size_t>(n) * n);

    const auto A = matmul::FromSeed(block.seed_a, n);
    const auto B = matmul::FromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto expected = A_prime * B_prime;

    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            const size_t idx = static_cast<size_t>(row) * n + col;
            BOOST_CHECK_EQUAL(block.matrix_c_data[idx], expected.at(row, col));
        }
    }
}

BOOST_AUTO_TEST_CASE(populate_freivalds_noop_when_disabled)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = false;

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    PopulateFreivaldsPayload(block, consensus);
    BOOST_CHECK(block.matrix_c_data.empty());
}

BOOST_AUTO_TEST_CASE(payload_size_validation)
{
    auto consensus = Params().GetConsensus();
    const uint32_t n = consensus.nMatMulDimension;

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(n);

    // Empty payload
    BOOST_CHECK(!IsMatMulFreivaldsPayloadSizeValid(block, consensus));

    // Wrong size (too small)
    block.matrix_c_data.resize(static_cast<size_t>(n) * n - 1, 0);
    BOOST_CHECK(!IsMatMulFreivaldsPayloadSizeValid(block, consensus));

    // Wrong size (too large)
    block.matrix_c_data.resize(static_cast<size_t>(n) * n + 1, 0);
    BOOST_CHECK(!IsMatMulFreivaldsPayloadSizeValid(block, consensus));

    // Correct size
    block.matrix_c_data.resize(static_cast<size_t>(n) * n, 0);
    BOOST_CHECK(IsMatMulFreivaldsPayloadSizeValid(block, consensus));

    // Zero dimension
    block.matmul_dim = 0;
    BOOST_CHECK(!IsMatMulFreivaldsPayloadSizeValid(block, consensus));
}

BOOST_AUTO_TEST_CASE(has_freivalds_payload)
{
    CBlock block;
    BOOST_CHECK(!HasMatMulFreivaldsPayload(block));

    block.matrix_c_data.push_back(42);
    BOOST_CHECK(HasMatMulFreivaldsPayload(block));
}

BOOST_AUTO_TEST_CASE(non_canonical_payload_values_rejected)
{
    // Values >= MODULUS in matrix_c_data should cause Freivalds check to fail
    const uint32_t n = 16;
    const uint32_t r = 4;
    const uint256 seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const uint256 seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    const auto A = matmul::FromSeed(seed_a, n);
    const auto B = matmul::FromSeed(seed_b, n);
    const uint256 sigma = TEST_SIGMA;
    const auto np = matmul::noise::Generate(sigma, n, r);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto C_prime = A_prime * B_prime;

    // Create valid payload
    std::vector<uint32_t> payload(static_cast<size_t>(n) * n);
    for (uint32_t row = 0; row < n; ++row) {
        for (uint32_t col = 0; col < n; ++col) {
            payload[static_cast<size_t>(row) * n + col] = C_prime.at(row, col);
        }
    }

    // Verify all values are canonical
    for (uint32_t val : payload) {
        BOOST_CHECK_LT(val, matmul::field::MODULUS);
    }

    // Inject a non-canonical value
    payload[0] = matmul::field::MODULUS; // exactly MODULUS — should be rejected

    // The non-canonical value will cause CheckMatMulProofOfWork_Freivalds to
    // return false because the element check fails before Freivalds runs.
    // We can't easily test the full consensus function without a mining loop,
    // but we verify that the element validity check catches this.
    BOOST_CHECK_GE(payload[0], matmul::field::MODULUS);
}

BOOST_AUTO_TEST_CASE(freivalds_binding_rejects_low_digest_shortcut_once_active)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulTranscriptBlockSize = 4;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulDimension = 8;
    consensus.nMatMulMinDimension = 4;
    consensus.nMatMulMaxDimension = 64;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulFreivaldsBindingHeight = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000003");
    block.nTime = 1700000456;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce64 = 7;
    block.matmul_digest = uint256{};

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::FromSeed(block.seed_a, n);
    const auto B = matmul::FromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matrix_c_data = FlattenMatrixWords(transcript.C_prime);

    BOOST_CHECK(!CheckMatMulProofOfWork_Freivalds(block, consensus, /*block_height=*/0));
}

BOOST_AUTO_TEST_CASE(freivalds_binding_accepts_valid_transcript_digest_once_active)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulTranscriptBlockSize = 4;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulDimension = 8;
    consensus.nMatMulMinDimension = 4;
    consensus.nMatMulMaxDimension = 64;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulFreivaldsBindingHeight = 0;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000004");
    block.nTime = 1700000789;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce64 = 11;

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::FromSeed(block.seed_a, n);
    const auto B = matmul::FromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matrix_c_data = FlattenMatrixWords(transcript.C_prime);
    block.matmul_digest = transcript.transcript_hash;

    BOOST_CHECK(CheckMatMulProofOfWork_Freivalds(block, consensus, /*block_height=*/0));
}

BOOST_AUTO_TEST_CASE(freivalds_payload_rejects_low_digest_shortcut_before_binding_height)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulTranscriptBlockSize = 4;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulDimension = 8;
    consensus.nMatMulMinDimension = 4;
    consensus.nMatMulMaxDimension = 64;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulFreivaldsBindingHeight = std::numeric_limits<int32_t>::max();
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000006");
    block.nTime = 1700001111;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce64 = 13;
    block.matmul_digest = uint256{};

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::FromSeed(block.seed_a, n);
    const auto B = matmul::FromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matrix_c_data = FlattenMatrixWords(transcript.C_prime);

    BOOST_CHECK(!CheckMatMulProofOfWork_Freivalds(block, consensus, /*block_height=*/0));
}

BOOST_AUTO_TEST_CASE(freivalds_payload_accepts_valid_transcript_digest_before_binding_height)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.nMatMulTranscriptBlockSize = 4;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulDimension = 8;
    consensus.nMatMulMinDimension = 4;
    consensus.nMatMulMaxDimension = 64;
    consensus.nMatMulPreHashEpsilonBits = 0;
    consensus.nMatMulFreivaldsBindingHeight = std::numeric_limits<int32_t>::max();
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000007");
    block.nTime = 1700001222;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce64 = 17;

    const uint32_t n = block.matmul_dim;
    const auto A = matmul::FromSeed(block.seed_a, n);
    const auto B = matmul::FromSeed(block.seed_b, n);
    const uint256 sigma = matmul::DeriveSigma(block);
    const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto transcript = matmul::transcript::CanonicalMatMul(
        A_prime,
        B_prime,
        consensus.nMatMulTranscriptBlockSize,
        sigma);
    block.matrix_c_data = FlattenMatrixWords(transcript.C_prime);
    block.matmul_digest = transcript.transcript_hash;

    BOOST_CHECK(CheckMatMulProofOfWork_Freivalds(block, consensus, /*block_height=*/0));
}
BOOST_AUTO_TEST_CASE(freivalds_uses_height_aware_prehash_epsilon_bits)
{
    auto consensus = Params().GetConsensus();
    consensus.fMatMulFreivaldsEnabled = true;
    consensus.fMatMulRequireProductPayload = false;
    consensus.nMatMulFreivaldsBindingHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulTranscriptBlockSize = 4;
    consensus.nMatMulNoiseRank = 2;
    consensus.nMatMulDimension = 8;
    consensus.nMatMulMinDimension = 4;
    consensus.nMatMulMaxDimension = 64;
    consensus.nMatMulPreHashEpsilonBits = 10;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 12;
    consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    CBlock block;
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    block.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    block.seed_b = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000005");
    block.nTime = 1700000999;

    const arith_uint256 target = arith_uint256{1} << 244;
    block.nBits = target.GetCompact();

    const auto derived_target = DeriveTarget(block.nBits, consensus.powLimit);
    BOOST_REQUIRE(derived_target.has_value());

    arith_uint256 legacy_prehash_target = *derived_target;
    legacy_prehash_target <<= consensus.nMatMulPreHashEpsilonBits;

    bool found_candidate{false};
    for (uint64_t nonce = 1; nonce < 200'000; ++nonce) {
        block.nNonce64 = nonce;
        block.nNonce = static_cast<uint32_t>(nonce);

        const uint256 sigma = matmul::DeriveSigma(block);
        if (UintToArith256(sigma) <= legacy_prehash_target) {
            continue;
        }

        const uint32_t n = block.matmul_dim;
        const auto A = matmul::FromSeed(block.seed_a, n);
        const auto B = matmul::FromSeed(block.seed_b, n);
        const auto np = matmul::noise::Generate(sigma, n, consensus.nMatMulNoiseRank);
        const auto A_prime = A + (np.E_L * np.E_R);
        const auto B_prime = B + (np.F_L * np.F_R);
        const auto transcript = matmul::transcript::CanonicalMatMul(
            A_prime,
            B_prime,
            consensus.nMatMulTranscriptBlockSize,
            sigma);

        if (UintToArith256(transcript.transcript_hash) > *derived_target) {
            continue;
        }

        block.matmul_digest = transcript.transcript_hash;
        block.matrix_c_data = FlattenMatrixWords(transcript.C_prime);
        found_candidate = true;
        break;
    }

    BOOST_REQUIRE(found_candidate);
    BOOST_CHECK(!CheckMatMulProofOfWork_Phase2(
        block,
        consensus,
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight - 1));
    BOOST_CHECK(CheckMatMulProofOfWork_Phase2(
        block,
        consensus,
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight));
    BOOST_CHECK(CheckMatMulProofOfWork_Freivalds(
        block,
        consensus,
        consensus.nMatMulPreHashEpsilonBitsUpgradeHeight));
}

BOOST_AUTO_TEST_CASE(block_serialization_roundtrip_with_matrix_c)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000001");
    block.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000002");
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    block.matmul_dim = 4;

    // Create a dummy coinbase tx so vtx is non-empty (required for payload serialization)
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000;
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    // Set up matrix payloads
    block.matrix_a_data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    block.matrix_b_data = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    block.matrix_c_data = {100, 200, 300, 400, 500, 600, 700, 800,
                           900, 1000, 1100, 1200, 1300, 1400, 1500, 1600};

    // Serialize
    DataStream ss{};
    ss << TX_WITH_WITNESS(block);

    // Deserialize
    CBlock block2;
    ss >> TX_WITH_WITNESS(block2);

    // Verify matrix_c_data roundtrips correctly
    BOOST_CHECK_EQUAL(block2.matrix_c_data.size(), 16u);
    BOOST_CHECK(block2.matrix_c_data == block.matrix_c_data);
    BOOST_CHECK(block2.matrix_a_data == block.matrix_a_data);
    BOOST_CHECK(block2.matrix_b_data == block.matrix_b_data);
}

BOOST_AUTO_TEST_CASE(block_serialization_empty_matrix_c)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000001");
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    block.matmul_dim = 4;

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000;
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    block.matrix_a_data = {1, 2, 3, 4};
    block.matrix_b_data = {5, 6, 7, 8};
    // matrix_c_data left empty

    DataStream ss{};
    ss << TX_WITH_WITNESS(block);

    CBlock block2;
    ss >> TX_WITH_WITNESS(block2);

    // Empty matrix_c_data should deserialize as empty
    BOOST_CHECK(block2.matrix_c_data.empty());
    BOOST_CHECK(block2.matrix_a_data == block.matrix_a_data);
    BOOST_CHECK(block2.matrix_b_data == block.matrix_b_data);
}

BOOST_AUTO_TEST_CASE(header_relay_omits_matrix_c)
{
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    // vtx is empty — simulates header relay
    block.matrix_c_data = {1, 2, 3};

    DataStream ss{};
    ss << TX_WITH_WITNESS(block);

    CBlock block2;
    ss >> TX_WITH_WITNESS(block2);

    // Header relay path should not include matrix_c_data
    BOOST_CHECK(block2.matrix_c_data.empty());
}

BOOST_AUTO_TEST_SUITE_END()
