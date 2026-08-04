// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

namespace {

uint256 FixtureSeed(unsigned char marker)
{
    uint256 seed;
    for (uint32_t i = 0; i < 32; ++i) {
        seed.data()[i] =
            static_cast<unsigned char>(marker + 17 * i);
    }
    return seed;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_fri_ext3_alg_fixture_tests)

BOOST_AUTO_TEST_CASE(dual_q128_zero_fixture_matches_honest_small_prover)
{
    // W=4 has the same (3W mod rate)=4 padding boundary as production W=1092.
    constexpr uint32_t WIDTH = 4;
    constexpr uint32_t COEFFICIENTS = 8;
    constexpr uint64_t NONCE = 43;
    const uint256 seed = FixtureSeed(0x71);

    const auto fixture =
        rc::BuildFri3AlgDualZeroVerifierFixture(
            WIDTH, COEFFICIENTS, seed, NONCE);
    BOOST_REQUIRE_MESSAGE(fixture.ok, fixture.note);

    std::vector<std::vector<rc::Fp3>> zero_columns(
        WIDTH,
        std::vector<rc::Fp3>(
            COEFFICIENTS, rc::Fp3::Zero()));
    const auto honest =
        rc::Fri3AlgDualBatchCommit(
            zero_columns, seed, NONCE);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);

    std::vector<unsigned char> fixture_bytes;
    std::vector<unsigned char> honest_bytes;
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualBatchProof(
            fixture.proof, fixture_bytes),
        fixture.proof_bytes);
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualBatchProof(
            honest.proof, honest_bytes),
        honest.proof_bytes);
    BOOST_CHECK(fixture_bytes == honest_bytes);

    const auto expected_size =
        rc::EstimateFri3AlgDualBatchProofBytes(
            WIDTH, COEFFICIENTS);
    BOOST_REQUIRE(expected_size.has_value());
    BOOST_CHECK_EQUAL(fixture.proof_bytes, *expected_size);

    const auto decoded =
        rc::DeserializeFri3AlgDualBatchProof(fixture_bytes);
    BOOST_REQUIRE(decoded.has_value());
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgDualBatchVerify(*decoded, seed, &why),
        why);

    auto tampered = *decoded;
    BOOST_REQUIRE(!tampered.lane[0].queries.empty());
    BOOST_REQUIRE(
        !tampered.lane[0].queries[0].row.values.empty());
    tampered.lane[0].queries[0].row.values[0].c0 = 1;
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(
        tampered, seed, &why));
}

BOOST_AUTO_TEST_CASE(dual_q128_combined_production_verifier_fixture)
{
    const char* enabled =
        std::getenv("BTX_RC_DUAL_Q128_PRODUCTION_FIXTURE");
    if (enabled == nullptr || std::string(enabled) != "1") {
        BOOST_TEST_MESSAGE(
            "combined production verifier fixture skipped; set "
            "BTX_RC_DUAL_Q128_PRODUCTION_FIXTURE=1. This is a zero-"
            "polynomial FRI verifier-path fixture, not an episode proof "
            "or production prover benchmark.");
        return;
    }

    // Exact selected normalized-root dimensions: W=1092 verifier columns and
    // N=2^19 coefficient rows (LDE N=2^23). The specialized honest builder
    // avoids all 1092 coefficient FFTs only because every polynomial is zero.
    constexpr uint32_t WIDTH = 1092;
    constexpr uint32_t COEFFICIENTS = 1U << 19;
    constexpr uint64_t NONCE = 47;
    constexpr int64_t VERIFY_BUDGET_US = 900000;
    const uint256 seed = FixtureSeed(0x79);

    const auto build_start = std::chrono::steady_clock::now();
    const auto fixture =
        rc::BuildFri3AlgDualZeroVerifierFixture(
            WIDTH, COEFFICIENTS, seed, NONCE);
    const auto build_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - build_start)
            .count();
    BOOST_REQUIRE_MESSAGE(fixture.ok, fixture.note);

    const auto expected_size =
        rc::EstimateFri3AlgDualBatchProofBytes(
            WIDTH, COEFFICIENTS);
    BOOST_REQUIRE(expected_size.has_value());
    BOOST_REQUIRE_EQUAL(fixture.proof_bytes, *expected_size);

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualBatchProof(
            fixture.proof, encoded),
        fixture.proof_bytes);
    const auto decode_start = std::chrono::steady_clock::now();
    const auto decoded =
        rc::DeserializeFri3AlgDualBatchProof(encoded);
    const auto decode_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - decode_start)
            .count();
    BOOST_REQUIRE(decoded.has_value());

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgDualBatchVerify(
            *decoded, seed, &why),
        why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count();
    const int64_t accept_us = decode_us + verify_us;

    BOOST_TEST_MESSAGE(
        "FRI3ALG_DUAL_PRODUCTION_VERIFIER_FIXTURE"
        << " width=" << WIDTH
        << " n_coeffs=" << COEFFICIENTS
        << " n_lde=" << (COEFFICIENTS * rc::kRCFriBlowup)
        << " folds="
        << fixture.proof.lane[0].fold_challenges.size()
        << " q_per_lane=" << rc::kRCFri3AlgDualQueriesPerLane
        << " proof_bytes=" << fixture.proof_bytes
        << " merkle_nodes_built=" << fixture.merkle_nodes_built
        << " fixture_build_us=" << build_us
        << " canonical_decode_us=" << decode_us
        << " native_verify_us=" << verify_us
        << " decode_plus_verify_us=" << accept_us
        << " budget_us=" << VERIFY_BUDGET_US
        << " all_zero_fri_fixture=1"
        << " episode_relation_complete=0"
        << " production_prover_cost_measured=0"
        << " recursive_root_measured=0");
    BOOST_CHECK_LT(accept_us, VERIFY_BUDGET_US);
}

BOOST_AUTO_TEST_SUITE_END()
