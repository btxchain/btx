// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_airq_p2_transcript.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace airqtx =
    matmul::v4::rc::stage3_airq_p2_transcript;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_airq_p2_transcript_tests,
    BasicTestingSetup)

namespace {

uint256 U256FromLimbs(
    const std::array<uint64_t, 4>& limbs)
{
    uint256 out;
    for (uint32_t limb = 0; limb < 4; ++limb) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            out.data()[8 * limb + byte] =
                static_cast<unsigned char>(
                    limbs[limb] >> (8 * byte));
        }
    }
    return out;
}

airqtx::Statement TestStatement()
{
    airqtx::Statement out;
    out.fs_seed =
        U256FromLimbs({3, 5, 7, 11});
    out.trace_commit =
        U256FromLimbs({13, 17, 19, 23});
    out.n_rows = 64;
    out.quotient_len = 8;
    out.trace_width = 3;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_native_lanes_digest_and_lambda_execute)
{
    const airqtx::Statement statement =
        TestStatement();
    const auto built =
        airqtx::BuildAirqLambdaTranscriptAir(
            statement);
    BOOST_REQUIRE_MESSAGE(built.valid, built.note);
    BOOST_CHECK_EQUAL(built.violations, 0U);
    BOOST_CHECK(built.local_air_complete);
    BOOST_CHECK(built.exact_air_challenge_lanes);
    BOOST_CHECK(built.exact_air_challenge_digest);
    BOOST_CHECK(built.exact_from_challenge_bytes3);
    BOOST_CHECK(
        built.native_lanes ==
        aq::AirChallengeP2Lanes(
            statement.fs_seed, "airq_lambda",
            {statement.trace_commit}, {64, 8, 3}));
    BOOST_CHECK(
        built.native_digest ==
        aq::AirChallengeDigestP2(
            statement.fs_seed, "airq_lambda",
            {statement.trace_commit}, {64, 8, 3}));
    BOOST_CHECK(
        gf::Eq(
            built.native_lambda,
            gf::FromChallengeBytes3(
                built.native_digest.data())));
    BOOST_CHECK_EQUAL(built.active_rows, 5U);
    BOOST_CHECK_EQUAL(built.n_rows, 8U);
    BOOST_CHECK_EQUAL(built.max_alg_degree, 2U);
    BOOST_CHECK(
        built.source_map.canonical_u32_encoding);
    BOOST_CHECK(
        built.source_map.appendable_layout_only);
    BOOST_CHECK(
        built.consumer_map.appendable_layout_only);
    BOOST_CHECK(!built.proof_owned_source_cells_bound);
    BOOST_CHECK(
        !built.same_parent_consumer_cells_bound);
    BOOST_CHECK(!built.recursive_authority);
}

BOOST_AUTO_TEST_CASE(
    goldilocks_x_plus_p_alias_is_not_an_airq_source_alias)
{
    constexpr uint64_t p = gf::kP;
    const uint64_t x = 5;
    const uint64_t x_plus_p = x + p;
    BOOST_REQUIRE_EQUAL(
        gf::FromU64(x),
        gf::FromU64(x_plus_p));

    airqtx::Statement a = TestStatement();
    airqtx::Statement b = a;
    a.trace_commit =
        U256FromLimbs({x, 11, 22, 33});
    b.trace_commit =
        U256FromLimbs({x_plus_p, 11, 22, 33});
    BOOST_REQUIRE(a.trace_commit != b.trace_commit);

    const auto built_a =
        airqtx::BuildAirqLambdaTranscriptAir(a);
    const auto built_b =
        airqtx::BuildAirqLambdaTranscriptAir(b);
    BOOST_REQUIRE(built_a.valid);
    BOOST_REQUIRE(built_b.valid);
    BOOST_CHECK(
        built_a.source_map.absorb_lanes !=
        built_b.source_map.absorb_lanes);
    BOOST_CHECK(
        built_a.native_digest !=
        built_b.native_digest);
}

BOOST_AUTO_TEST_CASE(
    root_shape_seed_domain_and_label_substitutions_reject_or_move)
{
    const airqtx::Statement honest =
        TestStatement();
    const auto baseline =
        airqtx::BuildAirqLambdaTranscriptAir(honest);
    BOOST_REQUIRE(baseline.valid);

    for (uint32_t which = 0; which < 5; ++which) {
        airqtx::Statement changed = honest;
        if (which == 0) {
            changed.trace_commit.data()[0] ^= 1;
        } else if (which == 1) {
            changed.n_rows = 128;
        } else if (which == 2) {
            changed.fs_seed.data()[0] ^= 1;
        } else if (which == 3) {
            changed.domain_tag =
                "BTX_RC_AIRQ_P2_V0";
        } else {
            changed.label = "airq_gamma";
        }
        const auto result =
            airqtx::BuildAirqLambdaTranscriptAir(
                changed);
        if (which < 3) {
            BOOST_REQUIRE(result.valid);
            BOOST_CHECK(
                !gf::Eq(
                    result.native_lambda,
                    baseline.native_lambda));
        } else {
            BOOST_CHECK(!result.valid);
        }
    }

    airqtx::Statement changed = honest;
    changed.quotient_len = 16;
    const auto quotient =
        airqtx::BuildAirqLambdaTranscriptAir(changed);
    BOOST_REQUIRE(quotient.valid);
    BOOST_CHECK(
        !gf::Eq(
            quotient.native_lambda,
            baseline.native_lambda));

    changed = honest;
    changed.trace_width = 4;
    const auto width =
        airqtx::BuildAirqLambdaTranscriptAir(changed);
    BOOST_REQUIRE(width.valid);
    BOOST_CHECK(
        !gf::Eq(
            width.native_lambda,
            baseline.native_lambda));
}

BOOST_AUTO_TEST_CASE(
    consumer_lambda_and_poseidon_witness_mutations_reject)
{
    const auto built =
        airqtx::BuildAirqLambdaTranscriptAir(
            TestStatement());
    BOOST_REQUIRE(built.valid);

    auto forged = built.columns;
    forged[
        built.layout.LambdaCol(0)]
          [built.consumer_map.terminal_row] =
        gf::Add(
            forged[
                built.layout.LambdaCol(0)]
                  [built.consumer_map.terminal_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        airqtx::CountViolations(
            built.cs, forged),
        0U);

    forged = built.columns;
    forged[
        built.layout.poseidon.X4Col(0)][0] =
        gf::Add(
            forged[
                built.layout.poseidon.X4Col(0)][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        airqtx::CountViolations(
            built.cs, forged),
        0U);
}

BOOST_AUTO_TEST_CASE(
    q192_proof_accepts_and_opening_tamper_rejects)
{
    using Backend =
        aq::AirFriBackendAlg<gf::Fp3>;
    const auto built =
        airqtx::BuildAirqLambdaTranscriptAir(
            TestStatement());
    BOOST_REQUIRE(built.valid);
    const uint256 seed =
        U256FromLimbs({29, 31, 37, 41});
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            built.cs, built.columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            built.cs, proved.proof, seed, &why)),
        why);

    for (uint32_t attack = 0; attack < 3; ++attack) {
        airqtx::Statement changed = TestStatement();
        if (attack == 0) {
            changed.trace_commit.data()[0] ^= 1;
        } else if (attack == 1) {
            changed.n_rows = 128;
        } else {
            changed.fs_seed.data()[0] ^= 1;
        }
        const auto changed_air =
            airqtx::BuildAirqLambdaTranscriptAir(
                changed);
        BOOST_REQUIRE(changed_air.valid);
        BOOST_REQUIRE_EQUAL(
            changed_air.cs.n_rows,
            built.cs.n_rows);
        BOOST_REQUIRE_EQUAL(
            changed_air.cs.n_columns,
            built.cs.n_columns);
        why.clear();
        BOOST_CHECK(
            !(aq::AirQuotientVerify<gf::Fp3, Backend>(
                changed_air.cs,
                proved.proof, seed, &why)));
        BOOST_CHECK(!why.empty());
    }

    auto forged = proved.proof;
    BOOST_REQUIRE(!forged.batch.queries.empty());
    BOOST_REQUIRE_GT(
        forged.batch.queries[0].row.values.size(),
        built.layout.LambdaCol(0));
    forged.batch.queries[0]
        .row.values[built.layout.LambdaCol(0)] =
        gf::Add(
            forged.batch.queries[0]
                .row.values[
                    built.layout.LambdaCol(0)],
            gf::Fp3::One());
    why.clear();
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            built.cs, forged, seed, &why)));
    BOOST_CHECK(!why.empty());
}

BOOST_AUTO_TEST_SUITE_END()
