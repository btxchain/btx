// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_params.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_builder_params_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(consensus_params_are_the_proved_endpoint_vector)
{
    const auto params = rc::MakeToyRCEpisodeParams();
    const uint256 statement = uint256::ONE;
    rc::RCStage3EpisodeBuilderParamsProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        (rc::ProveRCStage3EpisodeBuilderParamsProduct(
            statement, params, product, &why)),
        why);
    BOOST_CHECK_MESSAGE(
        (rc::VerifyRCStage3EpisodeBuilderParamsProduct(
            statement, params, product, &why)),
        why);

    auto changed = params;
    ++changed.rounds;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderParamsProduct(
            statement, changed, product, &why));

    auto detached = product;
    detached.memory_manifest.address_begin = 1;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderParamsProduct(
            statement, params, detached, &why));

    const auto audit =
        rc::CurrentRCStage3EpisodeBuilderParamsAudit();
    BOOST_CHECK(audit.local_relation_complete);
    BOOST_CHECK(audit.producer_provenance_complete);
    BOOST_CHECK(audit.semantic_complete);
    BOOST_CHECK(!audit.recursively_consumed);
}

BOOST_AUTO_TEST_SUITE_END()
