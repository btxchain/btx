// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/research_index.h>
#include <modelnet/swarm_bound/swarm_bound.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_bound_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_pass_runs_decode_train_and_two_ranks)
{
    modelnet::SwarmBoundProbe bound;
    std::string err = "prior";
    BOOST_CHECK(bound.Pass(1, err));
    BOOST_CHECK_EQUAL(err, "");
    BOOST_CHECK_EQUAL(bound.infer_tokens(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(bound.train_steps(), static_cast<int64_t>(1));
    BOOST_CHECK(bound.exchange_bytes() > static_cast<int64_t>(0));
    BOOST_CHECK(bound.replay_ok());
    BOOST_CHECK_EQUAL(bound.hosts(), 1);
    BOOST_CHECK_EQUAL(bound.ranks(), 2);
    BOOST_CHECK(!bound.gpu());
    BOOST_CHECK(!bound.gpu_passed());
    BOOST_CHECK(!bound.windows_passed());
    BOOST_CHECK(!bound.passed());
    BOOST_CHECK(!bound.launched());
    BOOST_CHECK(!bound.broadcast());
    BOOST_CHECK(!bound.release_qualified());
    BOOST_CHECK_EQUAL(bound.remote_engine(), modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(bound.ticks(), static_cast<int64_t>(1));

    BOOST_CHECK(bound.Pass(2, err));
    BOOST_CHECK_EQUAL(bound.train_steps(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(bound.ticks(), static_cast<int64_t>(2));
    BOOST_CHECK(!bound.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!bound.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
}

BOOST_AUTO_TEST_CASE(index_view_follows_an_announcement)
{
    modelnet::ResearchIndex index;
    modelnet::Digest48 contribution;
    modelnet::Digest48 author;
    contribution.data[0] = 1;
    author.data[0] = 2;
    std::string err;
    BOOST_REQUIRE(index.Announce("lab-topic", contribution, author, false, "measured", err));
    const std::vector<std::string> leading = index.View("LEADING", "lab-topic", err);
    BOOST_REQUIRE_EQUAL(leading.size(), 1U);
    BOOST_CHECK_EQUAL(leading[0], contribution.Hex());
    BOOST_CHECK(index.View("UNKNOWN", "lab-topic", err).empty());
    BOOST_CHECK_EQUAL(err, "VIEW");
}

BOOST_AUTO_TEST_SUITE_END()
