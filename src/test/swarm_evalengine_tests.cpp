// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(author_cannot_score_own_subject)
{
    modelnet::SwarmEvalEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.Submit("r1", "model-a", "model-a", 500000, true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(!engine.Accepted("model-a"));
    BOOST_CHECK(!engine.attached("model-a"));
    BOOST_REQUIRE(engine.Submit("r2", "model-b", "model-a", 500000, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!engine.Accepted("model-a"));
}

BOOST_AUTO_TEST_CASE(fixed_holdout_is_refused)
{
    modelnet::SwarmEvalEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.Submit("r1", "model-b", "model-a", 500000, false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_CHECK(!engine.Accepted("model-a"));
    BOOST_REQUIRE(engine.Submit("r2", "model-c", "model-a", 500000, true, true, err));
    BOOST_CHECK(!engine.Accepted("model-a"));
}

BOOST_AUTO_TEST_CASE(two_close_authors_accept)
{
    modelnet::SwarmEvalEngine engine;
    std::string err;
    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 500000, true, true, err));
    BOOST_REQUIRE(engine.Submit("r2", "model-c", "model-a", 510000, true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.Accepted("model-a"));
    BOOST_REQUIRE(engine.Attach("model-a", false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.attached("model-a"));
}

BOOST_AUTO_TEST_CASE(two_far_authors_are_not_averaged_into_a_pass)
{
    modelnet::SwarmEvalEngine engine;
    std::string err = "prior";
    // 100000 and 900000 are each inside 0..1000000. Their mean is 500000.
    // Acceptance uses the spread, so this pair does not pass.
    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 100000, true, true, err));
    BOOST_REQUIRE(engine.Submit("r2", "model-c", "model-a", 900000, true, true, err));
    BOOST_CHECK(!engine.Accepted("model-a"));
    BOOST_CHECK(!engine.Attach("model-a", false, false, err));
    BOOST_CHECK_EQUAL(err, "QUORUM");
    BOOST_CHECK(!engine.attached("model-a"));
}

BOOST_AUTO_TEST_CASE(spread_one_past_the_bound_does_not_accept)
{
    modelnet::SwarmEvalEngine engine;
    std::string err;
    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 0, true, true, err));
    BOOST_REQUIRE(engine.Submit("r2", "model-c", "model-a", 10001, true, true, err));
    BOOST_CHECK(!engine.Accepted("model-a"));
}

BOOST_AUTO_TEST_CASE(same_author_twice_is_not_accepted)
{
    modelnet::SwarmEvalEngine engine;
    std::string err;
    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 500000, true, true, err));
    BOOST_REQUIRE(engine.Submit("r2", "model-b", "model-a", 500000, true, true, err));
    BOOST_CHECK(!engine.Accepted("model-a"));
}

BOOST_AUTO_TEST_CASE(regression_blocks_attach)
{
    modelnet::SwarmEvalEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 400000, true, true, err));
    BOOST_REQUIRE(engine.Submit("r2", "model-c", "model-a", 405000, true, true, err));
    BOOST_CHECK(engine.Accepted("model-a"));
    BOOST_CHECK(!engine.Attach("model-a", true, false, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.attached("model-a"));
    BOOST_CHECK(!engine.Attach("model-a", false, true, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.attached("model-a"));
    BOOST_CHECK(!engine.Attach("model-a", true, true, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.attached("model-a"));
}

BOOST_AUTO_TEST_CASE(empty_duplicate_dependent_and_range)
{
    modelnet::SwarmEvalEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.Submit("", "model-a", "model-a", -1, false, false, err));
    BOOST_CHECK_EQUAL(err, "REPORT");
    BOOST_CHECK(!engine.Submit("r1", "", "model-a", 1, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");
    BOOST_CHECK(!engine.Submit("r1", "model-b", "", 1, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPORT");

    BOOST_REQUIRE(engine.Submit("r1", "model-b", "model-a", 10, true, true, err));
    BOOST_CHECK(!engine.Submit("r1", "model-c", "model-a", 900000, true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!engine.Submit("r2", "model-a", "model-a", -1, false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(!engine.Submit("r3", "model-c", "model-a", -1, false, false, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!engine.Submit("r4", "model-c", "model-a", -1, false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
    BOOST_CHECK(!engine.Submit("r5", "model-c", "model-a", -1, true, true, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!engine.Submit("r6", "model-c", "model-a", 1000001, true, true, err));
    BOOST_CHECK_EQUAL(err, "RANGE");

    BOOST_REQUIRE(engine.Submit("r7", "model-c", "model-a", 10, true, true, err));
    BOOST_CHECK(engine.Accepted("model-a"));
    BOOST_CHECK(!engine.attached("model-a"));
}

BOOST_AUTO_TEST_SUITE_END()
