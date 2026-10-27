// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_canaryhold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_canary)
{
    std::string err = "prior";
    modelnet::SwarmCanaryHoldRequest request;
    request.canary_started = true;
    request.regression = true;
    request.want_activate = true;
    const modelnet::SwarmCanaryHoldResult result = modelnet::SwarmHoldCanary(request, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "CANARY");
    BOOST_CHECK_EQUAL(err, "CANARY");
}

BOOST_AUTO_TEST_CASE(not_started_wins_over_regression_and_want_activate)
{
    std::string err = "prior";
    modelnet::SwarmCanaryHoldRequest request;
    request.candidate_id = "cand-a";
    request.canary_started = false;
    request.regression = true;
    request.want_activate = true;
    const modelnet::SwarmCanaryHoldResult result = modelnet::SwarmHoldCanary(request, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(regression_wins_over_want_activate)
{
    std::string err = "prior";
    modelnet::SwarmCanaryHoldRequest request;
    request.candidate_id = "cand-a";
    request.canary_started = true;
    request.regression = true;
    request.want_activate = true;
    const modelnet::SwarmCanaryHoldResult result = modelnet::SwarmHoldCanary(request, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "REGRESSION");
    BOOST_CHECK_EQUAL(err, "REGRESSION");
}

BOOST_AUTO_TEST_CASE(want_activate_is_held_and_does_not_activate)
{
    std::string err = "prior";
    modelnet::SwarmCanaryHoldRequest request;
    request.candidate_id = "cand-a";
    request.canary_started = true;
    request.regression = false;
    request.want_activate = true;
    const modelnet::SwarmCanaryHoldResult result = modelnet::SwarmHoldCanary(request, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_does_not_activate)
{
    std::string err = "prior";
    modelnet::SwarmCanaryHoldRequest request;
    request.candidate_id = "cand-a";
    request.canary_started = true;
    request.regression = false;
    request.want_activate = false;
    const modelnet::SwarmCanaryHoldResult result = modelnet::SwarmHoldCanary(request, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
