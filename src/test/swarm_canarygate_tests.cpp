// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canarygate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_canarygate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_candidate)
{
    modelnet::SwarmCanaryGate gate;
    std::string err = "prior";
    const modelnet::SwarmCanaryGateResult result = modelnet::SwarmGateCanary(gate, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.parent_kept);
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(regression_keeps_parent)
{
    modelnet::SwarmCanaryGate gate;
    gate.candidate_id = "cand-a";
    gate.regression = true;
    gate.qualified = true;
    gate.want_promote = false;
    std::string err = "prior";
    const modelnet::SwarmCanaryGateResult result = modelnet::SwarmGateCanary(gate, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.parent_kept);
    BOOST_CHECK_EQUAL(result.code, "REGRESSION");
    BOOST_CHECK_EQUAL(err, "REGRESSION");
}

BOOST_AUTO_TEST_CASE(unqualified_when_not_qualified)
{
    modelnet::SwarmCanaryGate gate;
    gate.candidate_id = "cand-a";
    gate.regression = false;
    gate.qualified = false;
    gate.want_promote = false;
    std::string err = "prior";
    const modelnet::SwarmCanaryGateResult result = modelnet::SwarmGateCanary(gate, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.parent_kept);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(want_promote_is_held)
{
    modelnet::SwarmCanaryGate gate;
    gate.candidate_id = "cand-a";
    gate.regression = false;
    gate.qualified = true;
    gate.want_promote = true;
    std::string err = "prior";
    const modelnet::SwarmCanaryGateResult result = modelnet::SwarmGateCanary(gate, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.parent_kept);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_does_not_promote)
{
    modelnet::SwarmCanaryGate gate;
    gate.candidate_id = "cand-a";
    gate.regression = false;
    gate.qualified = true;
    gate.want_promote = false;
    std::string err = "prior";
    const modelnet::SwarmCanaryGateResult result = modelnet::SwarmGateCanary(gate, err);
    BOOST_CHECK(!result.promoted);
    BOOST_CHECK(result.parent_kept);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
