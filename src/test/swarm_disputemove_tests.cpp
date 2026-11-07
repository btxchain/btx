// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputemove.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_disputemove_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_dispute_at_open)
{
    std::string err;
    const modelnet::SwarmDisputeStep step{"", modelnet::SwarmDisputeMove::Open, false, false, false};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "DISPUTE");
    BOOST_CHECK_EQUAL(err, "DISPUTE");
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Open);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(open_advances_to_evidence)
{
    std::string err = "stale";
    const modelnet::SwarmDisputeStep step{"d1", modelnet::SwarmDisputeMove::Open, false, false, false};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Evidence);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(evidence_without_receipt_stays_evidence)
{
    std::string err;
    const modelnet::SwarmDisputeStep step{"d1", modelnet::SwarmDisputeMove::Evidence, false, false, false};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Evidence);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(evidence_with_receipt_becomes_accepted)
{
    std::string err = "stale";
    const modelnet::SwarmDisputeStep step{"d1", modelnet::SwarmDisputeMove::Evidence, true, false, false};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Accepted);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(accepted_want_settle_stays_held)
{
    std::string err;
    const modelnet::SwarmDisputeStep step{"d1", modelnet::SwarmDisputeMove::Accepted, true, true, true};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Accepted);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(accepted_known_outpoint_stays_unsettled)
{
    std::string err;
    const modelnet::SwarmDisputeStep step{"d1", modelnet::SwarmDisputeMove::Accepted, true, true, false};
    const modelnet::SwarmDisputeStepResult result = modelnet::SwarmStepDispute(step, err);
    BOOST_CHECK_EQUAL(result.code, "UNSETTLED");
    BOOST_CHECK_EQUAL(err, "UNSETTLED");
    BOOST_CHECK(result.state == modelnet::SwarmDisputeMove::Accepted);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
