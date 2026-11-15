// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputeout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_disputeout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_dispute_id_is_dispute)
{
    std::string err = "prior";
    modelnet::SwarmDisputeOut dispute;
    dispute.want_settle = true;
    const modelnet::SwarmDisputeOutResult result = modelnet::SwarmNoteDisputeOut(dispute, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "DISPUTE");
    BOOST_CHECK_EQUAL(err, "DISPUTE");
}

BOOST_AUTO_TEST_CASE(want_settle_is_held)
{
    std::string err = "prior";
    modelnet::SwarmDisputeOut dispute;
    dispute.dispute_id = "dispute-1";
    dispute.want_settle = true;
    const modelnet::SwarmDisputeOutResult result = modelnet::SwarmNoteDisputeOut(dispute, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_settle_false_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmDisputeOut dispute;
    dispute.dispute_id = "dispute-1";
    dispute.want_settle = false;
    const modelnet::SwarmDisputeOutResult result = modelnet::SwarmNoteDisputeOut(dispute, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
