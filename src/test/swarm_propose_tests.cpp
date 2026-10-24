// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_propose.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_propose_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_weakness_is_propose)
{
    modelnet::SwarmProposal proposal;
    proposal.weakness_id.clear();
    proposal.recipe_id = "recipe-v1";
    proposal.scheduled = true;
    proposal.trained = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmProposeExperiment(proposal, 4, 0, err));
    BOOST_CHECK_EQUAL(err, "PROPOSE");
    BOOST_CHECK(!proposal.scheduled);
    BOOST_CHECK(!proposal.trained);
}

BOOST_AUTO_TEST_CASE(used_equal_to_budget_is_budget)
{
    modelnet::SwarmProposal proposal;
    proposal.weakness_id = "weak-1";
    proposal.recipe_id = "recipe-v1";
    proposal.scheduled = true;
    proposal.trained = true;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmProposeExperiment(proposal, 3, 3, err));
    BOOST_CHECK_EQUAL(err, "BUDGET");
    BOOST_CHECK(!proposal.scheduled);
    BOOST_CHECK(!proposal.trained);
}

BOOST_AUTO_TEST_CASE(one_free_slot_schedules_and_trained_stays_false)
{
    modelnet::SwarmProposal proposal;
    proposal.weakness_id = "weak-1";
    proposal.recipe_id = "recipe-v1";
    proposal.slots = 0;
    proposal.scheduled = false;
    proposal.trained = true;
    std::string err = "prior";
    BOOST_REQUIRE(modelnet::SwarmProposeExperiment(proposal, 1, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(proposal.scheduled);
    BOOST_CHECK(!proposal.trained);
    BOOST_CHECK_EQUAL(proposal.slots, 1);
}

BOOST_AUTO_TEST_SUITE_END()
