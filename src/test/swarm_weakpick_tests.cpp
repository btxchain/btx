// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_weakpick.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_weakpick_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_proposer_id_is_proposer)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.weakness_id = "weak-a";
    pick.budget_slots = 4;
    pick.used_slots = 1;
    pick.want_schedule = true;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 0);
    BOOST_CHECK_EQUAL(result.code, "PROPOSER");
    BOOST_CHECK_EQUAL(err, "PROPOSER");
}

BOOST_AUTO_TEST_CASE(empty_weakness_id_is_weakness)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.proposer_id = "prop-a";
    pick.budget_slots = 4;
    pick.used_slots = 1;
    pick.want_schedule = true;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 0);
    BOOST_CHECK_EQUAL(result.code, "WEAKNESS");
    BOOST_CHECK_EQUAL(err, "WEAKNESS");
}

BOOST_AUTO_TEST_CASE(used_above_budget_is_budget)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.proposer_id = "prop-a";
    pick.weakness_id = "weak-a";
    pick.budget_slots = 2;
    pick.used_slots = 3;
    pick.want_schedule = true;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 0);
    BOOST_CHECK_EQUAL(result.code, "BUDGET");
    BOOST_CHECK_EQUAL(err, "BUDGET");
}

BOOST_AUTO_TEST_CASE(used_equals_budget_is_full)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.proposer_id = "prop-a";
    pick.weakness_id = "weak-a";
    pick.budget_slots = 2;
    pick.used_slots = 2;
    pick.want_schedule = true;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 0);
    BOOST_CHECK_EQUAL(result.code, "FULL");
    BOOST_CHECK_EQUAL(err, "FULL");
}

BOOST_AUTO_TEST_CASE(want_schedule_is_held)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.proposer_id = "prop-a";
    pick.weakness_id = "weak-a";
    pick.budget_slots = 4;
    pick.used_slots = 1;
    pick.want_schedule = true;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 2);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_does_not_schedule)
{
    std::string err = "prior";
    modelnet::SwarmWeakPick pick;
    pick.proposer_id = "prop-a";
    pick.weakness_id = "weak-a";
    pick.budget_slots = 4;
    pick.used_slots = 1;
    pick.want_schedule = false;
    const modelnet::SwarmWeakPickResult result = modelnet::SwarmPickWeakness(pick, err);
    BOOST_CHECK(!result.running);
    BOOST_CHECK(!result.scheduled);
    BOOST_CHECK_EQUAL(result.slots_left, 3);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
