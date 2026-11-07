// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cycleparent.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cycleparent_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_parent_is_parent)
{
    std::string err = "prior";
    modelnet::SwarmCycleParent cycle;
    cycle.parent_id.clear();
    cycle.candidate_id = "c";
    cycle.qualified = true;
    cycle.want_advance = false;
    const modelnet::SwarmCycleParentResult result = modelnet::SwarmAdvanceParent(cycle, err);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK(result.parent_id.empty());
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(empty_candidate_keeps_parent)
{
    std::string err = "prior";
    modelnet::SwarmCycleParent cycle;
    cycle.parent_id = "p";
    cycle.candidate_id.clear();
    cycle.qualified = true;
    cycle.want_advance = false;
    const modelnet::SwarmCycleParentResult result = modelnet::SwarmAdvanceParent(cycle, err);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(result.parent_id, "p");
    BOOST_CHECK_EQUAL(result.code, "CANDIDATE");
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
}

BOOST_AUTO_TEST_CASE(unqualified_leaves_parent)
{
    std::string err = "prior";
    modelnet::SwarmCycleParent cycle;
    cycle.parent_id = "p";
    cycle.candidate_id = "c";
    cycle.qualified = false;
    cycle.want_advance = false;
    const modelnet::SwarmCycleParentResult result = modelnet::SwarmAdvanceParent(cycle, err);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(result.parent_id, "p");
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(want_advance_is_held)
{
    std::string err = "prior";
    modelnet::SwarmCycleParent cycle;
    cycle.parent_id = "p";
    cycle.candidate_id = "c";
    cycle.qualified = true;
    cycle.want_advance = true;
    const modelnet::SwarmCycleParentResult result = modelnet::SwarmAdvanceParent(cycle, err);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(result.parent_id, "p");
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(qualified_notes_candidate)
{
    std::string err = "prior";
    modelnet::SwarmCycleParent cycle;
    cycle.parent_id = "p";
    cycle.candidate_id = "c";
    cycle.qualified = true;
    cycle.want_advance = false;
    const modelnet::SwarmCycleParentResult result = modelnet::SwarmAdvanceParent(cycle, err);
    BOOST_CHECK(result.advanced);
    BOOST_CHECK_EQUAL(result.parent_id, "c");
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
