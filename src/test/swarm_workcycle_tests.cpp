// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workcycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workcycle_tests, BasicTestingSetup)

static modelnet::SwarmWorkCycle NotedCycle()
{
    modelnet::SwarmWorkCycle cycle;
    cycle.cycle_id = "cycle-local";
    cycle.publish = true;
    cycle.fund = true;
    cycle.lease = true;
    cycle.pay = true;
    cycle.frontier = true;
    cycle.graduate = true;
    cycle.want_advance = false;
    return cycle;
}

static void ExpectAdvancedStaysFalse(const modelnet::SwarmWorkCycleResult& result)
{
    BOOST_CHECK(!result.advanced);
}

BOOST_AUTO_TEST_CASE(empty_cycle_id_is_cycle)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.cycle_id.clear();
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "CYCLE");
    BOOST_CHECK_EQUAL(err, "CYCLE");
}

BOOST_AUTO_TEST_CASE(empty_cycle_id_wins_over_funding_and_want_advance)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.cycle_id.clear();
    cycle.fund = false;
    cycle.publish = false;
    cycle.want_advance = true;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "CYCLE");
    BOOST_CHECK_EQUAL(err, "CYCLE");
}

BOOST_AUTO_TEST_CASE(missing_fund_is_funding)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.fund = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "FUNDING");
    BOOST_CHECK_EQUAL(err, "FUNDING");
}

BOOST_AUTO_TEST_CASE(funding_wins_when_want_advance_is_true)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.fund = false;
    cycle.want_advance = true;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "FUNDING");
    BOOST_CHECK_EQUAL(err, "FUNDING");
}

BOOST_AUTO_TEST_CASE(funding_wins_when_another_flag_is_also_false)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.fund = false;
    cycle.publish = false;
    cycle.lease = false;
    cycle.pay = false;
    cycle.frontier = false;
    cycle.graduate = false;
    cycle.want_advance = true;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "FUNDING");
    BOOST_CHECK_EQUAL(err, "FUNDING");
}

BOOST_AUTO_TEST_CASE(missing_publish_is_incomplete)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.publish = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(missing_lease_is_incomplete)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.lease = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(missing_pay_is_incomplete)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.pay = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(missing_frontier_is_incomplete)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.frontier = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(missing_graduate_is_incomplete)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.graduate = false;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(incomplete_wins_when_want_advance_is_true)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.graduate = false;
    cycle.want_advance = true;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(want_advance_is_held)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    cycle.want_advance = true;
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(all_six_flags_without_want_advance_is_noted)
{
    modelnet::SwarmWorkCycle cycle = NotedCycle();
    std::string err = "prior";
    const modelnet::SwarmWorkCycleResult result = modelnet::SwarmNoteWorkCycle(cycle, err);
    ExpectAdvancedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
