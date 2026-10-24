// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag13.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag13_tests, BasicTestingSetup)

static modelnet::SwarmFlag13 NotedIn()
{
    modelnet::SwarmFlag13 in;
    in.parent_id = "parent-1";
    in.cycle_id = "cycle-2";
    in.parent_graduated = true;
    in.second_cycle = true;
    in.want_repeat = false;
    in.want_pass = false;
    return in;
}

static void ExpectFalse(const modelnet::SwarmFlag13Result& result)
{
    BOOST_CHECK(!result.repeated);
    BOOST_CHECK(!result.produced);
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_CASE(empty_parent_id_is_parent)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.parent_id.clear();
    in.parent_graduated = true;
    in.second_cycle = true;
    in.want_repeat = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(empty_cycle_id_is_parent)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.cycle_id.clear();
    in.parent_graduated = true;
    in.second_cycle = true;
    in.want_repeat = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PARENT");
    BOOST_CHECK_EQUAL(err, "PARENT");
}

BOOST_AUTO_TEST_CASE(not_graduated_is_not_graduated)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.parent_graduated = false;
    in.second_cycle = true;
    in.want_repeat = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(first_cycle_is_first_only)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.parent_graduated = true;
    in.second_cycle = false;
    in.want_repeat = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "FIRST_ONLY");
    BOOST_CHECK_EQUAL(err, "FIRST_ONLY");
}

BOOST_AUTO_TEST_CASE(want_repeat_is_not_repeated)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.parent_graduated = true;
    in.second_cycle = true;
    in.want_repeat = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_REPEATED");
    BOOST_CHECK_EQUAL(err, "NOT_REPEATED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag13 in = NotedIn();
    in.parent_graduated = true;
    in.second_cycle = true;
    in.want_repeat = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFlag13 in = NotedIn();
    std::string err = "prior";
    const modelnet::SwarmFlag13Result result = modelnet::SwarmStageRepeat(in, err);
    ExpectFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
