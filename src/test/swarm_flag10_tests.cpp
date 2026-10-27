// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag10.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag10_tests, BasicTestingSetup)

static modelnet::SwarmFlag10 Subscribed()
{
    modelnet::SwarmFlag10 in;
    in.node_id = "node-10";
    in.descendant_id = "desc-10";
    in.previous_id = "prev-10";
    in.want_adopt = false;
    in.want_pass = false;
    return in;
}

static void ExpectNoMove(const modelnet::SwarmFlag10Result& result)
{
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmFlag10 in = Subscribed();
    in.node_id.clear();
    in.previous_id.clear();
    in.want_adopt = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.rollback_kept);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(empty_descendant_id_is_node)
{
    modelnet::SwarmFlag10 in = Subscribed();
    in.descendant_id.clear();
    in.want_adopt = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.rollback_kept);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(empty_previous_id_is_no_rollback)
{
    modelnet::SwarmFlag10 in = Subscribed();
    in.previous_id.clear();
    in.want_adopt = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(!result.rollback_kept);
    BOOST_CHECK_EQUAL(result.code, "NO_ROLLBACK");
    BOOST_CHECK_EQUAL(err, "NO_ROLLBACK");
}

BOOST_AUTO_TEST_CASE(want_adopt_is_not_adopted_and_previous_id_stays)
{
    modelnet::SwarmFlag10 in = Subscribed();
    in.want_adopt = true;
    in.want_pass = true;
    const std::string previous = in.previous_id;
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(result.rollback_kept);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADOPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ADOPTED");
    BOOST_CHECK_EQUAL(in.previous_id, previous);
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag10 in = Subscribed();
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(result.rollback_kept);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(subscribed_second_node_is_noted)
{
    modelnet::SwarmFlag10 in = Subscribed();
    std::string err = "prior";
    const modelnet::SwarmFlag10Result result = modelnet::SwarmStageAdopt(in, err);
    ExpectNoMove(result);
    BOOST_CHECK(!result.adopted);
    BOOST_CHECK(result.rollback_kept);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
