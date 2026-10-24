// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_idle_tests, BasicTestingSetup)

static modelnet::SwarmIdleDefault NotedIdle()
{
    modelnet::SwarmIdleDefault idle;
    idle.node_id = "node-1";
    idle.device_json_present = false;
    idle.want_train = false;
    idle.want_spend = false;
    idle.want_private = false;
    return idle;
}

static void ExpectSpendOff(const modelnet::SwarmIdleDefaultResult& result, bool seed_eval)
{
    BOOST_CHECK(!result.trainer);
    BOOST_CHECK(!result.spend_armed);
    BOOST_CHECK_EQUAL(result.spend, "0");
    BOOST_CHECK_EQUAL(result.seeder, seed_eval);
    BOOST_CHECK_EQUAL(result.evaluator, seed_eval);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_idle)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "IDLE");
    BOOST_CHECK_EQUAL(err, "IDLE");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_other_flags)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.node_id.clear();
    idle.device_json_present = true;
    idle.want_train = true;
    idle.want_spend = true;
    idle.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "IDLE");
    BOOST_CHECK_EQUAL(err, "IDLE");
}

BOOST_AUTO_TEST_CASE(device_json_present_is_present)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.device_json_present = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "PRESENT");
    BOOST_CHECK_EQUAL(err, "PRESENT");
}

BOOST_AUTO_TEST_CASE(device_json_present_wins_over_train_spend_and_private)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.device_json_present = true;
    idle.want_train = true;
    idle.want_spend = true;
    idle.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "PRESENT");
    BOOST_CHECK_EQUAL(err, "PRESENT");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_trainer)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAINER");
    BOOST_CHECK_EQUAL(err, "NOT_TRAINER");
}

BOOST_AUTO_TEST_CASE(want_train_wins_over_spend_and_private)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.want_train = true;
    idle.want_spend = true;
    idle.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAINER");
    BOOST_CHECK_EQUAL(err, "NOT_TRAINER");
}

BOOST_AUTO_TEST_CASE(want_spend_is_spend_refused)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "SPEND_REFUSED");
    BOOST_CHECK_EQUAL(err, "SPEND_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_spend_wins_over_private)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.want_spend = true;
    idle.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "SPEND_REFUSED");
    BOOST_CHECK_EQUAL(err, "SPEND_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_private_is_private_refused)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    idle.want_private = true;
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, false);
    BOOST_CHECK_EQUAL(result.code, "PRIVATE_REFUSED");
    BOOST_CHECK_EQUAL(err, "PRIVATE_REFUSED");
}

BOOST_AUTO_TEST_CASE(absent_device_file_is_noted)
{
    modelnet::SwarmIdleDefault idle = NotedIdle();
    std::string err = "prior";
    const modelnet::SwarmIdleDefaultResult result = modelnet::SwarmNoteIdleDefault(idle, err);
    ExpectSpendOff(result, true);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
