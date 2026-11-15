// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_joinflag.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_joinflag_tests, BasicTestingSetup)

static modelnet::SwarmJoinFlag NotedFlag()
{
    modelnet::SwarmJoinFlag flag;
    flag.model_id = "model-a";
    flag.modelnet_on = true;
    flag.extra_flag_required = false;
    return flag;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_join)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    flag.model_id.clear();
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "JOIN");
    BOOST_CHECK_EQUAL(err, "JOIN");
}

BOOST_AUTO_TEST_CASE(empty_model_id_wins_over_extra_flag_and_modelnet)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    flag.model_id.clear();
    flag.modelnet_on = true;
    flag.extra_flag_required = true;
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "JOIN");
    BOOST_CHECK_EQUAL(err, "JOIN");
}

BOOST_AUTO_TEST_CASE(extra_flag_required_is_no_flag_even_when_modelnet_on)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    flag.modelnet_on = true;
    flag.extra_flag_required = true;
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NO_FLAG");
    BOOST_CHECK_EQUAL(err, "NO_FLAG");
}

BOOST_AUTO_TEST_CASE(extra_flag_required_wins_over_modelnet_off)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    flag.modelnet_on = false;
    flag.extra_flag_required = true;
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NO_FLAG");
    BOOST_CHECK_EQUAL(err, "NO_FLAG");
}

BOOST_AUTO_TEST_CASE(modelnet_off_is_modelnet)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    flag.modelnet_on = false;
    flag.extra_flag_required = false;
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "MODELNET");
    BOOST_CHECK_EQUAL(err, "MODELNET");
}

BOOST_AUTO_TEST_CASE(modelnet_on_is_noted_and_does_not_join)
{
    modelnet::SwarmJoinFlag flag = NotedFlag();
    std::string err = "prior";
    const modelnet::SwarmJoinFlagResult result = modelnet::SwarmNoteJoinFlag(flag, err);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK(!result.socket_opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
