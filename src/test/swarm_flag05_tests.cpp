// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag05.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag05_tests, BasicTestingSetup)

static modelnet::SwarmFlag05 NotedExperience()
{
    modelnet::SwarmFlag05 in;
    in.agent_id = "agent-1";
    in.task_id = "task-1";
    in.authorized = true;
    in.synthetic_or_public = true;
    in.want_record = false;
    in.want_pass = false;
    return in;
}

static void ExpectUnmoved(const modelnet::SwarmFlag05Result& result)
{
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
}

BOOST_AUTO_TEST_CASE(empty_agent_id_is_agent)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.agent_id.clear();
    in.authorized = false;
    in.synthetic_or_public = false;
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "AGENT");
    BOOST_CHECK_EQUAL(err, "AGENT");
}

BOOST_AUTO_TEST_CASE(empty_task_id_is_agent)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.task_id.clear();
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "AGENT");
    BOOST_CHECK_EQUAL(err, "AGENT");
}

BOOST_AUTO_TEST_CASE(empty_ids_win_over_later_flags)
{
    modelnet::SwarmFlag05 in;
    in.agent_id.clear();
    in.task_id.clear();
    in.authorized = false;
    in.synthetic_or_public = false;
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "AGENT");
    BOOST_CHECK_EQUAL(err, "AGENT");
}

BOOST_AUTO_TEST_CASE(not_authorized_is_unauthorized)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.authorized = false;
    in.synthetic_or_public = true;
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(not_synthetic_or_public_is_unauthorized)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.authorized = true;
    in.synthetic_or_public = false;
    in.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(unauthorized_even_if_want_record)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.authorized = false;
    in.synthetic_or_public = false;
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "UNAUTHORIZED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(err, "UNAUTHORIZED");
}

BOOST_AUTO_TEST_CASE(want_record_is_not_recorded)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.want_record = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_RECORDED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(err, "NOT_RECORDED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    in.want_record = false;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(authorized_public_note_is_noted)
{
    modelnet::SwarmFlag05 in = NotedExperience();
    std::string err = "prior";
    const modelnet::SwarmFlag05Result result = modelnet::SwarmStageExperience(in, err);
    ExpectUnmoved(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
