// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrollout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrollout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_agent_id)
{
    modelnet::SwarmNotRollout note;
    std::string err = "stale";
    const modelnet::SwarmNotRolloutResult result = modelnet::SwarmNoteNotRollout(note, err);
    BOOST_CHECK_EQUAL(result.code, "AGENT");
    BOOST_CHECK(!result.generated);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(err, "AGENT");
}

BOOST_AUTO_TEST_CASE(want_generate_not_recorded)
{
    modelnet::SwarmNotRollout note;
    note.agent_id = "agent-1";
    note.want_generate = true;
    std::string err;
    const modelnet::SwarmNotRolloutResult result = modelnet::SwarmNoteNotRollout(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RECORDED");
    BOOST_CHECK(!result.generated);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(err, "NOT_RECORDED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotRollout note;
    note.agent_id = "agent-1";
    std::string err = "stale";
    const modelnet::SwarmNotRolloutResult result = modelnet::SwarmNoteNotRollout(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.generated);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
