// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottrajectory.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nottrajectory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_agent_id_is_agent)
{
    modelnet::SwarmNotTrajectory note;
    std::string err = "prior";
    const modelnet::SwarmNotTrajectoryResult result = modelnet::SwarmNoteNotTrajectory(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.code, "AGENT");
    BOOST_CHECK_EQUAL(err, "AGENT");
}

BOOST_AUTO_TEST_CASE(want_record_is_not_recorded)
{
    modelnet::SwarmNotTrajectory note;
    note.agent_id = "agent-1";
    note.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmNotTrajectoryResult result = modelnet::SwarmNoteNotTrajectory(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_RECORDED");
    BOOST_CHECK_EQUAL(err, "NOT_RECORDED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTrajectory note;
    note.agent_id = "agent-1";
    note.want_record = false;
    std::string err = "prior";
    const modelnet::SwarmNotTrajectoryResult result = modelnet::SwarmNoteNotTrajectory(note, err);
    BOOST_CHECK_EQUAL(result.recorded, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
