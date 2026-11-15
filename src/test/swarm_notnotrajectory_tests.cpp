// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrajectory.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotrajectory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_traj_id_is_traj)
{
    modelnet::SwarmNotNoTrajectory note;
    note.unstored = true;
    note.want_learn = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajectoryResult result = modelnet::SwarmNoteNotNoTrajectory(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "TRAJ");
    BOOST_CHECK_EQUAL(err, "TRAJ");
}

BOOST_AUTO_TEST_CASE(unstored_is_not_stored_when_want_learn_is_false)
{
    modelnet::SwarmNotNoTrajectory note;
    note.traj_id = "traj-1";
    note.unstored = true;
    note.want_learn = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajectoryResult result = modelnet::SwarmNoteNotNoTrajectory(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_STORED");
    BOOST_CHECK_EQUAL(err, "NOT_STORED");
}

BOOST_AUTO_TEST_CASE(want_learn_is_held)
{
    modelnet::SwarmNotNoTrajectory note;
    note.traj_id = "traj-1";
    note.unstored = false;
    note.want_learn = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajectoryResult result = modelnet::SwarmNoteNotNoTrajectory(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTrajectory note;
    note.traj_id = "traj-1";
    note.unstored = false;
    note.want_learn = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajectoryResult result = modelnet::SwarmNoteNotNoTrajectory(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
