// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotraj.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotraj_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTraj NotedNote()
{
    modelnet::SwarmNotNoTraj note;
    note.traj_id = "traj-1";
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_traj_id_is_traj)
{
    modelnet::SwarmNotNoTraj note = NotedNote();
    note.traj_id.clear();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajResult result = modelnet::SwarmNoteNotNoTraj(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRAJ");
    BOOST_CHECK_EQUAL(err, "TRAJ");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_train)
{
    modelnet::SwarmNotNoTraj note = NotedNote();
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajResult result = modelnet::SwarmNoteNotNoTraj(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAIN");
    BOOST_CHECK_EQUAL(err, "NOT_TRAIN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTraj note = NotedNote();
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajResult result = modelnet::SwarmNoteNotNoTraj(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
