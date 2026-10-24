// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotraj2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotraj2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_traj_id_is_traj)
{
    modelnet::SwarmNotNoTraj2 note;
    note.stored = false;
    note.want_learn = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTraj2Result result = modelnet::SwarmNoteNotNoTraj2(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRAJ");
    BOOST_CHECK_EQUAL(err, "TRAJ");
}

BOOST_AUTO_TEST_CASE(stored_false_is_not_learned_when_want_learn_is_false)
{
    modelnet::SwarmNotNoTraj2 note;
    note.traj_id = "traj-1";
    note.stored = false;
    note.want_learn = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTraj2Result result = modelnet::SwarmNoteNotNoTraj2(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_LEARNED");
    BOOST_CHECK_EQUAL(err, "NOT_LEARNED");
}

BOOST_AUTO_TEST_CASE(want_learn_is_held)
{
    modelnet::SwarmNotNoTraj2 note;
    note.traj_id = "traj-1";
    note.stored = true;
    note.want_learn = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTraj2Result result = modelnet::SwarmNoteNotNoTraj2(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTraj2 note;
    note.traj_id = "traj-1";
    note.stored = true;
    note.want_learn = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTraj2Result result = modelnet::SwarmNoteNotNoTraj2(note, err);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
