// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nocheckpoint.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nocheckpoint_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_check)
{
    std::string err = "prior";
    modelnet::SwarmNoCheckpoint note;
    note.checkpoint_saved = true;
    note.want_publish = true;
    const modelnet::SwarmNoCheckpointResult result = modelnet::SwarmNoteNoCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
}

BOOST_AUTO_TEST_CASE(want_publish_without_checkpoint_is_no_checkpoint)
{
    std::string err = "prior";
    modelnet::SwarmNoCheckpoint note;
    note.run_id = "run-a";
    note.checkpoint_saved = false;
    note.want_publish = true;
    const modelnet::SwarmNoCheckpointResult result = modelnet::SwarmNoteNoCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(saved_checkpoint_want_publish_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNoCheckpoint note;
    note.run_id = "run-a";
    note.checkpoint_saved = true;
    note.want_publish = true;
    const modelnet::SwarmNoCheckpointResult result = modelnet::SwarmNoteNoCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(saved_checkpoint_without_publish_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNoCheckpoint note;
    note.run_id = "run-a";
    note.checkpoint_saved = true;
    note.want_publish = false;
    const modelnet::SwarmNoCheckpointResult result = modelnet::SwarmNoteNoCheckpoint(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
