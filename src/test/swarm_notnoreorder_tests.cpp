// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreorder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoreorder_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_child_id_is_child)
{
    modelnet::SwarmNotNoReorder note;
    note.reordered = true;
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorderResult result = modelnet::SwarmNoteNotNoReorder(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "CHILD");
    BOOST_CHECK_EQUAL(err, "CHILD");
}

BOOST_AUTO_TEST_CASE(reordered_is_not_streamed_when_want_stream_is_false)
{
    modelnet::SwarmNotNoReorder note;
    note.child_id = "child-1";
    note.reordered = true;
    note.want_stream = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorderResult result = modelnet::SwarmNoteNotNoReorder(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "NOT_STREAMED");
    BOOST_CHECK_EQUAL(err, "NOT_STREAMED");
}

BOOST_AUTO_TEST_CASE(want_stream_is_held)
{
    modelnet::SwarmNotNoReorder note;
    note.child_id = "child-1";
    note.reordered = false;
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorderResult result = modelnet::SwarmNoteNotNoReorder(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoReorder note;
    note.child_id = "child-1";
    note.reordered = false;
    note.want_stream = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoReorderResult result = modelnet::SwarmNoteNotNoReorder(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
