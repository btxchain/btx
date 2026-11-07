// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostream.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostream_tests, BasicTestingSetup)

static modelnet::SwarmNotNoStream NotedNote()
{
    modelnet::SwarmNotNoStream note;
    note.engine_id = "engine-1";
    note.want_stream = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    modelnet::SwarmNotNoStream note = NotedNote();
    note.engine_id.clear();
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStreamResult result = modelnet::SwarmNoteNotNoStream(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(want_stream_is_unstreamed)
{
    modelnet::SwarmNotNoStream note = NotedNote();
    note.want_stream = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStreamResult result = modelnet::SwarmNoteNotNoStream(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "UNSTREAMED");
    BOOST_CHECK_EQUAL(err, "UNSTREAMED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoStream note = NotedNote();
    note.want_stream = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStreamResult result = modelnet::SwarmNoteNotNoStream(note, err);
    BOOST_CHECK(!result.streamed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
