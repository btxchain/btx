// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_notnoincludepath2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoincludepath2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_note_id_yields_note)
{
    modelnet::SwarmNotNoIncludePath2 note;
    note.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncludePath2Result result = modelnet::SwarmNoteNotNoIncludePath2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "NOTE");
    BOOST_CHECK_EQUAL(err, "NOTE");
}

BOOST_AUTO_TEST_CASE(want_record_yields_held)
{
    modelnet::SwarmNotNoIncludePath2 note;
    note.note_id = "note-1";
    note.want_record = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncludePath2Result result = modelnet::SwarmNoteNotNoIncludePath2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoIncludePath2 note;
    note.note_id = "note-1";
    note.want_record = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIncludePath2Result result = modelnet::SwarmNoteNotNoIncludePath2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
