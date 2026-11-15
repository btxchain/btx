// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohostnote2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnohostnote2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_note_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHostNote2 note;
    note.names_host = true;
    note.want_record = true;
    const modelnet::SwarmNotNoHostNote2Result result = modelnet::SwarmNoteNotNoHostNote2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "NOTE");
    BOOST_CHECK_EQUAL(err, "NOTE");
}

BOOST_AUTO_TEST_CASE(names_host)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHostNote2 note;
    note.note_id = "note-1";
    note.names_host = true;
    note.want_record = false;
    const modelnet::SwarmNotNoHostNote2Result result = modelnet::SwarmNoteNotNoHostNote2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(want_record)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHostNote2 note;
    note.note_id = "note-1";
    note.names_host = false;
    note.want_record = true;
    const modelnet::SwarmNotNoHostNote2Result result = modelnet::SwarmNoteNotNoHostNote2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmNotNoHostNote2 note;
    note.note_id = "note-1";
    note.names_host = false;
    note.want_record = false;
    const modelnet::SwarmNotNoHostNote2Result result = modelnet::SwarmNoteNotNoHostNote2(note, err);
    BOOST_CHECK(!result.recorded);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
