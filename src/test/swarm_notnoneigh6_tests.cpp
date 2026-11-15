// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh6.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoneigh6_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh6 note;
    note.count = 7;
    note.want_add = true;
    const modelnet::SwarmNotNoNeigh6Result result = modelnet::SwarmNoteNotNoNeigh6(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(count_7)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh6 note;
    note.peer_id = "peer-1";
    note.count = 7;
    note.want_add = false;
    const modelnet::SwarmNotNoNeigh6Result result = modelnet::SwarmNoteNotNoNeigh6(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(want_add_with_count_6)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh6 note;
    note.peer_id = "peer-1";
    note.count = 6;
    note.want_add = true;
    const modelnet::SwarmNotNoNeigh6Result result = modelnet::SwarmNoteNotNoNeigh6(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_with_count_6)
{
    std::string err = "prior";
    modelnet::SwarmNotNoNeigh6 note;
    note.peer_id = "peer-1";
    note.count = 6;
    note.want_add = false;
    const modelnet::SwarmNotNoNeigh6Result result = modelnet::SwarmNoteNotNoNeigh6(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
