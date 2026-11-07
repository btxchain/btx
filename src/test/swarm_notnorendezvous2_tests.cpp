// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorendezvous2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorendezvous2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_meet_id_is_meet)
{
    modelnet::SwarmNotNoRendezvous2 note;
    note.meet_id.clear();
    note.public_meet = true;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRendezvous2Result result = modelnet::SwarmNoteNotNoRendezvous2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "MEET");
    BOOST_CHECK_EQUAL(err, "MEET");
}

BOOST_AUTO_TEST_CASE(public_meet_is_not_open)
{
    modelnet::SwarmNotNoRendezvous2 note;
    note.meet_id = "meet-1";
    note.public_meet = true;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRendezvous2Result result = modelnet::SwarmNoteNotNoRendezvous2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPEN");
    BOOST_CHECK_EQUAL(err, "NOT_OPEN");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmNotNoRendezvous2 note;
    note.meet_id = "meet-1";
    note.public_meet = false;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRendezvous2Result result = modelnet::SwarmNoteNotNoRendezvous2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRendezvous2 note;
    note.meet_id = "meet-1";
    note.public_meet = false;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRendezvous2Result result = modelnet::SwarmNoteNotNoRendezvous2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
