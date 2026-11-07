// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoowner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoowner_tests, BasicTestingSetup)

static modelnet::SwarmNotNoOwner NotedNote()
{
    modelnet::SwarmNotNoOwner note;
    note.owner_id = "owner-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_owner_id_is_owner)
{
    modelnet::SwarmNotNoOwner note = NotedNote();
    note.owner_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOwnerResult result = modelnet::SwarmNoteNotNoOwner(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "OWNER");
    BOOST_CHECK_EQUAL(err, "OWNER");
}

BOOST_AUTO_TEST_CASE(want_move_is_refused)
{
    modelnet::SwarmNotNoOwner note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOwnerResult result = modelnet::SwarmNoteNotNoOwner(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoOwner note = NotedNote();
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOwnerResult result = modelnet::SwarmNoteNotNoOwner(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
