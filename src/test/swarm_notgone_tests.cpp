// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgone.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgone_tests, BasicTestingSetup)

static modelnet::SwarmNotGone NotedNote()
{
    modelnet::SwarmNotGone note;
    note.coord_id = "coord-1";
    note.want_vanish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_coord_id_is_coord)
{
    modelnet::SwarmNotGone note = NotedNote();
    note.coord_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotGoneResult result = modelnet::SwarmNoteNotGone(note, err);
    BOOST_CHECK(!result.vanished);
    BOOST_CHECK_EQUAL(result.code, "COORD");
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(want_vanish_is_not_injected)
{
    modelnet::SwarmNotGone note = NotedNote();
    note.want_vanish = true;
    std::string err = "prior";
    const modelnet::SwarmNotGoneResult result = modelnet::SwarmNoteNotGone(note, err);
    BOOST_CHECK(!result.vanished);
    BOOST_CHECK_EQUAL(result.code, "NOT_INJECTED");
    BOOST_CHECK_EQUAL(err, "NOT_INJECTED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotGone note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotGoneResult result = modelnet::SwarmNoteNotGone(note, err);
    BOOST_CHECK(!result.vanished);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
