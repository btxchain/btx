// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrajstore2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotrajstore2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTrajStore2 NotedNote()
{
    modelnet::SwarmNotNoTrajStore2 note;
    note.store_id = "store-1";
    note.want_store = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_store_id_is_store)
{
    modelnet::SwarmNotNoTrajStore2 note = NotedNote();
    note.store_id.clear();
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajStore2Result result = modelnet::SwarmNoteNotNoTrajStore2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STORE");
    BOOST_CHECK_EQUAL(err, "STORE");
}

BOOST_AUTO_TEST_CASE(want_store_is_held)
{
    modelnet::SwarmNotNoTrajStore2 note = NotedNote();
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajStore2Result result = modelnet::SwarmNoteNotNoTrajStore2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTrajStore2 note = NotedNote();
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTrajStore2Result result = modelnet::SwarmNoteNotNoTrajStore2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
