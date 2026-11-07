// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokeymap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnokeymap_tests, BasicTestingSetup)

static modelnet::SwarmNotNoKeyMap NotedNote()
{
    modelnet::SwarmNotNoKeyMap note;
    note.key_id = "key-1";
    note.compromised = false;
    note.want_remap = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmNotNoKeyMap note = NotedNote();
    note.key_id.clear();
    note.compromised = true;
    note.want_remap = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyMapResult result = modelnet::SwarmNoteNotNoKeyMap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(compromised_is_not_remapped)
{
    modelnet::SwarmNotNoKeyMap note = NotedNote();
    note.compromised = true;
    note.want_remap = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyMapResult result = modelnet::SwarmNoteNotNoKeyMap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOT_REMAPPED");
    BOOST_CHECK_EQUAL(err, "NOT_REMAPPED");
}

BOOST_AUTO_TEST_CASE(want_remap_is_held)
{
    modelnet::SwarmNotNoKeyMap note = NotedNote();
    note.compromised = false;
    note.want_remap = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyMapResult result = modelnet::SwarmNoteNotNoKeyMap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoKeyMap note = NotedNote();
    note.compromised = false;
    note.want_remap = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKeyMapResult result = modelnet::SwarmNoteNotNoKeyMap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
