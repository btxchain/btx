// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoidremap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoidremap_tests, BasicTestingSetup)

static modelnet::SwarmNotNoIdRemap NotedNote()
{
    modelnet::SwarmNotNoIdRemap note;
    note.key_id = "key-1";
    note.compromised = false;
    note.want_remap = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_key_id_is_key)
{
    modelnet::SwarmNotNoIdRemap note = NotedNote();
    note.key_id.clear();
    note.compromised = true;
    note.want_remap = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdRemapResult result = modelnet::SwarmNoteNotNoIdRemap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "KEY");
    BOOST_CHECK_EQUAL(err, "KEY");
}

BOOST_AUTO_TEST_CASE(compromised_is_identity_remap)
{
    modelnet::SwarmNotNoIdRemap note = NotedNote();
    note.compromised = true;
    note.want_remap = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdRemapResult result = modelnet::SwarmNoteNotNoIdRemap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "IDENTITY_REMAP");
    BOOST_CHECK_EQUAL(err, "IDENTITY_REMAP");
}

BOOST_AUTO_TEST_CASE(want_remap_is_held)
{
    modelnet::SwarmNotNoIdRemap note = NotedNote();
    note.compromised = false;
    note.want_remap = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdRemapResult result = modelnet::SwarmNoteNotNoIdRemap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoIdRemap note = NotedNote();
    note.compromised = false;
    note.want_remap = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIdRemapResult result = modelnet::SwarmNoteNotNoIdRemap(note, err);
    BOOST_CHECK(!result.remapped);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
