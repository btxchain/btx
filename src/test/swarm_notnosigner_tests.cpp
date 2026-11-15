// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosigner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosigner_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSigner NotedNote()
{
    modelnet::SwarmNotNoSigner note;
    note.node_id = "node-1";
    note.want_start = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoSigner note = NotedNote();
    note.node_id.clear();
    note.want_start = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerResult result = modelnet::SwarmNoteNotNoSigner(note, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.signed_block);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_start_is_held)
{
    modelnet::SwarmNotNoSigner note = NotedNote();
    note.want_start = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerResult result = modelnet::SwarmNoteNotNoSigner(note, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.signed_block);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSigner note = NotedNote();
    note.want_start = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSignerResult result = modelnet::SwarmNoteNotNoSigner(note, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK(!result.signed_block);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
