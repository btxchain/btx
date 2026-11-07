// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nothashleaf.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nothashleaf_tests, BasicTestingSetup)

static modelnet::SwarmNotHashLeaf NotedNote()
{
    modelnet::SwarmNotHashLeaf note;
    note.channel_id = "channel-1";
    note.want_build = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotHashLeaf note = NotedNote();
    note.channel_id.clear();
    note.want_build = true;
    std::string err = "prior";
    const modelnet::SwarmNotHashLeafResult result = modelnet::SwarmNoteNotHashLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_build_is_not_built)
{
    modelnet::SwarmNotHashLeaf note = NotedNote();
    note.want_build = true;
    std::string err = "prior";
    const modelnet::SwarmNotHashLeafResult result = modelnet::SwarmNoteNotHashLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_BUILT");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "NOT_BUILT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotHashLeaf note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotHashLeafResult result = modelnet::SwarmNoteNotHashLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
