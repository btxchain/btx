// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoglobalck.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoglobalck_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island_id)
{
    modelnet::SwarmNotNoGlobalCk note;
    note.want_checkpoint = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoGlobalCkResult result = modelnet::SwarmNoteNotNoGlobalCk(note, err);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(want_checkpoint)
{
    modelnet::SwarmNotNoGlobalCk note;
    note.island_id = "island-a";
    note.want_checkpoint = true;
    std::string err;
    const modelnet::SwarmNotNoGlobalCkResult result = modelnet::SwarmNoteNotNoGlobalCk(note, err);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoGlobalCk note;
    note.island_id = "island-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoGlobalCkResult result = modelnet::SwarmNoteNotNoGlobalCk(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.saved);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_SUITE_END()
