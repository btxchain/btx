// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoglobal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoglobal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island_id)
{
    modelnet::SwarmNotNoGlobal note;
    note.want_build = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoGlobalResult result = modelnet::SwarmNoteNotNoGlobal(note, err);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(want_build)
{
    modelnet::SwarmNotNoGlobal note;
    note.island_id = "island-a";
    note.want_build = true;
    std::string err;
    const modelnet::SwarmNotNoGlobalResult result = modelnet::SwarmNoteNotNoGlobal(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_BUILT");
    BOOST_CHECK_EQUAL(err, "NOT_BUILT");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoGlobal note;
    note.island_id = "island-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoGlobalResult result = modelnet::SwarmNoteNotNoGlobal(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_SUITE_END()
