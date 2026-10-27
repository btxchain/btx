// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notisland.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notisland_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    std::string err = "prior";
    modelnet::SwarmNotIsland note;
    note.want_publish = true;
    const modelnet::SwarmNotIslandResult result = modelnet::SwarmNoteNotIsland(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotIsland note;
    note.run_id = "run-island";
    note.want_publish = true;
    const modelnet::SwarmNotIslandResult result = modelnet::SwarmNoteNotIsland(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotIsland note;
    note.run_id = "run-island";
    note.want_publish = false;
    const modelnet::SwarmNotIslandResult result = modelnet::SwarmNoteNotIsland(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.delta, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
