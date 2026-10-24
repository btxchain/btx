// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwall.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notwall_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    std::string err = "prior";
    modelnet::SwarmNotWall note;
    note.want_publish = true;
    const modelnet::SwarmNotWallResult result = modelnet::SwarmNoteNotWall(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotWall note;
    note.node_id = "node-wall";
    note.want_publish = true;
    const modelnet::SwarmNotWallResult result = modelnet::SwarmNoteNotWall(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotWall note;
    note.node_id = "node-wall";
    note.want_publish = false;
    const modelnet::SwarmNotWallResult result = modelnet::SwarmNoteNotWall(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.recovered);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
