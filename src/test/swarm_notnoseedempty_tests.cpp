// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedempty.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoseedempty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoSeedEmpty note;
    note.want_seed = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedEmptyResult result = modelnet::SwarmNoteNotNoSeedEmpty(note, err);
    BOOST_CHECK(!result.seeded);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_seed_is_empty)
{
    modelnet::SwarmNotNoSeedEmpty note;
    note.node_id = "node-1";
    note.want_seed = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedEmptyResult result = modelnet::SwarmNoteNotNoSeedEmpty(note, err);
    BOOST_CHECK(!result.seeded);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSeedEmpty note;
    note.node_id = "node-1";
    note.want_seed = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedEmptyResult result = modelnet::SwarmNoteNotNoSeedEmpty(note, err);
    BOOST_CHECK(!result.seeded);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
