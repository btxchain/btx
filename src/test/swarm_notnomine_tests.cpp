// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomine.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_chain_id_is_chain)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMine note;
    note.want_mine = true;
    const modelnet::SwarmNotNoMineResult result = modelnet::SwarmNoteNotNoMine(note, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
}

BOOST_AUTO_TEST_CASE(want_mine_is_not_mined)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMine note;
    note.chain_id = "chain-a";
    note.want_mine = true;
    const modelnet::SwarmNotNoMineResult result = modelnet::SwarmNoteNotNoMine(note, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_MINED");
    BOOST_CHECK_EQUAL(err, "NOT_MINED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMine note;
    note.chain_id = "chain-a";
    note.want_mine = false;
    const modelnet::SwarmNotNoMineResult result = modelnet::SwarmNoteNotNoMine(note, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
