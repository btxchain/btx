// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoregtest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoregtest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_chain_id)
{
    modelnet::SwarmNotNoRegtest note;
    note.want_mine = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoRegtestResult result = modelnet::SwarmNoteNotNoRegtest(note, err);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(want_mine)
{
    modelnet::SwarmNotNoRegtest note;
    note.chain_id = "chain-a";
    note.want_mine = true;
    std::string err;
    const modelnet::SwarmNotNoRegtestResult result = modelnet::SwarmNoteNotNoRegtest(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_MINED");
    BOOST_CHECK_EQUAL(err, "NOT_MINED");
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoRegtest note;
    note.chain_id = "chain-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoRegtestResult result = modelnet::SwarmNoteNotNoRegtest(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.mined);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_SUITE_END()
