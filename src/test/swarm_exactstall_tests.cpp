// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_exactstall.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_exactstall_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_chain_id_is_chain)
{
    modelnet::SwarmExactStall chain;
    chain.want_mine = true;
    std::string err = "prior";
    const modelnet::SwarmExactStallResult result = modelnet::SwarmHoldExactMine(chain, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
}

BOOST_AUTO_TEST_CASE(want_mine_is_held)
{
    modelnet::SwarmExactStall chain;
    chain.chain_id = "chain-1";
    chain.want_mine = true;
    std::string err = "prior";
    const modelnet::SwarmExactStallResult result = modelnet::SwarmHoldExactMine(chain, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_mine_false_is_noted)
{
    modelnet::SwarmExactStall chain;
    chain.chain_id = "chain-1";
    chain.want_mine = false;
    std::string err = "prior";
    const modelnet::SwarmExactStallResult result = modelnet::SwarmHoldExactMine(chain, err);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
