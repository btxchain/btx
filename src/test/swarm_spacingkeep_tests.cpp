// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_spacingkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_spacingkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_chain_is_chain)
{
    modelnet::SwarmSpacingKeep chain;
    chain.want_guarantee = false;
    std::string err = "prior";
    const modelnet::SwarmSpacingKeepResult result = modelnet::SwarmKeepBlockSpacing(chain, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 90);
    BOOST_CHECK_EQUAL(result.code, "CHAIN");
    BOOST_CHECK_EQUAL(err, "CHAIN");
}

BOOST_AUTO_TEST_CASE(guarantee_request_is_held)
{
    modelnet::SwarmSpacingKeep chain;
    chain.chain_id = "main";
    chain.want_guarantee = true;
    std::string err = "prior";
    const modelnet::SwarmSpacingKeepResult result = modelnet::SwarmKeepBlockSpacing(chain, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 90);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(kept_spacing_is_noted)
{
    modelnet::SwarmSpacingKeep chain;
    chain.chain_id = "main";
    chain.want_guarantee = false;
    std::string err = "prior";
    const modelnet::SwarmSpacingKeepResult result = modelnet::SwarmKeepBlockSpacing(chain, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 90);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
