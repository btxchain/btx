// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptroute.h>

#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_scriptroute_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_hops_build_pinned_claim_leaves)
{
    const std::vector<unsigned char> hash(32, 0x21);
    const std::vector<unsigned char> key(MLDSA44_PUBKEY_SIZE, 0x02);
    std::string err;
    const modelnet::SwarmScriptRoute short_route = modelnet::SwarmBuildScriptRoute({{hash, key, 100}}, err);
    BOOST_CHECK(!short_route.scripts_ok);
    BOOST_CHECK_EQUAL(err, "HOPS");

    modelnet::SwarmScriptHop early{hash, key, 100};
    modelnet::SwarmScriptHop overlap{hash, key, 200};
    const modelnet::SwarmScriptRoute held = modelnet::SwarmBuildScriptRoute({early, overlap}, err);
    BOOST_CHECK(!held.scripts_ok);
    BOOST_CHECK_EQUAL(err, "TIMEOUT");

    modelnet::SwarmScriptHop later{hash, key, 260};
    const modelnet::SwarmScriptRoute built = modelnet::SwarmBuildScriptRoute({early, later}, err);
    BOOST_CHECK(built.scripts_ok);
    BOOST_CHECK(!built.qualified);
    BOOST_CHECK(!built.secp_penalty);
    BOOST_CHECK_EQUAL(built.scripts.size(), 2U);
    BOOST_CHECK(!built.scripts[0].empty());
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_SUITE_END()
