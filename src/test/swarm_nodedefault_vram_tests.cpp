// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_vram_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(nonzero_vram_claim_is_vram_zero)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);
    BOOST_REQUIRE(!node.ClaimVram(1, err));
    BOOST_REQUIRE_EQUAL(err, "VRAM_ZERO");
    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);

    err = "prior";
    BOOST_REQUIRE(!node.ClaimVram(-1, err));
    BOOST_REQUIRE_EQUAL(err, "VRAM_ZERO");
    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);
}

BOOST_AUTO_TEST_CASE(zero_vram_claim_leaves_zero)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.ClaimVram(0, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
