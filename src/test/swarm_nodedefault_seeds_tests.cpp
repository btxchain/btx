// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_seeds_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(add_seed_is_held)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.dns_seeds().empty());

    BOOST_REQUIRE(!node.AddSeed("label", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(node.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!node.AddSeed("", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(node.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!node.AddSeed("other-label", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(node.dns_seeds().empty());
}

BOOST_AUTO_TEST_SUITE_END()
