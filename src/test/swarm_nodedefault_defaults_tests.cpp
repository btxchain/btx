// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_defaults_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(defaults_are_readable_from_construction)
{
    modelnet::SwarmNodeDefault node;

    BOOST_REQUIRE(node.modelnet_on());
    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");
    BOOST_REQUIRE(node.dns_seeds().empty());
    BOOST_REQUIRE(!node.training());
    BOOST_REQUIRE(!node.private_prompts());
    BOOST_REQUIRE_EQUAL(node.automatic_spend(), "0");
    BOOST_REQUIRE(!node.armed());
    BOOST_REQUIRE_EQUAL(node.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(node.cpu_threads(), 64);
    BOOST_REQUIRE_EQUAL(node.vram_mib(), 0);
    BOOST_REQUIRE(node.seeder());
    BOOST_REQUIRE(node.evaluator());
    BOOST_REQUIRE_EQUAL(node.slots(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
