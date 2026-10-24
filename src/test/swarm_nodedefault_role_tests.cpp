// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_role_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(seeder_evaluator_and_one_slot)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(node.seeder());
    BOOST_REQUIRE(node.evaluator());
    BOOST_REQUIRE_EQUAL(node.slots(), 1);

    BOOST_REQUIRE(!node.DisableModelNet(err));
    BOOST_REQUIRE(!node.EnableTraining(err));
    BOOST_REQUIRE(!node.EnablePrivate(err));
    BOOST_REQUIRE(node.seeder());
    BOOST_REQUIRE(node.evaluator());
    BOOST_REQUIRE_EQUAL(node.slots(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
