// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_training_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(enable_training_is_held)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE(!node.training());
    BOOST_REQUIRE(!node.private_prompts());

    BOOST_REQUIRE(!node.EnableTraining(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!node.training());
    BOOST_REQUIRE(!node.private_prompts());

    err = "prior";
    BOOST_REQUIRE(!node.EnableTraining(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!node.training());
    BOOST_REQUIRE(!node.private_prompts());
}

BOOST_AUTO_TEST_SUITE_END()
