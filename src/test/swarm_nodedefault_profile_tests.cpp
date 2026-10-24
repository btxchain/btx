// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nodedefault_profile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rename_profile_is_held)
{
    modelnet::SwarmNodeDefault node;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");

    BOOST_REQUIRE(!node.RenameProfile("other", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");

    err = "prior";
    BOOST_REQUIRE(!node.RenameProfile("", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");

    err = "prior";
    BOOST_REQUIRE(!node.RenameProfile("BTX035-LAUNCH-DECODER-2x64", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(node.launch_profile(), "BTX035-LAUNCH-DECODER-2x64");
}

BOOST_AUTO_TEST_SUITE_END()
