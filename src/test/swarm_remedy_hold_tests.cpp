// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/remedy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_hold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(revocation_plane_does_not_broadcast)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
    BOOST_REQUIRE(!remedy.secret_released());

    BOOST_REQUIRE(remedy.Open(1, 0x61, err));
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());

    BOOST_REQUIRE(remedy.Supersede(2, 0x62, err));
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
}

BOOST_AUTO_TEST_SUITE_END()
