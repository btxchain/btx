// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_remedy/remedy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_stores_one_unreleased_revocation)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";
    BOOST_REQUIRE(!remedy.opened());
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());

    BOOST_REQUIRE(!remedy.Open(0, 0x11, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(!remedy.opened());
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 0);
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.has_prior());

    err = "prior";
    BOOST_REQUIRE(!remedy.Open(-3, 0x12, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE(!remedy.opened());
    BOOST_REQUIRE(!remedy.secret_released());

    const modelnet::SwarmRevocation expected = modelnet::SwarmNewRevocation(1, 0x21);
    BOOST_REQUIRE(remedy.Open(1, 0x21, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(remedy.opened());
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 1);
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, expected.hash_hex);
    BOOST_REQUIRE(remedy.current().secret == expected.secret);
    BOOST_REQUIRE(!remedy.has_prior());

    err = "prior";
    BOOST_REQUIRE(!remedy.Open(0, 0x23, err));
    BOOST_REQUIRE_EQUAL(err, "SEQUENCE");
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 1);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, expected.hash_hex);
    BOOST_REQUIRE(!remedy.secret_released());

    err = "prior";
    BOOST_REQUIRE(!remedy.Open(2, 0x22, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 1);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, expected.hash_hex);
    BOOST_REQUIRE(remedy.current().secret == expected.secret);
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
}

BOOST_AUTO_TEST_SUITE_END()
