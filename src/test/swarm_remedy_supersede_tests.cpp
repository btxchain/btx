// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_remedy/remedy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_supersede_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stale_supersede_leaves_the_open_revocation)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";

    BOOST_REQUIRE(!remedy.Supersede(2, 0x31, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!remedy.opened());
    BOOST_REQUIRE(!remedy.has_prior());
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 0);

    BOOST_REQUIRE(remedy.Open(3, 0x32, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!remedy.secret_released());
    const modelnet::SwarmRevocation opened = remedy.current();

    err = "prior";
    BOOST_REQUIRE(!remedy.Supersede(3, 0x33, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 3);
    BOOST_REQUIRE(remedy.current().secret == opened.secret);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, opened.hash_hex);
    BOOST_REQUIRE(!remedy.has_prior());
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);

    err = "prior";
    BOOST_REQUIRE(!remedy.Supersede(2, 0x34, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 3);
    BOOST_REQUIRE(remedy.current().secret == opened.secret);
    BOOST_REQUIRE(!remedy.secret_released());

    modelnet::SwarmRevocation prior = modelnet::SwarmNewRevocation(3, 0x32);
    const modelnet::SwarmRevocation next = modelnet::SwarmNewRevocation(4, 0x35);
    std::string superseded;
    BOOST_REQUIRE(modelnet::SwarmSupersede(prior, next, superseded));

    BOOST_REQUIRE(remedy.Supersede(4, 0x35, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(remedy.has_prior());
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 4);
    BOOST_REQUIRE_EQUAL(remedy.prior().sequence, prior.sequence);
    BOOST_REQUIRE_EQUAL(remedy.prior().hash_hex, prior.hash_hex);
    BOOST_REQUIRE(remedy.prior().secret == prior.secret);
    BOOST_REQUIRE_EQUAL(remedy.prior().released, prior.released);
    BOOST_REQUIRE_EQUAL(remedy.secret_released(), prior.released);
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, next.hash_hex);
    BOOST_REQUIRE(remedy.current().secret == next.secret);

    err = "prior";
    BOOST_REQUIRE(!remedy.Supersede(4, 0x99, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 4);
    BOOST_REQUIRE_EQUAL(remedy.current().hash_hex, next.hash_hex);
    BOOST_REQUIRE(remedy.current().secret == next.secret);
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE_EQUAL(remedy.prior().hash_hex, prior.hash_hex);
    BOOST_REQUIRE_EQUAL(remedy.secret_released(), prior.released);
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
}

BOOST_AUTO_TEST_SUITE_END()
