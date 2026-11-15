// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/remedy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_watch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(watched_sequence_does_not_release_the_secret)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";
    BOOST_REQUIRE(remedy.Open(2, 0x51, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);

    const modelnet::SwarmRemedyReport stale = remedy.Watch(1, 100, 1000);
    BOOST_REQUIRE_EQUAL(stale.action, "STALE_STATE_ALERT");
    BOOST_REQUIRE(!stale.hashlock_remedy);
    BOOST_REQUIRE(!stale.secp_penalty);
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE_EQUAL(remedy.sequence(), 2);

    const modelnet::SwarmRemedyReport quiet = remedy.Watch(2, 100, 1000);
    BOOST_REQUIRE_EQUAL(quiet.action, "OBSERVE");
    BOOST_REQUIRE(!quiet.hashlock_remedy);
    BOOST_REQUIRE(!remedy.secret_released());
    BOOST_REQUIRE(!remedy.current().released);
    BOOST_REQUIRE(!remedy.has_prior());
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
}

BOOST_AUTO_TEST_SUITE_END()
