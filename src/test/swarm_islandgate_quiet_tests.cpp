// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/swarm_islandgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_islandgate_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(gpu_and_launched_stay_false_and_bytes_stay_zero)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(!plane.Admit("", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "ISLAND");
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{1}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.exchanged());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{20}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Exchange(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.admitted_count() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
