// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/swarm_islandgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_islandgate_admit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fresh_epoch_equal_to_now_stores_the_island)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 0);
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.admitted("isle-b"));
    BOOST_REQUIRE(plane.epoch_of("isle-b") == 0);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(later_epoch_stores_the_island)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{40}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 40);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(zero_epoch_at_now_zero_stores_the_island)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{0}, int64_t{0}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 0);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(two_islands_keep_their_own_epochs)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Admit("isle-b", int64_t{25}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.admitted("isle-b"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.epoch_of("isle-b") == 25);
    BOOST_REQUIRE(plane.admitted_count() == 2);
    BOOST_REQUIRE(!plane.admitted("isle-c"));
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
