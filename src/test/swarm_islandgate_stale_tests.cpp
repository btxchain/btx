// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/swarm_islandgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_islandgate_stale_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(epoch_before_now_is_stale_and_stores_nothing)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{9}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 0);
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{-1}, int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(empty_island_is_island_and_stores_nothing)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "ISLAND");
    BOOST_REQUIRE(!plane.admitted(""));
    BOOST_REQUIRE(plane.epoch_of("") == 0);
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("", int64_t{1}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "ISLAND");
    BOOST_REQUIRE(plane.admitted_count() == 0);
    BOOST_REQUIRE(!plane.admitted(""));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(a_later_fresh_admit_after_stale_stores)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{4}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.admitted("isle-a"));

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
