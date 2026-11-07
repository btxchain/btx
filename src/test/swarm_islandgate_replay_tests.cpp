// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/swarm_islandgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_islandgate_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_admit_is_replay_and_keeps_the_first_epoch)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(!plane.exchanged());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{80}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_stale_second_admit_is_replay_and_keeps_the_first_epoch)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{30}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Admit("isle-a", int64_t{4}, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 30);
    BOOST_REQUIRE(plane.admitted_count() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_different_island_is_not_a_replay)
{
    modelnet::SwarmIslandGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Admit("isle-a", int64_t{10}, int64_t{10}, err));
    BOOST_REQUIRE(plane.Admit("isle-b", int64_t{12}, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.admitted("isle-a"));
    BOOST_REQUIRE(plane.admitted("isle-b"));
    BOOST_REQUIRE(plane.epoch_of("isle-a") == 10);
    BOOST_REQUIRE(plane.epoch_of("isle-b") == 12);
    BOOST_REQUIRE(plane.admitted_count() == 2);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.exchanged());
}

BOOST_AUTO_TEST_SUITE_END()
