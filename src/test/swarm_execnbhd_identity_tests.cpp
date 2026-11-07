// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_identity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_neighborhood_and_stores_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    BOOST_CHECK(plane.identity().empty());
    std::string err = "prior";
    BOOST_CHECK(!plane.Identity("", err));
    BOOST_CHECK_EQUAL(err, "NEIGHBORHOOD");
    BOOST_CHECK(plane.identity().empty());
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(first_id_is_stored)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Identity("nb-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.identity(), "nb-1");
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(same_id_is_replay_and_different_id_is_held)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Identity("nb-1", err));

    err = "prior";
    BOOST_CHECK(!plane.Identity("nb-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(plane.identity(), "nb-1");

    err = "prior";
    BOOST_CHECK(!plane.Identity("nb-2", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(plane.identity(), "nb-1");

    err = "prior";
    BOOST_CHECK(!plane.Identity("", err));
    BOOST_CHECK_EQUAL(err, "NEIGHBORHOOD");
    BOOST_CHECK_EQUAL(plane.identity(), "nb-1");
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
