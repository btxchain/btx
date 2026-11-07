// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_fallback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_is_peer)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Fallback("", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(!plane.seated(""));
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(named_peer_is_not_connected_and_is_not_stored)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Fallback("peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK(!plane.seated("peer-a"));
    BOOST_CHECK(!plane.nearby("peer-a"));
    BOOST_CHECK(!plane.remote("peer-a"));
    BOOST_CHECK(plane.domain_of("peer-a").empty());
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(fallback_does_not_change_an_existing_seat)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("peer-a", 4, "dom-a", true, true, err));
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(plane.seated("peer-a"));

    err = "prior";
    BOOST_CHECK(!plane.Fallback("peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
    BOOST_CHECK(plane.seated("peer-a"));
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{1});
    BOOST_CHECK_EQUAL(plane.domain_of("peer-a"), "dom-a");

    err = "prior";
    BOOST_CHECK(!plane.Fallback("peer-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{1});
    BOOST_CHECK(!plane.seated("peer-b"));
    BOOST_CHECK(plane.domain_of("peer-b").empty());
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
}

BOOST_AUTO_TEST_SUITE_END()
