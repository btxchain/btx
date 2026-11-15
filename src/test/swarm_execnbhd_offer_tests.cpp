// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_offer_tests, BasicTestingSetup)

static void CheckInert(const modelnet::SwarmExecNeighborhood& plane)
{
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(empty_peer_is_peer_and_stores_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer("", -5, "", false, false, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK(plane.domain_of("").empty());
    BOOST_CHECK(!plane.seated(""));
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{0});
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(negative_rtt_is_rtt_and_stores_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer("peer-a", -1, "", false, false, err));
    BOOST_CHECK_EQUAL(err, "RTT");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK(plane.domain_of("peer-a").empty());
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(empty_domain_is_domain_and_stores_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer("peer-a", 0, "", false, false, err));
    BOOST_CHECK_EQUAL(err, "DOMAIN");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(unauthorized_is_not_authorized_before_compat)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer("peer-a", 1, "dom-a", false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    err = "prior";
    BOOST_CHECK(!plane.Offer("peer-a", 1, "dom-a", false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORIZED");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(incompatible_is_not_compat_and_stores_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.Offer("peer-a", 1, "dom-a", true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK(!plane.seated("peer-a"));
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(offer_stores_the_peer_and_does_not_seat)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("peer-a", 0, "dom-a", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{1});
    BOOST_CHECK_EQUAL(plane.domain_of("peer-a"), "dom-a");
    BOOST_CHECK(!plane.seated("peer-a"));
    BOOST_CHECK(!plane.nearby("peer-a"));
    BOOST_CHECK(!plane.remote("peer-a"));
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.domain_of("missing").empty());
    CheckInert(plane);
}

BOOST_AUTO_TEST_CASE(second_offer_is_replay_and_keeps_the_first_record)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("peer-high", 50, "dom-a", true, true, err));
    BOOST_REQUIRE(plane.Offer("peer-a", 10, "dom-a", true, true, err));
    BOOST_REQUIRE(plane.Offer("peer-b", 20, "dom-a", true, true, err));
    BOOST_REQUIRE(plane.Offer("peer-c", 30, "dom-a", true, true, err));
    BOOST_REQUIRE(plane.Offer("peer-d", 40, "dom-a", true, true, err));

    err = "prior";
    BOOST_CHECK(!plane.Offer("peer-high", 50, "dom-a", true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(plane.domain_of("peer-high"), "dom-a");

    err = "prior";
    BOOST_CHECK(!plane.Offer("peer-high", 1, "dom-z", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{5});
    BOOST_CHECK_EQUAL(plane.domain_of("peer-high"), "dom-a");
    BOOST_CHECK(!plane.seated("peer-high"));

    err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.nearby("peer-a"));
    BOOST_CHECK(plane.nearby("peer-b"));
    BOOST_CHECK(plane.nearby("peer-c"));
    BOOST_CHECK(plane.nearby("peer-d"));
    BOOST_CHECK(!plane.seated("peer-high"));
    BOOST_CHECK_EQUAL(plane.domain_of("peer-high"), "dom-a");
    CheckInert(plane);
}

BOOST_AUTO_TEST_SUITE_END()
