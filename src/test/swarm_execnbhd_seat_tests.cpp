// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_seat_tests, BasicTestingSetup)

static void OfferOk(modelnet::SwarmExecNeighborhood& plane, const std::string& peer, int64_t rtt_ms,
                    const std::string& trust_domain)
{
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer(peer, rtt_ms, trust_domain, true, true, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(five_peers_in_one_domain_seat_four_nearby)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "peer-c", 30, "dom-a");
    OfferOk(plane, "peer-a", 10, "dom-a");
    OfferOk(plane, "peer-e", 50, "dom-a");
    OfferOk(plane, "peer-b", 20, "dom-a");
    OfferOk(plane, "peer-d", 40, "dom-a");
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.nearby("peer-a"));
    BOOST_CHECK(plane.nearby("peer-b"));
    BOOST_CHECK(plane.nearby("peer-c"));
    BOOST_CHECK(plane.nearby("peer-d"));
    BOOST_CHECK(plane.seated("peer-a"));
    BOOST_CHECK(plane.seated("peer-d"));
    BOOST_CHECK(!plane.seated("peer-e"));
    BOOST_CHECK(!plane.nearby("peer-e"));
    BOOST_CHECK(!plane.remote("peer-e"));
    BOOST_CHECK(!plane.remote("peer-a"));
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(equal_rtt_tie_breaks_by_ascending_peer_id)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "id-b", 5, "dom-a");
    OfferOk(plane, "id-e", 5, "dom-a");
    OfferOk(plane, "id-a", 5, "dom-a");
    OfferOk(plane, "id-d", 5, "dom-a");
    OfferOk(plane, "id-c", 5, "dom-a");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.nearby("id-a"));
    BOOST_CHECK(plane.nearby("id-b"));
    BOOST_CHECK(plane.nearby("id-c"));
    BOOST_CHECK(plane.nearby("id-d"));
    BOOST_CHECK(!plane.seated("id-e"));
    BOOST_CHECK(!plane.connected());
}

BOOST_AUTO_TEST_CASE(boundary_tie_uses_bytewise_peer_id)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "p-1", 1, "dom-a");
    OfferOk(plane, "p-3", 2, "dom-a");
    OfferOk(plane, "p-4", 3, "dom-a");
    OfferOk(plane, "p-9", 8, "dom-a");
    OfferOk(plane, "p-10", 8, "dom-a");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.nearby("p-1"));
    BOOST_CHECK(plane.nearby("p-3"));
    BOOST_CHECK(plane.nearby("p-4"));
    // '1' precedes '9', so p-10 is seated and p-9 is left out.
    BOOST_CHECK(plane.nearby("p-10"));
    BOOST_CHECK(!plane.seated("p-9"));
}

BOOST_AUTO_TEST_CASE(fewer_than_four_still_seats_and_seat_replaces)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "peer-z", 100, "dom-a");
    OfferOk(plane, "peer-y", 90, "dom-a");
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{2});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.seated("peer-z"));
    BOOST_CHECK(plane.seated("peer-y"));

    OfferOk(plane, "peer-a", 1, "dom-a");
    OfferOk(plane, "peer-b", 2, "dom-a");
    OfferOk(plane, "peer-c", 3, "dom-a");
    OfferOk(plane, "peer-d", 4, "dom-a");
    err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(plane.nearby("peer-a"));
    BOOST_CHECK(plane.nearby("peer-b"));
    BOOST_CHECK(plane.nearby("peer-c"));
    BOOST_CHECK(plane.nearby("peer-d"));
    BOOST_CHECK(!plane.seated("peer-z"));
    BOOST_CHECK(!plane.seated("peer-y"));
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
}

BOOST_AUTO_TEST_CASE(empty_book_seats_nothing)
{
    modelnet::SwarmExecNeighborhood plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.offered_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{0});
    BOOST_CHECK(!plane.connected());
}

BOOST_AUTO_TEST_SUITE_END()
