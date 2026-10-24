// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_remote_tests, BasicTestingSetup)

static void OfferOk(modelnet::SwarmExecNeighborhood& plane, const std::string& peer, int64_t rtt_ms,
                    const std::string& trust_domain)
{
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer(peer, rtt_ms, trust_domain, true, true, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(two_absent_domains_are_remote_and_a_third_is_not)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "near-a", 1, "dom-near");
    OfferOk(plane, "near-b", 2, "dom-near");
    OfferOk(plane, "near-c", 3, "dom-near");
    OfferOk(plane, "near-d", 4, "dom-near");
    OfferOk(plane, "near-e", 5, "dom-near");
    OfferOk(plane, "far-a", 10, "dom-far-a");
    OfferOk(plane, "far-b", 11, "dom-far-b");
    OfferOk(plane, "far-c", 12, "dom-far-c");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{2});
    BOOST_CHECK(plane.nearby("near-a"));
    BOOST_CHECK(plane.nearby("near-b"));
    BOOST_CHECK(plane.nearby("near-c"));
    BOOST_CHECK(plane.nearby("near-d"));
    BOOST_CHECK(!plane.nearby("near-e"));
    BOOST_CHECK(!plane.remote("near-e"));
    BOOST_CHECK(!plane.seated("near-e"));
    BOOST_CHECK(plane.remote("far-a"));
    BOOST_CHECK(plane.remote("far-b"));
    BOOST_CHECK(plane.seated("far-a"));
    BOOST_CHECK(plane.seated("far-b"));
    BOOST_CHECK(!plane.nearby("far-a"));
    BOOST_CHECK(!plane.nearby("far-b"));
    BOOST_CHECK(!plane.seated("far-c"));
    BOOST_CHECK(!plane.remote("far-c"));
    BOOST_CHECK(!plane.nearby("far-c"));
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(domain_already_nearby_cannot_fill_a_remote_slot)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "a1", 1, "dom-a");
    OfferOk(plane, "b1", 2, "dom-b");
    OfferOk(plane, "a2", 3, "dom-a");
    OfferOk(plane, "c1", 4, "dom-c");
    OfferOk(plane, "d1", 5, "dom-d");
    OfferOk(plane, "e1", 6, "dom-e");
    OfferOk(plane, "f1", 7, "dom-f");
    OfferOk(plane, "a3", 8, "dom-a");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{2});
    BOOST_CHECK(plane.nearby("a1"));
    BOOST_CHECK(plane.nearby("b1"));
    BOOST_CHECK(plane.nearby("a2"));
    BOOST_CHECK(plane.nearby("c1"));
    BOOST_CHECK(plane.remote("d1"));
    BOOST_CHECK(plane.remote("e1"));
    BOOST_CHECK(!plane.seated("f1"));
    BOOST_CHECK(!plane.seated("a3"));
    BOOST_CHECK(!plane.remote("a3"));
    BOOST_CHECK(!plane.connected());
}

BOOST_AUTO_TEST_CASE(equal_rtt_remote_tie_breaks_by_peer_id)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "near-a", 1, "dom-near");
    OfferOk(plane, "near-b", 2, "dom-near");
    OfferOk(plane, "near-c", 3, "dom-near");
    OfferOk(plane, "near-d", 4, "dom-near");
    OfferOk(plane, "r-c", 20, "dom-c");
    OfferOk(plane, "r-a", 20, "dom-a");
    OfferOk(plane, "r-b", 20, "dom-b");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{2});
    BOOST_CHECK(plane.remote("r-a"));
    BOOST_CHECK(plane.remote("r-b"));
    BOOST_CHECK(!plane.seated("r-c"));
}

BOOST_AUTO_TEST_CASE(one_new_domain_still_returns_true)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "near-a", 1, "dom-near");
    OfferOk(plane, "near-b", 2, "dom-near");
    OfferOk(plane, "near-c", 3, "dom-near");
    OfferOk(plane, "near-d", 4, "dom-near");
    OfferOk(plane, "far-a", 9, "dom-far");

    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.nearby_count(), int64_t{4});
    BOOST_CHECK_EQUAL(plane.remote_count(), int64_t{1});
    BOOST_CHECK(plane.remote("far-a"));
    BOOST_CHECK(!plane.connected());
}

BOOST_AUTO_TEST_SUITE_END()
