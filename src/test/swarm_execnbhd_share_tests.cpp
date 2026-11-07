// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/swarm_execnbhd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_execnbhd_share_tests, BasicTestingSetup)

static void OfferOk(modelnet::SwarmExecNeighborhood& plane, const std::string& peer, int64_t rtt_ms,
                    const std::string& trust_domain)
{
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer(peer, rtt_ms, trust_domain, true, true, err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(different_domains_are_not_compat_and_move_no_bytes)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "peer-a", 1, "dom-a");
    OfferOk(plane, "peer-b", 2, "dom-b");
    OfferOk(plane, "peer-c", 3, "dom-a");
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(plane.seated("peer-a"));
    BOOST_CHECK(plane.seated("peer-b"));
    BOOST_CHECK(plane.seated("peer-c"));

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("peer-a", "peer-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.connected());
    BOOST_CHECK(!plane.socket_opened());
    BOOST_CHECK(!plane.launched());
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(plane.seated("peer-a"));
    BOOST_CHECK(plane.seated("peer-b"));
}

BOOST_AUTO_TEST_CASE(same_domain_returns_true_and_moves_no_bytes)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "peer-a", 1, "dom-a");
    OfferOk(plane, "peer-c", 3, "dom-a");
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));

    err = "prior";
    BOOST_REQUIRE(plane.ShareKv("peer-a", "peer-c", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.broadcast());
    BOOST_CHECK(!plane.connected());

    err = "prior";
    BOOST_REQUIRE(plane.ShareKv("peer-c", "peer-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(unknown_or_unseated_peer_is_not_seated)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "peer-a", 10, "dom-a");
    OfferOk(plane, "peer-b", 20, "dom-a");
    OfferOk(plane, "peer-c", 30, "dom-a");
    OfferOk(plane, "peer-d", 40, "dom-a");
    OfferOk(plane, "peer-e", 50, "dom-a");
    OfferOk(plane, "peer-held", 60, "dom-a");
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(!plane.seated("peer-e"));
    BOOST_CHECK(plane.domain_of("peer-held") == "dom-a");

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("peer-a", "missing", err));
    BOOST_CHECK_EQUAL(err, "NOT_SEATED");
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("missing", "peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_SEATED");

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("peer-a", "peer-e", err));
    BOOST_CHECK_EQUAL(err, "NOT_SEATED");
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("", "peer-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_SEATED");

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("peer-a", "peer-held", err));
    BOOST_CHECK_EQUAL(err, "NOT_SEATED");
    BOOST_CHECK_EQUAL(plane.atoms_moved(), int64_t{0});
    BOOST_CHECK(!plane.connected());
}

BOOST_AUTO_TEST_CASE(nearby_and_remote_domains_do_not_share)
{
    modelnet::SwarmExecNeighborhood plane;
    OfferOk(plane, "near-a", 1, "dom-near");
    OfferOk(plane, "near-b", 2, "dom-near");
    OfferOk(plane, "near-c", 3, "dom-near");
    OfferOk(plane, "near-d", 4, "dom-near");
    OfferOk(plane, "far-a", 10, "dom-far");
    std::string err = "prior";
    BOOST_REQUIRE(plane.Seat(err));
    BOOST_CHECK(plane.nearby("near-a"));
    BOOST_CHECK(plane.remote("far-a"));

    err = "prior";
    BOOST_CHECK(!plane.ShareKv("near-a", "far-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(plane.bytes_moved(), int64_t{0});
    BOOST_CHECK_EQUAL(plane.automatic_spend(), "0");
    BOOST_CHECK(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
