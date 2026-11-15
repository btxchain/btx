// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/hashlock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_hashlock_offer_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(std::size_t n, unsigned char fill)
{
    return std::vector<unsigned char>(n, fill);
}

void RequireSilent(const modelnet::SwarmHashlock& plane)
{
    BOOST_REQUIRE(!plane.qualified());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

} // namespace

BOOST_AUTO_TEST_CASE(empty_id_is_invoice_and_stores_nothing)
{
    modelnet::SwarmHashlock plane;
    std::string err = "prior";
    BOOST_REQUIRE(!plane.Offer("", Bytes(32, 0x11), err));
    BOOST_REQUIRE_EQUAL(err, "INVOICE");
    BOOST_REQUIRE(!plane.offered(""));
    BOOST_REQUIRE(!plane.claimed(""));
    BOOST_REQUIRE_EQUAL(plane.claims(""), 0);
    RequireSilent(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("", Bytes(31, 0x11), err));
    BOOST_REQUIRE_EQUAL(err, "INVOICE");
    BOOST_REQUIRE(!plane.offered(""));
    RequireSilent(plane);
}

BOOST_AUTO_TEST_CASE(payment_hash_size_other_than_32_is_preimage)
{
    modelnet::SwarmHashlock plane;
    std::string err = "prior";
    BOOST_REQUIRE(!plane.Offer("id-1", Bytes(0, 0x22), err));
    BOOST_REQUIRE_EQUAL(err, "PREIMAGE");
    BOOST_REQUIRE(!plane.offered("id-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("id-1", Bytes(31, 0x22), err));
    BOOST_REQUIRE_EQUAL(err, "PREIMAGE");
    BOOST_REQUIRE(!plane.offered("id-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("id-1", Bytes(33, 0x22), err));
    BOOST_REQUIRE_EQUAL(err, "PREIMAGE");
    BOOST_REQUIRE(!plane.offered("id-1"));
    BOOST_REQUIRE(!plane.claimed("id-1"));
    RequireSilent(plane);

    const std::vector<unsigned char> first = Bytes(32, 0x31);
    BOOST_REQUIRE(plane.Offer("id-1", first, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("id-1"));
    BOOST_REQUIRE(!plane.claimed("id-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("id-1", Bytes(31, 0x99), err));
    BOOST_REQUIRE_EQUAL(err, "PREIMAGE");
    std::vector<unsigned char> stored;
    BOOST_REQUIRE(plane.stored_hash("id-1", stored));
    BOOST_REQUIRE(stored == first);
    RequireSilent(plane);
}

BOOST_AUTO_TEST_CASE(duplicate_id_is_replay_and_keeps_the_first_hash)
{
    modelnet::SwarmHashlock plane;
    const std::vector<unsigned char> first = Bytes(32, 0x41);
    const std::vector<unsigned char> second = Bytes(32, 0x42);
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("id-1", first, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Offer("id-2", second, err));

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("id-1", second, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    std::vector<unsigned char> stored;
    BOOST_REQUIRE(plane.stored_hash("id-1", stored));
    BOOST_REQUIRE(stored == first);
    BOOST_REQUIRE(!plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 0);

    stored.assign(1, 0x00);
    BOOST_REQUIRE(plane.stored_hash("id-2", stored));
    BOOST_REQUIRE(stored == second);
    RequireSilent(plane);
}

BOOST_AUTO_TEST_SUITE_END()
