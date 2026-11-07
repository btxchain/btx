// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/swarm_privfam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_privfam_public_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(public_flag_is_public_and_stores_nothing)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Offer("fam-1", false, err));
    BOOST_REQUIRE_EQUAL(err, "PUBLIC");
    BOOST_REQUIRE(!plane.offered("fam-1"));
    BOOST_REQUIRE(!plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("fam-1"));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("fam-1"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("fam-2", false, err));
    BOOST_REQUIRE_EQUAL(err, "PUBLIC");
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(!plane.offered("fam-1"));
    BOOST_REQUIRE(!plane.offered("fam-2"));
    BOOST_REQUIRE(!plane.is_private("fam-1"));
    BOOST_REQUIRE(!plane.is_private("fam-2"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(public_refusal_does_not_block_a_later_private_offer)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Offer("fam-1", false, err));
    BOOST_REQUIRE_EQUAL(err, "PUBLIC");
    BOOST_REQUIRE(plane.offered_count() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Offer("fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("fam-1"));
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.offered_count() == 1);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(empty_family_is_family_before_public)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Offer("", false, err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
