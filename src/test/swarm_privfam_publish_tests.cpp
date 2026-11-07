// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/swarm_privfam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_privfam_publish_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_family_is_not_published)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("fam-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Publish("fam-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PUBLISHED");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("fam-1"));
    BOOST_REQUIRE(plane.offered("fam-1"));
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.offered_count() == 1);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("fam-1"));
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Publish("fam-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PUBLISHED");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(unknown_family_is_family)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Publish("fam-9", err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("fam-9"));
    BOOST_REQUIRE(!plane.offered("fam-9"));
    BOOST_REQUIRE(!plane.is_private("fam-9"));
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Offer("fam-9", false, err));
    BOOST_REQUIRE_EQUAL(err, "PUBLIC");
    err = "prior";
    BOOST_REQUIRE(!plane.Publish("fam-9", err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(empty_family_publish_is_family)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("fam-1", true, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Publish("", err));
    BOOST_REQUIRE_EQUAL(err, "FAMILY");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published(""));
    BOOST_REQUIRE(plane.offered("fam-1"));
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.offered_count() == 1);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(publish_of_one_family_leaves_another_private)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("fam-1", true, err));
    BOOST_REQUIRE(plane.Offer("fam-2", true, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Publish("fam-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PUBLISHED");
    BOOST_REQUIRE(!plane.published());
    BOOST_REQUIRE(!plane.published("fam-1"));
    BOOST_REQUIRE(!plane.published("fam-2"));
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.is_private("fam-2"));
    BOOST_REQUIRE(plane.offered_count() == 2);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.connected());
}

BOOST_AUTO_TEST_SUITE_END()
