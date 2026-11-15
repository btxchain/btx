// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/swarm_privfam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_privfam_seed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dns_seeds_stay_empty_and_addseed_is_held)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    const std::vector<std::string>& seeds = plane.dns_seeds();
    BOOST_REQUIRE(seeds.empty());
    BOOST_REQUIRE(seeds.size() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.published());

    BOOST_REQUIRE(!plane.AddSeed("label-1", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.dns_seeds().size() == 0);
    BOOST_REQUIRE(!plane.offered("label-1"));
    BOOST_REQUIRE(!plane.is_private("label-1"));
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("label-1"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("label-2", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.offered_count() == 0);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("label-2"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(offer_and_publish_do_not_fill_dns_seeds)
{
    modelnet::SwarmPrivFamily plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Offer("fam-1", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.offered("fam-1"));
    BOOST_REQUIRE(plane.dns_seeds().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Publish("fam-1", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PUBLISHED");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(!plane.published());

    err = "prior";
    BOOST_REQUIRE(!plane.AddSeed("label-1", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.dns_seeds().empty());
    BOOST_REQUIRE(plane.offered("fam-1"));
    BOOST_REQUIRE(plane.is_private("fam-1"));
    BOOST_REQUIRE(plane.offered_count() == 1);
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.connected("fam-1"));
    BOOST_REQUIRE(!plane.connected("label-1"));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
